import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

const digest = value => crypto.createHash('sha256').update(value).digest('hex');
export function validateAuthority(authority, connect = false) {
  if (!(connect ? /^registry\.npmjs\.org:443$/i : /^registry\.npmjs\.org(?::443)?$/i).test(authority ?? '')) {
    throw new Error('unexpected authority');
  }
}

export function requestKey(request) {
  validateAuthority(request.headers[':authority'] ?? request.headers.host);
  if (request.headers.host !== undefined) validateAuthority(request.headers.host);
  for (const name of ['authorization', 'proxy-authorization', 'cookie']) {
    if (request.headers[name] !== undefined) throw new Error('credential-bearing request');
  }
  if (request.method !== 'GET') throw new Error('unexpected method');
  const target = request.url;
  if (!target.startsWith('/') || target.startsWith('//') || /[?#\\\s]/.test(target)) throw new Error('unexpected request target');
  if (decodeURIComponent(target).split('/').some(part => part === '.' || part === '..')) throw new Error('dot path segment');
  return ['GET', target, String(request.headers.accept ?? '*/*')];
}

export async function createReplayProxy({ directory, key, cert, expectedManifestSha256 }) {
  fs.mkdirSync(directory, { recursive: true });
  const manifestPath = path.join(directory, 'manifest.json');
  if (fs.existsSync(manifestPath) && digest(fs.readFileSync(manifestPath)) !== expectedManifestSha256) {
    throw new Error('pinned capture manifest mismatch');
  }
  const entries = new Map();
  const pending = new Map();
  const events = [];
  const misses = [];
  const rejected = [];
  const captures = [];
  let frozen = false;
  let phase = 'capture';
  let upstreamRequests = 0;
  const sockets = new Set();
  const agent = new https.Agent({ keepAlive: true });
  const fixturePath = request => path.join(directory, digest(JSON.stringify(request)));

  function verifyEntry(entry) {
    if (digest(entry.body) !== entry.meta.sha256 || entry.body.length !== entry.meta.bytes) throw new Error('fixture hash mismatch');
    const base = fixturePath(entry.meta.request);
    if (digest(fs.readFileSync(base + '.body')) !== entry.meta.sha256) throw new Error('stored fixture hash mismatch');
    if (JSON.stringify(JSON.parse(fs.readFileSync(base + '.json'))) !== JSON.stringify(entry.meta)) throw new Error('stored metadata mismatch');
  }

  function loadEntry(base) {
    const meta = JSON.parse(fs.readFileSync(base + '.json', 'utf8'));
    const body = fs.readFileSync(base + '.body');
    const entry = { meta, body };
    verifyEntry(entry);
    entry.gzip = meta.json ? zlib.gzipSync(body) : undefined;
    return entry;
  }

  for (const filename of fs.readdirSync(directory).filter(name => name.endsWith('.json') && /^[a-f0-9]{64}\.json$/.test(name))) {
    const entry = loadEntry(path.join(directory, filename.slice(0, -5)));
    entries.set(JSON.stringify(entry.meta.request), entry);
  }

  async function capture(request) {
    upstreamRequests += 1;
    const response = await new Promise((resolve, reject) => {
      const req = https.request({ hostname: 'registry.npmjs.org', port: 443, method: 'GET', path: request[1], agent,
        headers: { Accept: request[2], 'Accept-Encoding': 'identity' } }, res => {
        const chunks = [];
        let bytes = 0;
        res.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > 128 * 1024 * 1024) res.destroy(new Error('fixture response too large'));
          else chunks.push(chunk);
        });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on('error', reject);
      });
      req.setTimeout(60000, () => req.destroy(new Error('capture timeout')));
      req.on('error', reject);
      req.end();
    });
    captures.push({ request, status: response.status, bytes: response.body.length });
    if (![200, 404].includes(response.status)) throw new Error(`upstream capture status ${response.status}`);
    const contentType = response.headers['content-type'] ?? 'application/octet-stream';
    const meta = { request, status: response.status, content_type: contentType, json: contentType.includes('json'),
      bytes: response.body.length, sha256: digest(response.body), headers: Object.fromEntries(
        ['cache-control', 'etag', 'last-modified', 'vary'].filter(name => response.headers[name] !== undefined).map(name => [name, response.headers[name]])) };
    const base = fixturePath(request);
    fs.writeFileSync(base + '.body', response.body);
    fs.writeFileSync(base + '.json', JSON.stringify(meta, null, 2));
    return loadEntry(base);
  }

  function freeze() {
    for (const entry of entries.values()) {
      verifyEntry(entry);
      const base = fixturePath(entry.meta.request);
      fs.chmodSync(base + '.body', 0o444);
      fs.chmodSync(base + '.json', 0o444);
    }
    const manifest = JSON.stringify([...entries.values()].map(entry => entry.meta).sort((a, b) => JSON.stringify(a.request).localeCompare(JSON.stringify(b.request))), null, 2);
    if (fs.existsSync(path.join(directory, 'manifest.json'))) {
      if (fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8') !== manifest) throw new Error('capture manifest mismatch');
    } else fs.writeFileSync(path.join(directory, 'manifest.json'), manifest);
    fs.chmodSync(path.join(directory, 'manifest.json'), 0o444);
    frozen = true;
  }

  if (fs.existsSync(path.join(directory, 'manifest.json'))) freeze();

  function status() {
    return { frozen, phase, upstreamRequests, fixtures: entries.size, events, misses, rejected, captures };
  }

  // Queued tarball bodies count toward session credit even when a stream is flow-controlled.
  const tlsServer = http2.createSecureServer({ key, cert, allowHTTP1: true,
    maxSessionMemory: 1024, settings: { maxConcurrentStreams: 256 } });
  tlsServer.on('secureConnection', socket => {
    if (socket.servername !== 'registry.npmjs.org') {
      rejected.push({ phase, reason: 'unexpected SNI' });
      socket.destroy();
    }
  });
  tlsServer.on('sessionError', error => rejected.push({ phase, reason: error.code ?? 'HTTP/2 session error' }));
  tlsServer.on('request', async (req, res) => {
    const requestPhase = phase;
    const received = process.hrtime.bigint();
    try {
      if (req.socket.servername !== 'registry.npmjs.org') throw new Error('unexpected SNI');
      const request = requestKey(req);
      const encoded = JSON.stringify(request);
      let entry = entries.get(encoded);
      if (!entry) {
        if (frozen) {
          misses.push({ phase: requestPhase, request });
          throw new Error('uncaptured response');
        }
        if (!pending.has(encoded)) pending.set(encoded, capture(request).then(value => { entries.set(encoded, value); return value; }).finally(() => pending.delete(encoded)));
        entry = await pending.get(encoded);
      }
      const useGzip = entry.gzip && /\bgzip\b/.test(req.headers['accept-encoding'] ?? '');
      const body = useGzip ? entry.gzip : entry.body;
      res.writeHead(entry.meta.status, { ...entry.meta.headers, 'content-type': entry.meta.content_type,
        'content-length': body.length, ...(useGzip ? { 'content-encoding': 'gzip' } : {}) });
      res.on('finish', () => events.push({ phase: requestPhase, request, status: entry.meta.status, sha256: entry.meta.sha256,
        bytes: entry.body.length, wire_bytes: body.length, gzip: !!useGzip, http_version: req.httpVersion,
        received_ns: Number(received), completed_ns: Number(process.hrtime.bigint()) }));
      res.end(body);
    } catch (error) {
      rejected.push({ phase: requestPhase, reason: error.message });
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('frozen registry request rejected');
    }
  });
  await new Promise(resolve => tlsServer.listen(0, '127.0.0.1', resolve));
  const server = http.createServer(async (req, res) => {
    try {
      for (const name of ['authorization', 'proxy-authorization', 'cookie']) if (req.headers[name] !== undefined) throw new Error('credential-bearing control');
      if (req.method === 'GET' && req.url === '/_status') {
        res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(status())); return;
      }
      if (req.method !== 'POST' || req.url !== '/_control') throw new Error('unexpected control request');
      let body = '';
      for await (const chunk of req) { body += chunk; if (body.length > 4096) throw new Error('control body too large'); }
      const value = JSON.parse(body);
      if (value.frozen === false && frozen) throw new Error('cannot unfreeze');
      if (value.frozen && !frozen) freeze();
      if (frozen) freeze();
      phase = value.phase ?? phase;
      res.writeHead(200, { 'content-length': '0' }); res.end();
    } catch (error) { res.writeHead(400); res.end(error.message); }
  });
  server.on('connect', (req, client, head) => {
    try {
      validateAuthority(req.url, true);
      for (const name of ['authorization', 'proxy-authorization', 'cookie']) if (req.headers[name] !== undefined) throw new Error('credential-bearing CONNECT');
    } catch (error) {
      rejected.push({ phase, reason: error.message }); client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); return;
    }
    const target = net.connect(tlsServer.address().port, '127.0.0.1', () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) target.write(head);
      client.pipe(target); target.pipe(client);
    });
    for (const socket of [target, client]) { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); }
    client.on('error', () => target.destroy()); target.on('error', () => client.destroy());
    client.on('close', () => target.destroy()); target.on('close', () => client.destroy());
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, status, freeze,
    close: async () => { agent.destroy(); for (const socket of sockets) socket.destroy();
      await Promise.all([server, tlsServer].map(value => new Promise(resolve => value.close(resolve)))); } };
}
