import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import http2 from 'node:http2';
import tlsClient from 'node:tls';
import vm from 'node:vm';
import { validateAuthority, requestKey, createReplayProxy } from './replay-proxy.mjs';
import { benchmarkTls } from './tls.mjs';

test('CONNECT accepts only the npm registry TLS authority', () => {
  validateAuthority('registry.npmjs.org:443', true);
  for (const authority of ['registry.npmjs.org:80', 'other.test:443', 'user@registry.npmjs.org:443', 'registry.npmjs.org.:443']) {
    assert.throws(() => validateAuthority(authority, true));
  }
});

test('inner request rejects credentials and origin confusion without normalizing encoded names', () => {
  const request = { method: 'GET', url: '/@nestjs%2fcore/latest', headers: { host: 'registry.npmjs.org', accept: 'application/json' } };
  assert.equal(requestKey(request)[1], request.url);
  for (const name of ['authorization', 'proxy-authorization', 'cookie']) assert.throws(() => requestKey({ ...request, headers: { ...request.headers, [name]: 'sentinel' } }));
  for (const url of ['https://other.test/package', '//other.test/package', '/%2e%2e/package', '/package?token=sentinel', '/package#fragment']) assert.throws(() => requestKey({ ...request, url }));
  assert.throws(() => requestKey({ ...request, method: 'POST' }));
  assert.throws(() => requestKey({ ...request, headers: { host: 'other.test' } }));
  assert.throws(() => requestKey({ ...request, headers: { ':authority': 'registry.npmjs.org', host: 'other.test' } }));
});

test('benchmark child environment replaces proxy bypasses and excludes inherited credentials', () => {
  const source = fs.readFileSync(new URL('./runner.mjs', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('function managerEnv('), source.indexOf('function verifyInstalledProject('));
  const scope = { path, config: { registry: 'http://127.0.0.1:12345', ca: '/isolated/ca.pem' }, activeExtraEnv: {},
    homeDir: () => '/isolated/home', lpmHomeDir: () => '/isolated/lpm',
    process: { env: { HOME: '/real/home', NO_PROXY: '*', no_proxy: 'npmjs.org', HTTPS_PROXY: 'http://wrong:123',
      https_proxy: 'http://wrong:456', LPM_TOKEN: 'sentinel', NPM_TOKEN: 'sentinel', NODE_AUTH_TOKEN: 'sentinel',
      NPM_CONFIG_USERCONFIG: '/real/home/.npmrc', npm_config__authToken: 'sentinel' } } };
  vm.runInNewContext(body + '\nthis.result = managerEnv("lpm", "/isolated");', scope);
  const env = scope.result;
  for (const name of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy']) assert.equal(env[name], scope.config.registry);
  for (const name of ['NO_PROXY', 'no_proxy']) assert.equal(env[name], '');
  for (const name of ['LPM_TOKEN', 'NPM_TOKEN', 'NODE_AUTH_TOKEN', 'npm_config__authToken']) assert.equal(env[name], undefined);
  assert.equal(env.HOME, '/isolated/home');
  assert.equal(env.NPM_CONFIG_USERCONFIG, '/isolated/home/.npmrc');
  assert.equal(env.NODE_EXTRA_CA_CERTS, '/isolated/ca.pem');
});

test('runner stops when registry control rejects fixture validation', async () => {
  const source = fs.readFileSync(new URL('./runner.mjs', import.meta.url), 'utf8');
  const helper = source.indexOf('async function control(');
  const start = helper >= 0 ? helper : source.indexOf("await fetch(config.registry+'/_control'");
  const code = source.slice(start, source.indexOf('\nconst rows=[];'));
  const scope = { assert, config: { registry: 'http://127.0.0.1:1' }, fetch: async () => ({ ok: false, status: 400, text: async () => 'changed fixture' }) };
  await assert.rejects(vm.runInNewContext('(async () => {' + code + '})()', scope), /registry control failed/);
});

test('frozen proxy rejects unknown requests and protects captured body hashes', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-proxy-test-'));
  const tls = benchmarkTls(root);
  const directory = path.join(root, 'fixtures'); fs.mkdirSync(directory);
  const body = Buffer.from('{"name":"fixed"}');
  const request = ['GET', '/fixed', 'application/json'];
  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  const base = path.join(directory, hash(JSON.stringify(request)));
  fs.writeFileSync(base + '.body', body);
  fs.writeFileSync(base + '.json', JSON.stringify({ request, status: 200, content_type: 'application/json', json: true, bytes: body.length, sha256: hash(body), headers: {} }));
  const proxy = await createReplayProxy({ ...tls, directory });
  let session;
  try {
    proxy.freeze();
    const socket = await new Promise((resolve, reject) => {
      const req = http.request(proxy.url, { method: 'CONNECT', path: 'registry.npmjs.org:443' });
      req.on('connect', (response, socket) => response.statusCode === 200 ? resolve(socket) : reject(new Error('CONNECT rejected')));
      req.on('error', reject); req.end();
    });
    session = http2.connect('https://registry.npmjs.org', { createConnection: () => tlsClient.connect({ socket,
      servername: 'registry.npmjs.org', ca: fs.readFileSync(tls.ca), ALPNProtocols: ['h2'] }) });
    async function get(target, extra = {}) {
      return new Promise((resolve, reject) => {
        const req = session.request({ ':path': target, accept: 'application/json', ...extra });
        let status; const chunks = [];
        req.on('response', headers => { status = headers[':status']; });
        req.on('data', chunk => chunks.push(chunk)); req.on('error', reject);
        req.on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() })); req.end();
      });
    }
    assert.deepEqual(await get('/fixed'), { status: 200, body: body.toString() });
    assert.equal((await get('/missing')).status, 502);
    assert.equal((await get('/fixed', { authorization: 'sentinel' })).status, 502);
    assert.equal((await get('/fixed', { ':authority': 'other.test' })).status, 502);
    assert.equal(proxy.status().misses.length, 1);
    assert.equal(proxy.status().events[0].http_version, '2.0');
    assert.equal(proxy.status().upstreamRequests, 0);
    const response = await fetch(proxy.url + '/_control', { method: 'POST', body: JSON.stringify({ frozen: false }) });
    assert.equal(response.status, 400);
    assert.equal(proxy.status().frozen, true);
    fs.chmodSync(base + '.body', 0o644); fs.writeFileSync(base + '.body', 'corrupt');
    const changed = await fetch(proxy.url + '/_control', { method: 'POST', body: JSON.stringify({ phase: 'next' }) });
    assert.equal(changed.status, 400);
    assert.match(await changed.text(), /stored fixture hash mismatch/);
  } finally { session?.destroy(); await proxy.close(); tls.close(); }
  fs.chmodSync(base + '.body', 0o644); fs.writeFileSync(base + '.body', 'corrupt');
  const otherTls = benchmarkTls(root);
  try { await assert.rejects(createReplayProxy({ ...otherTls, directory,
    expectedManifestSha256: hash(fs.readFileSync(path.join(directory, 'manifest.json'))) }), /fixture hash mismatch/); }
  finally { otherTls.close(); fs.rmSync(root, { recursive: true }); }
});

test('startup rejects coordinated fixture replacement against the pinned capture manifest', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-proxy-pin-test-'));
  const tls = benchmarkTls(root);
  const directory = path.join(root, 'fixtures'); fs.mkdirSync(directory);
  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  const request = ['GET', '/fixed', 'application/json'];
  const original = Buffer.from('{"name":"original"}');
  const body = Buffer.from('{"name":"changed"}');
  const meta = { request, status: 200, content_type: 'application/json', json: true, bytes: original.length, sha256: hash(original), headers: {} };
  const expectedManifestSha256 = hash(JSON.stringify([meta], null, 2));
  meta.bytes = body.length; meta.sha256 = hash(body);
  const base = path.join(directory, hash(JSON.stringify(request)));
  fs.writeFileSync(base + '.body', body);
  fs.writeFileSync(base + '.json', JSON.stringify(meta));
  fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify([meta], null, 2));
  let unexpected;
  try {
    await assert.rejects(async () => { unexpected = await createReplayProxy({ ...tls, directory, expectedManifestSha256 }); }, /pinned capture manifest mismatch/);
  } finally { await unexpected?.close(); tls.close(); fs.rmSync(root, { recursive: true }); }
});

test('queued large tarball does not reject a concurrent metadata stream', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-proxy-capacity-'));
  const tls = benchmarkTls(root);
  const directory = path.join(root, 'fixtures'); fs.mkdirSync(directory);
  const hash = value => crypto.createHash('sha256').update(value).digest('hex');
  for (const [target, body, json] of [
    ['/large.tgz', Buffer.alloc(12 * 1024 * 1024, 1), false],
    ['/small', Buffer.from('{"name":"small"}'), true],
  ]) {
    const request = ['GET', target, '*/*'];
    const base = path.join(directory, hash(JSON.stringify(request)));
    fs.writeFileSync(base + '.body', body);
    fs.writeFileSync(base + '.json', JSON.stringify({ request, status: 200,
      content_type: json ? 'application/json' : 'application/octet-stream', json,
      bytes: body.length, sha256: hash(body), headers: {} }));
  }
  let proxy, session;
  try {
    proxy = await createReplayProxy({ ...tls, directory }); proxy.freeze();
    const socket = await new Promise((resolve, reject) => {
      const req = http.request(proxy.url, { method: 'CONNECT', path: 'registry.npmjs.org:443' });
      req.on('connect', (response, socket) => response.statusCode === 200 ? resolve(socket) : reject(new Error('CONNECT rejected')));
      req.on('error', reject); req.end();
    });
    session = http2.connect('https://registry.npmjs.org', { settings: { initialWindowSize: 16 * 1024 },
      createConnection: () => tlsClient.connect({ socket, servername: 'registry.npmjs.org',
        ca: fs.readFileSync(tls.ca), ALPNProtocols: ['h2'] }) });
    session.on('error', () => {});
    await new Promise((resolve, reject) => { session.once('connect', resolve); session.once('error', reject); });
    session.setLocalWindowSize(32 * 1024 * 1024);
    const large = session.request({ ':path': '/large.tgz', accept: '*/*' });
    large.on('error', () => {}); large.pause();
    await new Promise((resolve, reject) => {
      large.once('response', headers => headers[':status'] === 200 ? resolve() : reject(new Error('large response failed')));
      large.once('error', reject); large.end();
    });
    const metadata = await new Promise((resolve, reject) => {
      const req = session.request({ ':path': '/small', accept: '*/*' }, { signal: AbortSignal.timeout(5000) });
      let status; const chunks = [];
      req.on('response', headers => { status = headers[':status']; });
      req.on('data', chunk => chunks.push(chunk)); req.on('error', reject);
      req.on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() })); req.end();
    });
    assert.deepEqual(metadata, { status: 200, body: '{"name":"small"}' });
    assert.equal(large.readableEnded, false);
    const largeDigest = await new Promise((resolve, reject) => {
      const digest = crypto.createHash('sha256');
      large.on('data', chunk => digest.update(chunk));
      large.on('end', () => resolve(digest.digest('hex'))); large.once('error', reject); large.resume();
    });
    assert.equal(largeDigest, hash(Buffer.alloc(12 * 1024 * 1024, 1)));
    assert.equal(proxy.status().upstreamRequests, 0);
    assert.deepEqual(proxy.status().misses, []);
    assert.deepEqual(proxy.status().rejected, []);
  } finally { session?.destroy(); await proxy?.close(); tls.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
