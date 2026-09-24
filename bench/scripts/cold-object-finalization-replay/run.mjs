import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReplayProxy } from './replay-proxy.mjs';
import { benchmarkTls } from './tls.mjs';

const root = '/tmp/lpm-cold-nest-isolation';
const preparation = process.argv.includes('--prepare');
const preflight = process.argv.includes('--preflight');
const stage = preparation ? 'prepare' : preflight ? 'preflight' : 'scored';
const anchorPath = path.join(root, 'capture-manifest-sha256.json');
const expectedManifestSha256 = fs.existsSync(anchorPath) ? JSON.parse(fs.readFileSync(anchorPath)).sha256 : undefined;
if (!preparation && !expectedManifestSha256) throw new Error('scoring requires a pinned capture manifest');
const tls = benchmarkTls(root);
const proxy = await createReplayProxy({ ...tls, directory: path.join(root, 'frozen-registry'), expectedManifestSha256 })
  .catch(error => { tls.close(); throw error; });
const output = path.join(root, stage);
const variants = ['baseline', 'candidate', 'bun'].map(id => ({ id, manager: id === 'bun' ? 'bun' : 'lpm',
  ...(id === 'bun' ? {} : { binary: `/tmp/lpm-cold-local-cost/lpm-${id}` }) }));
const config = { output, samples: preparation || preflight ? 0 : 72, diagnostics: preparation ? 0 : preflight ? 2 : 8, states: ['first-install'], variants,
  balancedOrders: true, sharedLpmRoot: true, keepWork: true, fixture: path.resolve('bench/audit-fixtures/peer-heavy/nestjs-deep'),
  verifyModule: '@nestjs/core/package.json', registry: proxy.url, ca: tls.ca };
fs.writeFileSync(path.join(root, stage + '-config.json'), JSON.stringify(config, null, 2));

function verifyArchives() {
  const directory = path.join(root, 'frozen-registry');
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json')));
  const records = manifest.map(meta => {
    const base = crypto.createHash('sha256').update(JSON.stringify(meta.request)).digest('hex');
    const body = fs.readFileSync(path.join(directory, base + '.body'));
    if (crypto.createHash('sha256').update(body).digest('hex') !== meta.sha256) throw new Error('fixture hash mismatch');
    return { meta, body };
  });
  const expected = new Map();
  function collect(value) {
    if (Array.isArray(value)) for (const item of value) collect(item);
    else if (value && typeof value === 'object') {
      if (value.dist?.tarball && value.dist.integrity) {
        const url = new URL(value.dist.tarball);
        if (url.hostname !== 'registry.npmjs.org') throw new Error('unexpected tarball origin');
        expected.set(decodeURIComponent(url.pathname), value.dist.integrity);
      }
      for (const item of Object.values(value)) collect(item);
    }
  }
  for (const { meta, body } of records) if (meta.status === 200 && meta.json) collect(JSON.parse(body));
  const verified = [];
  for (const { meta, body } of records) if (meta.status === 200 && meta.request[1].includes('/-/')) {
    const integrity = expected.get(decodeURIComponent(meta.request[1]));
    if (!integrity || !integrity.split(/\s+/).some(item => {
      const split = item.indexOf('-'); return crypto.createHash(item.slice(0, split)).update(body).digest('base64') === item.slice(split + 1);
    })) throw new Error('archive integrity mismatch');
    verified.push({ request: meta.request, integrity, sha256: meta.sha256, bytes: body.length });
  }
  fs.writeFileSync(path.join(root, stage + '-parity.json'), JSON.stringify(verified, null, 2));
  return verified.length;
}

try {
  if (!preparation) { if (!proxy.status().frozen) throw new Error('scoring requires a frozen manifest'); console.log('Verified archives before scoring:', verifyArchives()); }
  const before = proxy.status().upstreamRequests;
  const file = fs.openSync(path.join(root, stage + '.log'), 'w');
  const child = spawn(process.execPath, [path.join(root, 'runner.mjs'), path.join(root, stage + '-config.json')], { stdio: ['ignore', file, file] });
  const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', resolve); });
  fs.closeSync(file);
  fs.writeFileSync(path.join(root, stage + '-status.json'), JSON.stringify({ code, ...proxy.status() }, null, 2));
  if (code !== 0) throw new Error(`runner exited ${code}`);
  if (!preparation && proxy.status().upstreamRequests !== before) throw new Error('upstream requests during scoring');
  console.log('Verified archives after run:', verifyArchives());
  if (preparation && !expectedManifestSha256) fs.writeFileSync(anchorPath, JSON.stringify({
    sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'frozen-registry/manifest.json'))).digest('hex'),
    source: 'Completed HTTPS capture; all bodies and tarball SRI verified' }, null, 2), { flag: 'wx' });
} finally { await proxy.close(); tls.close(); }
