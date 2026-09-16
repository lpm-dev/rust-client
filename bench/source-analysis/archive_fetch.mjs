#!/usr/bin/env node
// Read-only retrieval. Archive locations come from the private frozen inventory.
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile, rename, unlink, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const [selection, destination, envFile, sdkRoot] = process.argv.slice(2);
if (!sdkRoot) throw new Error('Usage: archive_fetch.mjs selection.json destination env-file sdk-root');
process.loadEnvFile(resolve(envFile));
const require = createRequire(join(resolve(sdkRoot), 'package.json'));
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const endpoint = process.env.LPM_R2_ENDPOINT;
if (!endpoint || !/^https:\/\/[a-z0-9]+\.r2\.cloudflarestorage\.com\/?$/.test(endpoint)) {
  throw new Error('Expected a Cloudflare R2 HTTPS endpoint');
}
const client = new S3Client({
  endpoint, region: 'auto', maxAttempts: 3,
  credentials: { accessKeyId: process.env.LPM_R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.LPM_R2_SECRET_ACCESS_KEY },
});
const packages = JSON.parse(await readFile(selection, 'utf8')).packages;
await mkdir(destination, { recursive: true, mode: 0o700 });
const results = [];
for (const item of packages) {
  if (!/^[a-f0-9]{64}$/.test(item.sha256) || item.size_bytes > 150 * 1024 * 1024) {
    throw new Error('Invalid archive hash or size');
  }
  let local = false;
  for (const location of item.locations.filter(p => !p.startsWith('r2://'))) {
    if (await stat(location).then(s => s.isFile()).catch(() => false)) local = true;
  }
  if (local) continue;
  const target = join(destination, item.sha256);
  const valid = data => data.length === item.size_bytes &&
    createHash('sha256').update(data).digest('hex') === item.sha256;
  if (await readFile(target).then(valid).catch(() => false)) continue;
  try {
    const uri = new URL(item.locations.find(p => p.startsWith('r2://')));
    if (uri.hostname !== process.env.LPM_R2_BUCKET || uri.search || uri.hash) {
      throw new Error('Unexpected storage location');
    }
    const response = await client.send(new GetObjectCommand({
      Bucket: uri.hostname, Key: decodeURIComponent(uri.pathname.slice(1)),
    }), { abortSignal: AbortSignal.timeout(60000) });
    const chunks = [];
    let size = 0;
    for await (const chunk of response.Body) {
      size += chunk.length;
      if (size > item.size_bytes) { response.Body.destroy(); throw new Error('Archive size mismatch'); }
      chunks.push(chunk);
    }
    const bytes = Buffer.concat(chunks);
    if (!valid(bytes)) throw new Error('Archive integrity mismatch');
    await writeFile(target + '.tmp', bytes, { mode: 0o600 });
    await rename(target + '.tmp', target);
    results.push({ sha256: item.sha256, status: 'retrieved', bytes: size });
  } catch (error) {
    await unlink(target + '.tmp').catch(() => {});
    results.push({ sha256: item.sha256, status: 'failed', error_type: error.name });
  }
  if (results.length % 20 === 0) console.log(JSON.stringify({ processed: results.length }));
}
await writeFile(join(destination, 'retrieval.json'), JSON.stringify(results, null, 2) + '\n');
console.log(JSON.stringify({ retrieved: results.filter(r => r.status === 'retrieved').length,
  failures: results.filter(r => r.status === 'failed').length }));
client.destroy();
if (results.some(r => r.status === 'failed')) process.exitCode = 1;
