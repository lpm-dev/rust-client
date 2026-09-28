#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const harness = fileURLToPath(new URL('./run-t3-install-six-states.mjs', import.meta.url));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-six-state-integration-'));
const output = path.join(root, 'results');
const fixture = path.join(root, 'fixture');
const lpm = path.join(root, 'fake-lpm.cjs');
const aube = path.join(root, 'fake-aube.cjs');
const bins = path.join(root, 'bins.json');
const writeJson = (name, value) => fs.writeFileSync(name, JSON.stringify(value));
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(output, name), 'utf8'));

try {
  fs.mkdirSync(fixture);
  writeJson(path.join(fixture, 'package.json'), { dependencies: { next: '1.0.0' } });
  fs.writeFileSync(lpm, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
if (process.argv.includes('--version')) { console.log('fake-lpm 1.0.0'); process.exit(0); }
if (process.env.LPM_NPM_FIREWALL !== 'monitor') throw new Error('missing monitor override');
if (process.env.LPM_TOKEN !== 'fixture-token-not-secret') throw new Error('missing LPM token');
const upToDate = fs.existsSync('node_modules/next/package.json');
const rpcFailed = fs.existsSync(${JSON.stringify(path.join(root, 'fail-firewall'))});
for (const target of ['node_modules/next', path.join(process.env.LPM_HOME, 'cache'), path.join(process.env.LPM_HOME, 'store')]) {
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'entry'), 'fixture');
}
fs.writeFileSync('node_modules/next/package.json', JSON.stringify({ name: 'next', version: '1.0.0' }));
fs.writeFileSync('lpm.lock', 'fixture lock');
console.log(JSON.stringify({ duration_ms: 1, count: 1, up_to_date: upToDate,
  security: upToDate ? undefined : { firewall: { enabled: true, mode: process.env.LPM_NPM_FIREWALL,
    checked_count: 1, allow_count: rpcFailed ? 0 : 1, warn_count: 0, block_count: 0, unknown_count: 0,
    rpc_failed: rpcFailed, offline_skipped: false } },
  timing: { resolve_ms: 0, fetch_ms: 0, link_ms: 0 } }));
`, { mode: 0o755 });
  fs.writeFileSync(aube, `#!${process.execPath}
if (process.argv.includes('--version')) { console.log('fake-aube 1.0.0'); process.exit(0); }
if (process.env.LPM_NPM_FIREWALL !== undefined) throw new Error('LPM override leaked to another manager');
if (process.env.LPM_TOKEN !== undefined) throw new Error('LPM token leaked to another manager');
console.error('ERR_AUBE_TRUST_DOWNGRADE fixture');
process.exit(23);
`, { mode: 0o755 });
  writeJson(bins, { aube });
  const args = [harness, '--samples', '1', '--timing-samples', '1', '--managers', 'lpm,aube',
    '--manager-bins', bins, '--lpm-bin', lpm, '--fixture', fixture, '--output', output,
    '--work-dir', path.join(root, 'work'), '--timeout-ms', '5000', '--lpm-firewall', 'monitor'];
  const run = (extra = []) => {
    const result = spawnSync(process.execPath, [...args, ...extra], {
      encoding: 'utf8', timeout: 30_000, env: { PATH: process.env.PATH, LPM_TOKEN: 'fixture-token-not-secret' },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /results:/, 'failures must not prevent final summaries');
  };
  run();
  const rows = readJson('rows.json');
  assert.equal(rows.length, 12);
  assert.equal(rows.filter((row) => row.ok && row.verification.ok).length, 6);
  assert.equal(readJson('plan.json').lpm_firewall_override, 'monitor');
  assert.ok(rows.filter((row) => row.manager === 'lpm' && !['installed-cache-gone', 'up-to-date'].includes(row.scenario))
    .every((row) => row.firewall.mode === 'monitor'));
  assert.equal(rows.filter((row) => row.phase === 'preparation').length, 5);
  assert.equal(rows.find((row) => row.manager === 'aube' && row.scenario === 'first-install').exit_code, 23);
  const timing = readJson('timing-rows.json');
  assert.equal(timing.length, 6);
  assert.ok(timing.every((row) => row.ok && row.verification.ok));
  assert.match(fs.readFileSync(path.join(output, 'summary.md'), 'utf8'), /0\/1/);
  assert.match(fs.readFileSync(path.join(output, 'summary.md'), 'utf8'), /LPM firewall diagnostics from scored samples/);
  assert.equal(readJson('summary.json').find((row) => row.scenario === 'first-install').managers.lpm.firewall.verdict_samples, 1);
  assert.equal(readJson('summary.json').find((row) => row.scenario === 'up-to-date').managers.lpm.firewall.up_to_date_samples, 1);

  const prefix = rows.slice(0, 5);
  writeJson(path.join(output, 'rows.partial.json'), prefix);
  writeJson(path.join(output, 'timing-rows.partial.json'), timing.slice(0, 1));
  fs.unlinkSync(path.join(output, 'summary.json'));
  run(['--resume']);
  const resumed = readJson('rows.json');
  assert.deepEqual(resumed.slice(0, prefix.length), prefix, 'resume must preserve previous attempts');
  assert.equal(resumed.length, 12);
  assert.equal(new Set(resumed.map((row) => `${row.sample}:${row.scenario}:${row.manager}`)).size, 12);
  assert.equal(resumed.filter((row) => row.ok && row.verification.ok).length, 6);
  assert.equal(readJson('timing-rows.json').length, 6);
  assert.deepEqual(readJson('timing-rows.json')[0], timing[0]);
  assert.ok(fs.readdirSync(output).some((name) => /^resume-.*\.json$/.test(name)));
  fs.writeFileSync(path.join(root, 'fail-firewall'), 'fixture');
  const failedOutput = path.join(root, 'failed-firewall-results');
  run(['--output', failedOutput]);
  for (const name of ['rows.json', 'timing-rows.json']) {
    const failed = JSON.parse(fs.readFileSync(path.join(failedOutput, name), 'utf8'))
      .filter((row) => row.manager === 'lpm');
    assert.equal(failed.length, 6);
    assert.ok(failed.every((row) => !row.ok), 'failed firewall requests must never count as successful benchmarks');
    assert.equal(failed.filter((row) => row.phase === 'preparation').length, 5,
      'a failed firewall preparation must block no-op measurements too');
  }
  console.log('blocked-preparation and resume integration tests passed');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
