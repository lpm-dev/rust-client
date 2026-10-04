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
const versionProbeLog = path.join(root, 'version-probes.jsonl');
const writeJson = (name, value) => fs.writeFileSync(name, JSON.stringify(value));
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(output, name), 'utf8'));

try {
  fs.mkdirSync(fixture);
  writeJson(path.join(fixture, 'package.json'), { dependencies: { next: '1.0.0' } });
  fs.writeFileSync(lpm, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
if (process.argv.includes('--version')) {
  fs.appendFileSync(${JSON.stringify(versionProbeLog)}, JSON.stringify({ manager: 'lpm', token_present: process.env.LPM_TOKEN !== undefined }) + '\\n');
  console.log('fake-lpm 1.0.0'); process.exit(0);
}
if (!['monitor', 'off'].includes(process.env.LPM_NPM_FIREWALL)) throw new Error('missing firewall override');
const monitor = process.env.LPM_NPM_FIREWALL === 'monitor';
if (monitor && process.env.LPM_TOKEN !== 'fixture-token-not-secret') throw new Error('missing LPM token');
if (!monitor && process.env.LPM_TOKEN !== undefined) throw new Error('token leaked to baseline');
const upToDate = fs.existsSync('node_modules/next/package.json');
const rpcFailed = fs.existsSync(${JSON.stringify(path.join(root, 'fail-firewall'))});
for (const target of ['node_modules/next', path.join(process.env.LPM_HOME, 'cache'), path.join(process.env.LPM_HOME, 'store')]) {
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'entry'), 'fixture');
}
fs.writeFileSync('node_modules/next/package.json', JSON.stringify({ name: 'next', version: '1.0.0' }));
fs.writeFileSync('lpm.lock', 'fixture lock');
console.log(JSON.stringify({ duration_ms: 1, count: 1, up_to_date: upToDate,
  security: upToDate || !monitor ? undefined : { firewall: { enabled: true, mode: process.env.LPM_NPM_FIREWALL,
    checked_count: 1, allow_count: rpcFailed ? 0 : 1, warn_count: 0, block_count: 0, unknown_count: 0,
    rpc_failed: rpcFailed, offline_skipped: false } },
  timing: { resolve_ms: 0, fetch_ms: 0, link_ms: 0 } }));
`, { mode: 0o755 });
  fs.writeFileSync(aube, `#!${process.execPath}
if (process.argv.includes('--version')) {
  require('node:fs').appendFileSync(${JSON.stringify(versionProbeLog)}, JSON.stringify({ manager: 'aube', token_present: process.env.LPM_TOKEN !== undefined }) + '\\n');
  console.log('fake-aube 1.0.0'); process.exit(0);
}
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
  const versionProbes = fs.readFileSync(versionProbeLog, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(versionProbes.map(probe => probe.manager).sort(), ['aube', 'lpm']);
  assert.ok(versionProbes.every(probe => !probe.token_present), 'version probes must not inherit LPM_TOKEN');
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

  const combinedOutput = path.join(root, 'combined-results');
  const combinedArgs = ['--managers', 'lpm,lpm-monitor,aube', '--lpm-firewall', 'off', '--output', combinedOutput];
  run(combinedArgs);
  const combinedRead = name => JSON.parse(fs.readFileSync(path.join(combinedOutput, name), 'utf8'));
  const combinedRows = combinedRead('rows.json');
  assert.equal(combinedRows.length, 18);
  for (const manager of ['lpm', 'lpm-monitor']) {
    assert.equal(combinedRows.filter(row => row.manager === manager && row.ok).length, 6);
    assert.equal(combinedRead('timing-rows.json').filter(row => row.manager === manager && row.ok).length, 6);
    assert.equal(combinedRead('timing-summary.json').filter(row => row.manager === manager).length, 6);
  }
  assert.ok(combinedRows.filter(row => row.manager === 'lpm').every(row => row.firewall === undefined));
  assert.ok(combinedRows.filter(row => row.manager === 'lpm-monitor')
    .every(row => row.firewall_validation.ok && row.firewall_validation.status !== 'not-requested'));
  for (const row of combinedRows.filter(row => row.ok)) {
    const command = JSON.parse(fs.readFileSync(path.join(combinedOutput, 'artifacts', row.scenario,
      row.manager, 'sample-1', 'command.json'), 'utf8'));
    assert.equal(command.lpm_firewall_override, row.manager === 'lpm-monitor' ? 'monitor' : 'off');
    assert.ok(command.cwd.includes(`-${row.manager}/project`), 'each entry has its own installed tree and home');
    assert.deepEqual([...row.manager_order_ids].sort(), ['aube', 'lpm', 'lpm-monitor']);
  }
  const combinedPlan = combinedRead('plan.json');
  assert.deepEqual(combinedPlan.manager_info.lpm, combinedPlan.manager_info['lpm-monitor']);
  const combinedPrefix = combinedRows.slice(0, 4);
  writeJson(path.join(combinedOutput, 'rows.partial.json'), combinedPrefix);
  writeJson(path.join(combinedOutput, 'timing-rows.partial.json'), combinedRead('timing-rows.json').slice(0, 3));
  fs.unlinkSync(path.join(combinedOutput, 'summary.json'));
  run([...combinedArgs, '--resume']);
  assert.deepEqual(combinedRead('rows.json').slice(0, combinedPrefix.length), combinedPrefix);
  assert.equal(combinedRead('rows.json').length, 18);
  assert.equal(combinedRead('timing-rows.json').length, 12);
  assert.match(fs.readFileSync(path.join(combinedOutput, 'summary.md'), 'utf8'), /scored samples \(lpm-monitor\)/);

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
  const failedCombined = path.join(root, 'failed-combined-results');
  run([...combinedArgs, '--output', failedCombined]);
  for (const name of ['rows.json', 'timing-rows.json']) {
    const failed = JSON.parse(fs.readFileSync(path.join(failedCombined, name), 'utf8'));
    assert.ok(failed.filter(row => row.manager === 'lpm').every(row => row.ok));
    assert.ok(failed.filter(row => row.manager === 'lpm-monitor').every(row => !row.ok));
  }
  console.log('blocked-preparation and resume integration tests passed');
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
