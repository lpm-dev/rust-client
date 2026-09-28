import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { command, DEPS, environment, execute, fixture, MANAGERS, measure, outputValid, prepare, rotate, ROWS, sourceHashes, stats } from './run-dev-command-suite.mjs';

test('statistics use the midpoint median and nearest-rank p95', () => {
  assert.deepEqual(stats([5, 1, 3, 2]), { n: 4, median: 2.5, min: 1, max: 5, p95: 5 });
  assert.equal(stats([3, 1, 2]).median, 2);
  for (const value of [[], [NaN], [-1], [Infinity]]) assert.throws(() => stats(value));
});

test('rotating order preserves each manager exactly once per round', () => {
  for (let round = 0; round < 10; round++) assert.deepEqual(rotate(MANAGERS, round).sort(), [...MANAGERS].sort());
  assert.notDeepEqual(rotate(MANAGERS, 0), rotate(MANAGERS, 1));
});

test('commands execute Vite tasks without result caching and format without writes', () => {
  for (const manager of MANAGERS) for (const row of ROWS) assert.ok(command(manager, row).length);
  assert.deepEqual(command('vite', 'echo'), ['run', '--no-cache', 'noop']);
  for (const manager of MANAGERS) assert.ok(!command(manager, 'fmt').includes('--write'));
  assert.deepEqual(command('npm', 'tsx'), ['exec', '--no', '--', 'tsx', 'scripts/entry.tsx']);
  assert.deepEqual(command('aube', 'esbuild'), ['exec', '--', 'esbuild', '--version']);
  assert.throws(() => command('../escape', 'echo'));
  assert.throws(() => command('lpm', 'unknown'));
});

test('preparation refuses an existing output directory without modifying its contents', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-dev-suite-test-'));
  try {
    fs.writeFileSync(path.join(root, 'sentinel'), 'preserve');
    await assert.rejects(prepare(root, {}, []), /EEXIST/);
    assert.deepEqual(fs.readdirSync(root), ['sentinel']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('measurement rejects fixture drift before it launches a command', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-dev-suite-test-'));
  try {
    const project = path.join(root, 'work/lpm/project');
    fixture(project, 'lpm');
    fs.writeFileSync(path.join(root, 'plan.json'), JSON.stringify({ managers: ['lpm'], projects: { lpm: {
      cases: { echo: { ok: true, args: ['-e', 'console.log("hi")'] } }, source_hashes: sourceHashes(project),
    } } }));
    fs.appendFileSync(path.join(project, 'src/file-00.js'), '\nchanged');
    await assert.rejects(measure(root, 2, 1), /Fixture changed: lpm/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('fixture gives vlt a nested registry config and permits only esbuild builds for pnpm', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-dev-suite-test-'));
  try {
    fixture(path.join(root, 'vlt'), 'vlt');
    const settings = JSON.parse(fs.readFileSync(path.join(root, 'vlt/vlt.json')));
    assert.equal(settings.config.registries.npm, 'https://registry.npmjs.org/');
    fixture(path.join(root, 'pnpm'), 'pnpm');
    assert.equal(fs.readFileSync(path.join(root, 'pnpm/pnpm-workspace.yaml'), 'utf8'), 'allowBuilds:\n  esbuild: true\n');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('Vite uses its bundled lint and format engines without project version overrides', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-dev-suite-test-'));
  try {
    fixture(root, 'vite');
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json')));
    assert.equal(pkg.dependencies['vite-plus'], '1.0.0');
    assert.equal(pkg.dependencies.oxlint, undefined);
    assert.equal(pkg.dependencies['@biomejs/biome'], undefined);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('validation rejects failures, timeouts, and echoed commands without their output', () => {
  const result = { code: 0, stdout: 'hi\n', timed_out: false, error: null };
  assert.ok(outputValid('echo', result));
  assert.ok(!outputValid('echo', { ...result, stdout: '> echo hi\n' }));
  assert.ok(!outputValid('echo', { ...result, code: 1 }));
  assert.ok(!outputValid('echo', { ...result, timed_out: true }));
  assert.ok(!outputValid('lint', { ...result, error: 'spawn failed' }));
  assert.ok(outputValid('esbuild', { ...result, stdout: DEPS.esbuild + '\n' }));
});

test('fixture and environment isolate state without inheriting authentication', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-dev-suite-test-'));
  const previous = process.env.LPM_TOKEN;
  process.env.LPM_TOKEN = 'test-sentinel';
  try {
    const project = path.join(root, 'project');
    fixture(project, 'lpm');
    const env = environment(root, { lpm: process.execPath });
    assert.equal(env.LPM_TOKEN, undefined);
    assert.equal(env.HOME, path.join(root, 'home'));
    assert.ok(Buffer.byteLength(env.TMPDIR + '/tsx-501/123456.pipe') < 104);
    assert.equal(environment(root, { lpm: process.execPath }).TMPDIR, env.TMPDIR);
    assert.equal(fs.readdirSync(path.join(project, 'src')).length, 20);
    assert.equal(fs.readdirSync(path.join(project, 'scripts')).length, 11);
    const pkg = JSON.parse(fs.readFileSync(path.join(project, 'package.json')));
    const result = await execute('/bin/sh', ['-c', pkg.scripts['node-noop']], { cwd: project, env });
    assert.ok(outputValid('node', result));
    fs.rmSync(env.TMPDIR, { recursive: true, force: true });
  } finally {
    if (previous === undefined) delete process.env.LPM_TOKEN; else process.env.LPM_TOKEN = previous;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('execution captures status and never turns a timeout into a passing sample', async () => {
  const success = await execute(process.execPath, ['-e', 'console.log("hi")']);
  assert.ok(outputValid('echo', success));
  const missing = await execute('/no-such-benchmark-executable', []);
  assert.ok(missing.error);
  const timeout = await execute(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeout: 100 });
  assert.ok(timeout.timed_out);
  assert.ok(timeout.wall_ms < 3000);
  assert.ok(!outputValid('lint', timeout));
});
