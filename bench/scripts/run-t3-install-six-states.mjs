#!/usr/bin/env node

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));

const SCENARIOS = [
  {
    id: 'first-install',
    title: 'First install, ever',
    state: 'no cache · no lockfile · no node_modules',
  },
  {
    id: 'fresh-checkout-warm-cache',
    title: 'Fresh checkout, warm cache',
    state: 'no lockfile · warm dependency cache · no node_modules',
  },
  {
    id: 'ci-cold-cache',
    title: 'CI without a cache',
    state: 'lockfile · cold dependency cache · no node_modules',
  },
  {
    id: 'ci-warm-cache',
    title: 'CI with a warm cache',
    state: 'lockfile · warm dependency cache · no node_modules',
  },
  {
    id: 'installed-cache-gone',
    title: 'node_modules there, cache gone',
    state: 'lockfile · node_modules present · cold dependency cache',
  },
  {
    id: 'up-to-date',
    title: 'Everything already up to date',
    state: 'lockfile · warm dependency cache · node_modules present',
  },
];

const SUPPORTED_MANAGERS = ['lpm', 'bun', 'pnpm', 'npm', 'aube', 'nub', 'deno', 'vlt', 'upm', 'yarn'];
const DEFAULT_MANAGERS = ['lpm', 'bun'];
class PreparationError extends Error {}
const SCENARIO_POSITIONS = new Map(SCENARIOS.map(({ id }, index) => [id, index]));
const argv = parseArgs(process.argv.slice(2));
const lpmFirewallMode = parseFirewallMode(argv.lpmFirewall);
const binaryOverrides = argv.managerBins
  ? JSON.parse(fs.readFileSync(path.resolve(argv.managerBins), 'utf8'))
  : {};

if (argv.help) {
  printHelp();
  process.exit(0);
}

if (argv.selfTest) {
  selfTest();
  process.exit(0);
}

const managers = parseManagerList(argv.managers ?? DEFAULT_MANAGERS.join(','));
if (!managers.includes('lpm')) {
  throw new Error('--managers must include lpm because the harness records LPM timing diagnostics');
}
const samples = positiveInteger(argv.samples ?? '10', '--samples');
const timingSamples = positiveInteger(argv.timingSamples ?? '3', '--timing-samples');
const lpmBin = path.resolve(argv.lpmBin ?? path.join(repoRoot, 'target/release/lpm-rs'));
const fixtureDir = path.resolve(
  argv.fixture ?? path.join(repoRoot, 'bench/audit-fixtures/t3-install'),
);
const packageJsonPath = path.join(fixtureDir, 'package.json');
const outputDir = path.resolve(
  argv.output ?? path.join(os.tmpdir(), `lpm-t3-six-${new Date().toISOString().replaceAll(/[:.]/g, '-')}`),
);
const keepWork = Boolean(argv.keepWork);
const resume = Boolean(argv.resume);
const timeoutMs = positiveInteger(argv.timeoutMs ?? '600000', '--timeout-ms');

requireFile(lpmBin, 'LPM binary');
requireFile(packageJsonPath, 'fixture package.json');
if (fs.existsSync(outputDir) && !resume) {
  throw new Error(`output already exists: ${outputDir}`);
}
const previousPlan = resume ? JSON.parse(fs.readFileSync(path.join(outputDir, 'plan.json'), 'utf8')) : null;
if (resume && fs.existsSync(path.join(outputDir, 'summary.json'))) throw new Error('run already complete');

const fixturePackageJson = fs.readFileSync(packageJsonPath);
const workspaceDir = argv.workDir ? path.resolve(argv.workDir) : path.join(outputDir, 'work');
if (fs.existsSync(workspaceDir) && !resume) throw new Error(`work directory already exists: ${workspaceDir}`);
const artifactDir = path.join(outputDir, 'artifacts');

const managerInfo = Object.fromEntries(
  managers.map((manager) => [manager, describeManager(manager)]),
);

const metadata = {
  created_at: new Date().toISOString(),
  samples,
  timing_samples: timingSamples,
  managers,
  work_directory: workspaceDir,
  command_line: process.argv.slice(2),
  repository_commit: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8' }).stdout.trim(),
  harness_sha256: sha256(fs.readFileSync(fileURLToPath(import.meta.url))),
  statistics: 'Median averages the two middle samples for even counts. p95 uses nearest rank; with 10 samples it is the maximum.',
  policy: 'Product security and release-age defaults. Lifecycle scripts disabled. Direct npm registry. Yarn node-modules linker.' +
    (lpmFirewallMode ? ` LPM firewall override: ${lpmFirewallMode}.` : ''),
  lpm_firewall_override: lpmFirewallMode,
  firewall_validation: ['monitor', 'enforce'].includes(lpmFirewallMode) ? 'successful-verdicts-and-preparation-v1' : undefined,
  scenarios: SCENARIOS,
  fixture: {
    directory: fixtureDir,
    upstream_url: 'https://github.com/oven-sh/bun/tree/main/bench/install',
    upstream_commit: '9dd73746c7b51b6450bb675ce2abcf86a0ae076f',
    package_json_sha256: sha256(fixturePackageJson),
    package_json: JSON.parse(fixturePackageJson),
  },
  manager_info: managerInfo,
  lpm: managerInfo.lpm,
  bun: managerInfo.bun,
  pnpm: managerInfo.pnpm,
  npm: managerInfo.npm,
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  os_release: os.release(),
  cpu: os.cpus()[0]?.model,
  total_memory_bytes: os.totalmem(),
  timeout_ms: timeoutMs,
  lpm_npm_fanout_override: process.env.LPM_NPM_FANOUT,
  timing_scope:
    'scored wall/RSS samples omit timing instrumentation; separate LPM-only diagnostics use --timing with trace detail',
  script_policy: 'install scripts disabled for every manager',
  state_mapping: {
    lpm_cache: 'LPM_HOME/cache (ephemeral metadata)',
    lpm_store: 'LPM_HOME/store (content store backing V2 node_modules symlinks)',
    bun_cache: 'BUN_INSTALL_CACHE_DIR',
    pnpm_cache: 'isolated pnpm content-addressable store',
    npm_cache: 'isolated npm _cacache',
    pnpm_metadata: 'XDG_CACHE_HOME/pnpm, cleared together with the content store',
    aube_cache: 'AUBE_CACHE_DIR and AUBE_STORE_DIR',
    nub_cache: 'XDG_CACHE_HOME/nub/pm and XDG_DATA_HOME/nub/store; runtime cache retained',
    deno_cache: 'DENO_DIR/npm',
    vlt_cache: 'explicit isolated --cache',
    upm_cache: 'explicit isolated --store; runtime compile cache retained',
    yarn_cache: 'YARN_GLOBAL_FOLDER; node-modules linker',
    installed_cache_gone:
      'clear each manager dependency cache; preserve LPM_HOME/store because V2 node_modules links target it',
  },
};
if (resume) assertResumeCompatible(previousPlan, metadata);
if (resume) for (const manager of managers) drainManagerWorkers(manager);
fs.mkdirSync(workspaceDir, { recursive: true });
fs.mkdirSync(artifactDir, { recursive: true });
const rows = resume ? readPartialRows('rows.partial.json', true) : [];
const timingRows = resume ? readPartialRows('timing-rows.partial.json') : [];
const completed = completedCells(rows, managers, samples);
const completedTiming = completedCells(timingRows, ['lpm'], timingSamples);
if (resume) {
  const id = `resume-${Date.now()}`;
  writeJson(path.join(outputDir, `${id}.json`), { ...metadata, completed_rows: rows.length, completed_timing_rows: timingRows.length });
  fs.copyFileSync(fileURLToPath(import.meta.url), path.join(outputDir, `harness-${id}.mjs`));
} else {
  writeJson(path.join(outputDir, 'plan.json'), metadata);
  fs.copyFileSync(fileURLToPath(import.meta.url), path.join(outputDir, 'harness.mjs'));
  fs.writeFileSync(path.join(outputDir, 'fixture.package.json'), fixturePackageJson);
}

for (let sample = 1; sample <= samples; sample += 1) {
  const scenarioOrder = rotate(SCENARIOS, (sample - 1) % SCENARIOS.length);
  for (const scenario of scenarioOrder) {
    const managerOrder = managerOrderFor(sample, scenario.id, managers);
    const comparisonId = `${scenario.id}:sample-${sample}`;
    const pendingManagers = managers.filter((manager) => !completed.has(cellKey(sample, scenario.id, manager)));
    const prepared = new Map();
    for (const manager of pendingManagers) {
      const root = path.join(workspaceDir, `sample-${sample}-${scenario.id}-${manager}`);
      resetInterruptedRoot(root);
      try {
        prepareScenario({ manager, scenario: scenario.id, root });
      } catch (error) {
        if (!(error instanceof PreparationError)) throw error;
        const row = { sample, comparison_id: comparisonId, manager_order: managerOrder.join('-'),
          scenario: scenario.id, manager, ok: false, phase: 'preparation', error: error.message,
          verification: { ok: false }, wall_ms: null, max_rss_bytes: null };
        rows.push(row);
        writeJson(path.join(artifactDir, scenario.id, manager, `sample-${sample}`, 'metrics.json'), row);
        writeJson(path.join(outputDir, 'rows.partial.json'), rows);
        console.log(`[${scenario.id} ${manager}] ${sample}/${samples} BLOCKED during preparation: ${error.message}`);
        if (!keepWork) fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        continue;
      }
      const setup = captureState(manager, root);
      assertScenarioState(manager, scenario.id, setup);
      prepared.set(manager, { root, setup });
    }
    for (const manager of managerOrder) {
      if (!prepared.has(manager)) continue;
      const { root, setup } = prepared.get(manager);
      const output = path.join(artifactDir, scenario.id, manager, `sample-${sample}`);
      const result = runInstall({ manager, root, output, measured: true,
        allowUpToDate: ['installed-cache-gone', 'up-to-date'].includes(scenario.id) });
      const verification = verifyInstalledProject(root);
      const row = {
        sample,
        comparison_id: comparisonId,
        manager_order: managerOrder.join('-'),
        pair_id: comparisonId,
        pair_order: managerOrder.join('-'),
        scenario: scenario.id,
        manager,
        setup,
        verification,
        ...result,
      };
      rows.push(row);
      writeJson(path.join(output, 'metrics.json'), row);
      writeJson(path.join(outputDir, 'rows.partial.json'), rows);
      for (const name of managerLockfileNames(manager)) {
        const lockfile = path.join(projectDir(root), name);
        if (fs.existsSync(lockfile)) fs.copyFileSync(lockfile, path.join(output, name));
      }
      console.log(
        `[${scenario.id} ${manager}] ${sample}/${samples} ${result.ok && verification.ok ? 'ok' : 'FAIL'} ` +
          `wall=${result.wall_ms}ms rss=${formatMiB(result.max_rss_bytes)} ` +
          `${manager === 'lpm' ? `resolve=${formatMs(result.resolve_ms)} fetch=${formatMs(result.fetch_ms)} link=${formatMs(result.link_ms)}` : ''}`,
      );
      if (!keepWork) {
        fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    }
  }
  writeJson(path.join(outputDir, 'rows.partial.json'), rows);
}

for (let sample = 1; sample <= timingSamples; sample += 1) {
  const scenarioOrder = rotate(SCENARIOS, (sample - 1) % SCENARIOS.length);
  for (const scenario of scenarioOrder) {
    if (completedTiming.has(cellKey(sample, scenario.id, 'lpm'))) continue;
    const root = path.join(workspaceDir, `timing-${sample}-${scenario.id}-lpm`);
    resetInterruptedRoot(root);
    const output = path.join(artifactDir, 'timing', scenario.id, `sample-${sample}`);
    try {
      prepareScenario({ manager: 'lpm', scenario: scenario.id, root });
    } catch (error) {
      if (!(error instanceof PreparationError)) throw error;
      const row = { sample, scenario: scenario.id, manager: 'lpm', ok: false,
        phase: 'preparation', error: error.message, verification: { ok: false } };
      timingRows.push(row);
      writeJson(path.join(output, 'metrics.json'), row);
      writeJson(path.join(outputDir, 'timing-rows.partial.json'), timingRows);
      console.log(`[timing ${scenario.id} lpm] ${sample}/${timingSamples} BLOCKED during preparation: ${error.message}`);
      if (!keepWork) fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      continue;
    }
    const setup = captureState('lpm', root);
    assertScenarioState('lpm', scenario.id, setup);
    const result = runInstall({
      manager: 'lpm',
      root,
      output,
      measured: false,
      timing: true,
      allowUpToDate: ['installed-cache-gone', 'up-to-date'].includes(scenario.id),
    });
    const verification = verifyInstalledProject(root);
    const row = { sample, scenario: scenario.id, manager: 'lpm', setup, verification, ...result };
    timingRows.push(row);
    writeJson(path.join(output, 'metrics.json'), row);
    writeJson(path.join(outputDir, 'timing-rows.partial.json'), timingRows);
    console.log(
      `[timing ${scenario.id} lpm] ${sample}/${timingSamples} ${result.ok && verification.ok ? 'ok' : 'FAIL'} ` +
        `pipeline=${formatMs(result.pipeline_wall_max_ms)} package=${result.streamed_package ?? 'none'}`,
    );
    if (!keepWork) {
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  }
  writeJson(path.join(outputDir, 'timing-rows.partial.json'), timingRows);
}

const summary = summarize(rows);
const timingSummary = summarizeTiming(timingRows);
writeJson(path.join(outputDir, 'rows.json'), rows);
writeJson(path.join(outputDir, 'summary.json'), summary);
writeJson(path.join(outputDir, 'timing-rows.json'), timingRows);
writeJson(path.join(outputDir, 'timing-summary.json'), timingSummary);
fs.writeFileSync(
  path.join(outputDir, 'summary.md'),
  renderMarkdown(metadata, summary, timingSummary),
);
fs.rmSync(path.join(outputDir, 'rows.partial.json'), { force: true });
fs.rmSync(path.join(outputDir, 'timing-rows.partial.json'), { force: true });

if (!keepWork) {
  fs.rmSync(workspaceDir, { recursive: true, force: true });
}

console.log(`results: ${outputDir}`);
if (
  rows.some((row) => !row.ok || !row.verification.ok) ||
  timingRows.some((row) => !row.ok || !row.verification.ok)
) {
  process.exitCode = 1;
}

function prepareScenario({ manager, scenario, root }) {
  createFreshRoot(root);
  if (scenario !== 'first-install') {
    seedInPlace(manager, scenario, root);
  }
  switch (scenario) {
    case 'first-install':
      break;
    case 'fresh-checkout-warm-cache':
      removeInstallState(root);
      removeLockfiles(manager, projectDir(root));
      break;
    case 'ci-cold-cache':
      removeInstallState(root);
      clearAllDependencyState(manager, root);
      break;
    case 'ci-warm-cache':
      removeInstallState(root);
      break;
    case 'installed-cache-gone':
      clearDependencyCache(manager, root);
      break;
    case 'up-to-date':
      break;
    default:
      throw new Error(`unknown scenario: ${scenario}`);
  }
}

function assertResumeCompatible(previous, current) {
  for (const key of ['samples', 'timing_samples', 'managers', 'work_directory', 'repository_commit',
    'statistics', 'policy', 'scenarios', 'fixture', 'manager_info', 'node', 'platform', 'os_release',
    'cpu', 'total_memory_bytes', 'timeout_ms', 'lpm_npm_fanout_override', 'lpm_firewall_override', 'firewall_validation', 'script_policy', 'state_mapping']) {
    assert.deepEqual(current[key], previous[key], `resume changed ${key}`);
  }
}

function cellKey(sample, scenario, manager) {
  return `${sample}:${scenario}:${manager}`;
}

function completedCells(rows, selectedManagers, sampleCount) {
  const keys = new Set();
  for (const row of rows) {
    assert.ok(Number.isInteger(row.sample) && row.sample >= 1 && row.sample <= sampleCount &&
      SCENARIO_POSITIONS.has(row.scenario) && selectedManagers.includes(row.manager), 'invalid saved cell');
    const key = cellKey(row.sample, row.scenario, row.manager);
    assert.ok(!keys.has(key), `duplicate saved cell: ${key}`);
    keys.add(key);
  }
  return keys;
}

function readPartialRows(name, required = false) {
  const target = path.join(outputDir, name);
  if (required) requireFile(target, 'saved scored rows');
  return fs.existsSync(target) ? JSON.parse(fs.readFileSync(target, 'utf8')) : [];
}

function archivePreparationLogs(root) {
  if (!fs.existsSync(root)) return;
  for (const name of fs.readdirSync(root).filter((entry) => /^preparation-\d+$/.test(entry))) {
    const target = path.join(artifactDir, 'preparation-retries', path.basename(root), `${name}-${crypto.randomUUID()}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.cpSync(path.join(root, name), target, { recursive: true });
  }
}

function resetInterruptedRoot(root) {
  if (!fs.existsSync(root)) return;
  if (!resume) throw new Error(`unexpected existing sample directory: ${root}`);
  assert.equal(path.dirname(root), workspaceDir, 'sample root must be directly inside the work directory');
  archivePreparationLogs(root);
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function seedInPlace(manager, scenario, root) {
  const attempts = 3;
  let lastResult;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    lastResult = runInstall({
      manager,
      root,
      output: path.join(root, `preparation-${attempt}`),
      measured: false,
    });
    if (lastResult.ok && verifyInstalledProject(root).ok) {
      assert.equal(lockfilePresent(manager, projectDir(root)), true, `${manager} seed lockfile`);
      return;
    }
    archivePreparationLogs(root);
    if (attempt < attempts) {
      fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      createFreshRoot(root);
    }
  }
  throw new PreparationError(`${manager} ${scenario} preparation failed: ${lastResult?.firewall_validation?.error ?? lastResult?.stderr_tail}`);
}

function createFreshRoot(root) {
  fs.mkdirSync(projectDir(root), { recursive: true });
  fs.mkdirSync(homeDir(root), { recursive: true });
  fs.mkdirSync(lpmHomeDir(root), { recursive: true });
  fs.writeFileSync(path.join(projectDir(root), 'package.json'), fixturePackageJson);
}

function removeInstallState(root) {
  fs.rmSync(path.join(projectDir(root), 'node_modules'), { recursive: true, force: true });
  fs.rmSync(path.join(projectDir(root), '.lpm'), { recursive: true, force: true });
  fs.rmSync(path.join(projectDir(root), '.yarn'), { recursive: true, force: true });
}

function removeLockfiles(manager, project) {
  for (const name of managerLockfileNames(manager)) {
    fs.rmSync(path.join(project, name), { force: true });
  }
}

function clearDependencyCache(manager, root) {
  for (const target of dependencyCacheDirs(manager, root)) {
    fs.rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

function clearAllDependencyState(manager, root) {
  clearDependencyCache(manager, root);
  if (manager === 'lpm') {
    fs.rmSync(path.join(lpmHomeDir(root), 'store'), { recursive: true, force: true });
  }
}

function captureState(manager, root) {
  const nodeModules = fs.existsSync(path.join(projectDir(root), 'node_modules'));
  return {
    lockfile: lockfilePresent(manager, projectDir(root)),
    node_modules: nodeModules,
    project_lpm: fs.existsSync(path.join(projectDir(root), '.lpm')),
    cache: dependencyCachePresent(manager, root),
    package_store: manager === 'lpm' ? hasEntries(path.join(lpmHomeDir(root), 'store')) : undefined,
    installed_resolves: nodeModules ? verifyInstalledProject(root).ok : false,
  };
}

function assertScenarioState(manager, scenario, state) {
  const expected = {
    'first-install': { lockfile: false, node_modules: false, cache: false },
    'fresh-checkout-warm-cache': { lockfile: false, node_modules: false, cache: true },
    'ci-cold-cache': { lockfile: true, node_modules: false, cache: false },
    'ci-warm-cache': { lockfile: true, node_modules: false, cache: true },
    'installed-cache-gone': { lockfile: true, node_modules: true, cache: false },
    'up-to-date': { lockfile: true, node_modules: true, cache: true },
  }[scenario];
  assert.deepEqual(
    { lockfile: state.lockfile, node_modules: state.node_modules, cache: state.cache },
    expected,
    `${manager} ${scenario} setup`,
  );
  assert.equal(
    state.installed_resolves,
    expected.node_modules,
    `${manager} ${scenario} installed graph validity`,
  );
  if (manager === 'lpm') {
    const storeExpected = !['first-install', 'ci-cold-cache'].includes(scenario);
    assert.equal(state.package_store, storeExpected, `lpm ${scenario} package store setup`);
  }
}

function dependencyCachePresent(manager, root) {
  return dependencyCacheDirs(manager, root).some(hasEntries);
}

function dependencyCacheDirs(manager, root) {
  const dirs = [dependencyCacheDir(manager, root)];
  if (manager === 'pnpm') dirs.push(path.join(homeDir(root), '.cache', 'pnpm'));
  if (manager === 'aube' || manager === 'nub') {
    dirs.push(path.join(homeDir(root), '.local', 'share', manager, 'store'));
  }
  return dirs;
}

function dependencyCacheDir(manager, root) {
  switch (manager) {
    case 'lpm':
      return path.join(lpmHomeDir(root), 'cache');
    case 'bun':
      return path.join(homeDir(root), '.bun', 'install', 'cache');
    case 'pnpm':
      return path.join(homeDir(root), '.pnpm-store');
    case 'npm':
      return path.join(homeDir(root), '.npm', '_cacache');
    case 'aube':
      return path.join(homeDir(root), '.cache', 'aube');
    case 'nub':
      return path.join(homeDir(root), '.cache', 'nub', 'pm');
    case 'deno':
      return path.join(homeDir(root), '.cache', 'deno', 'npm');
    case 'vlt':
      return path.join(homeDir(root), 'vlt-cache');
    case 'upm':
      return path.join(homeDir(root), 'upm-store');
    case 'yarn':
      return path.join(homeDir(root), '.yarn-global');
    default:
      throw new Error(`unsupported manager: ${manager}`);
  }
}

function hasEntries(target) {
  try {
    return fs.readdirSync(target).length > 0;
  } catch {
    return false;
  }
}

function lockfilePresent(manager, project) {
  return managerLockfileNames(manager).some((name) => fs.existsSync(path.join(project, name)));
}

function managerLockfileNames(manager) {
  switch (manager) {
    case 'lpm':
      return ['lpm.lock', 'lpm.lockb'];
    case 'bun':
      return ['bun.lock', 'bun.lockb'];
    case 'pnpm':
      return ['pnpm-lock.yaml'];
    case 'npm':
      return ['package-lock.json', 'npm-shrinkwrap.json'];
    case 'aube':
      return ['aube-lock.yaml'];
    case 'nub':
      return ['nub.lock'];
    case 'deno':
      return ['deno.lock'];
    case 'vlt':
      return ['vlt-lock.json'];
    case 'upm':
      return ['upm.lock'];
    case 'yarn':
      return ['yarn.lock'];
    default:
      throw new Error(`unsupported manager: ${manager}`);
  }
}

function runInstall({ manager, root, output, measured, timing = false, allowUpToDate = false }) {
  fs.mkdirSync(output, { recursive: true });
  const command = installCommand(manager, root, timing);
  const env = managerEnv(manager, root, timing);
  writeJson(path.join(output, 'command.json'), { command, cwd: projectDir(root), manager,
    lpm_firewall_override: manager === 'lpm' ? env.LPM_NPM_FIREWALL : undefined });
  const timePath = path.join(output, 'time.txt');
  const timed = measured ? timedCommand(command, timePath) : { command, enabled: false };
  const actual = timed.command;
  const { result, wallMs, cleanupMs } = runOwnedCommand(actual, {
    cwd: projectDir(root),
    env,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: timeoutMs,
  });
  const backgroundDrainMs = drainManagerWorkers(manager);
  fs.writeFileSync(path.join(output, 'stdout.log'), result.stdout ?? '');
  fs.writeFileSync(path.join(output, 'stderr.log'), result.stderr ?? '');
  if (result.error) {
    fs.writeFileSync(path.join(output, 'spawn-error.txt'), `${result.error.stack ?? result.error}\n`);
  }
  const timeOutput = timed.enabled && fs.existsSync(timePath) ? fs.readFileSync(timePath, 'utf8') : '';
  const parsed = manager === 'lpm' ? parseJson(result.stdout) : null;
  if (parsed) {
    writeJson(path.join(output, 'stdout.json'), parsed);
  }
  const firewallValidation = verifyFirewall(parsed, manager, lpmFirewallMode, allowUpToDate);
  return {
    ok: result.status === 0 && !result.error && (manager !== 'lpm' || parsed !== null) && firewallValidation.ok,
    exit_code: result.status ?? 1,
    signal: result.signal,
    spawn_error: result.error ? String(result.error) : undefined,
    wall_ms: wallMs,
    timeout_cleanup_ms: cleanupMs,
    background_drain_ms: backgroundDrainMs,
    max_rss_bytes: timed.enabled ? parseMaxRssBytes(timeOutput, process.platform) : undefined,
    stdout_tail: tail(result.stdout ?? ''),
    stderr_tail: tail(result.stderr ?? ''),
    duration_ms: numberAt(parsed, ['duration_ms']),
    package_count: numberAt(parsed, ['count']),
    downloaded: numberAt(parsed, ['downloaded']),
    cached: numberAt(parsed, ['cached']),
    firewall: parsed?.security?.firewall ?? parsed?.firewall,
    firewall_validation: firewallValidation,
    linked: numberAt(parsed, ['linked']),
    resolve_ms: numberAt(parsed, ['timing', 'resolve_ms']),
    fetch_ms: numberAt(parsed, ['timing', 'fetch_ms']),
    link_ms: numberAt(parsed, ['timing', 'link_ms']),
    link_reuse_check_sum_ms: numberAt(parsed, [
      'timing',
      'detail',
      'link',
      'v2_one',
      'reuse_check_sum_ms',
    ]),
    link_touch_sum_ns: numberAt(parsed, [
      'timing',
      'detail',
      'link',
      'v2_one',
      'touch_sum_ns',
    ]),
    ...streamingPipelineMetrics(parsed),
  };
}

function verifyFirewall(parsed, manager, mode, allowUpToDate = false) {
  if (manager !== 'lpm' || !['monitor', 'enforce'].includes(mode)) {
    return { ok: true, status: 'not-requested' };
  }
  const firewall = parsed?.security?.firewall ?? parsed?.firewall;
  if (!firewall && allowUpToDate && parsed?.up_to_date === true) {
    return { ok: true, status: 'up-to-date-after-validated-preparation' };
  }
  if (!firewall || firewall.enabled !== true || firewall.mode !== mode) {
    return { ok: false, error: `missing enabled ${mode} firewall report` };
  }
  if (firewall.rpc_failed !== false || firewall.offline_skipped !== false) {
    return { ok: false, error: 'firewall request failed, was skipped, or has no completion status' };
  }
  // Unknown is a verdict classification that overlaps the action counts.
  const counts = ['allow_count', 'warn_count', 'block_count'].map((key) => firewall[key]);
  if (!Number.isSafeInteger(firewall.checked_count) || firewall.checked_count <= 0 ||
      counts.some((count) => !Number.isSafeInteger(count) || count < 0) ||
      !Number.isSafeInteger(firewall.unknown_count) || firewall.unknown_count < 0 ||
      firewall.unknown_count > firewall.checked_count ||
      counts.reduce((sum, count) => sum + count, 0) !== firewall.checked_count) {
    return { ok: false, error: 'firewall report has no complete verdict counts' };
  }
  return { ok: true, status: 'validated-verdicts' };
}

function runOwnedCommand(command, options) {
  const ownsGroup = process.platform !== 'win32';
  const started = process.hrtime.bigint();
  const result = spawnSync(command[0], command.slice(1), {
    ...options,
    detached: ownsGroup,
    killSignal: 'SIGKILL',
  });
  const wallMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
  const cleanupStarted = Date.now();
  if (result.error && ownsGroup && Number.isInteger(result.pid) && result.pid > 0) {
    // The detached spawn owns this group, including children of the timing wrapper.
    const group = -result.pid;
    for (const signal of ['SIGTERM', 'SIGKILL']) {
      try { process.kill(group, signal); } catch (error) {
        if (error.code !== 'ESRCH') throw error;
        break;
      }
      const deadline = Date.now() + 1000;
      while (processGroupExists(group) && Date.now() < deadline) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
      if (!processGroupExists(group)) break;
    }
    if (processGroupExists(group)) throw new Error(`Timed-out process group ${result.pid} did not exit`);
  }
  return { result, wallMs, cleanupMs: Date.now() - cleanupStarted };
}

function processGroupExists(group) {
  try {
    process.kill(group, 0);
    return true;
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
    return false;
  }
}

function backgroundWorkerPids(snapshot, directory) {
  const scripts = [
    'registry-client-src-revalidate.js', 'cache-unzip-src-unzip.js',
    'security-archive-src-update-expired.js', 'rollback-remove-src-remove.js',
  ].map((name) => path.join(directory, name));
  const titles = new Set(['vlt-cache-revalidate', 'vlt-cache-unzip', 'vlt-security-archive-update']);
  return snapshot.split('\n').flatMap((line) => {
    const match = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!match) return [];
    const args = match[2].trim().split(/\s+/);
    return titles.has(args[0]) || scripts.some((script) => args.includes(script)) ? [Number(match[1])] : [];
  });
}

function drainManagerWorkers(manager) {
  if (manager !== 'vlt') return 0;
  const directory = path.dirname(fs.realpathSync(managerBinary(manager) === 'vlt' ? commandPath('vlt') : managerBinary(manager)));
  const started = Date.now();
  let quietChecks = 0;
  while (Date.now() - started < 30_000) {
    const snapshot = spawnSync('ps', ['-axo', 'pid=,args='], { encoding: 'utf8', timeout: 5000 });
    if (snapshot.status !== 0) throw new Error('Could not check vlt background workers');
    quietChecks = backgroundWorkerPids(snapshot.stdout, directory).length === 0 ? quietChecks + 1 : 0;
    if (quietChecks === 2) return Date.now() - started;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
  }
  throw new Error('vlt background workers did not finish within 30 seconds');
}

function installCommand(manager, root, timing) {
  switch (manager) {
    case 'lpm': {
      const command = [
        lpmBin,
        '--json',
        'install',
        '--no-security-summary',
        '--no-skills',
        '--no-editor-setup',
      ];
      if (timing) {
        command.push('--timing');
      }
      return command;
    }
    case 'bun':
      return [managerBinary(manager), 'install', '--ignore-scripts'];
    case 'pnpm':
      return [
        managerBinary(manager),
        'install',
        '--ignore-scripts',
        '--reporter',
        'silent',
        '--store-dir',
        dependencyCacheDir(manager, root),
      ];
    case 'npm':
      return [managerBinary(manager), 'install', '--ignore-scripts', '--no-fund', '--loglevel', 'silent'];
    case 'aube':
    case 'nub':
      return [managerBinary(manager), 'install', '--ignore-scripts', '--prefer-frozen-lockfile'];
    case 'deno':
      return [managerBinary(manager), 'install', '--node-modules-dir=auto'];
    case 'vlt':
      return [managerBinary(manager), 'install', '--cache', dependencyCacheDir(manager, root),
        '--registry', 'https://registry.npmjs.org/', '--registries', 'npm=https://registry.npmjs.org/'];
    case 'upm':
      return [managerBinary(manager), 'install', '--store', dependencyCacheDir(manager, root)];
    case 'yarn':
      return [managerBinary(manager), 'install'];
    default:
      throw new Error(`unsupported manager: ${manager}`);
  }
}

function managerEnv(manager, root, timing = false, firewallMode = lpmFirewallMode) {
  const keep = [
    'PATH',
    'SHELL',
    'LANG',
    'LC_ALL',
    'TMPDIR',
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'NODE_EXTRA_CA_CERTS',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy',
    'no_proxy',
  ];
  const env = {};
  for (const key of keep) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key];
    }
  }
  env.HOME = homeDir(root);
  env.USERPROFILE = homeDir(root);
  env.XDG_CACHE_HOME = path.join(homeDir(root), '.cache');
  env.XDG_CONFIG_HOME = path.join(homeDir(root), '.config');
  env.XDG_DATA_HOME = path.join(homeDir(root), '.local', 'share');
  env.CI = '1';
  env.NO_COLOR = '1';
  env.BUN_INSTALL = path.join(homeDir(root), '.bun');
  env.BUN_INSTALL_CACHE_DIR = path.join(homeDir(root), '.bun', 'install', 'cache');
  env.PNPM_HOME = path.join(homeDir(root), '.pnpm-home');
  env.NPM_CONFIG_USERCONFIG = path.join(homeDir(root), '.npmrc');
  env.npm_config_userconfig = env.NPM_CONFIG_USERCONFIG;
  env.NPM_CONFIG_CACHE = path.join(homeDir(root), '.npm');
  env.npm_config_cache = env.NPM_CONFIG_CACHE;
  env.AUBE_CACHE_DIR = path.join(homeDir(root), '.cache', 'aube');
  env.AUBE_STORE_DIR = path.join(homeDir(root), '.local', 'share', 'aube', 'store');
  env.AUBE_NO_UPDATE_CHECK = '1';
  env.DENO_DIR = path.join(homeDir(root), '.cache', 'deno');
  env.DENO_NO_UPDATE_CHECK = '1';
  env.DENO_NO_PROMPT = '1';
  env.YARN_GLOBAL_FOLDER = path.join(homeDir(root), '.yarn-global');
  env.YARN_NODE_LINKER = 'node-modules';
  env.YARN_ENABLE_SCRIPTS = 'false';
  env.YARN_ENABLE_IMMUTABLE_INSTALLS = 'false';
  if (manager === 'lpm') {
    for (const key of ['LPM_REGISTRY_URL', 'LPM_TOKEN', 'LPM_NPM_FANOUT']) {
      if (process.env[key] !== undefined) env[key] = process.env[key];
    }
    env.LPM_HOME = lpmHomeDir(root);
    env.LPM_STORE_VERSION = 'v2';
    if (firewallMode !== undefined) env.LPM_NPM_FIREWALL = firewallMode;
    if (timing) {
      env.LPM_TIMING_DETAIL = 'trace';
    }
  }
  return env;
}

function verifyInstalledProject(root) {
  const result = spawnSync(process.execPath, ['-e', `
    const fs = require('node:fs');
    const path = require('node:path');
    const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    const versions = {};
    for (const name of Object.keys({...manifest.dependencies, ...manifest.devDependencies})) {
      versions[name] = JSON.parse(fs.readFileSync(path.join('node_modules', name, 'package.json'), 'utf8')).version;
    }
    require.resolve('next/package.json');
    process.stdout.write(JSON.stringify(versions));
  `], {
    cwd: projectDir(root),
    env: { PATH: process.env.PATH, NODE_PATH: path.join(projectDir(root), 'node_modules') },
    encoding: 'utf8',
    timeout: 30_000,
  });
  return {
    ok: result.status === 0,
    exit_code: result.status ?? 1,
    stderr_tail: tail(result.stderr ?? ''),
    direct_versions: parseJson(result.stdout),
  };
}

function summarize(rows) {
  return SCENARIOS.map((scenario) => {
    const managers = Object.fromEntries(
      metadata.managers.map((manager) => {
        const group = rows.filter(
          (row) => row.scenario === scenario.id && row.manager === manager && row.ok && row.verification.ok,
        );
        return [
          manager,
          {
            successful_samples: group.length,
            firewall: manager === 'lpm' && ['monitor', 'enforce'].includes(lpmFirewallMode)
              ? summarizeFirewall(group) : undefined,
            wall_ms: stats(group.map((row) => row.wall_ms)),
            max_rss_bytes: stats(group.map((row) => row.max_rss_bytes)),
            resolve_ms: stats(group.map((row) => row.resolve_ms)),
            fetch_ms: stats(group.map((row) => row.fetch_ms)),
            link_ms: stats(group.map((row) => row.link_ms)),
            link_reuse_check_sum_ms: stats(
              group.map((row) => row.link_reuse_check_sum_ms),
            ),
            link_touch_sum_ns: stats(group.map((row) => row.link_touch_sum_ns)),
          },
        ];
      }),
    );
    return {
      scenario: scenario.id,
      title: scenario.title,
      state: scenario.state,
      managers,
      lpm_ratios: Object.fromEntries(
        metadata.managers.map((manager) => [
          manager,
          {
            wall: ratio(managers.lpm.wall_ms?.median, managers[manager].wall_ms?.median),
            rss: ratio(
              managers.lpm.max_rss_bytes?.median,
              managers[manager].max_rss_bytes?.median,
            ),
          },
        ]),
      ),
      lpm_to_bun_wall_ratio: ratio(managers.lpm.wall_ms?.median, managers.bun?.wall_ms?.median),
      lpm_to_bun_rss_ratio: ratio(
        managers.lpm.max_rss_bytes?.median,
        managers.bun?.max_rss_bytes?.median,
      ),
    };
  });
}

function summarizeFirewall(rows) {
  const reports = rows.filter((row) => row.firewall_validation?.status === 'validated-verdicts')
    .map((row) => row.firewall);
  return {
    verdict_samples: reports.length,
    up_to_date_samples: rows.filter((row) => row.firewall_validation?.status === 'up-to-date-after-validated-preparation').length,
    ...Object.fromEntries(['checked_count', 'allow_count', 'warn_count', 'block_count', 'unknown_count',
      'batch_ms', 'chunk_count', 'chunk_sum_ms', 'chunk_max_ms'].map((key) => [key, stats(reports.map((report) => report[key]))])),
    client_request_ms: stats(reports.map((report) => report.client?.requestMs)),
    worker_entitlement_ms: stats(reports.map((report) => report.worker?.entitlementMs)),
  };
}

function summarizeTiming(rows) {
  return SCENARIOS.map((scenario) => {
    const group = rows.filter(
      (row) => row.scenario === scenario.id && row.ok && row.verification.ok,
    );
    const streamedPackages = {};
    for (const row of group) {
      const name = row.streamed_package ?? 'none';
      streamedPackages[name] = (streamedPackages[name] ?? 0) + 1;
    }
    return {
      scenario: scenario.id,
      title: scenario.title,
      successful_samples: group.length,
      pipeline_wall_sum_ms: stats(group.map((row) => row.pipeline_wall_sum_ms)),
      pipeline_wall_max_ms: stats(group.map((row) => row.pipeline_wall_max_ms)),
      pipeline_wall_task_count: stats(group.map((row) => row.pipeline_wall_task_count)),
      stream_body_wall_ms: stats(group.map((row) => row.stream_body_wall_ms)),
      streaming_weight_requested: stats(
        group.map((row) => row.streaming_weight_requested),
      ),
      streaming_weight_acquired: stats(
        group.map((row) => row.streaming_weight_acquired),
      ),
      streaming_extract_permit_wait_ms: stats(
        group.map((row) => row.streaming_extract_permit_wait_ms),
      ),
      supplemental_permit_hold_ms: stats(
        group.map((row) => row.supplemental_permit_hold_ms),
      ),
      supplemental_permit_lease_expired: stats(
        group.map((row) => row.supplemental_permit_lease_expired),
      ),
      declared_unpacked_bytes: stats(group.map((row) => row.declared_unpacked_bytes)),
      actual_unpacked_bytes: stats(group.map((row) => row.actual_unpacked_bytes)),
      actual_to_declared_unpacked_ratio: stats(
        group.map((row) => row.actual_to_declared_unpacked_ratio),
      ),
      streamed_packages: streamedPackages,
    };
  });
}

function stats(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (sorted.length === 0) {
    return null;
  }
  const median = medianOfSorted(sorted);
  const deviations = sorted.map((value) => Math.abs(value - median)).sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    median,
    p95: percentile(sorted, 0.95),
    max: sorted.at(-1),
    iqr: percentile(sorted, 0.75) - percentile(sorted, 0.25),
    mad: medianOfSorted(deviations),
  };
}

function medianOfSorted(sorted) {
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function percentile(sorted, quantile) {
  return sorted[Math.ceil(quantile * sorted.length) - 1];
}

function renderMarkdown(plan, summary, timingSummary) {
  const lines = [
    '# T3 six-state install benchmark',
    '',
    `- Attempts per manager/state: ${plan.samples}`,
    '- Wall-time and RSS statistics include successful installs only. Success counts appear for every manager/state.',
    `- Statistics: ${plan.statistics}`,
    `- Policy: ${plan.policy}`,
    `- Fixture SHA-256: \`${plan.fixture.package_json_sha256}\``,
    ...plan.managers.map((manager) => {
      const info = plan.manager_info[manager];
      const digest = info.binary_sha256 ? ` (\`${info.binary_sha256}\`)` : '';
      return `- ${manager}: ${info.version}${digest}`;
    }),
    `- Host: ${plan.cpu}, ${formatMiB(plan.total_memory_bytes)} RAM, ${plan.platform}`,
    `- Timing: ${plan.timing_scope}`,
    `- Scripts: ${plan.script_policy}`,
    '',
    '| Scenario | Manager | Successes / attempts | Wall median / p95 | LPM/manager wall | RSS median / p95 | LPM/manager RSS | LPM resolve / fetch / link median |',
    '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const row of summary) {
    for (const [index, manager] of plan.managers.entries()) {
      const result = row.managers[manager];
      const timing =
        manager === 'lpm'
          ? `${formatMs(result.resolve_ms?.median)} / ${formatMs(result.fetch_ms?.median)} / ${formatMs(result.link_ms?.median)}`
          : 'n/a';
      lines.push(
        `| ${index === 0 ? `${row.title}<br><sub>${row.state}</sub>` : ''} | ${manager} | ${result.successful_samples}/${plan.samples} | ${wallCell(result.wall_ms)} | ${formatRatio(row.lpm_ratios[manager].wall)} | ${rssCell(result.max_rss_bytes)} | ${formatRatio(row.lpm_ratios[manager].rss)} | ${timing} |`,
      );
    }
  }
  if (['monitor', 'enforce'].includes(plan.lpm_firewall_override)) {
    lines.push('', '## LPM firewall diagnostics from scored samples', '',
      'Only validated requests contribute to these statistics. Unknown verdicts overlap the action counts.',
      'Up-to-date samples can skip requests after validated preparation. Request work can overlap download work.', '',
      '| Scenario | Verdict samples / up-to-date samples | Checked / allow / warn / block / unknown median | Batch wall median / p95 | Chunk work median / p95 | Client request work median / p95 | Server entitlement work median / p95 |',
      '| --- | ---: | ---: | ---: | ---: | ---: | ---: |');
    for (const row of summary) {
      const result = row.managers.lpm.firewall;
      const counts = ['checked_count', 'allow_count', 'warn_count', 'block_count', 'unknown_count']
        .map((key) => formatNumber(result[key]?.median)).join(' / ');
      lines.push(`| ${row.title} | ${result.verdict_samples} / ${result.up_to_date_samples} | ${counts} | ${wallCell(result.batch_ms)} | ${wallCell(result.chunk_sum_ms)} | ${wallCell(result.client_request_ms)} | ${wallCell(result.worker_entitlement_ms)} |`);
    }
  }
  lines.push(
    '',
    `## LPM timing diagnostics (${plan.timing_samples} samples, excluded from scored wall/RSS)`,
    '',
    '| Scenario | Pipeline / body wall median / p95 | Weight requested / acquired | Permit wait / supplemental hold | Lease expiries | Declared / actual unpacked | Streamed packages |',
    '| --- | ---: | ---: | ---: | ---: | ---: | --- |',
  );
  for (const row of timingSummary) {
    lines.push(
      `| ${row.title} | pipeline ${wallCell(row.pipeline_wall_max_ms)}<br>body ${wallCell(row.stream_body_wall_ms)} | ${formatNumber(row.streaming_weight_requested?.median)} / ${formatNumber(row.streaming_weight_acquired?.median)} | ${formatMs(row.streaming_extract_permit_wait_ms?.median)} / ${formatMs(row.supplemental_permit_hold_ms?.median)} | ${formatNumber(row.supplemental_permit_lease_expired?.median)} | ${formatMiB(row.declared_unpacked_bytes?.median)} / ${formatMiB(row.actual_unpacked_bytes?.median)} (${formatRatio(row.actual_to_declared_unpacked_ratio?.median)}) | ${Object.entries(row.streamed_packages)
        .map(([name, count]) => `${name} ×${count}`)
        .join(', ')} |`,
    );
  }
  return `${lines.join('\n')}\n`;
}

function wallCell(value) {
  return value ? `${value.median} / ${value.p95} ms` : 'n/a';
}

function rssCell(value) {
  return value ? `${formatMiB(value.median)} / ${formatMiB(value.p95)}` : 'n/a';
}

function formatMiB(bytes) {
  return Number.isFinite(bytes) ? `${(bytes / 1024 / 1024).toFixed(1)} MiB` : 'n/a';
}

function formatMs(value) {
  return Number.isFinite(value) ? `${value.toFixed(1)} ms` : 'n/a';
}

function formatNumber(value) {
  return Number.isFinite(value) ? String(value) : 'n/a';
}

function ratio(numerator, denominator) {
  return Number.isFinite(numerator) && Number.isFinite(denominator) && denominator !== 0
    ? numerator / denominator
    : null;
}

function formatRatio(value) {
  return Number.isFinite(value) ? `${value.toFixed(2)}×` : 'n/a';
}

function timedCommand(command, outputPath) {
  if (!fs.existsSync('/usr/bin/time')) {
    return { command, enabled: false };
  }
  if (process.platform === 'darwin') {
    return { command: ['/usr/bin/time', '-l', '-o', outputPath, ...command], enabled: true };
  }
  if (process.platform === 'linux') {
    return { command: ['/usr/bin/time', '-v', '-o', outputPath, ...command], enabled: true };
  }
  return { command, enabled: false };
}

function parseMaxRssBytes(output, platform) {
  if (platform === 'darwin') {
    const match = output.match(/^\s*(\d+)\s+maximum resident set size\s*$/im);
    return match ? Number(match[1]) : undefined;
  }
  if (platform === 'linux') {
    const match = output.match(/^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$/im);
    return match ? Number(match[1]) * 1024 : undefined;
  }
  return undefined;
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function numberAt(value, keys) {
  let current = value;
  for (const key of keys) {
    current = current?.[key];
  }
  return Number.isFinite(current) ? current : undefined;
}

function streamedTask(value) {
  const fetchTasks = value?.timing?.detail?.trace?.slow_packages?.fetch_tasks;
  if (Array.isArray(fetchTasks?.by_pipeline) && fetchTasks.by_pipeline.length > 0) {
    return fetchTasks.by_pipeline[0];
  }
  return Array.isArray(fetchTasks?.by_total)
    ? fetchTasks.by_total.find((row) => Number(row?.pipeline_wall_ms) > 0)
    : undefined;
}

function streamedPackage(value) {
  return streamedTask(value)?.package;
}

function streamingPipelineMetrics(value) {
  const task = streamedTask(value);
  return {
    pipeline_wall_sum_ms: numberAt(value, [
      'timing',
      'fetch_breakdown',
      'pipeline_wall',
      'sum_ms',
    ]),
    pipeline_wall_task_count: numberAt(value, [
      'timing',
      'fetch_breakdown',
      'pipeline_wall',
      'task_count',
    ]),
    pipeline_wall_max_ms: numberAt(value, [
      'timing',
      'fetch_breakdown',
      'pipeline_wall',
      'max_ms',
    ]),
    stream_body_wall_ms: numberAt(task, ['stream_body_wall_ms']),
    streaming_weight_requested: numberAt(task, ['streaming_weight_requested']),
    streaming_weight_acquired: numberAt(task, ['streaming_weight_acquired']),
    streaming_extract_permit_wait_ms: numberAt(task, ['extract_permit_wait_ms']),
    supplemental_permit_hold_ms: numberAt(task, ['supplemental_permit_hold_ms']),
    supplemental_permit_lease_expired:
      task?.supplemental_permit_lease_expired === true
        ? 1
        : task?.supplemental_permit_lease_expired === false
          ? 0
          : undefined,
    declared_unpacked_bytes: numberAt(task, ['declared_unpacked_bytes']),
    actual_unpacked_bytes: numberAt(task, ['unpacked_bytes']),
    actual_to_declared_unpacked_ratio: ratio(
      numberAt(task, ['unpacked_bytes']),
      numberAt(task, ['declared_unpacked_bytes']),
    ),
    streamed_package: task?.package,
  };
}

function rotate(values, offset) {
  return [...values.slice(offset), ...values.slice(0, offset)];
}

function managerOrderFor(sample, scenarioId, managers = DEFAULT_MANAGERS) {
  const scenarioPosition = SCENARIO_POSITIONS.get(scenarioId);
  if (scenarioPosition === undefined) {
    throw new Error(`unknown scenario: ${scenarioId}`);
  }
  return rotate(managers, (sample + scenarioPosition) % managers.length);
}

function projectDir(root) {
  return path.join(root, 'project');
}

function homeDir(root) {
  return path.join(root, 'home');
}

function lpmHomeDir(root) {
  return path.join(root, 'lpm-home');
}

function tail(value) {
  return value.trim().split('\n').slice(-20).join('\n');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeJson(target, value) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);
}

function commandVersion(command) {
  const result = spawnSync(command, ['--version'], { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`could not read version from ${command}`);
  }
  return result.stdout.trim();
}

function describeManager(manager) {
  if (manager === 'lpm') {
    return {
      binary: lpmBin,
      binary_sha256: sha256(fs.readFileSync(lpmBin)),
      version: commandVersion(lpmBin),
    };
  }
  const binary = commandPath(managerBinary(manager));
  return {
    binary,
    binary_sha256: sha256(fs.readFileSync(binary)),
    version: manager === 'upm' ? installedPackageVersion(binary, 'upm') : commandVersion(binary),
  };
}

function managerBinary(manager) {
  return binaryOverrides[manager] ?? manager;
}

function installedPackageVersion(binary, name) {
  let directory = path.dirname(fs.realpathSync(binary));
  while (true) {
    const manifestPath = path.join(directory, 'package.json');
    if (fs.existsSync(manifestPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      if (manifest.name === name) return manifest.version;
    }
    const parent = path.dirname(directory);
    if (parent === directory) throw new Error(`package version missing for ${name}`);
    directory = parent;
  }
}

function commandPath(command) {
  const result = spawnSync('which', [command], { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`missing command: ${command}`);
  }
  return result.stdout.trim();
}

function requireFile(target, label) {
  if (!fs.statSync(target, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`${label} missing: ${target}`);
  }
}

function positiveInteger(raw, flag) {
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return value;
}

function parseFirewallMode(raw) {
  if (raw !== undefined && !['off', 'monitor', 'enforce'].includes(raw)) {
    throw new Error('--lpm-firewall must be off, monitor, or enforce');
  }
  return raw;
}

function parseManagerList(raw) {
  const requested = raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  if (requested.length === 0) {
    throw new Error('--managers must not be empty');
  }
  if (new Set(requested).size !== requested.length) {
    throw new Error('--managers must not contain duplicates');
  }
  for (const manager of requested) {
    if (!SUPPORTED_MANAGERS.includes(manager)) {
      throw new Error(`unsupported manager: ${manager}`);
    }
  }
  return requested;
}

function parseArgs(values) {
  const out = {};
  for (let index = 0; index < values.length; index += 1) {
    const argument = values[index];
    if (argument === '--help' || argument === '-h') {
      out.help = true;
      continue;
    }
    if (argument === '--self-test') {
      out.selfTest = true;
      continue;
    }
    if (argument === '--keep-work') {
      out.keepWork = true;
      continue;
    }
    if (argument === '--resume') {
      out.resume = true;
      continue;
    }
    const key = {
      '-n': 'samples',
      '--samples': 'samples',
      '--timing-samples': 'timingSamples',
      '--managers': 'managers',
      '--manager-bins': 'managerBins',
      '--lpm-bin': 'lpmBin',
      '--lpm-firewall': 'lpmFirewall',
      '--fixture': 'fixture',
      '--output': 'output',
      '--work-dir': 'workDir',
      '--timeout-ms': 'timeoutMs',
    }[argument];
    if (!key || values[index + 1] === undefined) {
      throw new Error(`unsupported or incomplete argument: ${argument}`);
    }
    out[key] = values[index + 1];
    index += 1;
  }
  return out;
}

function selfTest() {
  const healthyFirewall = { enabled: true, mode: 'monitor', checked_count: 2,
    allow_count: 1, warn_count: 1, block_count: 0, unknown_count: 1,
    rpc_failed: false, offline_skipped: false };
  const firewallResult = (changes = {}) => ({ security: { firewall: { ...healthyFirewall, ...changes } } });
  assert.equal(verifyFirewall(firewallResult(), 'lpm', 'monitor').ok, true);
  assert.equal(verifyFirewall({ firewall: healthyFirewall }, 'lpm', 'monitor').ok, true);
  assert.equal(verifyFirewall(firewallResult({ mode: 'enforce' }), 'lpm', 'enforce').ok, true);
  for (const changes of [{ rpc_failed: true }, { offline_skipped: true }, { enabled: false },
    { mode: 'off' }, { checked_count: 0 }, { allow_count: 0 }, { unknown_count: -1 },
    { allow_count: '1' }, { rpc_failed: undefined }, { checked_count: NaN }, { unknown_count: 3 }]) {
    assert.equal(verifyFirewall(firewallResult(changes), 'lpm', 'monitor').ok, false, JSON.stringify(changes));
  }
  assert.equal(verifyFirewall(null, 'lpm', 'monitor').ok, false);
  assert.equal(verifyFirewall(null, 'bun', 'monitor').ok, true);
  assert.equal(verifyFirewall(null, 'lpm', 'off').ok, true);
  assert.equal(verifyFirewall(null, 'lpm', undefined).ok, true);
  assert.equal(verifyFirewall({ up_to_date: true }, 'lpm', 'monitor', true).ok, true);
  assert.equal(verifyFirewall({ up_to_date: true }, 'lpm', 'monitor', false).ok, false);
  assert.equal(verifyFirewall({ up_to_date: true, ...firewallResult({ rpc_failed: true }) }, 'lpm', 'monitor', true).ok, false);
  const firewallSummary = summarizeFirewall([
    { firewall: { ...healthyFirewall, batch_ms: 10 }, firewall_validation: { status: 'validated-verdicts' } },
    { firewall: { ...healthyFirewall, batch_ms: 20 }, firewall_validation: { status: 'validated-verdicts' } },
    { firewall_validation: { status: 'up-to-date-after-validated-preparation' } },
    { firewall: { batch_ms: 1000 }, firewall_validation: { ok: false } },
  ]);
  assert.equal(firewallSummary.verdict_samples, 2);
  assert.equal(firewallSummary.up_to_date_samples, 1);
  assert.equal(firewallSummary.batch_ms.median, 15);
  assert.equal(firewallSummary.client_request_ms, null);
  assert.deepEqual(parseArgs(['--lpm-firewall', 'monitor']), { lpmFirewall: 'monitor' });
  assert.equal(parseFirewallMode(undefined), undefined);
  assert.equal(parseFirewallMode('monitor'), 'monitor');
  assert.throws(() => parseFirewallMode('invalid'), /--lpm-firewall/);
  assert.equal(managerEnv('lpm', '/tmp/test-firewall', false, 'monitor').LPM_NPM_FIREWALL, 'monitor');
  assert.equal(managerEnv('bun', '/tmp/test-firewall', false, 'monitor').LPM_NPM_FIREWALL, undefined);
  assert.equal(managerEnv('lpm', '/tmp/test-firewall', false, undefined).LPM_NPM_FIREWALL, undefined);
  if (process.platform !== 'win32' && fs.existsSync('/usr/bin/time')) {
    let childPid;
    try {
      const { result } = runOwnedCommand(['/usr/bin/time', process.execPath, '-e',
        'process.on("SIGTERM", () => {}); console.log(process.pid); setInterval(() => {}, 1000);'],
      { encoding: 'utf8', timeout: 500 });
      childPid = Number(result.stdout.trim());
      assert.ok(Number.isInteger(childPid) && childPid > 0, 'timeout fixture started its child');
      assert.equal(result.error?.code, 'ETIMEDOUT');
      let alive = true;
      const deadline = Date.now() + 1000;
      while (alive && Date.now() < deadline) {
        try { process.kill(childPid, 0); } catch (error) {
          if (error.code !== 'ESRCH') throw error;
          alive = false;
        }
        if (alive) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
      assert.equal(alive, false, 'a timeout must terminate the child of the timing wrapper');
    } finally {
      if (Number.isInteger(childPid) && childPid > 0) {
        try { process.kill(childPid, 'SIGKILL'); } catch (error) {
          if (error.code !== 'ESRCH') throw error;
        }
      }
    }
  }
  assert.deepEqual(parseArgs(['--resume']), { resume: true });
  const partialSummary = renderMarkdown({
    samples: 10, managers: ['lpm'], manager_info: { lpm: { version: 'test' } }, fixture: {},
  }, [{ managers: { lpm: { successful_samples: 9 } }, lpm_ratios: { lpm: {} } }], []);
  assert.match(partialSummary, /9\/10/, 'the report must show successful attempts separately');
  const resumablePlan = {
    samples: 10, timing_samples: 3, managers: ['lpm', 'vlt'], work_directory: '/tmp/test-run',
    fixture: { package_json_sha256: 'fixture' }, manager_info: { lpm: { binary_sha256: 'binary' } },
    policy: 'defaults', statistics: 'median', scenarios: SCENARIOS,
  };
  assert.doesNotThrow(() => assertResumeCompatible(resumablePlan, structuredClone(resumablePlan)));
  assert.throws(() => assertResumeCompatible(resumablePlan, { ...resumablePlan, samples: 9 }));
  assert.throws(() => assertResumeCompatible(resumablePlan, { ...resumablePlan, manager_info: {} }));
  assert.throws(() => assertResumeCompatible(resumablePlan, { ...resumablePlan, lpm_firewall_override: 'monitor' }));
  assert.throws(() => assertResumeCompatible(resumablePlan, { ...resumablePlan, firewall_validation: 'successful-verdicts-and-preparation-v1' }));
  const resumedRows = [{ sample: 1, scenario: 'first-install', manager: 'lpm' }];
  assert.equal(completedCells(resumedRows, ['lpm'], 10).has('1:first-install:lpm'), true);
  assert.throws(() => completedCells([...resumedRows, ...resumedRows], ['lpm'], 10), /duplicate/);
  assert.throws(() => completedCells([{ ...resumedRows[0], sample: 11 }], ['lpm'], 10), /invalid/);
  assert.deepEqual(rotate([1, 2, 3], 1), [2, 3, 1]);
  assert.deepEqual(stats([1, 2, 3, 4, 100]), {
    count: 5,
    min: 1,
    median: 3,
    p95: 100,
    max: 100,
    iqr: 2,
    mad: 1,
  });
  assert.equal(parseMaxRssBytes('  12345  maximum resident set size\n', 'darwin'), 12345);
  assert.equal(
    parseMaxRssBytes('Maximum resident set size (kbytes): 12345\n', 'linux'),
    12_641_280,
  );
  assert.equal(ratio(20, 10), 2);
  assert.deepEqual(
    streamingPipelineMetrics({
      timing: {
        fetch_breakdown: {
          pipeline_wall: { task_count: 1, sum_ms: 17, max_ms: 17 },
          extract_permit_wait: { max_ms: 2 },
          streaming_admission: {
            requested_weight_max: 3,
            acquired_weight_max: 2,
            supplemental_hold_max_ms: 16,
            supplemental_lease_expired_count: 0,
          },
        },
        detail: {
          trace: {
            slow_packages: {
              fetch_tasks: {
                by_pipeline: [
                  {
                    package: 'next@16.3.2',
                    pipeline_wall_ms: 17,
                    stream_body_wall_ms: 15,
                    extract_permit_wait_ms: 2,
                    streaming_weight_requested: 3,
                    streaming_weight_acquired: 2,
                    declared_unpacked_bytes: 100,
                    unpacked_bytes: 120,
                    supplemental_permit_hold_ms: 16,
                    supplemental_permit_lease_expired: false,
                  },
                ],
              },
            },
          },
        },
      },
    }),
    {
      pipeline_wall_sum_ms: 17,
      pipeline_wall_task_count: 1,
      pipeline_wall_max_ms: 17,
      stream_body_wall_ms: 15,
      streaming_weight_requested: 3,
      streaming_weight_acquired: 2,
      streaming_extract_permit_wait_ms: 2,
      supplemental_permit_hold_ms: 16,
      supplemental_permit_lease_expired: 0,
      declared_unpacked_bytes: 100,
      actual_unpacked_bytes: 120,
      actual_to_declared_unpacked_ratio: 1.2,
      streamed_package: 'next@16.3.2',
    },
  );
  assert.equal(
    streamedPackage({
      timing: {
        detail: {
          trace: {
            slow_packages: {
              fetch_tasks: {
                by_pipeline: [{ package: 'tiny@1.0.0', pipeline_wall_ms: 0 }],
              },
            },
          },
        },
      },
    }),
    'tiny@1.0.0',
  );
  assert.equal(managerEnv('lpm', '/tmp/lpm-bench-self-test').LPM_TIMING_DETAIL, undefined);
  assert.equal(
    managerEnv('lpm', '/tmp/lpm-bench-self-test', true).LPM_TIMING_DETAIL,
    'trace',
  );
  assert.equal(
    managerEnv('npm', '/tmp/lpm-bench-self-test').NPM_CONFIG_CACHE,
    '/tmp/lpm-bench-self-test/home/.npm',
  );
  assert.equal(
    dependencyCacheDir('pnpm', '/tmp/lpm-bench-self-test'),
    '/tmp/lpm-bench-self-test/home/.pnpm-store',
  );
  assert.deepEqual(managerLockfileNames('pnpm'), ['pnpm-lock.yaml']);
  assert.deepEqual(managerLockfileNames('npm'), ['package-lock.json', 'npm-shrinkwrap.json']);
  assert.deepEqual(parseManagerList(SUPPORTED_MANAGERS.join(',')), SUPPORTED_MANAGERS);
  assert.throws(() => parseManagerList('lpm,lpm'), /duplicates/);
  assert.throws(() => parseManagerList('lpm,missing'), /unsupported manager/);
  assert.deepEqual(installCommand('bun', '/tmp/lpm-bench-self-test', false), [
    'bun',
    'install',
    '--ignore-scripts',
  ]);
  assert.deepEqual(installCommand('pnpm', '/tmp/lpm-bench-self-test', false), [
    'pnpm',
    'install',
    '--ignore-scripts',
    '--reporter',
    'silent',
    '--store-dir',
    '/tmp/lpm-bench-self-test/home/.pnpm-store',
  ]);
  assert.equal(SCENARIOS.length, 6);
  for (const scenario of SCENARIOS) {
    const orders = Array.from({ length: 10 }, (_, sampleIndex) => {
      const sample = sampleIndex + 1;
      return managerOrderFor(sample, scenario.id).join('-');
    });
    assert.equal(new Set(orders).size, 2, `${scenario.id} must use both manager orders`);
    assert.equal(
      orders.filter((order) => order === 'lpm-bun').length,
      5,
      `${scenario.id} manager order must be balanced`,
    );
    for (let index = 1; index < orders.length; index += 1) {
      assert.notEqual(
        orders[index],
        orders[index - 1],
        `${scenario.id} manager order must alternate across samples`,
      );
    }
    const managerOrders = Array.from({ length: SUPPORTED_MANAGERS.length * 2 }, (_, sampleIndex) =>
      managerOrderFor(sampleIndex + 1, scenario.id, SUPPORTED_MANAGERS),
    );
    assert.equal(
      new Set(managerOrders.map((order) => order.join('-'))).size,
      SUPPORTED_MANAGERS.length,
      `${scenario.id} must rotate all manager orders`,
    );
    for (const manager of SUPPORTED_MANAGERS) {
      for (let position = 0; position < SUPPORTED_MANAGERS.length; position += 1) {
        assert.equal(
          managerOrders.filter((order) => order[position] === manager).length,
          2,
          `${scenario.id} ${manager} must occupy position ${position} twice`,
        );
      }
    }
  }
  assert.throws(() => managerOrderFor(1, 'missing'), /unknown scenario/);
  assert.equal(stats([1, 2, 3, 10]).median, 2.5);
  assert.deepEqual(backgroundWorkerPids(
    '  31 /node /tools/vlt/registry-client-src-revalidate.js\n  32 /node /other/vlt/registry-client-src-revalidate.js\n  33 /node /tools/vlt/vlt.js\n',
    '/tools/vlt',
  ), [31]);
  assert.deepEqual(backgroundWorkerPids(
    '  41 vlt-cache-revalidate\n  42 vlt-cache-unzip\n  43 vlt-security-archive-update\n  44 unrelated-vlt-cache-unzip\n',
    '/tools/vlt',
  ), [41, 42, 43]);
  assert.equal(stats([1, 2, 3, 10]).p95, 10);
  assert.deepEqual(managerLockfileNames('nub'), ['nub.lock']);
  assert.deepEqual(managerLockfileNames('yarn'), ['yarn.lock']);
  assert.equal(managerEnv('yarn', '/tmp/lpm-bench-self-test').YARN_NODE_LINKER, 'node-modules');
  assert.equal(managerEnv('yarn', '/tmp/lpm-bench-self-test').YARN_ENABLE_SCRIPTS, 'false');
  assert.equal(managerEnv('yarn', '/tmp/lpm-bench-self-test').YARN_NPM_MINIMAL_AGE_GATE, undefined);
  assert.equal(installCommand('npm', '/tmp/lpm-bench-self-test', false).includes('--no-audit'), false);
  const cacheTestRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-six-state-cache-test-'));
  try {
    for (const manager of SUPPORTED_MANAGERS) {
      const root = path.join(cacheTestRoot, manager);
      for (const target of dependencyCacheDirs(manager, root)) {
        fs.mkdirSync(target, { recursive: true });
        fs.writeFileSync(path.join(target, 'cache-entry'), 'cached');
      }
      assert.equal(dependencyCachePresent(manager, root), true);
      const runtimeCache = path.join(homeDir(root), '.cache', 'nub', 'runtime-fixture');
      fs.mkdirSync(runtimeCache, { recursive: true });
      const store = path.join(lpmHomeDir(root), 'store');
      fs.mkdirSync(store, { recursive: true });
      fs.writeFileSync(path.join(store, 'package-entry'), 'installed');
      clearDependencyCache(manager, root);
      assert.equal(dependencyCachePresent(manager, root), false, `${manager} cache removal`);
      assert.equal(fs.existsSync(runtimeCache), true, `${manager} runtime remains`);
      assert.equal(hasEntries(store), true, 'installed LPM backing store remains');
      clearAllDependencyState(manager, root);
      if (manager === 'lpm') assert.equal(hasEntries(store), false);
    }
  } finally {
    fs.rmSync(cacheTestRoot, { recursive: true, force: true });
  }
  const expectedStates = {
    'first-install': { lockfile: false, node_modules: false, cache: false },
    'fresh-checkout-warm-cache': { lockfile: false, node_modules: false, cache: true },
    'ci-cold-cache': { lockfile: true, node_modules: false, cache: false },
    'ci-warm-cache': { lockfile: true, node_modules: false, cache: true },
    'installed-cache-gone': { lockfile: true, node_modules: true, cache: false },
    'up-to-date': { lockfile: true, node_modules: true, cache: true },
  };
  for (const manager of SUPPORTED_MANAGERS) {
    for (const scenario of SCENARIOS) {
      const expected = expectedStates[scenario.id];
      assertScenarioState(manager, scenario.id, {
        ...expected,
        installed_resolves: expected.node_modules,
        package_store:
          manager === 'lpm' && !['first-install', 'ci-cold-cache'].includes(scenario.id),
      });
    }
  }
  assert.throws(
    () =>
      assertScenarioState('lpm', 'installed-cache-gone', {
        ...expectedStates['installed-cache-gone'],
        installed_resolves: false,
        package_store: true,
      }),
    /installed graph validity/,
  );
  const fixtureBytes = fs.readFileSync(
    path.join(repoRoot, 'bench/audit-fixtures/t3-install/package.json'),
  );
  assert.equal(
    sha256(fixtureBytes),
    'fa994042232e39e73fd1c4436c5e90974b47c4656e9c4a742c3988c6097b9871',
  );
  console.log('self-test passed');
}

function printHelp() {
  console.log(`Usage: node bench/scripts/run-t3-install-six-states.mjs [options]

Benchmark LPM and selected reference managers against the T3-stack manifest in
six install states.
Each state is prepared outside the measured interval, pre-state assertions
must pass, manager order rotates within each comparison group, and every
measured install must resolve next/package.json and contain every direct dependency.

Options:
  -n, --samples N      Samples per manager/state (default: 10)
      --timing-samples N  Separate LPM --timing samples per state (default: 3)
      --managers LIST  lpm,bun,pnpm,npm,aube,nub,deno,vlt,upm,yarn
                       (default: lpm,bun; must include lpm)
      --manager-bins FILE  JSON object mapping manager names to executable paths
      --lpm-bin PATH   LPM binary (default: target/release/lpm-rs)
      --lpm-firewall MODE  Explicit LPM firewall mode: off, monitor, or enforce
      --fixture DIR    Override the directory containing package.json
      --output DIR     Result directory (default: /tmp/lpm-t3-six-*)
      --work-dir DIR   Separate temporary install directory (default: OUTPUT/work)
      --timeout-ms N   Per-install timeout (default: 600000)
      --resume         Continue an incomplete run without replacing completed attempts
      --keep-work      Preserve prepared projects in the work directory
      --self-test      Run harness unit checks without installing packages
  -h, --help           Show this help

Set LPM_NPM_FANOUT only to benchmark an explicit LPM metadata-concurrency
override.
`);
}
