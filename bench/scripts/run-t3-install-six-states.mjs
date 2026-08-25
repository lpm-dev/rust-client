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

const MANAGERS = ['lpm', 'bun'];
const SCENARIO_POSITIONS = new Map(SCENARIOS.map(({ id }, index) => [id, index]));
const argv = parseArgs(process.argv.slice(2));

if (argv.help) {
  printHelp();
  process.exit(0);
}

if (argv.selfTest) {
  selfTest();
  process.exit(0);
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
const timeoutMs = positiveInteger(argv.timeoutMs ?? '600000', '--timeout-ms');

requireFile(lpmBin, 'LPM binary');
requireFile(packageJsonPath, 'fixture package.json');
if (fs.existsSync(outputDir)) {
  throw new Error(`output already exists: ${outputDir}`);
}

const fixturePackageJson = fs.readFileSync(packageJsonPath);
const workspaceDir = path.join(outputDir, 'work');
const artifactDir = path.join(outputDir, 'artifacts');
fs.mkdirSync(workspaceDir, { recursive: true });
fs.mkdirSync(artifactDir, { recursive: true });

const metadata = {
  created_at: new Date().toISOString(),
  samples,
  timing_samples: timingSamples,
  managers: MANAGERS,
  scenarios: SCENARIOS,
  fixture: {
    directory: fixtureDir,
    upstream_url: 'https://github.com/oven-sh/bun/tree/main/bench/install',
    upstream_commit: '9dd73746c7b51b6450bb675ce2abcf86a0ae076f',
    package_json_sha256: sha256(fixturePackageJson),
    package_json: JSON.parse(fixturePackageJson),
  },
  lpm: {
    binary: lpmBin,
    binary_sha256: sha256(fs.readFileSync(lpmBin)),
    version: commandVersion(lpmBin),
  },
  bun: {
    binary: commandPath('bun'),
    version: commandVersion('bun'),
  },
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  os_release: os.release(),
  cpu: os.cpus()[0]?.model,
  total_memory_bytes: os.totalmem(),
  timeout_ms: timeoutMs,
  lpm_npm_fanout_override: process.env.LPM_NPM_FANOUT,
  timing_scope:
    'scored wall/RSS samples omit timing instrumentation; separate LPM-only diagnostics use --timing with trace detail',
  script_policy: 'install scripts disabled for both managers',
  state_mapping: {
    lpm_cache: 'LPM_HOME/cache (ephemeral metadata)',
    lpm_store: 'LPM_HOME/store (content store backing V2 node_modules symlinks)',
    installed_cache_gone: 'clear LPM_HOME/cache but preserve LPM_HOME/store for LPM',
  },
};
writeJson(path.join(outputDir, 'plan.json'), metadata);

const rows = [];
for (let sample = 1; sample <= samples; sample += 1) {
  const scenarioOrder = rotate(SCENARIOS, (sample - 1) % SCENARIOS.length);
  for (const scenario of scenarioOrder) {
    const managerOrder = managerOrderFor(sample, scenario.id);
    const pairId = `${scenario.id}:sample-${sample}`;
    const prepared = new Map();
    for (const manager of MANAGERS) {
      const root = path.join(workspaceDir, `sample-${sample}-${scenario.id}-${manager}`);
      prepareScenario({ manager, scenario: scenario.id, root });
      const setup = captureState(manager, root);
      assertScenarioState(manager, scenario.id, setup);
      prepared.set(manager, { root, setup });
    }
    for (const manager of managerOrder) {
      const { root, setup } = prepared.get(manager);
      const output = path.join(artifactDir, scenario.id, manager, `sample-${sample}`);
      const result = runInstall({ manager, root, output, measured: true });
      const verification = verifyInstalledProject(root);
      const row = {
        sample,
        pair_id: pairId,
        pair_order: managerOrder.join('-'),
        scenario: scenario.id,
        manager,
        setup,
        verification,
        ...result,
      };
      rows.push(row);
      writeJson(path.join(output, 'metrics.json'), row);
      console.log(
        `[${scenario.id} ${manager}] ${sample}/${samples} ${result.ok && verification.ok ? 'ok' : 'FAIL'} ` +
          `wall=${result.wall_ms}ms rss=${formatMiB(result.max_rss_bytes)} ` +
          `${manager === 'lpm' ? `resolve=${formatMs(result.resolve_ms)} fetch=${formatMs(result.fetch_ms)} link=${formatMs(result.link_ms)}` : ''}`,
      );
      if (!keepWork) {
        fs.rmSync(root, { recursive: true, force: true });
      }
    }
  }
  writeJson(path.join(outputDir, 'rows.partial.json'), rows);
}

const timingRows = [];
for (let sample = 1; sample <= timingSamples; sample += 1) {
  const scenarioOrder = rotate(SCENARIOS, (sample - 1) % SCENARIOS.length);
  for (const scenario of scenarioOrder) {
    const root = path.join(workspaceDir, `timing-${sample}-${scenario.id}-lpm`);
    prepareScenario({ manager: 'lpm', scenario: scenario.id, root });
    const setup = captureState('lpm', root);
    assertScenarioState('lpm', scenario.id, setup);
    const output = path.join(artifactDir, 'timing', scenario.id, `sample-${sample}`);
    const result = runInstall({
      manager: 'lpm',
      root,
      output,
      measured: false,
      timing: true,
    });
    const verification = verifyInstalledProject(root);
    const row = { sample, scenario: scenario.id, manager: 'lpm', setup, verification, ...result };
    timingRows.push(row);
    writeJson(path.join(output, 'metrics.json'), row);
    console.log(
      `[timing ${scenario.id} lpm] ${sample}/${timingSamples} ${result.ok && verification.ok ? 'ok' : 'FAIL'} ` +
        `pipeline=${formatMs(result.pipeline_wall_max_ms)} package=${result.streamed_package ?? 'none'}`,
    );
    if (!keepWork) {
      fs.rmSync(root, { recursive: true, force: true });
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
    if (attempt < attempts) {
      fs.rmSync(root, { recursive: true, force: true });
      createFreshRoot(root);
    }
  }
  throw new Error(`${manager} ${scenario} preparation failed: ${lastResult?.stderr_tail}`);
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
}

function removeLockfiles(manager, project) {
  const names = manager === 'lpm' ? ['lpm.lock', 'lpm.lockb'] : ['bun.lock', 'bun.lockb'];
  for (const name of names) {
    fs.rmSync(path.join(project, name), { force: true });
  }
}

function clearDependencyCache(manager, root) {
  if (manager === 'lpm') {
    fs.rmSync(path.join(lpmHomeDir(root), 'cache'), { recursive: true, force: true });
    return;
  }
  fs.rmSync(path.join(homeDir(root), '.bun', 'install', 'cache'), {
    recursive: true,
    force: true,
  });
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
  if (manager === 'lpm') {
    return hasEntries(path.join(lpmHomeDir(root), 'cache'));
  }
  return hasEntries(path.join(homeDir(root), '.bun', 'install', 'cache'));
}

function hasEntries(target) {
  try {
    return fs.readdirSync(target).length > 0;
  } catch {
    return false;
  }
}

function lockfilePresent(manager, project) {
  const names = manager === 'lpm' ? ['lpm.lock', 'lpm.lockb'] : ['bun.lock', 'bun.lockb'];
  return names.some((name) => fs.existsSync(path.join(project, name)));
}

function runInstall({ manager, root, output, measured, timing = false }) {
  fs.mkdirSync(output, { recursive: true });
  const command = installCommand(manager, timing);
  const env = managerEnv(manager, root, timing);
  const timePath = path.join(output, 'time.txt');
  const timed = measured ? timedCommand(command, timePath) : { command, enabled: false };
  const actual = timed.command;
  const started = process.hrtime.bigint();
  const result = spawnSync(actual[0], actual.slice(1), {
    cwd: projectDir(root),
    env,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: timeoutMs,
  });
  const wallMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
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
  return {
    ok: result.status === 0 && !result.error && (manager !== 'lpm' || parsed !== null),
    exit_code: result.status ?? 1,
    signal: result.signal,
    spawn_error: result.error ? String(result.error) : undefined,
    wall_ms: wallMs,
    max_rss_bytes: timed.enabled ? parseMaxRssBytes(timeOutput, process.platform) : undefined,
    stdout_tail: tail(result.stdout ?? ''),
    stderr_tail: tail(result.stderr ?? ''),
    duration_ms: numberAt(parsed, ['duration_ms']),
    package_count: numberAt(parsed, ['count']),
    downloaded: numberAt(parsed, ['downloaded']),
    cached: numberAt(parsed, ['cached']),
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

function installCommand(manager, timing) {
  if (manager === 'lpm') {
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
  return ['bun', 'install', '--ignore-scripts'];
}

function managerEnv(manager, root, timing = false) {
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
    'LPM_REGISTRY_URL',
    'LPM_TOKEN',
    'LPM_NPM_FANOUT',
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
  if (manager === 'lpm') {
    env.LPM_HOME = lpmHomeDir(root);
    env.LPM_STORE_VERSION = 'v2';
    if (timing) {
      env.LPM_TIMING_DETAIL = 'trace';
    }
  }
  return env;
}

function verifyInstalledProject(root) {
  const result = spawnSync(process.execPath, ['-e', "require.resolve('next/package.json')"], {
    cwd: projectDir(root),
    env: { ...process.env, NODE_PATH: path.join(projectDir(root), 'node_modules') },
    encoding: 'utf8',
    timeout: 30_000,
  });
  return {
    ok: result.status === 0,
    exit_code: result.status ?? 1,
    stderr_tail: tail(result.stderr ?? ''),
  };
}

function summarize(rows) {
  return SCENARIOS.map((scenario) => {
    const managers = Object.fromEntries(
      MANAGERS.map((manager) => {
        const group = rows.filter(
          (row) => row.scenario === scenario.id && row.manager === manager && row.ok && row.verification.ok,
        );
        return [
          manager,
          {
            successful_samples: group.length,
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
      lpm_to_bun_wall_ratio: ratio(managers.lpm.wall_ms?.median, managers.bun.wall_ms?.median),
      lpm_to_bun_rss_ratio: ratio(
        managers.lpm.max_rss_bytes?.median,
        managers.bun.max_rss_bytes?.median,
      ),
    };
  });
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
  const median = percentile(sorted, 0.5);
  const deviations = sorted.map((value) => Math.abs(value - median)).sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    median,
    p95: percentile(sorted, 0.95),
    max: sorted.at(-1),
    iqr: percentile(sorted, 0.75) - percentile(sorted, 0.25),
    mad: percentile(deviations, 0.5),
  };
}

function percentile(sorted, quantile) {
  return sorted[Math.ceil(quantile * sorted.length) - 1];
}

function renderMarkdown(plan, summary, timingSummary) {
  const lines = [
    '# T3 six-state install benchmark',
    '',
    `- Samples: ${plan.samples}`,
    `- Fixture SHA-256: \`${plan.fixture.package_json_sha256}\``,
    `- LPM: ${plan.lpm.version} (\`${plan.lpm.binary_sha256}\`)`,
    `- Bun: ${plan.bun.version}`,
    `- Host: ${plan.cpu}, ${formatMiB(plan.total_memory_bytes)} RAM, ${plan.platform}`,
    `- Timing: ${plan.timing_scope}`,
    `- Scripts: ${plan.script_policy}`,
    '',
    '| Scenario | LPM wall median / p95 | Bun wall median / p95 | Wall LPM/Bun | LPM RSS median / p95 | Bun RSS median / p95 | RSS LPM/Bun | LPM resolve / fetch / link median |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const row of summary) {
    const lpm = row.managers.lpm;
    const bun = row.managers.bun;
    lines.push(
      `| ${row.title}<br><sub>${row.state}</sub> | ${wallCell(lpm.wall_ms)} | ${wallCell(bun.wall_ms)} | ${formatRatio(row.lpm_to_bun_wall_ratio)} | ${rssCell(lpm.max_rss_bytes)} | ${rssCell(bun.max_rss_bytes)} | ${formatRatio(row.lpm_to_bun_rss_ratio)} | ${formatMs(lpm.resolve_ms?.median)} / ${formatMs(lpm.fetch_ms?.median)} / ${formatMs(lpm.link_ms?.median)} |`,
    );
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

function managerOrderFor(sample, scenarioId) {
  const scenarioPosition = SCENARIO_POSITIONS.get(scenarioId);
  if (scenarioPosition === undefined) {
    throw new Error(`unknown scenario: ${scenarioId}`);
  }
  return (sample + scenarioPosition) % 2 === 0 ? MANAGERS : [...MANAGERS].reverse();
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
    const key = {
      '-n': 'samples',
      '--samples': 'samples',
      '--timing-samples': 'timingSamples',
      '--lpm-bin': 'lpmBin',
      '--fixture': 'fixture',
      '--output': 'output',
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
  }
  assert.throws(() => managerOrderFor(1, 'missing'), /unknown scenario/);
  const expectedStates = {
    'first-install': { lockfile: false, node_modules: false, cache: false },
    'fresh-checkout-warm-cache': { lockfile: false, node_modules: false, cache: true },
    'ci-cold-cache': { lockfile: true, node_modules: false, cache: false },
    'ci-warm-cache': { lockfile: true, node_modules: false, cache: true },
    'installed-cache-gone': { lockfile: true, node_modules: true, cache: false },
    'up-to-date': { lockfile: true, node_modules: true, cache: true },
  };
  for (const manager of MANAGERS) {
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

Benchmark LPM and Bun against the T3-stack manifest in six install states.
Each state is prepared outside the measured interval, pre-state assertions
must pass, manager order alternates within each adjacent pair, and every
measured install must resolve next/package.json.

Options:
  -n, --samples N      Samples per manager/state (default: 10)
      --timing-samples N  Separate LPM --timing samples per state (default: 3)
      --lpm-bin PATH   LPM binary (default: target/release/lpm-rs)
      --fixture DIR    Override the directory containing package.json
      --output DIR     Result directory (default: /tmp/lpm-t3-six-*)
      --timeout-ms N   Per-install timeout (default: 600000)
      --keep-work      Preserve prepared projects under the result directory
      --self-test      Run harness unit checks without installing packages
  -h, --help           Show this help

Only LPM and Bun are included. Set LPM_NPM_FANOUT to benchmark an explicit
LPM metadata-concurrency override.
`);
}
