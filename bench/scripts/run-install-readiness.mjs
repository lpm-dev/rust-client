#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));

const BUILTIN_FIXTURES = new Map([
  [
    'dogfood',
    {
      path: 'bench/audit-fixtures/dogfood/realworld-app',
    },
  ],
  [
    'nest',
    {
      path: 'bench/audit-fixtures/peer-heavy/nestjs-deep',
    },
  ],
  [
    'vite-react',
    {
      path: 'bench/audit-fixtures/peer-heavy/vite-react',
    },
  ],
  [
    'native-sharp',
    {
      path: 'bench/audit-fixtures/native/sharp-image',
    },
  ],
  [
    'vitepress',
    {
      pathCandidates: ['bench/realworld-audit/.cache/vitepress-docs'],
      packageJson: {
        name: 'readiness-vitepress-install',
        version: '1.0.0',
        private: true,
        type: 'module',
        dependencies: {
          vitepress: '1.5.0',
          vue: '^3.4.0',
        },
      },
    },
  ],
]);

const DEFAULT_FIXTURES = ['dogfood', 'nest', 'vitepress'];
const DEFAULT_MANAGERS = ['lpm'];
const DEFAULT_MODES = ['cold'];
const DEFAULT_LPM_ROUTES = ['direct'];
const EXPECTED_WARNING_PATTERNS = [
  {
    id: 'npm-bin-shadow',
    label: 'npm/npx binary shadow warning',
    pattern: /package ["'`]npm["'`] declares bin ["'`](?:npm|npx)["'`] which shadows a common system binary/i,
  },
  {
    id: 'husky-git-missing',
    label: 'husky .git missing warning',
    pattern: /\.git (?:can['’]?t|cannot) be found/i,
  },
  {
    id: 'vite-cjs-api-deprecated',
    label: 'Vite CJS API deprecation warning',
    pattern: /CJS build of Vite.?s Node API is deprecated/i,
  },
];

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

const samples = positiveInt(args.samples, 5, '--samples');
const fixtures = parseFixtures(args.fixtures ?? DEFAULT_FIXTURES.join(','));
const managers = parseList(args.managers ?? DEFAULT_MANAGERS.join(','), '--managers');
const modes = parseModes(args.modes ?? DEFAULT_MODES.join(','));
const lpmRoutes = parseLpmRoutes(args.lpmRoutes ?? DEFAULT_LPM_ROUTES.join(','));
const lpmCells = parseLpmCells(args.lpmCells);
const scriptPolicy = args.scriptPolicy ?? 'ignore';
const timeoutMs = positiveInt(args.timeoutMs, 10 * 60 * 1000, '--timeout-ms');
const outputDir = path.resolve(
  args.output ?? defaultOutputDir(),
);
const lpmBin = path.resolve(args.lpmBin ?? path.join(repoRoot, 'target/release/lpm-rs'));
const keepProjects = Boolean(args.keepProjects);
const keepFailedProjects = Boolean(args.keepFailedProjects);
const allowFailures = Boolean(args.allowFailures);
const dryRun = Boolean(args.dryRun);

validateManagers(managers);
validateScriptPolicy(scriptPolicy);

const runSpecs = buildRunSpecs(managers, lpmCells, lpmRoutes);
validateUniqueKeys('fixture', fixtures, (fixture) => fixture.name);
validateUniqueKeys('run spec', runSpecs, (spec) => spec.id);
const plan = {
  samples,
  fixtures: fixtures.map((fixture) => fixture.source),
  managers,
  modes,
  lpm_routes: lpmRoutes,
  lpm_cells: lpmCells.map((cell) => ({ name: cell.name, env: cell.env })),
  script_policy: scriptPolicy,
  timeout_ms: timeoutMs,
  output_dir: outputDir,
  lpm_bin: lpmBin,
  run_specs: runSpecs.map((spec) => spec.id),
};

if (dryRun) {
  console.log(JSON.stringify(plan, null, 2));
  process.exit(0);
}

if (managers.includes('lpm') && !fs.existsSync(lpmBin)) {
  throw new Error(`lpm binary missing: ${lpmBin}`);
}

fs.mkdirSync(outputDir, { recursive: true });
fs.writeFileSync(path.join(outputDir, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`);

const rows = [];

for (let sample = 1; sample <= samples; sample += 1) {
  for (const fixture of fixtures) {
    for (const spec of rotated(runSpecs, sample - 1)) {
      const rowSet = runInstallSpec({ sample, fixture, spec, modes });
      rows.push(...rowSet);
    }
  }
}

const summary = summarize(rows);
const summaryMd = renderSummaryMarkdown(summary);
fs.writeFileSync(path.join(outputDir, 'rows.json'), `${JSON.stringify(rows, null, 2)}\n`);
fs.writeFileSync(path.join(outputDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
fs.writeFileSync(path.join(outputDir, 'summary.md'), `${summaryMd}\n`);

console.log(`\n[summary] ${outputDir}`);
console.log(summaryMd);

if (!allowFailures && rows.some(runFailed)) {
  process.exitCode = 1;
}

function runInstallSpec({ sample, fixture, spec, modes }) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `lpm-readiness-${fixture.name}-${spec.id}-${sample}-`));
  const projectDir = path.join(tmpRoot, 'project');
  const homeDir = path.join(tmpRoot, 'home');
  const lpmHome = path.join(tmpRoot, 'lpm-home');
  const runDir = path.join(outputDir, fixture.name, spec.id, `sample-${sample}`);
  const rowsForSpec = [];

  fs.mkdirSync(runDir, { recursive: true });

  try {
    fs.mkdirSync(homeDir, { recursive: true });
    materializeFixture(fixture, projectDir);
    cleanProject(projectDir);

    const env = buildEnv({ homeDir, lpmHome, spec });
    fs.writeFileSync(path.join(runDir, 'env.json'), `${JSON.stringify(redactedEnv(env), null, 2)}\n`);
    fs.writeFileSync(path.join(runDir, 'project-dir.txt'), `${projectDir}\n`);

    const shouldMeasureCold = modes.includes('cold');
    const shouldMeasureWarm = modes.includes('warm');
    let warmSeedOk = true;

    if (shouldMeasureCold) {
      const row = measureInstall({
        sample,
        fixture,
        spec,
        mode: 'cold',
        projectDir,
        env,
        runDir,
        phase: 'cold',
      });
      rowsForSpec.push(row);
      warmSeedOk = row.exit_code === 0 && !row.parse_error;
    } else if (shouldMeasureWarm) {
      const row = measureInstall({
        sample,
        fixture,
        spec,
        mode: 'seed',
        projectDir,
        env,
        runDir,
        phase: 'warm-seed',
        counted: false,
      });
      rowsForSpec.push(row);
      warmSeedOk = row.exit_code === 0 && !row.parse_error;
    }

    if (shouldMeasureWarm) {
      if (warmSeedOk) {
        cleanProject(projectDir);
        rowsForSpec.push(
          measureInstall({
            sample,
            fixture,
            spec,
            mode: 'warm',
            projectDir,
            env,
            runDir,
            phase: 'warm',
          }),
        );
      } else {
        rowsForSpec.push(
          recordSkippedInstall({
            sample,
            fixture,
            spec,
            mode: 'warm',
            runDir,
            phase: 'warm',
            reason: 'seed install failed',
          }),
        );
      }
    }
  } finally {
    if (!keepProjects && !(keepFailedProjects && rowsForSpec.some(runFailed))) {
      removeTree(tmpRoot);
    }
  }

  return rowsForSpec;
}

function measureInstall({
  sample,
  fixture,
  spec,
  mode,
  projectDir,
  env,
  runDir,
  phase,
  counted = true,
}) {
  const phaseDir = path.join(runDir, phase);
  fs.mkdirSync(phaseDir, { recursive: true });

  const command = installCommand(spec.manager, scriptPolicy);
  const started = process.hrtime.bigint();
  const result = spawnSync(command[0], command.slice(1), {
    cwd: projectDir,
    env,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: timeoutMs,
  });
  const wallMs = Number((process.hrtime.bigint() - started) / 1_000_000n);

  fs.writeFileSync(path.join(phaseDir, 'stdout.log'), result.stdout || '');
  fs.writeFileSync(path.join(phaseDir, 'stderr.log'), result.stderr || '');
  if (result.error) {
    fs.writeFileSync(path.join(phaseDir, 'spawn-error.txt'), `${result.error.stack || result.error}\n`);
  }
  const warningClassification = classifyInstallWarnings(result.stdout || '', result.stderr || '');

  let parsed = null;
  let parseError = null;
  if (spec.manager === 'lpm') {
    try {
      parsed = JSON.parse(result.stdout || 'null');
      fs.writeFileSync(path.join(phaseDir, 'stdout.json'), `${JSON.stringify(parsed, null, 2)}\n`);
    } catch (error) {
      parseError = String(error);
      fs.writeFileSync(path.join(phaseDir, 'parse-error.txt'), `${parseError}\n`);
    }
  }

  const row = {
    sample,
    fixture: fixture.name,
    fixture_source: fixture.source,
    manager: spec.manager,
    cell: spec.cellName,
    route: spec.route,
    spec: spec.id,
    mode,
    counted,
    exit_code: result.status ?? 1,
    signal: result.signal,
    spawn_error: result.error ? String(result.error) : undefined,
    wall_ms: wallMs,
    parse_error: parseError,
    stdout_tail: tail(result.stdout || ''),
    stderr_tail: tail(result.stderr || ''),
    ...warningClassification,
    ...extractLpmMetrics(parsed),
  };

  fs.writeFileSync(path.join(phaseDir, 'metrics.json'), `${JSON.stringify(row, null, 2)}\n`);

  const status = row.exit_code === 0 && !row.parse_error ? 'ok' : `exit=${row.exit_code}`;
  const detail =
    spec.manager === 'lpm'
      ? ` duration=${formatMs(row.duration_ms)} resolve=${formatMs(row.resolve_ms)} fetch=${formatMs(row.fetch_ms)} link=${formatMs(row.link_ms)}`
      : '';
  console.log(
    `[${fixture.name} ${spec.id} ${mode}] sample ${sample}/${samples}: ${status} wall=${wallMs}ms${detail}`,
  );

  return row;
}

function recordSkippedInstall({ sample, fixture, spec, mode, runDir, phase, reason }) {
  const phaseDir = path.join(runDir, phase);
  fs.mkdirSync(phaseDir, { recursive: true });
  const row = {
    sample,
    fixture: fixture.name,
    fixture_source: fixture.source,
    manager: spec.manager,
    cell: spec.cellName,
    route: spec.route,
    spec: spec.id,
    mode,
    counted: true,
    skipped: true,
    skip_reason: reason,
    exit_code: 1,
  };
  fs.writeFileSync(path.join(phaseDir, 'metrics.json'), `${JSON.stringify(row, null, 2)}\n`);
  console.log(
    `[${fixture.name} ${spec.id} ${mode}] sample ${sample}/${samples}: skipped (${reason})`,
  );
  return row;
}

function installCommand(manager, policy) {
  switch (manager) {
    case 'lpm':
      return [lpmBin, '--json', 'install', '--no-security-summary', '--no-skills', '--no-editor-setup'];
    case 'bun':
      return policy === 'ignore' ? ['bun', 'install', '--ignore-scripts'] : ['bun', 'install'];
    case 'pnpm':
      return policy === 'ignore'
        ? ['pnpm', 'install', '--ignore-scripts', '--reporter', 'append-only']
        : ['pnpm', 'install', '--reporter', 'append-only'];
    case 'npm':
      return policy === 'ignore'
        ? ['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund']
        : ['npm', 'install', '--no-audit', '--no-fund'];
    default:
      throw new Error(`unsupported manager: ${manager}`);
  }
}

function extractLpmMetrics(json) {
  const experimental = at(json, ['timing', 'experimental_installer_spike']);
  const metadata = experimental?.metadata;
  const metadataAttribution = metadata?.attribution;
  const fetchBreakdown = at(json, ['timing', 'fetch_breakdown']);
  const parity = experimental?.parity;

  return {
    duration_ms: numberAt(json, ['duration_ms']),
    package_count: numberAt(json, ['count']),
    downloaded: numberAt(json, ['downloaded']),
    cached: numberAt(json, ['cached']),
    linked: numberAt(json, ['linked']),
    resolve_ms: numberAt(json, ['timing', 'resolve_ms']),
    fetch_ms: numberAt(json, ['timing', 'fetch_ms']),
    link_ms: numberAt(json, ['timing', 'link_ms']),
    total_ms: numberAt(json, ['timing', 'total_ms']),
    fetch_task_sum_ms: numberAt(json, ['timing', 'fetch_breakdown', 'task_sum_ms']),
    fetch_task_max_ms: numberAt(json, ['timing', 'fetch_breakdown', 'task_max_ms']),
    fetch_queue_wait_sum_ms: breakdownStat(fetchBreakdown, 'queue_wait', 'sum_ms'),
    fetch_extract_sum_ms: breakdownStat(fetchBreakdown, 'extract', 'sum_ms'),
    fetch_finalize_sum_ms: breakdownStat(fetchBreakdown, 'finalize', 'sum_ms'),
    parity_matches: typeof parity?.matches === 'boolean' ? parity.matches : undefined,
    parity_candidate_count: finiteNumber(parity?.candidate_count),
    parity_baseline_count: finiteNumber(parity?.baseline_count),
    parity_extra_count: finiteNumber(parity?.extra_count),
    parity_missing_count: finiteNumber(parity?.missing_count),
    parity_fingerprint_mismatch_count: finiteNumber(parity?.fingerprint_mismatch_count),
    metadata_calls: finiteNumber(metadata?.calls),
    metadata_initial_fetches: finiteNumber(metadata?.initial_fetches),
    metadata_ready_hits: finiteNumber(metadata?.ready_hits),
    metadata_body_bytes_sum: finiteNumber(metadataAttribution?.body_bytes_sum),
    metadata_body_mb_sum: bytesToMb(metadataAttribution?.body_bytes_sum),
    metadata_version_count_sum: finiteNumber(metadataAttribution?.version_count_sum),
    metadata_raw_fetch_sum_ms: finiteNumber(metadataAttribution?.raw_fetch_sum_ms),
    metadata_http_sum_ms: finiteNumber(metadataAttribution?.http_sum_ms),
    metadata_body_read_sum_ms: finiteNumber(metadataAttribution?.body_read_sum_ms),
    metadata_json_decode_sum_ms: finiteNumber(metadataAttribution?.json_decode_sum_ms),
    metadata_cache_info_parse_sum_ms: finiteNumber(metadataAttribution?.cache_info_parse_sum_ms),
    metadata_policy_release_time_sum_ms: finiteNumber(
      metadataAttribution?.policy_release_time_sum_ms,
    ),
    metadata_policy_full_metadata_sum_ms: finiteNumber(
      metadataAttribution?.policy_full_metadata_sum_ms,
    ),
    metadata_version_doc_attempts: finiteNumber(metadataAttribution?.version_docs?.attempts),
    metadata_version_doc_hits: finiteNumber(metadataAttribution?.version_docs?.hits),
    metadata_version_doc_fallbacks: finiteNumber(metadataAttribution?.version_docs?.fallbacks),
    metadata_route_npm_direct: finiteNumber(metadataAttribution?.routes?.npm_direct),
    metadata_route_npm_direct_version_doc: finiteNumber(
      metadataAttribution?.routes?.npm_direct_version_doc,
    ),
  };
}

function buildRunSpecs(managers, cells, routes) {
  const specs = [];
  for (const manager of managers) {
    if (manager !== 'lpm') {
      specs.push({
        id: manager,
        manager,
        cellName: 'default',
        route: 'default',
        env: {},
      });
      continue;
    }
    for (const route of routes) {
      for (const cell of cells) {
        const suffix = [cell.name, route].filter((part) => part && part !== 'direct').join('-');
        specs.push({
          id: suffix ? `lpm-${suffix}` : 'lpm-current',
          manager,
          cellName: cell.name,
          route,
          env: cell.env,
        });
      }
    }
  }
  return specs;
}

function buildEnv({ homeDir, lpmHome, spec }) {
  const keep = [
    'PATH',
    'SHELL',
    'LANG',
    'LC_ALL',
    'TMPDIR',
    'TMP',
    'TEMP',
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
    'SystemRoot',
    'WINDIR',
    'COMSPEC',
    'PATHEXT',
  ];
  const env = {};
  for (const key of keep) {
    if (process.env[key] != null) {
      env[key] = process.env[key];
    }
  }

  env.HOME = homeDir;
  env.USERPROFILE = homeDir;
  env.XDG_CACHE_HOME = path.join(homeDir, '.cache');
  env.XDG_CONFIG_HOME = path.join(homeDir, '.config');
  env.XDG_DATA_HOME = path.join(homeDir, '.local', 'share');
  env.NPM_CONFIG_USERCONFIG = path.join(homeDir, '.npmrc');
  env.npm_config_userconfig = env.NPM_CONFIG_USERCONFIG;
  env.NPM_CONFIG_CACHE = path.join(homeDir, '.npm');
  env.npm_config_cache = env.NPM_CONFIG_CACHE;
  env.PNPM_HOME = path.join(homeDir, '.pnpm-home');
  env.BUN_INSTALL = path.join(homeDir, '.bun');
  env.BUN_INSTALL_CACHE_DIR = path.join(homeDir, '.bun', 'install', 'cache');
  env.CI = '1';

  if (spec.manager === 'lpm') {
    env.LPM_HOME = lpmHome;
    env.LPM_STORE_VERSION = 'v2';
    env.LPM_TIMING_DETAIL = 'trace';
    if (spec.route !== 'direct') {
      env.LPM_NPM_ROUTE = spec.route;
    }
    Object.assign(env, spec.env);
  }

  return env;
}

function materializeFixture(fixture, projectDir) {
  if (fixture.path) {
    fs.cpSync(fixture.path, projectDir, { recursive: true });
    return;
  }
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(
    path.join(projectDir, 'package.json'),
    `${JSON.stringify(fixture.packageJson, null, 2)}\n`,
  );
}

function cleanProject(projectDir) {
  for (const entry of [
    'node_modules',
    '.lpm',
    'lpm.lock',
    'lpm.lockb',
    'package-lock.json',
    'pnpm-lock.yaml',
    'bun.lock',
    'bun.lockb',
    'yarn.lock',
  ]) {
    removeTree(path.join(projectDir, entry));
  }
}

function summarize(rows) {
  const countedRows = rows.filter((row) => row.counted !== false);
  const groups = new Map();
  for (const row of countedRows) {
    const key = [row.fixture, row.spec, row.mode].join('\0');
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(row);
  }

  const out = [];
  for (const [key, groupRows] of groups) {
    const [fixture, spec, mode] = key.split('\0');
    const successful = groupRows.filter((row) => row.exit_code === 0 && !row.parse_error);
    const first = groupRows[0];
    out.push({
      fixture,
      manager: first.manager,
      spec,
      cell: first.cell,
      route: first.route,
      mode,
      samples: groupRows.length,
      successful_samples: successful.length,
      metrics: summarizeMetrics(successful),
    });
  }
  out.sort((a, b) =>
    [a.fixture, a.spec, a.mode].join('\0').localeCompare([b.fixture, b.spec, b.mode].join('\0')),
  );
  return out;
}

function summarizeMetrics(rows) {
  const keys = [
    'wall_ms',
    'duration_ms',
    'resolve_ms',
    'fetch_ms',
    'link_ms',
    'package_count',
    'downloaded',
    'cached',
    'fetch_task_sum_ms',
    'fetch_task_max_ms',
    'fetch_queue_wait_sum_ms',
    'fetch_extract_sum_ms',
    'fetch_finalize_sum_ms',
    'metadata_calls',
    'metadata_initial_fetches',
    'metadata_body_mb_sum',
    'metadata_version_count_sum',
    'metadata_raw_fetch_sum_ms',
    'metadata_http_sum_ms',
    'metadata_body_read_sum_ms',
    'metadata_json_decode_sum_ms',
    'metadata_cache_info_parse_sum_ms',
    'metadata_policy_release_time_sum_ms',
    'metadata_policy_full_metadata_sum_ms',
    'metadata_version_doc_attempts',
    'metadata_version_doc_hits',
    'metadata_version_doc_fallbacks',
    'metadata_route_npm_direct',
    'metadata_route_npm_direct_version_doc',
    'parity_candidate_count',
    'parity_baseline_count',
    'parity_extra_count',
    'parity_missing_count',
    'parity_fingerprint_mismatch_count',
    'warning_count',
    'expected_warning_count',
    'unexpected_warning_count',
  ];
  return Object.fromEntries(
    keys
      .map((key) => [key, medianMin(rows, key)])
      .filter(([, value]) => value != null),
  );
}

function renderSummaryMarkdown(summary) {
  const lines = [
    '| Fixture | Spec | Mode | OK | Wall med/min | Resolve med/min | Fetch med/min | Link med/min | Pkgs | Metadata MB | Version docs | Parity mismatches | Warnings exp/unknown |',
    '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const row of summary) {
    const m = row.metrics;
    const versionDocs =
      m.metadata_version_doc_hits || m.metadata_version_doc_attempts
        ? `${one(m.metadata_version_doc_hits)}/${one(m.metadata_version_doc_attempts)}`
        : 'n/a';
    const mismatches =
      m.parity_fingerprint_mismatch_count || m.parity_missing_count || m.parity_extra_count
        ? `${one(m.parity_fingerprint_mismatch_count)} fp, ${one(m.parity_missing_count)} missing, ${one(m.parity_extra_count)} extra`
        : 'n/a';
    const warnings =
      m.expected_warning_count || m.unexpected_warning_count
        ? `${one(m.expected_warning_count)}/${one(m.unexpected_warning_count)}`
        : '0/0';
    lines.push(
      `| ${row.fixture} | ${row.spec} | ${row.mode} | ${row.successful_samples}/${row.samples} | ${stat(m.wall_ms)} | ${stat(m.resolve_ms)} | ${stat(m.fetch_ms)} | ${stat(m.link_ms)} | ${one(m.package_count)} | ${stat(m.metadata_body_mb_sum)} | ${versionDocs} | ${mismatches} | ${warnings} |`,
    );
  }
  return lines.join('\n');
}

function parseArgs(argv) {
  const parsed = { lpmCells: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--dry-run') {
      parsed.dryRun = true;
      continue;
    }
    if (arg === '--keep-projects') {
      parsed.keepProjects = true;
      continue;
    }
    if (arg === '--keep-failed-projects') {
      parsed.keepFailedProjects = true;
      continue;
    }
    if (arg === '--allow-failures') {
      parsed.allowFailures = true;
      continue;
    }
    const valueFlags = new Map([
      ['--samples', 'samples'],
      ['-n', 'samples'],
      ['--fixtures', 'fixtures'],
      ['--managers', 'managers'],
      ['--modes', 'modes'],
      ['--lpm-routes', 'lpmRoutes'],
      ['--output', 'output'],
      ['--lpm-bin', 'lpmBin'],
      ['--script-policy', 'scriptPolicy'],
      ['--timeout-ms', 'timeoutMs'],
      ['--lpm-cell', 'lpmCell'],
    ]);
    if (!valueFlags.has(arg)) {
      throw new Error(`unknown argument: ${arg}`);
    }
    const key = valueFlags.get(arg);
    const value = argv[index + 1];
    if (!value) {
      throw new Error(`${arg} requires a value`);
    }
    index += 1;
    if (key === 'lpmCell') {
      parsed.lpmCells.push(value);
    } else {
      parsed[key] = value;
    }
  }
  return parsed;
}

function defaultOutputDir() {
  const stamp = new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15);
  const suffix = Math.random().toString(36).slice(2, 8);
  return path.join(os.tmpdir(), `lpm-install-readiness-${stamp}-${process.pid}-${suffix}`);
}

function parseFixtures(raw) {
  return parseList(raw, '--fixtures').map((entry) => {
    if (entry.startsWith('pkg:')) {
      return fixtureFromPackageSpec(entry.slice('pkg:'.length));
    }
    if (entry.includes('=')) {
      const [name, fixturePath] = splitOnce(entry, '=');
      return fixtureFromPath(name, fixturePath);
    }
    if (BUILTIN_FIXTURES.has(entry)) {
      const fixture = BUILTIN_FIXTURES.get(entry);
      if (fixture.path) {
        return fixtureFromPath(entry, fixture.path);
      }
      for (const candidate of fixture.pathCandidates ?? []) {
        const absolutePath = path.resolve(repoRoot, candidate);
        if (fs.existsSync(path.join(absolutePath, 'package.json'))) {
          return fixtureFromPath(entry, absolutePath);
        }
      }
      return fixtureFromPackageJson(entry, fixture.packageJson, 'generated');
    }
    if (fs.existsSync(path.resolve(repoRoot, entry)) || fs.existsSync(path.resolve(entry))) {
      return fixtureFromPath(path.basename(entry), entry);
    }
    throw new Error(`unknown fixture: ${entry}`);
  });
}

function fixtureFromPath(name, fixturePath) {
  const absolutePath = path.resolve(repoRoot, fixturePath);
  if (!fs.existsSync(path.join(absolutePath, 'package.json'))) {
    throw new Error(`fixture missing package.json: ${absolutePath}`);
  }
  return {
    name: sanitizeName(name),
    path: absolutePath,
    source: {
      name: sanitizeName(name),
      kind: 'path',
      path: path.relative(repoRoot, absolutePath) || '.',
      absolute_path: absolutePath,
    },
  };
}

function fixtureFromPackageSpec(spec) {
  const at = spec.startsWith('@') ? spec.lastIndexOf('@') : spec.indexOf('@');
  const packageName = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : 'latest';
  if (!packageName) {
    throw new Error(`invalid pkg fixture: ${spec}`);
  }
  const name = sanitizeName(`pkg-${packageName.replace(/^@/, '').replace(/[\/@]/g, '-')}`);
  return fixtureFromPackageJson(
    name,
    {
      name: `readiness-${packageName.replace(/^@/, '').replace(/[\/@]/g, '-')}`,
      version: '1.0.0',
      private: true,
      dependencies: {
        [packageName]: version || 'latest',
      },
    },
    'package-spec',
    { spec, package: packageName, version: version || 'latest' },
  );
}

function fixtureFromPackageJson(name, packageJson, kind, extra = {}) {
  const sanitized = sanitizeName(name);
  return {
    name: sanitized,
    packageJson,
    source: {
      name: sanitized,
      kind,
      package_json: packageJson,
      ...extra,
    },
  };
}

function parseLpmCells(rawCells) {
  if (!rawCells || rawCells.length === 0) {
    return [{ name: 'current', env: {} }];
  }
  return rawCells.map((raw) => {
    const [name, assignmentText = ''] = splitOnce(raw, ':');
    if (!name) {
      throw new Error(`invalid --lpm-cell: ${raw}`);
    }
    return {
      name: sanitizeName(name),
      env: parseEnvAssignments(assignmentText),
    };
  });
}

function parseEnvAssignments(raw) {
  const env = {};
  if (!raw) {
    return env;
  }
  for (const entry of raw.split(',').map((part) => part.trim()).filter(Boolean)) {
    const [key, value = ''] = splitOnce(entry, '=');
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`invalid env key in --lpm-cell: ${key}`);
    }
    env[key] = value;
  }
  return env;
}

function parseModes(raw) {
  const modes = parseList(raw, '--modes');
  for (const mode of modes) {
    if (!['cold', 'warm'].includes(mode)) {
      throw new Error(`unsupported mode: ${mode}`);
    }
  }
  return modes;
}

function parseLpmRoutes(raw) {
  const routes = parseList(raw, '--lpm-routes');
  for (const route of routes) {
    if (!['direct', 'proxy'].includes(route)) {
      throw new Error(`unsupported lpm route: ${route}`);
    }
  }
  return routes;
}

function validateManagers(managers) {
  for (const manager of managers) {
    if (!['lpm', 'bun', 'pnpm', 'npm'].includes(manager)) {
      throw new Error(`unsupported manager: ${manager}`);
    }
  }
}

function validateScriptPolicy(policy) {
  if (!['ignore', 'default'].includes(policy)) {
    throw new Error(`unsupported --script-policy: ${policy}`);
  }
}

function validateUniqueKeys(label, values, keyFor) {
  const seen = new Map();
  for (const value of values) {
    const key = keyFor(value);
    if (seen.has(key)) {
      throw new Error(`duplicate ${label} name after sanitization: ${key}`);
    }
    seen.set(key, value);
  }
}

function parseList(raw, flag) {
  const values = raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  if (values.length === 0) {
    throw new Error(`${flag} must not be empty`);
  }
  return values;
}

function positiveInt(raw, fallback, flag) {
  if (raw == null) {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${flag} must be a positive integer`);
  }
  return value;
}

function splitOnce(value, delimiter) {
  const index = value.indexOf(delimiter);
  if (index === -1) {
    return [value, undefined];
  }
  return [value.slice(0, index), value.slice(index + delimiter.length)];
}

function rotated(values, offset) {
  if (values.length <= 1) {
    return values;
  }
  const shift = offset % values.length;
  return values.slice(shift).concat(values.slice(0, shift));
}

function removeTree(target) {
  let lastError = null;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      fs.rmSync(target, { recursive: true, force: true });
      return true;
    } catch (error) {
      lastError = error;
      sleepSync(100 * (attempt + 1));
    }
  }
  console.warn(`[warn] could not remove ${target}: ${lastError}`);
  return false;
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function at(value, pathParts) {
  let current = value;
  for (const part of pathParts) {
    if (current == null || typeof current !== 'object' || !(part in current)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function numberAt(value, pathParts) {
  return finiteNumber(at(value, pathParts));
}

function finiteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function breakdownStat(breakdown, bucket, stat) {
  return finiteNumber(breakdown?.[bucket]?.[stat]);
}

function bytesToMb(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return undefined;
  }
  return Math.round((value / 1024 / 1024) * 10) / 10;
}

function classifyInstallWarnings(stdout, stderr) {
  const expected = new Map(
    EXPECTED_WARNING_PATTERNS.map((entry) => [
      entry.id,
      { id: entry.id, label: entry.label, count: 0, samples: [] },
    ]),
  );
  const unexpected = [];
  let warningCount = 0;
  let expectedWarningCount = 0;

  for (const rawLine of `${stdout}\n${stderr}`.split(/\r?\n/)) {
    const line = stripAnsi(rawLine).trim();
    if (!line) {
      continue;
    }
    const expectedPattern = EXPECTED_WARNING_PATTERNS.find((entry) => entry.pattern.test(line));
    if (!expectedPattern && !isWarningLikeLine(line)) {
      continue;
    }
    warningCount += 1;
    if (expectedPattern) {
      expectedWarningCount += 1;
      const bucket = expected.get(expectedPattern.id);
      bucket.count += 1;
      if (bucket.samples.length < 3 && !bucket.samples.includes(line)) {
        bucket.samples.push(line);
      }
      continue;
    }
    if (unexpected.length < 20 && !unexpected.includes(line)) {
      unexpected.push(line);
    }
  }

  return {
    warning_count: warningCount,
    expected_warning_count: expectedWarningCount,
    unexpected_warning_count: warningCount - expectedWarningCount,
    expected_warnings: [...expected.values()].filter((entry) => entry.count > 0),
    unexpected_warnings: unexpected,
  };
}

function isWarningLikeLine(line) {
  return (
    /\bwarn(?:ing)?\b/i.test(line) ||
    /\bdeprecated\b/i.test(line) ||
    /\bdeprecation\b/i.test(line) ||
    /(?:can['’]?t|cannot) be found/i.test(line)
  );
}

function stripAnsi(value) {
  return value.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '');
}

function medianMin(rows, key) {
  const values = rows
    .map((row) => row[key])
    .filter((value) => typeof value === 'number' && Number.isFinite(value))
    .sort((a, b) => a - b);
  if (values.length === 0) {
    return null;
  }
  return {
    median:
      values.length % 2 === 1
        ? values[Math.floor(values.length / 2)]
        : (values[values.length / 2 - 1] + values[values.length / 2]) / 2,
    min: values[0],
  };
}

function runFailed(row) {
  return row.exit_code !== 0 || Boolean(row.parse_error) || Boolean(row.skipped);
}

function stat(value) {
  return value ? `${value.median}/${value.min}` : 'n/a';
}

function formatMs(value) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value}ms` : 'n/a';
}

function one(value) {
  return value ? `${value.median}` : 'n/a';
}

function sanitizeName(value) {
  return value.replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'fixture';
}

function tail(value) {
  const trimmed = value.trim();
  if (trimmed.length <= 2000) {
    return trimmed;
  }
  return trimmed.slice(trimmed.length - 2000);
}

function redactedEnv(env) {
  return Object.fromEntries(
    Object.entries(env)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => [key, redactEnvValue(key, value)]),
  );
}

function redactEnvValue(key, value) {
  if (/(TOKEN|SECRET|PASSWORD|PASS|AUTH|COOKIE|KEY|CREDENTIAL)/i.test(key)) {
    return '[redacted]';
  }
  if (/proxy/i.test(key)) {
    try {
      const url = new URL(value);
      if (url.username || url.password) {
        url.username = url.username ? '[redacted]' : '';
        url.password = url.password ? '[redacted]' : '';
      }
      return url.toString();
    } catch {
      return value;
    }
  }
  return value;
}

function printHelp() {
  console.log(`Usage: node bench/scripts/run-install-readiness.mjs [options]

Production-readiness install benchmark harness. Every counted run uses an
isolated temp project, HOME, package-manager cache, and LPM_HOME. Runs are
round-robin interleaved by sample to reduce live-network bias.

Options:
  -n, --samples N              Samples per fixture/spec (default: 5)
      --fixtures LIST          Built-ins or paths (default: dogfood,nest,vitepress)
                               Built-ins: ${[...BUILTIN_FIXTURES.keys()].join(', ')}
                               Also supports name=/abs/path and pkg:<name>@<version>
      --managers LIST          lpm,bun,pnpm,npm (default: lpm)
      --modes LIST             cold,warm (default: cold)
      --lpm-routes LIST        direct,proxy for lpm runs (default: direct)
      --lpm-cell NAME:ENV      Add an lpm env cell. Repeatable.
                               Example: --lpm-cell cap:LPM_V2_FINALIZE_PERMITS=2
      --script-policy MODE     ignore or default for bun/pnpm/npm scripts (default: ignore)
      --timeout-ms N           Per-install timeout in milliseconds (default: 600000)
      --lpm-bin PATH           lpm binary path (default: target/release/lpm-rs)
      --output DIR             Result directory (default: /tmp/lpm-install-readiness-*)
      --keep-projects          Keep temp projects
      --keep-failed-projects   Keep temp projects for failed runs
      --allow-failures         Exit 0 even if a run fails
      --dry-run                Print the plan without running installs
  -h, --help                   Show this help

Examples:
  # Current lpm cold/warm reference.
  node bench/scripts/run-install-readiness.mjs --samples 10 --modes cold,warm

  # One-off proxy reference.
  node bench/scripts/run-install-readiness.mjs --samples 1 --lpm-routes proxy

  # Apples-to-apples reference snapshot.
  node bench/scripts/run-install-readiness.mjs --samples 5 --managers lpm,bun,pnpm,npm

  # Compare one lpm candidate knob against current lpm.
  node bench/scripts/run-install-readiness.mjs \\
    --samples 10 \\
    --lpm-cell current \\
    --lpm-cell cap:LPM_V2_FINALIZE_PERMITS=2

  # Compare exact-version-doc experimental path.
  node bench/scripts/run-install-readiness.mjs \\
    --samples 5 \\
    --lpm-cell current \\
    --lpm-cell exact-doc:LPM_EXPERIMENTAL_INSTALLER_SPIKE=1,LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1,LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist,LPM_INSTALLER_SPIKE_PARITY=deny,LPM_INSTALLER_SPIKE_EXACT_DOC=1
`);
}
