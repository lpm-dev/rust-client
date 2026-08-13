#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
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
  [
    'vitepress-workspace',
    {
      path: 'bench/fixtures/vitepress-docs',
    },
  ],
]);

const DEFAULT_FIXTURES = ['dogfood', 'nest', 'vitepress'];
const TAIL_METRICS = ['wall_ms', 'max_rss_bytes', 'resolve_ms', 'fetch_ms', 'link_ms'];
const DEFAULT_MANAGERS = ['lpm'];
const DEFAULT_MODES = ['cold'];
const DEFAULT_LPM_ROUTES = ['direct'];
const DEFAULT_LPM_FIREWALL_MODES = ['off'];
const INSTALL_DIRS = new Set(['node_modules', '.lpm']);
const COMPARISON_GATE_METRICS = new Set(['wall_ms', 'max_rss_bytes']);
const LOCKFILES = new Set([
  'lpm.lock',
  'lpm.lockb',
  'package-lock.json',
  'pnpm-lock.yaml',
  'bun.lock',
  'bun.lockb',
  'yarn.lock',
]);
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

if (args.selfTest) {
  runSelfTests();
  process.exit(0);
}

const samples = positiveInt(args.samples, 5, '--samples');
if (args.topNpmFile && args.fixtures) {
  throw new Error('--top-npm-file and --fixtures are mutually exclusive');
}
const topNpmFile = args.topNpmFile ? path.resolve(repoRoot, args.topNpmFile) : null;
const topNpmOffset = nonNegativeInt(args.topNpmOffset, 0, '--top-npm-offset');
const topNpmLimit = optionalPositiveInt(args.topNpmLimit, '--top-npm-limit');
const fixtures = topNpmFile
  ? parseTopNpmFixtures(topNpmFile, topNpmOffset, topNpmLimit)
  : parseFixtures(args.fixtures ?? DEFAULT_FIXTURES.join(','));
const managers = parseList(args.managers ?? DEFAULT_MANAGERS.join(','), '--managers');
const modes = parseModes(args.modes ?? DEFAULT_MODES.join(','));
const lpmRoutes = parseLpmRoutes(args.lpmRoutes ?? DEFAULT_LPM_ROUTES.join(','));
const lpmFirewallModes = parseLpmFirewallModes(
  args.lpmFirewallModes ?? DEFAULT_LPM_FIREWALL_MODES.join(','),
);
const lpmCells = parseLpmCells(args.lpmCells);
if (args.lpmBin && args.lpmBinaries.length > 0) {
  throw new Error('--lpm-bin and --lpm-binary are mutually exclusive');
}
const defaultLpmBin = path.resolve(args.lpmBin ?? path.join(repoRoot, 'target/release/lpm-rs'));
const lpmBinaries = parseLpmBinaries(args.lpmBinaries, defaultLpmBin);
const lpmComparison = parseLpmComparison(args.lpmCompare, lpmBinaries);
const comparisonThresholds = {
  wall_ms: {
    median_pct: nonNegativeNumber(args.medianRegressionPct, 5, '--median-regression-pct'),
    p95_pct: nonNegativeNumber(args.p95RegressionPct, 10, '--p95-regression-pct'),
    median_abs: nonNegativeNumber(args.medianRegressionMs, 20, '--median-regression-ms'),
    p95_abs: nonNegativeNumber(args.p95RegressionMs, 50, '--p95-regression-ms'),
  },
  max_rss_bytes: {
    median_pct: nonNegativeNumber(
      args.rssMedianRegressionPct,
      5,
      '--rss-median-regression-pct',
    ),
    p95_pct: nonNegativeNumber(
      args.rssP95RegressionPct,
      10,
      '--rss-p95-regression-pct',
    ),
    median_abs: mebibytesToBytes(
      nonNegativeNumber(args.rssMedianRegressionMb, 16, '--rss-median-regression-mb'),
    ),
    p95_abs: mebibytesToBytes(
      nonNegativeNumber(args.rssP95RegressionMb, 32, '--rss-p95-regression-mb'),
    ),
  },
};
const lpmTyposquatGuard = args.lpmTyposquatGuard ?? (topNpmFile ? 'off' : 'default');
const scriptPolicy = args.scriptPolicy ?? 'ignore';
const timeoutMs = positiveInt(args.timeoutMs, 10 * 60 * 1000, '--timeout-ms');
const outputDir = path.resolve(
  args.output ?? defaultOutputDir(),
);
const keepProjects = Boolean(args.keepProjects);
const keepFailedProjects = Boolean(args.keepFailedProjects);
const allowFailures = Boolean(args.allowFailures);
const allowInconclusive = Boolean(args.allowInconclusive);
const dryRun = Boolean(args.dryRun);

validateManagers(managers);
validateScriptPolicy(scriptPolicy);
validateLpmTyposquatGuard(lpmTyposquatGuard);
if (lpmComparison && !managers.includes('lpm')) {
  throw new Error('--lpm-compare requires lpm in --managers');
}

const runSpecs = buildRunSpecs(managers, lpmBinaries, lpmCells, lpmRoutes, lpmFirewallModes);
validateUniqueKeys('fixture', fixtures, (fixture) => fixture.name);
validateUniqueKeys('run spec', runSpecs, (spec) => spec.id);
const plan = {
  samples,
  fixtures: fixtures.map((fixture) => fixture.source),
  managers,
  modes,
  lpm_routes: lpmRoutes,
  lpm_firewall_modes: lpmFirewallModes,
  lpm_binaries: lpmBinaries.map((binary) => ({ name: binary.name, path: binary.path })),
  lpm_cells: lpmCells.map((cell) => ({ name: cell.name, env: cell.env })),
  lpm_comparison: lpmComparison
    ? {
        ...lpmComparison,
        thresholds: comparisonThresholds,
      }
    : undefined,
  lpm_typosquat_guard: lpmTyposquatGuard,
  top_npm: topNpmFile
    ? {
        file: path.relative(repoRoot, topNpmFile) || topNpmFile,
        absolute_file: topNpmFile,
        offset: topNpmOffset,
        limit: topNpmLimit,
      }
    : undefined,
  script_policy: scriptPolicy,
  timeout_ms: timeoutMs,
  output_dir: outputDir,
  lpm_bin: lpmBinaries.length === 1 ? lpmBinaries[0].path : undefined,
  run_specs: runSpecs.map((spec) => spec.id),
};

if (dryRun) {
  console.log(JSON.stringify(plan, null, 2));
  process.exit(0);
}

if (managers.includes('lpm')) {
  for (const binary of lpmBinaries) {
    if (!fs.existsSync(binary.path)) {
      throw new Error(`lpm binary missing (${binary.name}): ${binary.path}`);
    }
  }
}

fs.mkdirSync(outputDir, { recursive: true });
fs.writeFileSync(path.join(outputDir, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`);

const rows = [];
let executionSequence = 0;

for (let sample = 1; sample <= samples; sample += 1) {
  for (const fixture of fixtures) {
    const pairedSpecIds = new Set();
    if (lpmComparison) {
      const pairs = buildLpmComparisonPairs(runSpecs, lpmComparison);
      for (const [pairIndex, pair] of pairs.entries()) {
        pairedSpecIds.add(pair.baseline.id);
        pairedSpecIds.add(pair.candidate.id);
        rows.push(
          ...runPairedLpmSpecs({ sample, fixture, pair, pairIndex, modes }),
        );
      }
    }
    const referenceSpecs = runSpecs.filter((spec) => !pairedSpecIds.has(spec.id));
    for (const spec of rotated(referenceSpecs, sample - 1)) {
      const rowSet = runInstallSpec({ sample, fixture, spec, modes });
      rows.push(...rowSet);
    }
  }
}

const summary = summarize(rows);
const summaryMd = renderSummaryMarkdown(summary);
const comparisonSummary = lpmComparison
  ? summarizeLpmComparison(rows, lpmComparison, comparisonThresholds, samples)
  : null;
const comparisonMd = comparisonSummary ? renderLpmComparisonMarkdown(comparisonSummary) : null;
const warningSummary = summarizeWarnings(rows);
fs.writeFileSync(path.join(outputDir, 'rows.json'), `${JSON.stringify(rows, null, 2)}\n`);
fs.writeFileSync(path.join(outputDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
fs.writeFileSync(path.join(outputDir, 'summary.md'), `${summaryMd}\n`);
if (comparisonSummary) {
  fs.writeFileSync(
    path.join(outputDir, 'comparison.json'),
    `${JSON.stringify(comparisonSummary, null, 2)}\n`,
  );
  fs.writeFileSync(path.join(outputDir, 'comparison.md'), `${comparisonMd}\n`);
}
fs.writeFileSync(
  path.join(outputDir, 'warning-summary.json'),
  `${JSON.stringify(warningSummary, null, 2)}\n`,
);
fs.writeFileSync(
  path.join(outputDir, 'warning-summary.md'),
  `${renderWarningSummaryMarkdown(warningSummary)}\n`,
);

console.log(`\n[summary] ${outputDir}`);
console.log(summaryMd);
if (comparisonMd) {
  console.log('\n[paired lpm comparison]');
  console.log(comparisonMd);
}

if (!allowFailures && rows.some(runFailed)) {
  process.exitCode = 1;
}
if (
  comparisonSummary &&
  ['execution-failure', 'regression'].includes(comparisonSummary.verdict)
) {
  process.exitCode = 1;
} else if (comparisonSummary?.verdict === 'inconclusive' && !allowInconclusive) {
  process.exitCode = 2;
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
    cleanProjectForCold(projectDir);

    const env = buildEnv({ homeDir, lpmHome, spec });
    fs.writeFileSync(path.join(runDir, 'env.json'), `${JSON.stringify(redactedEnv(env), null, 2)}\n`);
    fs.writeFileSync(path.join(runDir, 'project-dir.txt'), `${projectDir}\n`);

    const shouldMeasureCold = modes.includes('cold');
    const shouldMeasureWarm = modes.includes('warm');
    const shouldMeasureUpToDate = modes.includes('up-to-date');
    let installedOk = true;

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
      installedOk = !runFailed(row);
    } else if (shouldMeasureWarm || shouldMeasureUpToDate) {
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
      installedOk = !runFailed(row);
    }

    if (shouldMeasureWarm) {
      if (installedOk) {
        cleanProjectForWarm(projectDir);
        const row = measureInstall({
          sample,
          fixture,
          spec,
          mode: 'warm',
          projectDir,
          env,
          runDir,
          phase: 'warm',
        });
        rowsForSpec.push(row);
        installedOk = !runFailed(row);
      } else {
        rowsForSpec.push(
          recordSkippedInstall({
            sample,
            fixture,
            spec,
            mode: 'warm',
            runDir,
            phase: 'warm',
            reason: 'previous install failed',
          }),
        );
      }
    }

    if (shouldMeasureUpToDate) {
      if (installedOk) {
        rowsForSpec.push(
          measureInstall({
            sample,
            fixture,
            spec,
            mode: 'up-to-date',
            projectDir,
            env,
            runDir,
            phase: 'up-to-date',
          }),
        );
      } else {
        rowsForSpec.push(
          recordSkippedInstall({
            sample,
            fixture,
            spec,
            mode: 'up-to-date',
            runDir,
            phase: 'up-to-date',
            reason: 'previous install failed',
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

function buildLpmComparisonPairs(specs, comparison) {
  const baselines = specs.filter(
    (spec) => spec.manager === 'lpm' && spec.binaryName === comparison.baseline,
  );
  const candidates = specs.filter(
    (spec) => spec.manager === 'lpm' && spec.binaryName === comparison.candidate,
  );
  const identity = (spec) => [spec.cellName, spec.route, spec.firewallMode].join('\0');
  const candidateByIdentity = new Map(candidates.map((spec) => [identity(spec), spec]));
  const pairs = baselines.map((baseline) => {
    const candidate = candidateByIdentity.get(identity(baseline));
    if (!candidate) {
      throw new Error(`missing candidate lpm run spec for ${baseline.id}`);
    }
    candidateByIdentity.delete(identity(baseline));
    return { baseline, candidate };
  });
  if (candidateByIdentity.size > 0) {
    throw new Error(
      `missing baseline lpm run spec for ${[...candidateByIdentity.values()][0].id}`,
    );
  }
  return pairs;
}

function runPairedLpmSpecs({ sample, fixture, pair, pairIndex, modes }) {
  const contexts = [pair.baseline, pair.candidate].map((spec) => {
    const tmpRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), `lpm-readiness-${fixture.name}-${spec.id}-${sample}-`),
    );
    const projectDir = path.join(tmpRoot, 'project');
    const homeDir = path.join(tmpRoot, 'home');
    const lpmHome = path.join(tmpRoot, 'lpm-home');
    const runDir = path.join(outputDir, fixture.name, spec.id, `sample-${sample}`);
    fs.mkdirSync(runDir, { recursive: true });
    fs.mkdirSync(homeDir, { recursive: true });
    materializeFixture(fixture, projectDir);
    cleanProjectForCold(projectDir);
    const env = buildEnv({ homeDir, lpmHome, spec });
    fs.writeFileSync(path.join(runDir, 'env.json'), `${JSON.stringify(redactedEnv(env), null, 2)}\n`);
    fs.writeFileSync(path.join(runDir, 'project-dir.txt'), `${projectDir}\n`);
    return { spec, tmpRoot, projectDir, env, runDir, installedOk: true, rows: [] };
  });
  const pairId = [
    fixture.name,
    contexts[0].spec.cellName,
    contexts[0].spec.route,
    contexts[0].spec.firewallMode,
    `sample-${sample}`,
  ].join(':');
  const baselineFirst = (sample + pairIndex) % 2 === 1;
  const ordered = baselineFirst ? contexts : contexts.slice().reverse();
  const pairOrder = baselineFirst ? 'baseline-candidate' : 'candidate-baseline';

  try {
    if (!modes.includes('cold') && modes.some((mode) => mode !== 'cold')) {
      for (const context of ordered) {
        const row = measureInstall({
          sample,
          fixture,
          ...context,
          mode: 'seed',
          phase: 'warm-seed',
          counted: false,
        });
        context.rows.push(row);
        context.installedOk = !runFailed(row);
      }
    }

    for (const mode of modes) {
      for (const context of ordered) {
        if (mode === 'warm' && context.installedOk) {
          cleanProjectForWarm(context.projectDir);
        }
        const pairMeta = { pairId: `${pairId}:${mode}`, pairOrder };
        const row = context.installedOk
          ? measureInstall({
              sample,
              fixture,
              ...context,
              mode,
              phase: mode,
              pairMeta,
            })
          : recordSkippedInstall({
              sample,
              fixture,
              ...context,
              mode,
              phase: mode,
              reason: 'previous install failed',
              pairMeta,
            });
        context.rows.push(row);
        context.installedOk = !runFailed(row);
      }
    }
  } finally {
    for (const context of contexts) {
      if (!keepProjects && !(keepFailedProjects && context.rows.some(runFailed))) {
        removeTree(context.tmpRoot);
      }
    }
  }
  return contexts.flatMap((context) => context.rows);
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
  pairMeta,
}) {
  const phaseDir = path.join(runDir, phase);
  fs.mkdirSync(phaseDir, { recursive: true });

  const command = installCommand(spec, scriptPolicy);
  const timeOutputPath = path.join(phaseDir, 'time.txt');
  const timed = timedCommand(command, timeOutputPath);
  const started = process.hrtime.bigint();
  const startedAt = new Date().toISOString();
  const result = spawnSync(timed.command[0], timed.command.slice(1), {
    cwd: projectDir,
    env,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: timeoutMs,
  });
  const wallMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
  const timeOutput = timed.enabled && fs.existsSync(timeOutputPath)
    ? fs.readFileSync(timeOutputPath, 'utf8')
    : '';
  const maxRssBytes = timed.enabled ? parseMaxRssBytes(timeOutput, process.platform) : undefined;
  const rssParseError = timed.enabled && maxRssBytes === undefined
    ? `could not parse peak RSS from ${timeOutputPath}`
    : null;

  fs.writeFileSync(path.join(phaseDir, 'stdout.log'), result.stdout || '');
  fs.writeFileSync(path.join(phaseDir, 'stderr.log'), result.stderr || '');
  if (result.error) {
    fs.writeFileSync(path.join(phaseDir, 'spawn-error.txt'), `${result.error.stack || result.error}\n`);
  }

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
  const warningClassification = classifyInstallWarnings({
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    parsedStdout: parsed,
  });
  fs.writeFileSync(
    path.join(phaseDir, 'warnings.json'),
    `${JSON.stringify(warningClassification, null, 2)}\n`,
  );

  const row = {
    sample,
    fixture: fixture.name,
    fixture_source: fixture.source,
    manager: spec.manager,
    binary: spec.binaryName,
    cell: spec.cellName,
    route: spec.route,
    firewall_mode: spec.firewallMode,
    spec: spec.id,
    mode,
    counted,
    pair_id: pairMeta?.pairId,
    pair_order: pairMeta?.pairOrder,
    execution_sequence: ++executionSequence,
    started_at: startedAt,
    exit_code: result.status ?? 1,
    signal: result.signal,
    spawn_error: result.error ? String(result.error) : undefined,
    wall_ms: wallMs,
    max_rss_bytes: maxRssBytes,
    rss_parse_error: rssParseError,
    parse_error: parseError,
    stdout_tail: tail(result.stdout || ''),
    stderr_tail: tail(result.stderr || ''),
    ...warningClassification,
    ...extractLpmMetrics(parsed),
  };

  fs.writeFileSync(path.join(phaseDir, 'metrics.json'), `${JSON.stringify(row, null, 2)}\n`);

  const status = row.exit_code === 0 && !row.parse_error && !row.rss_parse_error
    ? 'ok'
    : `exit=${row.exit_code}`;
  const detail =
    spec.manager === 'lpm'
      ? ` duration=${formatMs(row.duration_ms)} resolve=${formatMs(row.resolve_ms)} fetch=${formatMs(row.fetch_ms)} link=${formatMs(row.link_ms)}`
      : '';
  console.log(
    `[${fixture.name} ${spec.id} ${mode}] sample ${sample}/${samples}: ${status} wall=${wallMs}ms rss=${formatBytes(maxRssBytes)}${detail}`,
  );

  return row;
}

function recordSkippedInstall({ sample, fixture, spec, mode, runDir, phase, reason, pairMeta }) {
  const phaseDir = path.join(runDir, phase);
  fs.mkdirSync(phaseDir, { recursive: true });
  const row = {
    sample,
    fixture: fixture.name,
    fixture_source: fixture.source,
    manager: spec.manager,
    binary: spec.binaryName,
    cell: spec.cellName,
    route: spec.route,
    firewall_mode: spec.firewallMode,
    spec: spec.id,
    mode,
    counted: true,
    pair_id: pairMeta?.pairId,
    pair_order: pairMeta?.pairOrder,
    execution_sequence: ++executionSequence,
    started_at: new Date().toISOString(),
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

function installCommand(spec, policy) {
  switch (spec.manager) {
    case 'lpm':
      return [
        spec.binaryPath,
        '--json',
        'install',
        '--no-security-summary',
        '--no-skills',
        '--no-editor-setup',
      ];
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
      throw new Error(`unsupported manager: ${spec.manager}`);
  }
}

function extractLpmMetrics(json) {
  const experimental = at(json, ['timing', 'experimental_installer_spike']);
  const { metadata, attribution: metadataAttribution, routes: metadataRoutes, versionDocs } =
    lpmMetadataMetrics(json);
  const fetchBreakdown = at(json, ['timing', 'fetch_breakdown']);
  const fetchDetail = at(json, ['timing', 'detail', 'fetch']);
  const fetchOverlap = fetchDetail?.overlap;
  const fetchOverlapBreakdown = fetchOverlap?.breakdown;
  const reusableValidation = fetchDetail?.v2_reusable_validation;
  const firewall =
    at(json, ['timing', 'firewall']) ?? at(json, ['timing', 'detail', 'security', 'firewall']);
  const firewallClient = firewall?.client;
  const firewallWorker = firewall?.worker;
  const firewallWorkerMatchSources = firewallWorker?.matchSources;
  const firewallWorkerLookupDuration = firewallWorker?.lookupDuration;
  const firewallWorkerFlaggedIndex = firewallWorker?.flaggedPackageIndex;
  const resolveDetail = at(json, ['timing', 'resolve']);
  const resolveDispatcher = resolveDetail?.dispatcher;
  const streamingBfs = resolveDetail?.streaming_bfs;
  const parity = experimental?.parity;
  const metadataBodyBytesSum = firstFinite(
    metadata?.body_bytes_sum,
    metadataAttribution?.body_bytes_sum,
  );
  const metadataVersionCountSum = firstFinite(
    metadata?.version_count_sum,
    metadataAttribution?.version_count_sum,
  );
  const releaseTimeFetch = metadataAttribution?.policy_release_time_fetch;
  const fetchSourceScanSumNs = sumFinite(
    breakdownStat(fetchBreakdown, 'source_scan', 'sum_ns'),
    breakdownStat(fetchOverlapBreakdown, 'source_scan', 'sum_ns'),
  );
  const fetchSourceScanMaxNs = maxFinite(
    breakdownStat(fetchBreakdown, 'source_scan', 'max_ns'),
    breakdownStat(fetchOverlapBreakdown, 'source_scan', 'max_ns'),
  );

  return {
    duration_ms: numberAt(json, ['duration_ms']),
    package_count: numberAt(json, ['count']),
    downloaded: numberAt(json, ['downloaded']),
    cached: numberAt(json, ['cached']),
    linked: numberAt(json, ['linked']),
    resolve_ms: numberAt(json, ['timing', 'resolve_ms']),
    firewall_batch_ms: finiteNumber(
      firstFinite(at(json, ['timing', 'firewall_batch_ms']), firewall?.batch_ms),
    ),
    firewall_checked_count: finiteNumber(firewall?.checked_count),
    firewall_lookup_mode:
      typeof firewall?.lookup_mode === 'string' ? firewall.lookup_mode : undefined,
    firewall_chunk_count: finiteNumber(firewall?.chunk_count),
    firewall_chunk_sum_ms: finiteNumber(firewall?.chunk_sum_ms),
    firewall_chunk_max_ms: finiteNumber(firewall?.chunk_max_ms),
    firewall_allow_count: finiteNumber(firewall?.allow_count),
    firewall_warn_count: finiteNumber(firewall?.warn_count),
    firewall_block_count: finiteNumber(firewall?.block_count),
    firewall_unknown_count: finiteNumber(firewall?.unknown_count),
    firewall_matched_count: finiteNumber(firewall?.matched_count),
    firewall_worker_package_count: finiteNumber(firewallWorker?.packageCount),
    firewall_worker_lookup_concurrency: finiteNumber(firewallWorker?.lookupConcurrency),
    firewall_worker_kv_read_count: finiteNumber(firewallWorker?.kvReadCount),
    firewall_worker_kv_lookup_ms: finiteNumber(firewallWorker?.kvLookupMs),
    firewall_worker_entitlement_ms: finiteNumber(firewallWorker?.entitlementMs),
    firewall_worker_parse_ms: finiteNumber(firewallWorker?.parseMs),
    firewall_worker_total_ms: finiteNumber(firewallWorker?.totalMs),
    firewall_worker_matched_count: finiteNumber(firewallWorker?.matchedCount),
    firewall_worker_returned_decision_count: finiteNumber(firewallWorker?.returnedDecisionCount),
    firewall_worker_flagged_index_enabled:
      firewallWorkerFlaggedIndex?.enabled === true
        ? 1
        : firewallWorkerFlaggedIndex?.enabled === false
          ? 0
          : finiteNumber(firewallWorkerFlaggedIndex?.enabled),
    firewall_worker_flagged_index_used:
      firewallWorkerFlaggedIndex?.used === true
        ? 1
        : firewallWorkerFlaggedIndex?.used === false
          ? 0
          : finiteNumber(firewallWorkerFlaggedIndex?.used),
    firewall_worker_flagged_index_read_ms: finiteNumber(firewallWorkerFlaggedIndex?.readMs),
    firewall_worker_flagged_index_package_key_count: finiteNumber(
      firewallWorkerFlaggedIndex?.packageKeyCount,
    ),
    firewall_worker_flagged_index_candidate_count: finiteNumber(
      firewallWorkerFlaggedIndex?.candidateCount,
    ),
    firewall_worker_flagged_index_detail_read_count: finiteNumber(
      firewallWorkerFlaggedIndex?.detailReadCount,
    ),
    firewall_worker_flagged_index_skipped_package_lookup_count: finiteNumber(
      firewallWorkerFlaggedIndex?.skippedPackageLookupCount,
    ),
    firewall_worker_match_integrity_count: finiteNumber(firewallWorkerMatchSources?.integrity),
    firewall_worker_match_package_count: finiteNumber(firewallWorkerMatchSources?.package),
    firewall_worker_match_none_count: finiteNumber(firewallWorkerMatchSources?.none),
    firewall_worker_lookup_duration_count: finiteNumber(firewallWorkerLookupDuration?.count),
    firewall_worker_lookup_duration_sum_ms: finiteNumber(firewallWorkerLookupDuration?.sumMs),
    firewall_worker_lookup_duration_max_ms: finiteNumber(firewallWorkerLookupDuration?.maxMs),
    firewall_worker_lookup_duration_p50_ms: finiteNumber(firewallWorkerLookupDuration?.p50Ms),
    firewall_worker_lookup_duration_p95_ms: finiteNumber(firewallWorkerLookupDuration?.p95Ms),
    firewall_client_request_ms: finiteNumber(firewallClient?.requestMs),
    firewall_client_body_read_ms: finiteNumber(firewallClient?.bodyReadMs),
    firewall_client_json_parse_ms: finiteNumber(firewallClient?.jsonParseMs),
    firewall_client_total_ms: finiteNumber(firewallClient?.totalMs),
    firewall_client_request_body_bytes: finiteNumber(firewallClient?.requestBodyBytes),
    firewall_client_request_body_mb: bytesToMb(firewallClient?.requestBodyBytes),
    firewall_client_response_body_bytes: finiteNumber(firewallClient?.responseBodyBytes),
    firewall_client_response_body_mb: bytesToMb(firewallClient?.responseBodyBytes),
    firewall_rpc_failed_count:
      firewall?.rpc_failed === true
        ? 1
        : firewall?.rpc_failed === false
          ? 0
          : finiteNumber(firewall?.rpc_failed),
    firewall_offline_skipped_count:
      firewall?.offline_skipped === true
        ? 1
        : firewall?.offline_skipped === false
          ? 0
          : finiteNumber(firewall?.offline_skipped),
    resolve_initial_batch_ms: finiteNumber(resolveDetail?.initial_batch_ms),
    resolve_followup_rpc_ms: finiteNumber(resolveDetail?.followup_rpc_ms),
    resolve_followup_rpc_count: finiteNumber(resolveDetail?.followup_rpc_count),
    resolve_walker_rpc_count: finiteNumber(resolveDetail?.walker_rpc_count),
    resolve_escape_hatch_rpc_count: finiteNumber(resolveDetail?.escape_hatch_rpc_count),
    resolve_parse_ndjson_ms: finiteNumber(resolveDetail?.parse_ndjson_ms),
    resolve_pubgrub_ms: finiteNumber(resolveDetail?.pubgrub_ms),
    resolve_platform_skipped_count: finiteNumber(resolveDetail?.platform_skipped),
    resolve_dispatcher_rpc_count: finiteNumber(resolveDispatcher?.rpc_count),
    resolve_dispatcher_configured_fanout: finiteNumber(resolveDispatcher?.configured_fanout),
    resolve_dispatcher_inflight_high_water: finiteNumber(resolveDispatcher?.inflight_high_water),
    resolve_dispatcher_active_fetch_high_water: finiteNumber(
      resolveDispatcher?.active_fetch_high_water,
    ),
    resolve_dispatcher_pending_high_water: finiteNumber(resolveDispatcher?.pending_high_water),
    resolve_dispatcher_semaphore_wait_count: finiteNumber(
      resolveDispatcher?.semaphore_wait_count,
    ),
    resolve_dispatcher_semaphore_wait_ms: finiteNumber(resolveDispatcher?.semaphore_wait_ms),
    resolve_dispatcher_tarball_dispatched_count: finiteNumber(resolveDispatcher?.tarball_dispatched),
    resolve_dispatcher_peer_prefetch_count: finiteNumber(resolveDispatcher?.peer_prefetch_count),
    resolve_streaming_bfs_walk_ms: finiteNumber(streamingBfs?.walk_ms),
    resolve_streaming_bfs_manifests_fetched: finiteNumber(streamingBfs?.manifests_fetched),
    resolve_streaming_bfs_cache_hits: finiteNumber(streamingBfs?.cache_hits),
    fetch_ms: numberAt(json, ['timing', 'fetch_ms']),
    link_ms: numberAt(json, ['timing', 'link_ms']),
    total_ms: numberAt(json, ['timing', 'total_ms']),
    fetch_task_sum_ms: numberAt(json, ['timing', 'fetch_breakdown', 'task_sum_ms']),
    fetch_task_max_ms: numberAt(json, ['timing', 'fetch_breakdown', 'task_max_ms']),
    fetch_queue_wait_sum_ms: breakdownStat(fetchBreakdown, 'queue_wait', 'sum_ms'),
    fetch_extract_sum_ms: breakdownStat(fetchBreakdown, 'extract', 'sum_ms'),
    fetch_source_scan_sum_ns: fetchSourceScanSumNs,
    fetch_source_scan_max_ns: fetchSourceScanMaxNs,
    fetch_source_scan_sum_ms: nsToMs(fetchSourceScanSumNs),
    fetch_finalize_sum_ms: breakdownStat(fetchBreakdown, 'finalize', 'sum_ms'),
    cas_source_record_read_count: finiteNumber(reusableValidation?.cas_source_record_read_count),
    cas_source_record_read_ms: finiteNumber(reusableValidation?.cas_source_record_read_ms),
    cas_manifest_read_count: finiteNumber(reusableValidation?.cas_manifest_read_count),
    cas_manifest_read_ms: finiteNumber(reusableValidation?.cas_manifest_read_ms),
    cas_manifest_validate_ms: finiteNumber(reusableValidation?.cas_manifest_validate_ms),
    cas_blob_stat_count: finiteNumber(reusableValidation?.cas_blob_stat_count),
    cas_blob_stat_cache_hit_count: finiteNumber(
      reusableValidation?.cas_blob_stat_cache_hit_count,
    ),
    cas_blob_stat_ms: finiteNumber(reusableValidation?.cas_blob_stat_ms),
    cas_source_validation_read_count: finiteNumber(
      reusableValidation?.cas_source_validation_read_count,
    ),
    cas_source_validation_read_ms: finiteNumber(
      reusableValidation?.cas_source_validation_read_ms,
    ),
    cas_blob_rehash_count: finiteNumber(reusableValidation?.cas_blob_rehash_count),
    cas_blob_rehash_ms: finiteNumber(reusableValidation?.cas_blob_rehash_ms),
    fetch_overlap_selected_count: finiteNumber(fetchOverlap?.selected_count),
    fetch_overlap_dispatched_count: finiteNumber(fetchOverlap?.dispatched_count),
    fetch_overlap_completed_count: finiteNumber(fetchOverlap?.completed_count),
    fetch_overlap_cache_hit_count: finiteNumber(fetchOverlap?.cache_hit_count),
    fetch_overlap_skipped_platform_count: finiteNumber(fetchOverlap?.skipped_platform_count),
    fetch_overlap_failed_count: finiteNumber(fetchOverlap?.failed_count),
    fetch_overlap_buffered_count: finiteNumber(fetchOverlap?.buffered_count),
    fetch_overlap_buffered_dispatch_count: finiteNumber(fetchOverlap?.buffered_dispatch_count),
    fetch_overlap_buffered_undispatched_count: finiteNumber(
      fetchOverlap?.buffered_undispatched_count,
    ),
    fetch_overlap_buffer_wait_sum_ms: finiteNumber(fetchOverlap?.buffer_wait?.sum_ms),
    fetch_overlap_buffer_wait_max_ms: finiteNumber(fetchOverlap?.buffer_wait?.max_ms),
    fetch_overlap_task_sum_ms: finiteNumber(fetchOverlap?.task_sum_ms),
    fetch_overlap_task_max_ms: finiteNumber(fetchOverlap?.task_max_ms),
    fetch_overlap_drain_ms: finiteNumber(fetchOverlap?.drain_ms),
    parity_matches: typeof parity?.matches === 'boolean' ? parity.matches : undefined,
    parity_candidate_count: finiteNumber(parity?.candidate_count),
    parity_baseline_count: finiteNumber(parity?.baseline_count),
    parity_extra_count: finiteNumber(parity?.extra_count),
    parity_missing_count: finiteNumber(parity?.missing_count),
    parity_fingerprint_mismatch_count: finiteNumber(parity?.fingerprint_mismatch_count),
    metadata_calls: finiteNumber(metadata?.calls),
    metadata_initial_fetches: finiteNumber(metadata?.initial_fetches),
    metadata_ready_hits: finiteNumber(metadata?.ready_hits),
    metadata_body_bytes_sum: metadataBodyBytesSum,
    metadata_body_mb_sum: bytesToMb(metadataBodyBytesSum),
    metadata_version_count_sum: metadataVersionCountSum,
    metadata_raw_fetch_sum_ms: finiteNumber(metadataAttribution?.raw_fetch_sum_ms),
    metadata_http_sum_ms: finiteNumber(metadataAttribution?.http_sum_ms),
    metadata_body_read_sum_ms: finiteNumber(metadataAttribution?.body_read_sum_ms),
    metadata_json_decode_sum_ms: finiteNumber(metadataAttribution?.json_decode_sum_ms),
    metadata_cache_info_parse_sum_ms: finiteNumber(metadataAttribution?.cache_info_parse_sum_ms),
    metadata_policy_release_time_sum_ms: finiteNumber(
      metadataAttribution?.policy_release_time_sum_ms,
    ),
    metadata_policy_release_time_fetch_sum_ms: finiteNumber(releaseTimeFetch?.total_sum_ms),
    metadata_policy_release_time_fetch_http_sum_ms: finiteNumber(releaseTimeFetch?.http_sum_ms),
    metadata_policy_release_time_fetch_body_read_sum_ms: finiteNumber(
      releaseTimeFetch?.body_read_sum_ms,
    ),
    metadata_policy_release_time_fetch_json_decode_sum_ms: finiteNumber(
      releaseTimeFetch?.json_decode_sum_ms,
    ),
    metadata_policy_release_time_fetch_body_bytes_sum: finiteNumber(
      releaseTimeFetch?.body_bytes_sum,
    ),
    metadata_policy_release_time_fetch_body_mb_sum: bytesToMb(
      releaseTimeFetch?.body_bytes_sum,
    ),
    metadata_policy_release_time_fetch_version_count_sum: finiteNumber(
      releaseTimeFetch?.version_count_sum,
    ),
    metadata_policy_release_time_fetch_cache_hit_count: finiteNumber(
      releaseTimeFetch?.cache_hit_count,
    ),
    metadata_policy_release_time_fetch_not_modified_count: finiteNumber(
      releaseTimeFetch?.not_modified_count,
    ),
    metadata_policy_full_metadata_sum_ms: finiteNumber(
      metadataAttribution?.policy_full_metadata_sum_ms,
    ),
    metadata_version_doc_attempts: finiteNumber(versionDocs?.attempts),
    metadata_version_doc_hits: finiteNumber(versionDocs?.hits),
    metadata_version_doc_fallbacks: finiteNumber(versionDocs?.fallbacks),
    metadata_route_npm_direct: finiteNumber(metadataRoutes?.npm_direct),
    metadata_route_npm_direct_version_doc: finiteNumber(
      metadataRoutes?.npm_direct_version_doc,
    ),
  };
}

function lpmMetadataMetrics(json) {
  const current = at(json, ['timing', 'detail', 'resolve', 'metadata_fetch']);
  if (current && typeof current === 'object') {
    return {
      metadata: current,
      attribution: current.attribution,
      routes: current.routes ?? current.attribution?.routes,
      versionDocs: current.version_docs ?? current.attribution?.version_docs,
    };
  }

  const experimental = at(json, ['timing', 'experimental_installer_spike', 'metadata']);
  return {
    metadata: experimental,
    attribution: experimental?.attribution,
    routes: experimental?.routes ?? experimental?.attribution?.routes,
    versionDocs: experimental?.version_docs ?? experimental?.attribution?.version_docs,
  };
}

function firstFinite(...values) {
  for (const value of values) {
    const number = finiteNumber(value);
    if (number !== undefined) {
      return number;
    }
  }
  return undefined;
}

function sumFinite(...values) {
  let total = 0;
  let found = false;
  for (const value of values) {
    const number = finiteNumber(value);
    if (number !== undefined) {
      total += number;
      found = true;
    }
  }
  return found ? total : undefined;
}

function maxFinite(...values) {
  let maximum;
  for (const value of values) {
    const number = finiteNumber(value);
    if (number !== undefined) {
      maximum = maximum === undefined ? number : Math.max(maximum, number);
    }
  }
  return maximum;
}

function buildRunSpecs(managers, binaries, cells, routes, firewallModes) {
  const specs = [];
  for (const manager of managers) {
    if (manager !== 'lpm') {
      specs.push({
        id: manager,
        manager,
        cellName: 'default',
        route: 'default',
        firewallMode: 'default',
        env: {},
      });
      continue;
    }
    for (const binary of binaries) {
      for (const route of routes) {
        for (const firewallMode of firewallModes) {
          for (const cell of cells) {
            const firewallSuffix = firewallMode === 'off' ? '' : `firewall-${firewallMode}`;
            const defaultBinary = binaries.length === 1 && binary.name === 'current';
            const identitySuffix = defaultBinary
              ? cell.name
              : [binary.name, cell.name === 'current' ? '' : cell.name]
                  .filter(Boolean)
                  .join('-');
            const suffix = [identitySuffix, route, firewallSuffix]
              .filter((part) => part && part !== 'direct')
              .join('-');
            specs.push({
              id: `lpm-${suffix}`,
              manager,
              binaryName: binary.name,
              binaryPath: binary.path,
              cellName: cell.name,
              route,
              firewallMode,
              env: cell.env,
            });
          }
        }
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
    'LPM_REGISTRY_URL',
    'LPM_TOKEN',
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
    if (lpmTyposquatGuard === 'off') {
      env.LPM_TYPOSQUAT_GUARD = '0';
    }
    if (spec.route !== 'direct') {
      env.LPM_NPM_ROUTE = spec.route;
    }
    if (spec.firewallMode && spec.firewallMode !== 'off') {
      env.LPM_NPM_FIREWALL = spec.firewallMode;
    }
    Object.assign(env, spec.env);
  }

  return env;
}

function materializeFixture(fixture, projectDir) {
  if (fixture.path) {
    fs.cpSync(fixture.path, projectDir, { recursive: true });
    const fixtureNpmrc = path.join(projectDir, 'fixture.npmrc');
    const npmrc = path.join(projectDir, '.npmrc');
    if (fs.existsSync(fixtureNpmrc) && !fs.existsSync(npmrc)) {
      fs.copyFileSync(fixtureNpmrc, npmrc);
    }
    return;
  }
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(
    path.join(projectDir, 'package.json'),
    `${JSON.stringify(fixture.packageJson, null, 2)}\n`,
  );
}

function cleanProjectForCold(projectDir) {
  cleanProject(projectDir, true);
}

function cleanProjectForWarm(projectDir) {
  cleanProject(projectDir, false);
}

function cleanProject(projectDir, removeLockfiles) {
  const pending = [projectDir];

  while (pending.length > 0) {
    const current = pending.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const target = path.join(current, entry.name);
      if (INSTALL_DIRS.has(entry.name) || (removeLockfiles && LOCKFILES.has(entry.name))) {
        removeTree(target);
      } else if (entry.isDirectory() && entry.name !== '.git') {
        pending.push(target);
      }
    }
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
    const successful = groupRows.filter((row) => !runFailed(row));
    const first = groupRows[0];
    const metrics = summarizeMetrics(successful);
    out.push({
      fixture,
      manager: first.manager,
      binary: first.binary,
      spec,
      cell: first.cell,
      route: first.route,
      firewall_mode: first.firewall_mode,
      mode,
      samples: groupRows.length,
      successful_samples: successful.length,
      metrics,
      tail_warnings: summarizeTailWarnings(metrics),
    });
  }
  out.sort((a, b) =>
    [a.fixture, a.spec, a.mode].join('\0').localeCompare([b.fixture, b.spec, b.mode].join('\0')),
  );
  return out;
}

function summarizeLpmComparison(rows, comparison, thresholds, expectedSamples) {
  const counted = rows.filter((row) => row.counted !== false && row.manager === 'lpm');
  const groupKeys = new Set(
    counted.map((row) =>
      [row.fixture, row.mode, row.cell, row.route, row.firewall_mode].join('\0'),
    ),
  );
  const groups = [];
  let hasExecutionFailure = false;
  let hasRegression = false;
  let hasInconclusive = false;

  for (const key of [...groupKeys].sort()) {
    const [fixture, mode, cell, route, firewallMode] = key.split('\0');
    const groupRows = counted.filter(
      (row) =>
        row.fixture === fixture &&
        row.mode === mode &&
        row.cell === cell &&
        row.route === route &&
        row.firewall_mode === firewallMode,
    );
    const pairs = [];
    const failedSamples = [];

    for (let sample = 1; sample <= expectedSamples; sample += 1) {
      const baseline = groupRows.find(
        (row) => row.sample === sample && row.binary === comparison.baseline,
      );
      const candidate = groupRows.find(
        (row) => row.sample === sample && row.binary === comparison.candidate,
      );
      if (!baseline || !candidate || runFailed(baseline) || runFailed(candidate)) {
        failedSamples.push({
          sample,
          baseline: comparisonRowStatus(baseline),
          candidate: comparisonRowStatus(candidate),
        });
        continue;
      }
      if (
        baseline.pair_id !== candidate.pair_id ||
        Math.abs(baseline.execution_sequence - candidate.execution_sequence) !== 1
      ) {
        failedSamples.push({
          sample,
          baseline: 'not adjacent',
          candidate: 'not adjacent',
        });
        continue;
      }
      pairs.push({ sample, baseline, candidate });
    }

    const metrics = {};
    for (const metric of TAIL_METRICS) {
      const metricPairs = pairs
        .map((pair) => ({
          sample: pair.sample,
          baseline: pair.baseline[metric],
          candidate: pair.candidate[metric],
        }))
        .filter(
          (pair) =>
            Number.isFinite(pair.baseline) && Number.isFinite(pair.candidate) && pair.baseline > 0,
        );
      if (metricPairs.length === 0) {
        continue;
      }
      const metricThresholds = thresholds[metric] ?? thresholds.wall_ms;
      metrics[metric] = comparePairedMetric(metricPairs, metricThresholds);
      if (COMPARISON_GATE_METRICS.has(metric) && metrics[metric].verdict === 'regression') {
        hasRegression = true;
      } else if (
        COMPARISON_GATE_METRICS.has(metric) &&
        metrics[metric].verdict === 'inconclusive'
      ) {
        hasInconclusive = true;
      }
    }

    if (failedSamples.length > 0) {
      hasExecutionFailure = true;
    }
    const orderCounts = {
      'baseline-candidate': pairs.filter(
        (pair) => pair.baseline.pair_order === 'baseline-candidate',
      ).length,
      'candidate-baseline': pairs.filter(
        (pair) => pair.baseline.pair_order === 'candidate-baseline',
      ).length,
    };
    if (Math.abs(orderCounts['baseline-candidate'] - orderCounts['candidate-baseline']) > 1) {
      hasExecutionFailure = true;
      failedSamples.push({
        sample: 'schedule',
        baseline: 'imbalanced AB/BA order',
        candidate: 'imbalanced AB/BA order',
      });
    }
    groups.push({
      fixture,
      mode,
      cell,
      route,
      firewall_mode: firewallMode,
      expected_pairs: expectedSamples,
      successful_pairs: pairs.length,
      pair_orders: orderCounts,
      failed_samples: failedSamples,
      metrics,
    });
  }

  const verdict = hasExecutionFailure
    ? 'execution-failure'
    : hasRegression
      ? 'regression'
      : hasInconclusive
        ? 'inconclusive'
        : 'pass';
  return {
    baseline: comparison.baseline,
    candidate: comparison.candidate,
    thresholds,
    verdict,
    groups,
  };
}

function comparePairedMetric(pairs, thresholds) {
  const baseline = metricDistribution(
    pairs.map((pair) => ({ value: pair.baseline })),
    'value',
  );
  const candidate = metricDistribution(
    pairs.map((pair) => ({ value: pair.candidate })),
    'value',
  );
  const pairedDeltas = pairs.map((pair) => ({
    sample: pair.sample,
    baseline: pair.baseline,
    candidate: pair.candidate,
    delta: pair.candidate - pair.baseline,
    delta_pct: relativeDeltaPct(pair.baseline, pair.candidate),
  }));
  const pairedDeltaPct = metricDistribution(pairedDeltas, 'delta_pct');
  const pairedDelta = metricDistribution(pairedDeltas, 'delta');
  const medianDeltaPct = relativeDeltaPct(baseline.median, candidate.median);
  const p95DeltaPct = relativeDeltaPct(baseline.p95, candidate.p95);
  const medianDelta = candidate.median - baseline.median;
  const p95Delta = candidate.p95 - baseline.p95;
  const medianClearlyRegressed =
    medianDeltaPct > thresholds.median_pct &&
    medianDelta > thresholds.median_abs &&
    pairedDeltaPct.median - pairedDeltaPct.mad > thresholds.median_pct &&
    pairedDelta.median - pairedDelta.mad > thresholds.median_abs;
  const p95ClearlyRegressed =
    p95DeltaPct > thresholds.p95_pct &&
    p95Delta > thresholds.p95_abs &&
    pairedDeltaPct.p95 - pairedDeltaPct.iqr > thresholds.p95_pct &&
    pairedDelta.p95 - pairedDelta.iqr > thresholds.p95_abs;
  const withinThresholds =
    (medianDeltaPct <= thresholds.median_pct || medianDelta <= thresholds.median_abs) &&
    (p95DeltaPct <= thresholds.p95_pct || p95Delta <= thresholds.p95_abs);
  return {
    baseline,
    candidate,
    median_delta_pct: medianDeltaPct,
    p95_delta_pct: p95DeltaPct,
    median_delta: medianDelta,
    p95_delta: p95Delta,
    paired_delta_pct: pairedDeltaPct,
    paired_delta: pairedDelta,
    pairs: pairedDeltas,
    verdict: medianClearlyRegressed || p95ClearlyRegressed
      ? 'regression'
      : withinThresholds
        ? 'pass'
        : 'inconclusive',
  };
}

function relativeDeltaPct(baseline, candidate) {
  return roundDistributionValue(((candidate - baseline) / baseline) * 100);
}

function comparisonRowStatus(row) {
  if (!row) {
    return 'missing';
  }
  if (row.skipped) {
    return `skipped: ${row.skip_reason}`;
  }
  if (row.parse_error) {
    return `parse error: ${row.parse_error}`;
  }
  if (row.spawn_error) {
    return `spawn error: ${row.spawn_error}`;
  }
  return `exit ${row.exit_code}`;
}

function renderLpmComparisonMarkdown(comparison) {
  const lines = [
    `Verdict: **${comparison.verdict}**`,
    '',
    `Baseline: \`${comparison.baseline}\`. Candidate: \`${comparison.candidate}\`.`,
    '',
    `Wall limits: median ${comparison.thresholds.wall_ms.median_pct}% and ${comparison.thresholds.wall_ms.median_abs} ms; p95 ${comparison.thresholds.wall_ms.p95_pct}% and ${comparison.thresholds.wall_ms.p95_abs} ms.`,
    `RSS limits: median ${comparison.thresholds.max_rss_bytes.median_pct}% and ${formatBytes(comparison.thresholds.max_rss_bytes.median_abs)}; p95 ${comparison.thresholds.max_rss_bytes.p95_pct}% and ${formatBytes(comparison.thresholds.max_rss_bytes.p95_abs)}.`,
    '',
    '| Fixture | Mode | Pairs | Metric | Base med/p95 | Candidate med/p95 | Delta med/p95 | Paired delta med/p95 | Result |',
    '| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- |',
  ];
  for (const group of comparison.groups) {
    for (const [metric, result] of Object.entries(group.metrics)) {
      lines.push(
        `| ${group.fixture} | ${group.mode} | ${group.successful_pairs}/${group.expected_pairs} | ${metric} | ${result.baseline.median}/${result.baseline.p95} | ${result.candidate.median}/${result.candidate.p95} | ${result.median_delta_pct}%/${result.p95_delta_pct}% | ${result.paired_delta_pct.median}%/${result.paired_delta_pct.p95}% | ${result.verdict} |`,
      );
    }
  }
  const failures = comparison.groups.flatMap((group) =>
    group.failed_samples.map((failure) => ({ group, failure })),
  );
  if (failures.length > 0) {
    lines.push('', '## Execution failures', '');
    for (const { group, failure } of failures) {
      lines.push(
        `- ${group.fixture} ${group.mode} sample ${failure.sample}: baseline=${failure.baseline}; candidate=${failure.candidate}.`,
      );
    }
  }
  return lines.join('\n');
}

function summarizeMetrics(rows) {
  const keys = [
    'wall_ms',
    'max_rss_bytes',
    'duration_ms',
    'resolve_ms',
    'firewall_batch_ms',
    'firewall_chunk_count',
    'firewall_chunk_sum_ms',
    'firewall_chunk_max_ms',
    'firewall_checked_count',
    'firewall_allow_count',
    'firewall_warn_count',
    'firewall_block_count',
    'firewall_unknown_count',
    'firewall_matched_count',
    'firewall_worker_package_count',
    'firewall_worker_lookup_concurrency',
    'firewall_worker_kv_read_count',
    'firewall_worker_kv_lookup_ms',
    'firewall_worker_entitlement_ms',
    'firewall_worker_parse_ms',
    'firewall_worker_total_ms',
    'firewall_worker_matched_count',
    'firewall_worker_returned_decision_count',
    'firewall_worker_flagged_index_enabled',
    'firewall_worker_flagged_index_used',
    'firewall_worker_flagged_index_read_ms',
    'firewall_worker_flagged_index_package_key_count',
    'firewall_worker_flagged_index_candidate_count',
    'firewall_worker_flagged_index_detail_read_count',
    'firewall_worker_flagged_index_skipped_package_lookup_count',
    'firewall_worker_match_integrity_count',
    'firewall_worker_match_package_count',
    'firewall_worker_match_none_count',
    'firewall_worker_lookup_duration_count',
    'firewall_worker_lookup_duration_sum_ms',
    'firewall_worker_lookup_duration_max_ms',
    'firewall_worker_lookup_duration_p50_ms',
    'firewall_worker_lookup_duration_p95_ms',
    'firewall_client_request_ms',
    'firewall_client_body_read_ms',
    'firewall_client_json_parse_ms',
    'firewall_client_total_ms',
    'firewall_client_request_body_mb',
    'firewall_client_response_body_mb',
    'firewall_rpc_failed_count',
    'firewall_offline_skipped_count',
    'resolve_initial_batch_ms',
    'resolve_followup_rpc_ms',
    'resolve_followup_rpc_count',
    'resolve_walker_rpc_count',
    'resolve_escape_hatch_rpc_count',
    'resolve_parse_ndjson_ms',
    'resolve_pubgrub_ms',
    'resolve_platform_skipped_count',
    'resolve_dispatcher_rpc_count',
    'resolve_dispatcher_configured_fanout',
    'resolve_dispatcher_inflight_high_water',
    'resolve_dispatcher_active_fetch_high_water',
    'resolve_dispatcher_pending_high_water',
    'resolve_dispatcher_semaphore_wait_count',
    'resolve_dispatcher_semaphore_wait_ms',
    'resolve_dispatcher_tarball_dispatched_count',
    'resolve_dispatcher_peer_prefetch_count',
    'resolve_streaming_bfs_walk_ms',
    'resolve_streaming_bfs_manifests_fetched',
    'resolve_streaming_bfs_cache_hits',
    'fetch_ms',
    'link_ms',
    'package_count',
    'downloaded',
    'cached',
    'fetch_task_sum_ms',
    'fetch_task_max_ms',
    'fetch_queue_wait_sum_ms',
    'fetch_extract_sum_ms',
    'fetch_source_scan_sum_ns',
    'fetch_source_scan_max_ns',
    'fetch_source_scan_sum_ms',
    'fetch_finalize_sum_ms',
    'cas_source_record_read_count',
    'cas_source_record_read_ms',
    'cas_manifest_read_count',
    'cas_manifest_read_ms',
    'cas_manifest_validate_ms',
    'cas_blob_stat_count',
    'cas_blob_stat_cache_hit_count',
    'cas_blob_stat_ms',
    'cas_source_validation_read_count',
    'cas_source_validation_read_ms',
    'cas_blob_rehash_count',
    'cas_blob_rehash_ms',
    'fetch_overlap_selected_count',
    'fetch_overlap_dispatched_count',
    'fetch_overlap_completed_count',
    'fetch_overlap_cache_hit_count',
    'fetch_overlap_skipped_platform_count',
    'fetch_overlap_failed_count',
    'fetch_overlap_buffered_count',
    'fetch_overlap_buffered_dispatch_count',
    'fetch_overlap_buffered_undispatched_count',
    'fetch_overlap_buffer_wait_sum_ms',
    'fetch_overlap_buffer_wait_max_ms',
    'fetch_overlap_task_sum_ms',
    'fetch_overlap_task_max_ms',
    'fetch_overlap_drain_ms',
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
    'metadata_policy_release_time_fetch_sum_ms',
    'metadata_policy_release_time_fetch_http_sum_ms',
    'metadata_policy_release_time_fetch_body_read_sum_ms',
    'metadata_policy_release_time_fetch_json_decode_sum_ms',
    'metadata_policy_release_time_fetch_body_mb_sum',
    'metadata_policy_release_time_fetch_version_count_sum',
    'metadata_policy_release_time_fetch_cache_hit_count',
    'metadata_policy_release_time_fetch_not_modified_count',
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
      .map((key) => [key, metricDistribution(rows, key)])
      .filter(([, value]) => value != null),
  );
}

function summarizeTailWarnings(metrics) {
  const warnings = [];
  for (const metric of TAIL_METRICS) {
    const distribution = metrics[metric];
    if (!distribution || distribution.median <= 0) {
      continue;
    }
    const reasons = [];
    if (
      distribution.p95 - distribution.median >= 25 &&
      distribution.p95 >= distribution.median * 1.5
    ) {
      reasons.push('p95');
    }
    if (
      distribution.max - distribution.median >= 50 &&
      distribution.max >= distribution.median * 2
    ) {
      reasons.push('max');
    }
    if (reasons.length > 0) {
      warnings.push({
        metric,
        median: distribution.median,
        p95: distribution.p95,
        max: distribution.max,
        p95_to_median: roundDistributionValue(distribution.p95 / distribution.median),
        max_to_median: roundDistributionValue(distribution.max / distribution.median),
        reasons,
      });
    }
  }
  return warnings;
}

function renderSummaryMarkdown(summary) {
  const lines = [
    '| Fixture | Spec | Mode | OK | Wall med/p95/max | RSS MiB med/p95/max | Resolve med/p95/max | Firewall med/min | FW chunks | FW chunk sum | FW chunk max | Fetch med/p95/max | Link med/p95/max | Pkgs | FW checked | FW warn/block/unknown | Metadata MB | Version docs | Parity mismatches | Warnings exp/unknown |',
    '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
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
    const hasFirewall = Boolean(m.firewall_checked_count) || Boolean(m.firewall_batch_ms);
    const firewallVerdicts = hasFirewall
      ? `${one(m.firewall_warn_count)}/${one(m.firewall_block_count)}/${one(m.firewall_unknown_count)}`
      : 'n/a';
    lines.push(
      `| ${row.fixture} | ${row.spec} | ${row.mode} | ${row.successful_samples}/${row.samples} | ${tailStat(m.wall_ms)} | ${tailBytesMiB(m.max_rss_bytes)} | ${tailStat(m.resolve_ms)} | ${stat(m.firewall_batch_ms)} | ${one(m.firewall_chunk_count)} | ${stat(m.firewall_chunk_sum_ms)} | ${stat(m.firewall_chunk_max_ms)} | ${tailStat(m.fetch_ms)} | ${tailStat(m.link_ms)} | ${one(m.package_count)} | ${one(m.firewall_checked_count)} | ${firewallVerdicts} | ${stat(m.metadata_body_mb_sum)} | ${versionDocs} | ${mismatches} | ${warnings} |`,
    );
  }
  const tailWarnings = summary.flatMap((row) =>
    (row.tail_warnings ?? []).map((warning) => ({ row, warning })),
  );
  if (tailWarnings.length > 0) {
    lines.push(
      '',
      '## Tail latency warnings',
      '',
      '| Fixture | Spec | Mode | Metric | Median | p95 | Max | p95/med | max/med | Trigger |',
      '| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |',
    );
    for (const { row, warning } of tailWarnings) {
      lines.push(
        `| ${row.fixture} | ${row.spec} | ${row.mode} | ${warning.metric} | ${warning.median} | ${warning.p95} | ${warning.max} | ${warning.p95_to_median}× | ${warning.max_to_median}× | ${warning.reasons.join(', ')} |`,
      );
    }
  }
  return lines.join('\n');
}

function parseArgs(argv) {
  const parsed = { lpmBinaries: [], lpmCells: [] };
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
    if (arg === '--self-test') {
      parsed.selfTest = true;
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
    if (arg === '--allow-inconclusive') {
      parsed.allowInconclusive = true;
      continue;
    }
    const valueFlags = new Map([
      ['--samples', 'samples'],
      ['-n', 'samples'],
      ['--fixtures', 'fixtures'],
      ['--top-npm-file', 'topNpmFile'],
      ['--top-npm-offset', 'topNpmOffset'],
      ['--top-npm-limit', 'topNpmLimit'],
      ['--managers', 'managers'],
      ['--modes', 'modes'],
      ['--lpm-routes', 'lpmRoutes'],
      ['--lpm-firewall-modes', 'lpmFirewallModes'],
      ['--lpm-typosquat-guard', 'lpmTyposquatGuard'],
      ['--output', 'output'],
      ['--lpm-bin', 'lpmBin'],
      ['--lpm-binary', 'lpmBinary'],
      ['--lpm-compare', 'lpmCompare'],
      ['--median-regression-pct', 'medianRegressionPct'],
      ['--p95-regression-pct', 'p95RegressionPct'],
      ['--median-regression-ms', 'medianRegressionMs'],
      ['--p95-regression-ms', 'p95RegressionMs'],
      ['--rss-median-regression-pct', 'rssMedianRegressionPct'],
      ['--rss-p95-regression-pct', 'rssP95RegressionPct'],
      ['--rss-median-regression-mb', 'rssMedianRegressionMb'],
      ['--rss-p95-regression-mb', 'rssP95RegressionMb'],
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
    } else if (key === 'lpmBinary') {
      parsed.lpmBinaries.push(value);
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

function parseTopNpmFixtures(filePath, offset, limit) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`top npm file missing: ${filePath}`);
  }
  const specs = fs
    .readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*/, '').trim())
    .filter(Boolean);
  if (offset > specs.length) {
    throw new Error(`--top-npm-offset ${offset} is beyond ${specs.length} package(s)`);
  }
  const selected = specs.slice(offset, limit == null ? undefined : offset + limit);
  if (selected.length === 0) {
    throw new Error('top npm selection is empty');
  }
  return selected.map((spec) => fixtureFromPackageSpec(spec));
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

function parseLpmBinaries(rawBinaries, defaultBinary) {
  if (!rawBinaries || rawBinaries.length === 0) {
    return [{ name: 'current', path: defaultBinary }];
  }
  const binaries = rawBinaries.map((raw) => {
    const [name, binaryPath] = splitOnce(raw, '=');
    if (!name || !binaryPath) {
      throw new Error(`invalid --lpm-binary: ${raw}; expected NAME=PATH`);
    }
    return {
      name: sanitizeName(name),
      path: path.resolve(binaryPath),
    };
  });
  validateUniqueKeys('lpm binary', binaries, (binary) => binary.name);
  return binaries;
}

function parseLpmComparison(raw, binaries) {
  if (!raw) {
    return null;
  }
  const [rawBaseline, rawCandidate] = splitOnce(raw, ':');
  if (!rawBaseline || !rawCandidate || rawCandidate.includes(':')) {
    throw new Error('--lpm-compare must be BASELINE:CANDIDATE with different binary names');
  }
  const baseline = sanitizeName(rawBaseline);
  const candidate = sanitizeName(rawCandidate);
  if (baseline === candidate) {
    throw new Error('--lpm-compare must be BASELINE:CANDIDATE with different binary names');
  }
  const names = new Set(binaries.map((binary) => binary.name));
  if (!names.has(baseline) || !names.has(candidate)) {
    throw new Error('--lpm-compare names must match two --lpm-binary names');
  }
  return { baseline, candidate };
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
    if (!['cold', 'warm', 'up-to-date'].includes(mode)) {
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

function parseLpmFirewallModes(raw) {
  const modes = parseList(raw, '--lpm-firewall-modes').map(canonicalLpmFirewallMode);
  validateUniqueKeys('lpm firewall mode', modes, (mode) => mode);
  return modes;
}

function canonicalLpmFirewallMode(raw) {
  switch (raw.trim().toLowerCase()) {
    case 'off':
    case 'false':
    case '0':
    case 'no':
    case 'disabled':
      return 'off';
    case 'report':
    case 'warn':
      return 'report';
    case 'enforce':
    case 'enabled':
    case 'on':
    case 'true':
    case '1':
    case 'yes':
    case 'deny':
    case 'block':
      return 'enforce';
    default:
      throw new Error(`unsupported lpm firewall mode: ${raw}`);
  }
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

function validateLpmTyposquatGuard(mode) {
  if (!['default', 'off'].includes(mode)) {
    throw new Error(`unsupported --lpm-typosquat-guard: ${mode}`);
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

function optionalPositiveInt(raw, flag) {
  if (raw == null) {
    return null;
  }
  return positiveInt(raw, undefined, flag);
}

function nonNegativeInt(raw, fallback, flag) {
  if (raw == null) {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${flag} must be a non-negative integer`);
  }
  return value;
}

function nonNegativeNumber(raw, fallback, flag) {
  if (raw == null) {
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${flag} must be a non-negative number`);
  }
  return value;
}

function mebibytesToBytes(value) {
  return Math.round(value * 1024 * 1024);
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

function nsToMs(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value / 1_000_000 : undefined;
}

function bytesToMb(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return undefined;
  }
  return Math.round((value / 1024 / 1024) * 10) / 10;
}

function classifyInstallWarnings({ stdout = '', stderr = '', parsedStdout = null } = {}) {
  const expected = new Map(
    EXPECTED_WARNING_PATTERNS.map((entry) => [
      entry.id,
      { id: entry.id, label: entry.label, count: 0, samples: [] },
    ]),
  );
  const unexpected = [];
  let warningCount = 0;
  let expectedWarningCount = 0;

  const lines =
    parsedStdout === null
      ? `${stdout}\n${stderr}`.split(/\r?\n/)
      : [...warningLinesFromParsedJson(parsedStdout), ...stderr.split(/\r?\n/)];
  for (const rawLine of lines) {
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

function warningLinesFromParsedJson(parsed) {
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.warnings)) {
    return [];
  }
  return parsed.warnings.map(warningValueToLine).filter(Boolean);
}

function warningValueToLine(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (!value || typeof value !== 'object') {
    return '';
  }
  for (const key of ['message', 'warning', 'detail', 'description', 'title', 'code']) {
    if (typeof value[key] === 'string' && value[key].trim()) {
      return value[key];
    }
  }
  return JSON.stringify(value);
}

function summarizeWarnings(rows) {
  const expected = new Map();
  const unexpected = new Map();

  for (const row of rows.filter((entry) => entry.counted !== false)) {
    const run = {
      fixture: row.fixture,
      spec: row.spec,
      mode: row.mode,
      sample: row.sample,
      exit_code: row.exit_code,
    };

    for (const warning of row.expected_warnings ?? []) {
      const key = warning.id;
      const bucket =
        expected.get(key) ??
        {
          id: warning.id,
          label: warning.label,
          count: 0,
          samples: [],
          runs: [],
        };
      bucket.count += warning.count;
      for (const sample of warning.samples ?? []) {
        if (bucket.samples.length < 10 && !bucket.samples.includes(sample)) {
          bucket.samples.push(sample);
        }
      }
      if (bucket.runs.length < 50) {
        bucket.runs.push(run);
      }
      expected.set(key, bucket);
    }

    for (const line of row.unexpected_warnings ?? []) {
      const bucket =
        unexpected.get(line) ??
        {
          line,
          count: 0,
          runs: [],
        };
      bucket.count += 1;
      if (bucket.runs.length < 50) {
        bucket.runs.push(run);
      }
      unexpected.set(line, bucket);
    }
  }

  return {
    expected: [...expected.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)),
    unexpected: [...unexpected.values()].sort((a, b) => b.count - a.count || a.line.localeCompare(b.line)),
  };
}

function renderWarningSummaryMarkdown(summary) {
  const lines = ['# Warning Summary', ''];
  lines.push('## Expected');
  if (summary.expected.length === 0) {
    lines.push('', 'None.');
  } else {
    lines.push('', '| Count | ID | Label | Example |', '| ---: | --- | --- | --- |');
    for (const warning of summary.expected) {
      lines.push(
        `| ${warning.count} | ${warning.id} | ${warning.label} | ${markdownCell(warning.samples[0] ?? '')} |`,
      );
    }
  }

  lines.push('', '## Unexpected');
  if (summary.unexpected.length === 0) {
    lines.push('', 'None.');
  } else {
    lines.push('', '| Count | Warning | First run |', '| ---: | --- | --- |');
    for (const warning of summary.unexpected) {
      const firstRun = warning.runs[0]
        ? `${warning.runs[0].fixture}/${warning.runs[0].spec}/${warning.runs[0].mode}/sample-${warning.runs[0].sample}`
        : '';
      lines.push(`| ${warning.count} | ${markdownCell(warning.line)} | ${firstRun} |`);
    }
  }
  return lines.join('\n');
}

function markdownCell(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
}

function isWarningLikeLine(line) {
  return (
    /\bwarn(?:ing)?\b/i.test(line) ||
    /\bdeprecated\b/i.test(line) ||
    /\bdeprecation\b/i.test(line) ||
    /(?:can['’]?t|cannot) be found/i.test(line)
  );
}

function runSelfTests() {
  assert.deepEqual(parseModes('cold,warm,up-to-date'), ['cold', 'warm', 'up-to-date']);
  assert.throws(() => parseModes('repeat'), /unsupported mode/);
  assert.deepEqual(parseLpmBinaries([], '/tmp/default-lpm'), [
    { name: 'current', path: '/tmp/default-lpm' },
  ]);
  const binarySpecs = parseLpmBinaries(
    ['main=/tmp/lpm-main', 'candidate=/tmp/lpm-candidate'],
    '/tmp/unused',
  );
  assert.deepEqual(binarySpecs, [
    { name: 'main', path: '/tmp/lpm-main' },
    { name: 'candidate', path: '/tmp/lpm-candidate' },
  ]);
  assert.deepEqual(parseLpmComparison('main:candidate', binarySpecs), {
    baseline: 'main',
    candidate: 'candidate',
  });
  assert.throws(
    () => parseLpmComparison('main:missing', binarySpecs),
    /must match two --lpm-binary names/,
  );
  assert.equal(
    parseMaxRssBytes('       12345678  maximum resident set size\n', 'darwin'),
    12_345_678,
  );
  assert.equal(
    parseMaxRssBytes('Maximum resident set size (kbytes): 12345\n', 'linux'),
    12_641_280,
  );
  assert.equal(parseMaxRssBytes('no rss here', 'linux'), undefined);
  const wallMaterialityArgs = parseArgs([
    '--median-regression-ms',
    '20',
    '--p95-regression-ms',
    '50',
  ]);
  assert.equal(wallMaterialityArgs.medianRegressionMs, '20');
  assert.equal(wallMaterialityArgs.p95RegressionMs, '50');
  const pairedRows = (candidateValues, failedCandidateSample = null) =>
    candidateValues.flatMap((candidateWallMs, index) => {
      const sample = index + 1;
      const common = {
        sample,
        fixture: 'paired',
        mode: 'cold',
        manager: 'lpm',
        cell: 'current',
        route: 'direct',
        firewall_mode: 'off',
        exit_code: 0,
      };
      const baselineFirst = sample % 2 === 1;
      return [
        {
          ...common,
          binary: 'main',
          wall_ms: 100,
          pair_id: `paired:cold:${sample}`,
          pair_order: baselineFirst ? 'baseline-candidate' : 'candidate-baseline',
          execution_sequence: baselineFirst ? sample * 2 - 1 : sample * 2,
        },
        {
          ...common,
          binary: 'candidate',
          wall_ms: candidateWallMs,
          pair_id: `paired:cold:${sample}`,
          pair_order: baselineFirst ? 'baseline-candidate' : 'candidate-baseline',
          execution_sequence: baselineFirst ? sample * 2 : sample * 2 - 1,
          exit_code: failedCandidateSample === sample ? 1 : 0,
        },
      ];
    });
  const comparison = { baseline: 'main', candidate: 'candidate' };
  const thresholds = {
    wall_ms: { median_pct: 5, p95_pct: 10, median_abs: 0, p95_abs: 0 },
    max_rss_bytes: {
      median_pct: 5,
      p95_pct: 10,
      median_abs: 16 * 1024 * 1024,
      p95_abs: 32 * 1024 * 1024,
    },
  };
  assert.equal(
    summarizeLpmComparison(pairedRows([104, 104, 104, 104, 104]), comparison, thresholds, 5)
      .verdict,
    'pass',
  );
  const materialWallThresholds = {
    ...thresholds,
    wall_ms: { median_pct: 5, p95_pct: 10, median_abs: 20, p95_abs: 50 },
  };
  assert.equal(
    summarizeLpmComparison(
      pairedRows([106, 106, 106, 106, 106]),
      comparison,
      materialWallThresholds,
      5,
    ).verdict,
    'pass',
  );
  assert.equal(
    summarizeLpmComparison(
      pairedRows([125, 125, 125, 125, 125]),
      comparison,
      materialWallThresholds,
      5,
    ).verdict,
    'regression',
  );
  assert.equal(
    summarizeLpmComparison(pairedRows([120, 120, 120, 120, 120]), comparison, thresholds, 5)
      .verdict,
    'regression',
  );
  assert.equal(
    summarizeLpmComparison(pairedRows([100, 104, 106, 108, 112]), comparison, thresholds, 5)
      .verdict,
    'inconclusive',
  );
  assert.equal(
    summarizeLpmComparison(
      pairedRows([100, 100, 100, 100, 100], 3),
      comparison,
      thresholds,
      5,
    ).verdict,
    'execution-failure',
  );
  const rssRows = pairedRows([100, 100, 100, 100, 100]).map((row) => ({
    ...row,
    max_rss_bytes: row.binary === 'candidate' ? 160 * 1024 * 1024 : 100 * 1024 * 1024,
  }));
  assert.equal(
    summarizeLpmComparison(rssRows, comparison, thresholds, 5).verdict,
    'regression',
  );
  const rssNoiseRows = pairedRows([100, 100, 100, 100, 100]).map((row) => ({
    ...row,
    max_rss_bytes: row.binary === 'candidate' ? 110 * 1024 * 1024 : 100 * 1024 * 1024,
  }));
  assert.equal(
    summarizeLpmComparison(rssNoiseRows, comparison, thresholds, 5).verdict,
    'pass',
  );
  const pairedSpecs = buildLpmComparisonPairs(
    buildRunSpecs(['lpm', 'bun', 'pnpm'], binarySpecs, [{ name: 'current', env: {} }], ['direct'], ['off']),
    comparison,
  );
  assert.equal(pairedSpecs.length, 1);
  assert.equal(pairedSpecs[0].baseline.binaryName, 'main');
  assert.equal(pairedSpecs[0].candidate.binaryName, 'candidate');
  const tailSummary = summarize([
    { fixture: 'tail', spec: 'current', mode: 'cold', manager: 'lpm', exit_code: 0, wall_ms: 100 },
    { fixture: 'tail', spec: 'current', mode: 'cold', manager: 'lpm', exit_code: 0, wall_ms: 110 },
    { fixture: 'tail', spec: 'current', mode: 'cold', manager: 'lpm', exit_code: 0, wall_ms: 120 },
    { fixture: 'tail', spec: 'current', mode: 'cold', manager: 'lpm', exit_code: 0, wall_ms: 130 },
    { fixture: 'tail', spec: 'current', mode: 'cold', manager: 'lpm', exit_code: 0, wall_ms: 500 },
  ]);
  assert.equal(tailSummary[0]?.metrics.wall_ms.p95, 426);
  assert.equal(tailSummary[0]?.metrics.wall_ms.max, 500);
  assert.equal(tailSummary[0]?.metrics.wall_ms.iqr, 20);
  assert.equal(tailSummary[0]?.metrics.wall_ms.mad, 10);
  assert.equal(tailSummary[0]?.tail_warnings[0]?.metric, 'wall_ms');
  assert.match(renderSummaryMarkdown(tailSummary), /Tail latency warnings/);
  const [vitepressFixture] = parseFixtures('vitepress');
  assert.equal(
    vitepressFixture.source.kind,
    'generated',
    'the default VitePress benchmark must exercise the published package graph',
  );
  const [vitepressWorkspaceFixture] = parseFixtures('vitepress-workspace');
  assert.equal(
    vitepressWorkspaceFixture.source.kind,
    'path',
    'the checked-out VitePress workspace must remain available under an explicit fixture name',
  );
  const npmrcFixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-readiness-self-test-'));
  try {
    const sourceDir = path.join(npmrcFixtureRoot, 'source');
    const projectDir = path.join(npmrcFixtureRoot, 'project');
    fs.mkdirSync(sourceDir, { recursive: true });
    fs.writeFileSync(path.join(sourceDir, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n');
    fs.writeFileSync(path.join(sourceDir, 'fixture.npmrc'), 'shell-emulator=true\n');
    materializeFixture({ path: sourceDir }, projectDir);
    assert.equal(fs.readFileSync(path.join(projectDir, '.npmrc'), 'utf8'), 'shell-emulator=true\n');
  } finally {
    removeTree(npmrcFixtureRoot);
  }
  const cleanupFixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-readiness-cleanup-test-'));
  try {
    const memberDir = path.join(cleanupFixtureRoot, 'packages', 'member');
    fs.mkdirSync(path.join(cleanupFixtureRoot, 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(cleanupFixtureRoot, '.lpm'), { recursive: true });
    fs.mkdirSync(path.join(memberDir, 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(memberDir, '.lpm'), { recursive: true });
    fs.writeFileSync(path.join(cleanupFixtureRoot, 'lpm.lock'), 'root lock\n');
    fs.writeFileSync(path.join(memberDir, 'pnpm-lock.yaml'), 'member lock\n');
    fs.writeFileSync(path.join(memberDir, 'source.js'), 'export default 1;\n');

    cleanProjectForCold(cleanupFixtureRoot);

    assert.equal(fs.existsSync(path.join(cleanupFixtureRoot, 'node_modules')), false);
    assert.equal(fs.existsSync(path.join(cleanupFixtureRoot, '.lpm')), false);
    assert.equal(fs.existsSync(path.join(cleanupFixtureRoot, 'lpm.lock')), false);
    assert.equal(fs.existsSync(path.join(memberDir, 'node_modules')), false);
    assert.equal(fs.existsSync(path.join(memberDir, '.lpm')), false);
    assert.equal(fs.existsSync(path.join(memberDir, 'pnpm-lock.yaml')), false);
    assert.equal(fs.readFileSync(path.join(memberDir, 'source.js'), 'utf8'), 'export default 1;\n');
  } finally {
    removeTree(cleanupFixtureRoot);
  }
  const warmCleanupFixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), 'lpm-readiness-warm-cleanup-test-'),
  );
  try {
    const memberDir = path.join(warmCleanupFixtureRoot, 'packages', 'member');
    fs.mkdirSync(path.join(warmCleanupFixtureRoot, 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(warmCleanupFixtureRoot, '.lpm'), { recursive: true });
    fs.mkdirSync(path.join(memberDir, 'node_modules'), { recursive: true });
    fs.mkdirSync(path.join(memberDir, '.lpm'), { recursive: true });
    const lockfiles = [
      path.join(warmCleanupFixtureRoot, 'lpm.lock'),
      path.join(warmCleanupFixtureRoot, 'lpm.lockb'),
      path.join(warmCleanupFixtureRoot, 'package-lock.json'),
      path.join(warmCleanupFixtureRoot, 'pnpm-lock.yaml'),
      path.join(warmCleanupFixtureRoot, 'bun.lock'),
      path.join(warmCleanupFixtureRoot, 'bun.lockb'),
      path.join(warmCleanupFixtureRoot, 'yarn.lock'),
      path.join(memberDir, 'lpm.lock'),
    ];
    for (const lockfile of lockfiles) {
      fs.writeFileSync(lockfile, 'generated lockfile\n');
    }

    cleanProjectForWarm(warmCleanupFixtureRoot);

    assert.equal(fs.existsSync(path.join(warmCleanupFixtureRoot, 'node_modules')), false);
    assert.equal(fs.existsSync(path.join(warmCleanupFixtureRoot, '.lpm')), false);
    assert.equal(fs.existsSync(path.join(memberDir, 'node_modules')), false);
    assert.equal(fs.existsSync(path.join(memberDir, '.lpm')), false);
    assert.equal(
      lockfiles.every((lockfile) => fs.readFileSync(lockfile, 'utf8') === 'generated lockfile\n'),
      true,
    );
  } finally {
    removeTree(warmCleanupFixtureRoot);
  }
  assert.deepEqual(parseLpmFirewallModes('off,enabled,report'), ['off', 'enforce', 'report']);
  assert.throws(() => parseLpmFirewallModes('enabled,enforce'), /duplicate lpm firewall mode/);
  const firewallSpecs = buildRunSpecs(
    ['lpm', 'bun'],
    [{ name: 'current', path: '/tmp/lpm-current' }],
    [{ name: 'current', env: {} }],
    ['direct'],
    ['off', 'enforce'],
  );
  assert.deepEqual(
    firewallSpecs.map((spec) => [spec.id, spec.firewallMode]),
    [
      ['lpm-current', 'off'],
      ['lpm-current-firewall-enforce', 'enforce'],
      ['bun', 'default'],
    ],
  );
  const environmentCellSpecs = buildRunSpecs(
    ['lpm'],
    [{ name: 'current', path: '/tmp/lpm-current' }],
    [
      { name: 'current', env: {} },
      { name: 'cap', env: { LPM_V2_FINALIZE_PERMITS: '2' } },
    ],
    ['direct'],
    ['off'],
  );
  assert.deepEqual(environmentCellSpecs.map((spec) => spec.id), ['lpm-current', 'lpm-cap']);

  const packageNameOnly = classifyInstallWarnings({
    stdout: JSON.stringify(
      {
        dependencies: [{ name: 'process-warning' }],
        warnings: [],
      },
      null,
      2,
    ),
    parsedStdout: {
      dependencies: [{ name: 'process-warning' }],
      warnings: [],
    },
  });
  assert.equal(packageNameOnly.warning_count, 0);
  assert.equal(packageNameOnly.unexpected_warning_count, 0);

  const structuredWarning = classifyInstallWarnings({
    parsedStdout: {
      warnings: [
        {
          message: 'package "npm" declares bin "npm" which shadows a common system binary',
        },
      ],
    },
  });
  assert.equal(structuredWarning.warning_count, 1);
  assert.equal(structuredWarning.expected_warning_count, 1);
  assert.equal(structuredWarning.expected_warnings[0]?.id, 'npm-bin-shadow');

  const stderrWarning = classifyInstallWarnings({
    parsedStdout: { warnings: [] },
    stderr: ".git can't be found",
  });
  assert.equal(stderrWarning.warning_count, 1);
  assert.equal(stderrWarning.expected_warnings[0]?.id, 'husky-git-missing');

  const currentMetadataMetrics = extractLpmMetrics({
    count: 2,
    timing: {
      firewall_batch_ms: 31,
      firewall: {
        checked_count: 10,
        batch_ms: 31,
        allow_count: 7,
        warn_count: 1,
        block_count: 0,
        unknown_count: 2,
        matched_count: 1,
        rpc_failed: false,
        offline_skipped: false,
        client: {
          requestMs: 18,
          bodyReadMs: 3,
          jsonParseMs: 2,
          totalMs: 23,
          requestBodyBytes: 2 * 1024 * 1024,
          responseBodyBytes: 1024 * 1024,
        },
        worker: {
          packageCount: 10,
          lookupConcurrency: 64,
          kvReadCount: 12,
          kvLookupMs: 14,
          entitlementMs: 1,
          parseMs: 2,
          totalMs: 17,
          matchedCount: 1,
          returnedDecisionCount: 1,
          flaggedPackageIndex: {
            enabled: true,
            used: true,
            readMs: 2,
            packageKeyCount: 3,
            candidateCount: 1,
            detailReadCount: 1,
            skippedPackageLookupCount: 9,
          },
          matchSources: {
            integrity: 1,
            package: 0,
            none: 9,
          },
          lookupDuration: {
            count: 10,
            sumMs: 80,
            maxMs: 12,
            p50Ms: 7,
            p95Ms: 12,
          },
        },
      },
      resolve: {
        initial_batch_ms: 3,
        followup_rpc_ms: 13,
        followup_rpc_count: 2,
        walker_rpc_count: 1,
        escape_hatch_rpc_count: 0,
        parse_ndjson_ms: 5,
        pubgrub_ms: 17,
        platform_skipped: 4,
        dispatcher: {
          rpc_count: 6,
          configured_fanout: 32,
          inflight_high_water: 2,
          active_fetch_high_water: 2,
          pending_high_water: 7,
          semaphore_wait_count: 3,
          semaphore_wait_ms: 14.5,
          tarball_dispatched: 8,
          peer_prefetch_count: 1,
        },
        streaming_bfs: {
          walk_ms: 23,
          manifests_fetched: 11,
          cache_hits: 7,
        },
      },
      fetch_breakdown: {
        source_scan: {
          sum_ns: 12_500_000,
          max_ns: 3_750_000,
        },
      },
      detail: {
        fetch: {
          overlap: {
            selected_count: 5,
            dispatched_count: 4,
            completed_count: 3,
            cache_hit_count: 1,
            skipped_platform_count: 1,
            failed_count: 0,
            buffered_count: 2,
            buffered_dispatch_count: 1,
            buffered_undispatched_count: 1,
            buffer_wait: {
              sum_ms: 17,
              max_ms: 11,
            },
            task_sum_ms: 19,
            task_max_ms: 7,
            breakdown: {
              source_scan: {
                sum_ns: 8_500_000,
                max_ns: 4_250_000,
              },
            },
            drain_ms: 2,
          },
        },
        resolve: {
          metadata_fetch: {
            calls: 2,
            body_bytes_sum: 5 * 1024 * 1024,
            version_count_sum: 7,
            routes: {
              npm_direct: 2,
            },
            attribution: {
              raw_fetch_sum_ms: 12,
              http_sum_ms: 11,
              body_read_sum_ms: 3,
              json_decode_sum_ms: 1,
              cache_info_parse_sum_ms: 1,
              policy_release_time_sum_ms: 0,
              policy_release_time_fetch: {
                total_sum_ms: 9,
                http_sum_ms: 8,
                body_read_sum_ms: 7,
                json_decode_sum_ms: 6,
                body_bytes_sum: 2 * 1024 * 1024,
                version_count_sum: 5,
                cache_hit_count: 1,
                not_modified_count: 0,
              },
              policy_full_metadata_sum_ms: 0,
            },
          },
        },
      },
    },
  });
  assert.equal(currentMetadataMetrics.metadata_calls, 2);
  assert.equal(currentMetadataMetrics.metadata_body_mb_sum, 5);
  assert.equal(currentMetadataMetrics.metadata_version_count_sum, 7);
  assert.equal(currentMetadataMetrics.metadata_http_sum_ms, 11);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_sum_ms, 9);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_http_sum_ms, 8);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_body_read_sum_ms, 7);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_json_decode_sum_ms, 6);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_body_mb_sum, 2);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_version_count_sum, 5);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_cache_hit_count, 1);
  assert.equal(currentMetadataMetrics.metadata_policy_release_time_fetch_not_modified_count, 0);
  assert.equal(currentMetadataMetrics.metadata_route_npm_direct, 2);
  assert.equal(currentMetadataMetrics.resolve_initial_batch_ms, 3);
  assert.equal(currentMetadataMetrics.resolve_followup_rpc_ms, 13);
  assert.equal(currentMetadataMetrics.resolve_followup_rpc_count, 2);
  assert.equal(currentMetadataMetrics.resolve_walker_rpc_count, 1);
  assert.equal(currentMetadataMetrics.resolve_escape_hatch_rpc_count, 0);
  assert.equal(currentMetadataMetrics.resolve_parse_ndjson_ms, 5);
  assert.equal(currentMetadataMetrics.resolve_pubgrub_ms, 17);
  assert.equal(currentMetadataMetrics.resolve_platform_skipped_count, 4);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_rpc_count, 6);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_configured_fanout, 32);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_inflight_high_water, 2);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_active_fetch_high_water, 2);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_pending_high_water, 7);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_semaphore_wait_count, 3);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_semaphore_wait_ms, 14.5);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_tarball_dispatched_count, 8);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_peer_prefetch_count, 1);
  assert.equal(currentMetadataMetrics.resolve_streaming_bfs_walk_ms, 23);
  assert.equal(currentMetadataMetrics.resolve_streaming_bfs_manifests_fetched, 11);
  assert.equal(currentMetadataMetrics.resolve_streaming_bfs_cache_hits, 7);
  assert.equal(
    currentMetadataMetrics.fetch_source_scan_sum_ns,
    21_000_000,
    'source scan sum must include authoritative and overlap fetch tasks',
  );
  assert.equal(
    currentMetadataMetrics.fetch_source_scan_max_ns,
    4_250_000,
    'source scan max must include authoritative and overlap fetch tasks',
  );
  assert.equal(currentMetadataMetrics.fetch_source_scan_sum_ms, 21);
  assert.equal(currentMetadataMetrics.firewall_batch_ms, 31);
  assert.equal(currentMetadataMetrics.firewall_checked_count, 10);
  assert.equal(currentMetadataMetrics.firewall_warn_count, 1);
  assert.equal(currentMetadataMetrics.firewall_block_count, 0);
  assert.equal(currentMetadataMetrics.firewall_unknown_count, 2);
  assert.equal(currentMetadataMetrics.firewall_rpc_failed_count, 0);
  assert.equal(currentMetadataMetrics.firewall_worker_package_count, 10);
  assert.equal(currentMetadataMetrics.firewall_worker_lookup_concurrency, 64);
  assert.equal(currentMetadataMetrics.firewall_worker_kv_read_count, 12);
  assert.equal(currentMetadataMetrics.firewall_worker_kv_lookup_ms, 14);
  assert.equal(currentMetadataMetrics.firewall_worker_entitlement_ms, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_parse_ms, 2);
  assert.equal(currentMetadataMetrics.firewall_worker_total_ms, 17);
  assert.equal(currentMetadataMetrics.firewall_worker_matched_count, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_returned_decision_count, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_flagged_index_enabled, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_flagged_index_used, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_flagged_index_read_ms, 2);
  assert.equal(currentMetadataMetrics.firewall_worker_flagged_index_package_key_count, 3);
  assert.equal(currentMetadataMetrics.firewall_worker_flagged_index_candidate_count, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_flagged_index_detail_read_count, 1);
  assert.equal(
    currentMetadataMetrics.firewall_worker_flagged_index_skipped_package_lookup_count,
    9,
  );
  assert.equal(currentMetadataMetrics.firewall_worker_match_integrity_count, 1);
  assert.equal(currentMetadataMetrics.firewall_worker_match_none_count, 9);
  assert.equal(currentMetadataMetrics.firewall_worker_lookup_duration_p95_ms, 12);
  assert.equal(currentMetadataMetrics.firewall_client_request_ms, 18);
  assert.equal(currentMetadataMetrics.firewall_client_body_read_ms, 3);
  assert.equal(currentMetadataMetrics.firewall_client_json_parse_ms, 2);
  assert.equal(currentMetadataMetrics.firewall_client_total_ms, 23);
  assert.equal(currentMetadataMetrics.firewall_client_request_body_mb, 2);
  assert.equal(currentMetadataMetrics.firewall_client_response_body_mb, 1);
  assert.equal(currentMetadataMetrics.fetch_overlap_selected_count, 5);
  assert.equal(currentMetadataMetrics.fetch_overlap_buffered_count, 2);
  assert.equal(currentMetadataMetrics.fetch_overlap_buffered_dispatch_count, 1);
  assert.equal(currentMetadataMetrics.fetch_overlap_buffered_undispatched_count, 1);
  assert.equal(currentMetadataMetrics.fetch_overlap_buffer_wait_sum_ms, 17);
  assert.equal(currentMetadataMetrics.fetch_overlap_buffer_wait_max_ms, 11);
  assert.equal(currentMetadataMetrics.fetch_overlap_task_sum_ms, 19);
  assert.equal(currentMetadataMetrics.fetch_overlap_drain_ms, 2);

  const overlapOnlySourceScanMetrics = extractLpmMetrics({
    timing: {
      fetch_breakdown: {
        source_scan: {
          sum_ns: 0,
          max_ns: 0,
        },
      },
      detail: {
        fetch: {
          overlap: {
            breakdown: {
              source_scan: {
                sum_ns: 9_000_000,
                max_ns: 7_000_000,
              },
            },
          },
        },
      },
    },
  });
  assert.equal(overlapOnlySourceScanMetrics.fetch_source_scan_sum_ns, 9_000_000);
  assert.equal(overlapOnlySourceScanMetrics.fetch_source_scan_max_ns, 7_000_000);
  assert.equal(overlapOnlySourceScanMetrics.fetch_source_scan_sum_ms, 9);

  const experimentalMetadataMetrics = extractLpmMetrics({
    timing: {
      experimental_installer_spike: {
        metadata: {
          calls: 3,
          attribution: {
            body_bytes_sum: 1024 * 1024,
            version_count_sum: 9,
            http_sum_ms: 4,
            routes: {
              npm_direct_version_doc: 2,
            },
            version_docs: {
              attempts: 3,
              hits: 2,
              fallbacks: 1,
            },
          },
        },
      },
    },
  });
  assert.equal(experimentalMetadataMetrics.metadata_calls, 3);
  assert.equal(experimentalMetadataMetrics.metadata_body_mb_sum, 1);
  assert.equal(experimentalMetadataMetrics.metadata_version_doc_attempts, 3);
  assert.equal(experimentalMetadataMetrics.metadata_version_doc_hits, 2);
  assert.equal(experimentalMetadataMetrics.metadata_version_doc_fallbacks, 1);
  assert.equal(experimentalMetadataMetrics.metadata_route_npm_direct_version_doc, 2);

  console.log('run-install-readiness self-test passed');
}

function stripAnsi(value) {
  return value.replace(/\x1B\[[0-?]*[ -/]*[@-~]/g, '');
}

function metricDistribution(rows, key) {
  const values = rows
    .map((row) => row[key])
    .filter((value) => typeof value === 'number' && Number.isFinite(value))
    .sort((a, b) => a - b);
  if (values.length === 0) {
    return null;
  }
  const median = percentile(values, 0.5);
  const deviations = values.map((value) => Math.abs(value - median)).sort((a, b) => a - b);
  const q1 = percentile(values, 0.25);
  const q3 = percentile(values, 0.75);
  return {
    samples: values.length,
    median,
    min: values[0],
    p95: percentile(values, 0.95),
    max: values[values.length - 1],
    iqr: roundDistributionValue(q3 - q1),
    mad: percentile(deviations, 0.5),
  };
}

function percentile(sortedValues, probability) {
  const position = (sortedValues.length - 1) * probability;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) {
    return sortedValues[lower];
  }
  const weight = position - lower;
  return roundDistributionValue(
    sortedValues[lower] + (sortedValues[upper] - sortedValues[lower]) * weight,
  );
}

function roundDistributionValue(value) {
  return Number(value.toFixed(6));
}

function runFailed(row) {
  return (
    row.exit_code !== 0 ||
    Boolean(row.parse_error) ||
    Boolean(row.rss_parse_error) ||
    Boolean(row.skipped)
  );
}

function stat(value) {
  return value ? `${value.median}/${value.min}` : 'n/a';
}

function tailStat(value) {
  return value ? `${value.median}/${value.p95}/${value.max}` : 'n/a';
}

function tailBytesMiB(value) {
  return value
    ? [value.median, value.p95, value.max]
        .map((bytes) => roundDistributionValue(bytes / 1024 / 1024))
        .join('/')
    : 'n/a';
}

function formatMs(value) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value}ms` : 'n/a';
}

function formatBytes(value) {
  return typeof value === 'number' && Number.isFinite(value)
    ? `${roundDistributionValue(value / 1024 / 1024)} MiB`
    : 'n/a';
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
      --top-npm-file PATH      Use package list as one-root-per-package fixtures
      --top-npm-offset N       Zero-based package offset for chunked top-N sweeps
      --top-npm-limit N        Maximum packages from --top-npm-file
      --managers LIST          lpm,bun,pnpm,npm (default: lpm)
      --modes LIST             cold,warm,up-to-date (default: cold)
      --lpm-routes LIST        direct,proxy for lpm runs (default: direct)
      --lpm-firewall-modes LIST
                               off,report,enforce for lpm runs (default: off)
      --lpm-cell NAME:ENV      Add an lpm env cell. Repeatable.
                               Example: --lpm-cell cap:LPM_V2_FINALIZE_PERMITS=2
      --lpm-binary NAME=PATH   Add an lpm binary. Repeatable.
      --lpm-compare BASE:CAND  Compare two named lpm binaries.
      --median-regression-pct N
                               Median wall-time limit (default: 5).
      --p95-regression-pct N   p95 wall-time limit (default: 10).
      --median-regression-ms N Median wall-time absolute limit (default: 20).
      --p95-regression-ms N    p95 wall-time absolute limit (default: 50).
      --rss-median-regression-pct N
                               Median peak-RSS percentage limit (default: 5).
      --rss-p95-regression-pct N
                               p95 peak-RSS percentage limit (default: 10).
      --rss-median-regression-mb N
                               Median peak-RSS absolute limit in MiB (default: 16).
      --rss-p95-regression-mb N
                               p95 peak-RSS absolute limit in MiB (default: 32).
      --lpm-typosquat-guard MODE
                               default or off. Defaults to off for --top-npm-file.
      --script-policy MODE     ignore or default for bun/pnpm/npm scripts (default: ignore)
      --timeout-ms N           Per-install timeout in milliseconds (default: 600000)
      --lpm-bin PATH           lpm binary path (default: target/release/lpm-rs)
      --output DIR             Result directory (default: /tmp/lpm-install-readiness-*)
      --keep-projects          Keep temp projects
      --keep-failed-projects   Keep temp projects for failed runs
      --allow-failures         Exit 0 even if a run fails
      --allow-inconclusive     Exit 0 when the paired verdict is inconclusive
      --dry-run                Print the plan without running installs
  -h, --help                   Show this help

Examples:
  # Current lpm cold/warm/up-to-date reference.
  node bench/scripts/run-install-readiness.mjs --samples 10 --modes cold,warm,up-to-date

  # One-off firewall-enabled reference without fail-closed auth.
  node bench/scripts/run-install-readiness.mjs --samples 1 --lpm-firewall-modes off,report

  # Fail-closed firewall gate reference when LPM auth is available.
  node bench/scripts/run-install-readiness.mjs --samples 1 --lpm-firewall-modes off,enforce

  # Apples-to-apples reference snapshot.
  node bench/scripts/run-install-readiness.mjs --samples 5 --managers lpm,bun,pnpm,npm

  # Compare two release binaries in one interleaved run.
  node bench/scripts/run-install-readiness.mjs \
    --samples 10 \
    --lpm-binary main=/tmp/lpm-main \
    --lpm-binary candidate=/tmp/lpm-candidate \
    --lpm-compare main:candidate

  # Compare one lpm candidate knob against current lpm.
  node bench/scripts/run-install-readiness.mjs \\
    --samples 10 \\
    --lpm-cell current \\
    --lpm-cell cap:LPM_V2_FINALIZE_PERMITS=2

  # Compare exact-version-doc metadata path.
  node bench/scripts/run-install-readiness.mjs \\
    --samples 5 \\
    --lpm-cell current \\
    --lpm-cell exact-doc:LPM_EXPERIMENTAL_INSTALLER_SPIKE=1,LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1,LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist,LPM_INSTALLER_SPIKE_PARITY=deny,LPM_INSTALLER_SPIKE_EXACT_DOC=1

  # Top-N package sweep, 25 roots at a time.
  node bench/scripts/run-install-readiness.mjs \\
    --samples 1 \\
    --top-npm-file bench/top-npm-audit/top-100.txt \\
    --top-npm-offset 0 \\
    --top-npm-limit 25 \\
    --managers lpm \\
    --lpm-cell current \\
    --lpm-cell exact-doc:LPM_EXPERIMENTAL_INSTALLER_SPIKE=1,LPM_INSTALLER_SPIKE_BENCHMARK_ONLY=1,LPM_INSTALLER_SPIKE_GRAPH=resolve-worklist,LPM_INSTALLER_SPIKE_PARITY=deny,LPM_INSTALLER_SPIKE_EXACT_DOC=1 \\
    --allow-failures
`);
}
