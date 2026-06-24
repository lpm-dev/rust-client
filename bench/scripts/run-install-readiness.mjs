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
const lpmCells = parseLpmCells(args.lpmCells);
const lpmTyposquatGuard = args.lpmTyposquatGuard ?? (topNpmFile ? 'off' : 'default');
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
validateLpmTyposquatGuard(lpmTyposquatGuard);

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
const warningSummary = summarizeWarnings(rows);
fs.writeFileSync(path.join(outputDir, 'rows.json'), `${JSON.stringify(rows, null, 2)}\n`);
fs.writeFileSync(path.join(outputDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
fs.writeFileSync(path.join(outputDir, 'summary.md'), `${summaryMd}\n`);
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
  const { metadata, attribution: metadataAttribution, routes: metadataRoutes, versionDocs } =
    lpmMetadataMetrics(json);
  const fetchBreakdown = at(json, ['timing', 'fetch_breakdown']);
  const fetchOverlap = at(json, ['timing', 'detail', 'fetch', 'overlap']);
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
    resolve_dispatcher_inflight_high_water: finiteNumber(resolveDispatcher?.inflight_high_water),
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
    fetch_finalize_sum_ms: breakdownStat(fetchBreakdown, 'finalize', 'sum_ms'),
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
    if (lpmTyposquatGuard === 'off') {
      env.LPM_TYPOSQUAT_GUARD = '0';
    }
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
    'resolve_dispatcher_inflight_high_water',
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
    'fetch_finalize_sum_ms',
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
      .map((key) => [key, medianMin(rows, key)])
      .filter(([, value]) => value != null),
  );
}

function renderSummaryMarkdown(summary) {
  const lines = [
    '| Fixture | Spec | Mode | OK | Wall med/min | Resolve med/min | Firewall med/min | FW chunks | FW chunk sum | FW chunk max | Fetch med/min | Link med/min | Pkgs | FW checked | FW warn/block/unknown | Metadata MB | Version docs | Parity mismatches | Warnings exp/unknown |',
    '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
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
      `| ${row.fixture} | ${row.spec} | ${row.mode} | ${row.successful_samples}/${row.samples} | ${stat(m.wall_ms)} | ${stat(m.resolve_ms)} | ${stat(m.firewall_batch_ms)} | ${one(m.firewall_chunk_count)} | ${stat(m.firewall_chunk_sum_ms)} | ${stat(m.firewall_chunk_max_ms)} | ${stat(m.fetch_ms)} | ${stat(m.link_ms)} | ${one(m.package_count)} | ${one(m.firewall_checked_count)} | ${firewallVerdicts} | ${stat(m.metadata_body_mb_sum)} | ${versionDocs} | ${mismatches} | ${warnings} |`,
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
      ['--lpm-typosquat-guard', 'lpmTyposquatGuard'],
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
          inflight_high_water: 2,
          tarball_dispatched: 8,
          peer_prefetch_count: 1,
        },
        streaming_bfs: {
          walk_ms: 23,
          manifests_fetched: 11,
          cache_hits: 7,
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
  assert.equal(currentMetadataMetrics.resolve_dispatcher_inflight_high_water, 2);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_tarball_dispatched_count, 8);
  assert.equal(currentMetadataMetrics.resolve_dispatcher_peer_prefetch_count, 1);
  assert.equal(currentMetadataMetrics.resolve_streaming_bfs_walk_ms, 23);
  assert.equal(currentMetadataMetrics.resolve_streaming_bfs_manifests_fetched, 11);
  assert.equal(currentMetadataMetrics.resolve_streaming_bfs_cache_hits, 7);
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
      --top-npm-file PATH      Use package list as one-root-per-package fixtures
      --top-npm-offset N       Zero-based package offset for chunked top-N sweeps
      --top-npm-limit N        Maximum packages from --top-npm-file
      --managers LIST          lpm,bun,pnpm,npm (default: lpm)
      --modes LIST             cold,warm (default: cold)
      --lpm-routes LIST        direct,proxy for lpm runs (default: direct)
      --lpm-cell NAME:ENV      Add an lpm env cell. Repeatable.
                               Example: --lpm-cell cap:LPM_V2_FINALIZE_PERMITS=2
      --lpm-typosquat-guard MODE
                               default or off. Defaults to off for --top-npm-file.
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
