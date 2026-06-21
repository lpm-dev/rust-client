#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const repoRoot = path.resolve(new URL('../..', import.meta.url).pathname);
const runs = positiveInt(process.env.RUNS, 5);
const lpmBin = path.resolve(process.env.LPM_BIN || path.join(repoRoot, 'target/release/lpm-rs'));
const resultsDir = path.resolve(
  process.env.RESULTS_DIR ||
    path.join(os.tmpdir(), `lpm-install-attribution-${Date.now()}`),
);
const summaryOnly = truthy(process.env.LPM_ATTRIBUTION_SUMMARY_ONLY);
const keepProjects = truthy(process.env.KEEP_PROJECTS);
const keepFailedProjects = truthy(process.env.KEEP_FAILED_PROJECTS);

if (summaryOnly) {
  if (!fs.existsSync(resultsDir)) {
    throw new Error(`results directory missing: ${resultsDir}`);
  }
  const summary = summarize(readExistingMetrics(resultsDir));
  writeSummary(resultsDir, summary);
  process.exit(0);
}

const installEnvOverrides = parseEnvAssignments(process.env.LPM_ATTRIBUTION_INSTALL_ENV || '');
const npmRoute = process.env.LPM_ATTRIBUTION_NPM_ROUTE || 'direct';

const fixtures = configuredFixtures().filter((fixture) => {
  if (fs.existsSync(fixture.dir)) {
    return true;
  }
  console.error(`[skip] fixture missing: ${fixture.name} (${fixture.dir})`);
  return false;
});

if (!fs.existsSync(lpmBin)) {
  throw new Error(`lpm binary missing: ${lpmBin}`);
}
if (fixtures.length === 0) {
  throw new Error('no fixtures found');
}

fs.mkdirSync(resultsDir, { recursive: true });

const metricsByFixture = new Map();
for (const fixture of fixtures) {
  const rows = [];
  metricsByFixture.set(fixture.name, rows);
  for (let sample = 1; sample <= runs; sample += 1) {
    const sampleDir = path.join(resultsDir, fixture.name, `sample-${sample}`);
    fs.mkdirSync(sampleDir, { recursive: true });
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), `lpm-${fixture.name}-${sample}-`));
    const projectDir = path.join(workDir, 'project');
    const lpmHome = path.join(workDir, 'lpm-home');
    const homeDir = path.join(workDir, 'home');
    fs.mkdirSync(homeDir, { recursive: true });
    fs.cpSync(fixture.dir, projectDir, { recursive: true });
    cleanProject(projectDir);
    const installEnv = benchmarkEnv(lpmHome, homeDir);
    fs.writeFileSync(
      path.join(sampleDir, 'effective-env.json'),
      `${JSON.stringify(redactedEnv(installEnv), null, 2)}\n`,
    );

    const started = process.hrtime.bigint();
    const result = spawnSync(
      lpmBin,
      [
        '--json',
        'install',
        '--no-security-summary',
        '--no-skills',
        '--no-editor-setup',
      ],
      {
        cwd: projectDir,
        encoding: 'utf8',
        env: installEnv,
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    const ended = process.hrtime.bigint();
    const wallMs = Number((ended - started) / 1_000_000n);

    fs.writeFileSync(path.join(sampleDir, 'stdout.json'), result.stdout || '');
    fs.writeFileSync(path.join(sampleDir, 'stderr.log'), result.stderr || '');
    if (result.error) {
      fs.writeFileSync(
        path.join(sampleDir, 'spawn-error.txt'),
        `${result.error.stack || result.error}\n`,
      );
    }

    let json = null;
    try {
      json = JSON.parse(result.stdout);
    } catch (error) {
      fs.writeFileSync(path.join(sampleDir, 'parse-error.txt'), `${error}\n`);
    }

    const metrics = extractMetrics(json, wallMs, result.status ?? 1);
    rows.push(metrics);
    fs.writeFileSync(
      path.join(sampleDir, 'metrics.json'),
      `${JSON.stringify(metrics, null, 2)}\n`,
    );

    const status = metrics.exit_code === 0 ? 'ok' : `exit=${metrics.exit_code}`;
    console.log(
      `[${fixture.name}] sample ${sample}/${runs}: ${status} wall=${wallMs}ms duration=${metrics.duration_ms ?? 'n/a'}ms`,
    );

    if (!keepProjects && !(keepFailedProjects && metrics.exit_code !== 0)) {
      removeTree(workDir, { required: false });
    } else {
      fs.writeFileSync(path.join(sampleDir, 'project-dir.txt'), `${projectDir}\n`);
    }
  }
}

const summary = summarize(metricsByFixture);
writeSummary(resultsDir, summary);

function configuredFixtures() {
  const raw = process.env.LPM_ATTRIBUTION_FIXTURES;
  if (raw) {
    return raw
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const [name, fixturePath] = entry.includes('=')
          ? entry.split(/=(.*)/s, 2)
          : [path.basename(entry), entry];
        return { name, dir: path.resolve(repoRoot, fixturePath) };
      });
  }
  return [
    {
      name: 'dogfood',
      dir: path.join(repoRoot, 'bench/audit-fixtures/dogfood/realworld-app'),
    },
    {
      name: 'nest',
      dir: path.join(repoRoot, 'bench/audit-fixtures/peer-heavy/nestjs-deep'),
    },
    {
      name: 'vitepress',
      dir: path.join(repoRoot, 'bench/realworld-audit/.cache/vitepress-docs'),
    },
  ];
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

function removeTree(target, options = {}) {
  const required = options.required ?? true;
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
  if (required) {
    throw lastError;
  }
  console.warn(`[warn] could not remove temp directory: ${target}: ${lastError}`);
  return false;
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function benchmarkEnv(lpmHome, homeDir) {
  const env = {};
  for (const key of [
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
  ]) {
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
  env.LPM_HOME = lpmHome;
  env.LPM_STORE_VERSION = 'v2';
  env.LPM_TIMING_DETAIL = 'trace';
  env.LPM_NPM_ROUTE = npmRoute;
  return { ...env, ...installEnvOverrides };
}

function parseEnvAssignments(raw) {
  const assignments = {};
  for (const entry of raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)) {
    const equals = entry.indexOf('=');
    if (equals <= 0) {
      throw new Error(`invalid LPM_ATTRIBUTION_INSTALL_ENV entry: ${entry}`);
    }
    const key = entry.slice(0, equals).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`invalid environment variable name: ${key}`);
    }
    assignments[key] = entry.slice(equals + 1);
  }
  return assignments;
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
    return redactUrlCredentials(value);
  }
  return value;
}

function redactUrlCredentials(value) {
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

function extractMetrics(json, wallMs, exitCode) {
  const metadataAttribution = [
    'timing',
    'detail',
    'resolve',
    'metadata_fetch',
    'attribution',
  ];
  const fetchBreakdown = ['timing', 'fetch_breakdown'];
  const overlapBreakdown = ['timing', 'detail', 'fetch', 'overlap', 'breakdown'];
  const fetchStage = ['timing', 'detail', 'fetch', 'stage'];

  return {
    exit_code: exitCode,
    wall_ms: wallMs,
    duration_ms: numberAt(json, ['duration_ms']),
    resolve_ms: numberAt(json, ['timing', 'resolve_ms']),
    fetch_ms: numberAt(json, ['timing', 'fetch_ms']),
    link_ms: numberAt(json, ['timing', 'link_ms']),
    metadata_total_sum_ms: numberAt(json, [...metadataAttribution, 'total_sum_ms']),
    metadata_raw_fetch_sum_ms: numberAt(json, [...metadataAttribution, 'raw_fetch_sum_ms']),
    metadata_http_sum_ms: numberAt(json, [...metadataAttribution, 'http_sum_ms']),
    metadata_body_read_sum_ms: numberAt(json, [...metadataAttribution, 'body_read_sum_ms']),
    metadata_json_decode_sum_ms: numberAt(json, [
      ...metadataAttribution,
      'json_decode_sum_ms',
    ]),
    metadata_cache_info_parse_sum_ms: numberAt(json, [
      ...metadataAttribution,
      'cache_info_parse_sum_ms',
    ]),
    metadata_policy_release_time_sum_ms: numberAt(json, [
      ...metadataAttribution,
      'policy_release_time_sum_ms',
    ]),
    metadata_policy_full_sum_ms: numberAt(json, [
      ...metadataAttribution,
      'policy_full_metadata_sum_ms',
    ]),
    metadata_body_bytes_sum: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'metadata_fetch',
      'body_bytes_sum',
    ]),
    metadata_version_count_sum: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'metadata_fetch',
      'version_count_sum',
    ]),
    metadata_calls: numberAt(json, ['timing', 'detail', 'resolve', 'metadata_fetch', 'calls']),
    metadata_cache_hits: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'metadata_fetch',
      'cache_hit_count',
    ]),
    edge_process_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'edge_process_count',
    ]),
    edge_reuse_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'edge_reuse_count',
    ]),
    edge_reuse_range_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'edge_reuse_range_count',
    ]),
    edge_reuse_exact_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'edge_reuse_exact_count',
    ]),
    edge_non_reuse_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'edge_non_reuse_count',
    ]),
    node_allocated_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'node_allocated_count',
    ]),
    child_edge_enqueued_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'child_edge_enqueued_count',
    ]),
    peer_requirement_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'peer_requirement_count',
    ]),
    selected_package_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'selected_package_count',
    ]),
    selected_unique_canonical_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'selected_unique_canonical_count',
    ]),
    selected_duplicate_canonical_count: numberAt(json, [
      'timing',
      'detail',
      'resolve',
      'work',
      'selected_duplicate_canonical_count',
    ]),
    fetch_stage_wall_ms: numberAt(json, [...fetchStage, 'wall_ms']),
    fetch_stage_download_wall_ms: numberAt(json, [...fetchStage, 'download_wall_ms']),
    fetch_stage_plan_ms: numberAt(json, [...fetchStage, 'plan_ms']),
    fetch_stage_v2_reusable_prevalidate_ms: numberAt(json, [
      ...fetchStage,
      'v2_reusable_prevalidate_ms',
    ]),
    fetch_task_sum_ms: numberAt(json, [...fetchBreakdown, 'task_sum_ms']),
    fetch_task_max_ms: numberAt(json, [...fetchBreakdown, 'task_max_ms']),
    fetch_queue_wait_sum_ms: breakdownStat(json, fetchBreakdown, 'queue_wait', 'sum_ms'),
    fetch_queue_wait_max_ms: breakdownStat(json, fetchBreakdown, 'queue_wait', 'max_ms'),
    fetch_extract_sum_ms: breakdownStat(json, fetchBreakdown, 'extract', 'sum_ms'),
    fetch_finalize_sum_ms: breakdownStat(json, fetchBreakdown, 'finalize', 'sum_ms'),
    overlap_task_count: numberAt(json, [...overlapBreakdown, 'task_count']),
    overlap_task_sum_ms: numberAt(json, [...overlapBreakdown, 'task_sum_ms']),
    overlap_task_max_ms: numberAt(json, [...overlapBreakdown, 'task_max_ms']),
    overlap_queue_wait_sum_ms: breakdownStat(json, overlapBreakdown, 'queue_wait', 'sum_ms'),
    overlap_queue_wait_max_ms: breakdownStat(json, overlapBreakdown, 'queue_wait', 'max_ms'),
    overlap_download_sum_ms: breakdownStat(json, overlapBreakdown, 'download', 'sum_ms'),
    overlap_download_max_ms: breakdownStat(json, overlapBreakdown, 'download', 'max_ms'),
    overlap_integrity_sum_ms: breakdownStat(json, overlapBreakdown, 'integrity', 'sum_ms'),
    overlap_extract_permit_wait_sum_ms: breakdownStat(
      json,
      overlapBreakdown,
      'extract_permit_wait',
      'sum_ms',
    ),
    overlap_extract_permit_wait_max_ms: breakdownStat(
      json,
      overlapBreakdown,
      'extract_permit_wait',
      'max_ms',
    ),
    overlap_extract_sum_ms: breakdownStat(json, overlapBreakdown, 'extract', 'sum_ms'),
    overlap_extract_max_ms: breakdownStat(json, overlapBreakdown, 'extract', 'max_ms'),
    overlap_security_sum_ms: breakdownStat(json, overlapBreakdown, 'security', 'sum_ms'),
    overlap_security_max_ms: breakdownStat(json, overlapBreakdown, 'security', 'max_ms'),
    overlap_finalize_permit_wait_sum_ms: breakdownStat(
      json,
      overlapBreakdown,
      'finalize_permit_wait',
      'sum_ms',
    ),
    overlap_finalize_permit_wait_max_ms: breakdownStat(
      json,
      overlapBreakdown,
      'finalize_permit_wait',
      'max_ms',
    ),
    overlap_finalize_sum_ms: breakdownStat(json, overlapBreakdown, 'finalize', 'sum_ms'),
    overlap_finalize_max_ms: breakdownStat(json, overlapBreakdown, 'finalize', 'max_ms'),
    v2_link_task_sum_ms: numberAt(json, [
      'timing',
      'detail',
      'link',
      'v2_one',
      'task_sum_ms',
    ]),
    v2_link_task_max_ms: numberAt(json, [
      'timing',
      'detail',
      'link',
      'v2_one',
      'task_max_ms',
    ]),
  };
}

function readExistingMetrics(rootDir) {
  const metricsByFixture = new Map();
  for (const fixtureEntry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (!fixtureEntry.isDirectory()) {
      continue;
    }
    const fixtureDir = path.join(rootDir, fixtureEntry.name);
    const rows = [];
    for (const sampleEntry of fs.readdirSync(fixtureDir, { withFileTypes: true })) {
      if (!sampleEntry.isDirectory()) {
        continue;
      }
      const sampleDir = path.join(fixtureDir, sampleEntry.name);
      const stdoutPath = path.join(sampleDir, 'stdout.json');
      const metricsPath = path.join(sampleDir, 'metrics.json');
      if (!fs.existsSync(stdoutPath) || !fs.existsSync(metricsPath)) {
        continue;
      }
      const previousMetrics = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));
      const json = JSON.parse(fs.readFileSync(stdoutPath, 'utf8'));
      rows.push(extractMetrics(json, previousMetrics.wall_ms, previousMetrics.exit_code));
    }
    if (rows.length > 0) {
      metricsByFixture.set(fixtureEntry.name, rows);
    }
  }
  return metricsByFixture;
}

function summarize(metricsByFixture) {
  const out = {};
  for (const [fixture, rows] of metricsByFixture) {
    const successful = rows.filter((row) => row.exit_code === 0);
    out[fixture] = {
      samples: rows.length,
      successful_samples: successful.length,
      metrics: Object.fromEntries(
        metricKeys(successful).map((key) => [key, medianMin(successful, key)]),
      ),
    };
  }
  return out;
}

function metricKeys(rows) {
  const keys = new Set();
  for (const row of rows) {
    for (const [key, value] of Object.entries(row)) {
      if (key !== 'exit_code' && typeof value === 'number' && Number.isFinite(value)) {
        keys.add(key);
      }
    }
  }
  return [...keys].sort();
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
    median: values[Math.floor(values.length / 2)],
    min: values[0],
  };
}

function summaryMarkdown(summary) {
  const priority = [
    'wall_ms',
    'duration_ms',
    'resolve_ms',
    'fetch_ms',
    'link_ms',
    'metadata_total_sum_ms',
    'metadata_raw_fetch_sum_ms',
    'metadata_http_sum_ms',
    'metadata_body_read_sum_ms',
    'metadata_json_decode_sum_ms',
    'metadata_cache_info_parse_sum_ms',
    'metadata_policy_release_time_sum_ms',
    'metadata_body_bytes_sum',
    'metadata_version_count_sum',
    'metadata_calls',
    'edge_process_count',
    'edge_reuse_count',
    'edge_reuse_range_count',
    'edge_reuse_exact_count',
    'edge_non_reuse_count',
    'node_allocated_count',
    'child_edge_enqueued_count',
    'peer_requirement_count',
    'selected_package_count',
    'selected_unique_canonical_count',
    'selected_duplicate_canonical_count',
    'fetch_stage_wall_ms',
    'fetch_stage_download_wall_ms',
    'fetch_task_sum_ms',
    'fetch_queue_wait_sum_ms',
    'fetch_extract_sum_ms',
    'fetch_finalize_sum_ms',
    'overlap_task_count',
    'overlap_task_sum_ms',
    'overlap_task_max_ms',
    'overlap_queue_wait_sum_ms',
    'overlap_queue_wait_max_ms',
    'overlap_download_sum_ms',
    'overlap_extract_permit_wait_sum_ms',
    'overlap_extract_sum_ms',
    'overlap_extract_max_ms',
    'overlap_security_sum_ms',
    'overlap_finalize_permit_wait_sum_ms',
    'overlap_finalize_sum_ms',
    'overlap_finalize_max_ms',
    'v2_link_task_sum_ms',
  ];
  const lines = [
    '| Fixture | Samples | Metric | Median | Min |',
    '| --- | ---: | --- | ---: | ---: |',
  ];
  for (const [fixture, data] of Object.entries(summary)) {
    for (const key of priority) {
      const stat = data.metrics[key];
      if (!stat) {
        continue;
      }
      lines.push(
        `| ${fixture} | ${data.successful_samples}/${data.samples} | ${key} | ${stat.median} | ${stat.min} |`,
      );
    }
  }
  return lines.join('\n');
}

function writeSummary(dir, summary) {
  fs.writeFileSync(path.join(dir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, 'summary.md'), `${summaryMarkdown(summary)}\n`);
  console.log(`\n[summary] ${dir}`);
  console.log(summaryMarkdown(summary));
}

function numberAt(value, pathParts) {
  let current = value;
  for (const part of pathParts) {
    if (current == null || typeof current !== 'object' || !(part in current)) {
      return undefined;
    }
    current = current[part];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : undefined;
}

function breakdownStat(value, pathParts, bucket, stat) {
  return numberAt(value, [...pathParts, bucket, stat]);
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value || '', 10);
  return parsed > 0 ? parsed : fallback;
}

function truthy(value) {
  return /^(1|true|yes|on)$/i.test(value || '');
}
