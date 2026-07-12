#!/usr/bin/env node

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const options = parseArgs(process.argv.slice(2));
const samples = Number(options.samples ?? 10);
const fixture = path.resolve(
  repoRoot,
  options.fixture ?? 'bench/audit-fixtures/native/esbuild-prebuilt',
);
const lpmBin = path.resolve(options['lpm-bin'] ?? path.join(repoRoot, 'target/release/lpm-rs'));
const timestamp = new Date().toISOString().replaceAll(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
const outputDir = path.resolve(
  options.output ?? path.join(repoRoot, 'bench/perf-results', `native-build-cache-${timestamp}`),
);

if (!Number.isInteger(samples) || samples < 2) {
  throw new Error('--samples must be an integer >= 2');
}
for (const required of [lpmBin, path.join(fixture, 'package.json')]) {
  if (!fs.existsSync(required)) throw new Error(`missing required path: ${required}`);
}

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'lpm-native-build-cache-bench-'));
const home = path.join(tempRoot, 'home');
const lpmHome = path.join(tempRoot, 'lpm-home');
const primary = path.join(tempRoot, 'primary');
fs.mkdirSync(home, { recursive: true });
materializeProject(primary);

const env = {
  ...process.env,
  HOME: home,
  USERPROFILE: home,
  LPM_HOME: lpmHome,
  LPM_STORE_VERSION: 'v2',
  LPM_TYPOSQUAT_GUARD: '0',
  CI: '1',
};

const rows = [];
try {
  runChecked(['install'], primary);
  for (let sample = 1; sample <= samples; sample += 1) {
    rematerialize(primary);
    rows.push(measureRebuild('cache_disabled', sample, primary, false));

    fs.rmSync(path.join(lpmHome, 'store/v2/builds'), { recursive: true, force: true });
    rematerialize(primary);
    rows.push(measureRebuild('cache_miss', sample, primary, true));

    rematerialize(primary);
    rows.push(measureRebuild('local_hit', sample, primary, true));

    const ciProject = path.join(tempRoot, `ci-project-${sample}`);
    materializeProject(ciProject);
    runChecked(['install'], ciProject);
    rows.push(measureRebuild('ci_warm_store_hit', sample, ciProject, true));
  }

  const artifactBytes = directorySize(path.join(lpmHome, 'store/v2/builds'));
  const summary = summarize(rows, artifactBytes);
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, 'rows.json'), `${JSON.stringify(rows, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(outputDir, 'summary.md'), `${renderMarkdown(summary)}\n`);
  console.log(outputDir);
  console.log(renderMarkdown(summary));
} finally {
  if (!options.keep) {
    fs.rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

function materializeProject(projectDir) {
  fs.mkdirSync(projectDir, { recursive: true });
  fs.copyFileSync(path.join(fixture, 'package.json'), path.join(projectDir, 'package.json'));
}

function rematerialize(projectDir) {
  fs.rmSync(path.join(projectDir, 'node_modules'), { recursive: true, force: true });
  runChecked(['install', '--force', '--no-frozen-lockfile'], projectDir);
}

function measureRebuild(scenario, sample, cwd, strict) {
  const args = ['--json', 'rebuild', '--all'];
  if (strict) args.push('--strict-sandbox');
  const started = process.hrtime.bigint();
  const result = runTimed(args, cwd);
  const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
  if (result.status !== 0) {
    throw new Error(
      `${scenario} failed (${result.status})\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  const envelope = JSON.parse(result.stdout);
  return {
    scenario,
    sample,
    wall_ms: round(wallMs),
    user_cpu_ms: result.userCpuMs,
    system_cpu_ms: result.systemCpuMs,
    max_rss_bytes: result.maxRssBytes,
    build_cache: envelope.build_cache,
  };
}

function runChecked(args, cwd) {
  const result = spawnSync(lpmBin, args, {
    cwd,
    env,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `lpm ${args.join(' ')} failed (${result.status})\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
}

function runTimed(args, cwd) {
  if (process.platform === 'darwin' && fs.existsSync('/usr/bin/time')) {
    const result = spawnSync('/usr/bin/time', ['-l', lpmBin, ...args], {
      cwd,
      env,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    });
    const cpu = result.stderr.match(/([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys/);
    const rss = result.stderr.match(/\s+(\d+)\s+maximum resident set size/);
    return {
      ...result,
      userCpuMs: cpu ? Number(cpu[2]) * 1000 : null,
      systemCpuMs: cpu ? Number(cpu[3]) * 1000 : null,
      maxRssBytes: rss ? Number(rss[1]) : null,
    };
  }
  if (process.platform === 'linux' && fs.existsSync('/usr/bin/time')) {
    const result = spawnSync('/usr/bin/time', ['-v', lpmBin, ...args], {
      cwd,
      env,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    });
    const user = result.stderr.match(/User time \(seconds\): ([\d.]+)/);
    const system = result.stderr.match(/System time \(seconds\): ([\d.]+)/);
    const rss = result.stderr.match(/Maximum resident set size \(kbytes\): (\d+)/);
    return {
      ...result,
      userCpuMs: user ? Number(user[1]) * 1000 : null,
      systemCpuMs: system ? Number(system[1]) * 1000 : null,
      maxRssBytes: rss ? Number(rss[1]) * 1024 : null,
    };
  }
  const result = spawnSync(lpmBin, args, {
    cwd,
    env,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  return { ...result, userCpuMs: null, systemCpuMs: null, maxRssBytes: null };
}

function summarize(allRows, artifactBytes) {
  const scenarios = {};
  for (const scenario of [...new Set(allRows.map((row) => row.scenario))]) {
    const selected = allRows.filter((row) => row.scenario === scenario);
    const walls = selected.map((row) => row.wall_ms).sort((a, b) => a - b);
    const rss = selected
      .map((row) => row.max_rss_bytes)
      .filter((value) => value != null)
      .sort((a, b) => a - b);
    scenarios[scenario] = {
      samples: selected.length,
      wall_ms_median: percentile(walls, 0.5),
      wall_ms_p95: percentile(walls, 0.95),
      max_rss_bytes_median: rss.length ? percentile(rss, 0.5) : null,
      user_cpu_ms_median: medianNullable(selected.map((row) => row.user_cpu_ms)),
      system_cpu_ms_median: medianNullable(selected.map((row) => row.system_cpu_ms)),
      cache_hits: selected.reduce((sum, row) => sum + row.build_cache.hits, 0),
      cache_misses: selected.reduce((sum, row) => sum + row.build_cache.misses, 0),
      lifecycle_ms_avoided: selected.reduce(
        (sum, row) => sum + row.build_cache.lifecycle_ms_avoided,
        0,
      ),
    };
  }
  const baseline = scenarios.cache_disabled.wall_ms_median;
  for (const scenario of ['local_hit', 'ci_warm_store_hit']) {
    scenarios[scenario].speedup_vs_disabled = round(baseline / scenarios[scenario].wall_ms_median);
    scenarios[scenario].wall_reduction_percent = round(
      100 * (1 - scenarios[scenario].wall_ms_median / baseline),
    );
  }
  return {
    generated_at: new Date().toISOString(),
    platform: `${process.platform}-${process.arch}`,
    node: process.version,
    lpm_bin: lpmBin,
    fixture: path.relative(repoRoot, fixture),
    samples,
    artifact_bytes: artifactBytes,
    scenarios,
  };
}

function renderMarkdown(summary) {
  const lines = [
    '# Native lifecycle-build cache benchmark',
    '',
    `- Platform: ${summary.platform}`,
    `- Fixture: \`${summary.fixture}\``,
    `- Samples per scenario: ${summary.samples}`,
    `- Build artifact bytes: ${summary.artifact_bytes}`,
    '',
    '| Scenario | Median wall | p95 wall | Median RSS | Hits | Misses | Speedup |',
    '|---|---:|---:|---:|---:|---:|---:|',
  ];
  for (const [name, value] of Object.entries(summary.scenarios)) {
    lines.push(
      `| ${name} | ${value.wall_ms_median} ms | ${value.wall_ms_p95} ms | ${value.max_rss_bytes_median ?? 'n/a'} B | ${value.cache_hits} | ${value.cache_misses} | ${value.speedup_vs_disabled ? `${value.speedup_vs_disabled}×` : '—'} |`,
    );
  }
  lines.push(
    '',
    'The disabled and miss scenarios rematerialize pristine dependencies before each sample. Local-hit samples rematerialize the same project; CI-hit samples create a fresh project while retaining the warm LPM store.',
  );
  return lines.join('\n');
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

function medianNullable(values) {
  const present = values.filter((value) => value != null).sort((a, b) => a - b);
  return present.length ? percentile(present, 0.5) : null;
}

function directorySize(root) {
  if (!fs.existsSync(root)) return 0;
  let total = 0;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) total += directorySize(candidate);
    else if (entry.isFile()) total += fs.statSync(candidate).size;
  }
  return total;
}

function round(value) {
  return Math.round(value * 100) / 100;
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`);
    const key = token.slice(2);
    if (key === 'keep') parsed.keep = true;
    else parsed[key] = argv[++index];
  }
  return parsed;
}
