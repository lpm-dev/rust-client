#!/usr/bin/env node

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const SCHEMA_VERSION = 2;
const STREAM_RETAIN_BYTES = 64 * 1024;
const SAMPLE_INTERVAL_MS = 50;
const STEADY_WINDOW_MS = 350;
const PR_TIMEOUT_MS = 15_000;
const FULL_TIMEOUT_MS = 60_000;
const SHUTDOWN_TIMEOUT_MS = 10_000;
const TASK_RSS_HOLD_MS = 300;
const MiB = 1024 * 1024;

function defaultTimeoutMs(profile) {
  return profile === 'full' ? FULL_TIMEOUT_MS : PR_TIMEOUT_MS;
}

function benchmarkShutdownTimeoutMs() {
  return SHUTDOWN_TIMEOUT_MS;
}

class BoundedCollector {
  constructor(limit) {
    if (!Number.isInteger(limit) || limit < 2) throw new Error('collector limit must be at least 2 bytes');
    this.limit = limit;
    this.prefixLimit = Math.floor(limit / 2);
    this.tailLimit = limit - this.prefixLimit;
    this.prefix = Buffer.alloc(0);
    this.tail = Buffer.alloc(0);
    this.total = 0;
    this.hash = crypto.createHash('sha256');
  }

  push(chunk) {
    const bytes = Buffer.from(chunk);
    this.total += bytes.length;
    this.hash.update(bytes);
    if (this.prefix.length < this.prefixLimit) {
      const take = Math.min(bytes.length, this.prefixLimit - this.prefix.length);
      this.prefix = Buffer.concat([this.prefix, bytes.subarray(0, take)]);
    }
    this.tail = Buffer.concat([this.tail, bytes]);
    if (this.tail.length > this.tailLimit) this.tail = this.tail.subarray(this.tail.length - this.tailLimit);
  }

  finish() {
    const truncated = this.total > this.limit;
    const separator = truncated ? Buffer.from('\n... output truncated by benchmark harness ...\n') : Buffer.alloc(0);
    const overlap = Math.max(0, this.prefix.length + this.tail.length - this.total);
    const retained = truncated
      ? Buffer.concat([this.prefix, separator, this.tail])
      : Buffer.concat([this.prefix, this.tail.subarray(overlap)], this.total);
    return {
      total_bytes: this.total,
      retained_bytes: retained.length,
      truncated,
      sha256: this.hash.digest('hex'),
      retained: retained.toString('utf8'),
    };
  }
}

class WebSocketFrameParser {
  constructor(onFrame) {
    this.onFrame = onFrame;
    this.chunks = [];
    this.totalBytes = 0;
  }

  push(chunk) {
    if (chunk.length === 0) return;
    this.chunks.push(Buffer.from(chunk));
    this.totalBytes += chunk.length;
    while (this.totalBytes >= 2) {
      const header = this.peek(Math.min(this.totalBytes, 14));
      const first = header[0];
      const second = header[1];
      const masked = (second & 0x80) !== 0;
      let payloadLength = BigInt(second & 0x7f);
      let headerLength = 2;
      if (payloadLength === 126n) {
        if (this.totalBytes < 4) break;
        payloadLength = BigInt(header.readUInt16BE(2));
        headerLength = 4;
      } else if (payloadLength === 127n) {
        if (this.totalBytes < 10) break;
        payloadLength = header.readBigUInt64BE(2);
        headerLength = 10;
      }
      if (payloadLength > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`WebSocket payload exceeds the parser's safe integer range: ${payloadLength}`);
      }
      const maskLength = masked ? 4 : 0;
      const frameLength = headerLength + maskLength + Number(payloadLength);
      if (this.totalBytes < frameLength) break;
      const frame = this.consume(frameLength);
      const payloadStart = headerLength + maskLength;
      const payload = frame.subarray(payloadStart, payloadStart + Number(payloadLength));
      if (masked) {
        const mask = frame.subarray(headerLength, headerLength + 4);
        for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
      }
      this.onFrame(payload, first & 0x0f);
    }
  }

  peek(length) {
    if (this.chunks[0].length >= length) return this.chunks[0].subarray(0, length);
    const slices = [];
    let remaining = length;
    for (const chunk of this.chunks) {
      const take = Math.min(remaining, chunk.length);
      slices.push(chunk.subarray(0, take));
      remaining -= take;
      if (remaining === 0) break;
    }
    return Buffer.concat(slices, length);
  }

  consume(length) {
    const slices = [];
    let remaining = length;
    while (remaining > 0) {
      const chunk = this.chunks[0];
      const take = Math.min(remaining, chunk.length);
      slices.push(chunk.subarray(0, take));
      if (take === chunk.length) this.chunks.shift();
      else this.chunks[0] = chunk.subarray(take);
      remaining -= take;
    }
    this.totalBytes -= length;
    return slices.length === 1 ? Buffer.from(slices[0]) : Buffer.concat(slices, length);
  }
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
  printHelp();
  process.exit(0);
}
if (options.selfTest) {
  await runSelfTests();
  process.exit(0);
}
if (!['darwin', 'linux'].includes(process.platform)) {
  throw new Error(`runtime readiness supports macOS and Linux, not ${process.platform}`);
}

const samples = balancedPairCount(options.samples, options.profile === 'full' ? 10 : 4, '--samples');
const warmups = nonNegativeInt(options.warmups, 1, '--warmups');
const timeoutMs = positiveInt(
  options.timeoutMs,
  defaultTimeoutMs(options.profile),
  '--timeout-ms',
);
const binaries = parseBinaries(options.binaries);
const comparison = parseComparison(options.compare, binaries);
const allScenarios = buildScenarios();
const scenarioIds = options.scenarios
  ? parseList(options.scenarios, '--scenarios')
  : allScenarios
      .filter((scenario) => options.profile === 'full' || !scenario.fullOnly)
      .map((scenario) => scenario.id);
const scenarios = scenarioIds.map((id) => {
  const scenario = allScenarios.find((candidate) => candidate.id === id);
  if (!scenario) throw new Error(`unknown scenario: ${id}`);
  return scenario;
});
validateUnique(scenarioIds, 'scenario');
const scenarioOrder = new Map(scenarios.map((scenario, index) => [scenario.id, index]));
for (const binary of binaries) {
  if (!isExecutable(binary.path)) throw new Error(`lpm binary is not executable (${binary.name}): ${binary.path}`);
}
if (scenarios.some((scenario) => scenario.requiresPty) && !findExecutable('script')) {
  throw new Error('the full dashboard profile requires the script(1) PTY utility');
}

const outputDir = path.resolve(options.output ?? defaultOutputDir());
const thresholds = {
  wall_ms: threshold(options, 'wall', 5, 10, 20, 50),
  startup_ms: threshold(options, 'startup', 5, 10, 20, 50),
  shutdown_ms: threshold(options, 'shutdown', 10, 20, 50, 100),
  tree_peak_rss_bytes: threshold(options, 'rss', 5, 10, 16 * MiB, 32 * MiB),
  root_peak_rss_bytes: threshold(options, 'rootRss', 5, 10, 8 * MiB, 16 * MiB),
  steady_tree_rss_bytes: threshold(options, 'steadyRss', 5, 10, 16 * MiB, 32 * MiB),
  steady_root_rss_bytes: threshold(options, 'steadyRootRss', 5, 10, 8 * MiB, 16 * MiB),
  peak_process_count: threshold(options, 'process', 10, 20, 1, 2),
  maximum_observed_fd_count: threshold(options, 'fd', 10, 20, 8, 16),
  maximum_observed_thread_count: threshold(options, 'thread', 10, 20, 2, 4),
};
const plan = {
  schema_version: SCHEMA_VERSION,
  generated_at: new Date().toISOString(),
  git_revision: commandOutput('git', ['rev-parse', 'HEAD'], repoRoot),
  harness_sha256: sha256File(fileURLToPath(import.meta.url)),
  host: hostMetadata(),
  profile: options.profile,
  samples,
  warmups,
  timeout_ms: timeoutMs,
  sample_interval_ms: SAMPLE_INTERVAL_MS,
  steady_window_ms: STEADY_WINDOW_MS,
  stream_retained_bytes: STREAM_RETAIN_BYTES,
  scenarios: scenarios.map((scenario) => scenario.id),
  binaries: binaries.map((binary) => ({
    ...binary,
    sha256: sha256File(binary.path),
    version: commandOutput(binary.path, ['--version'], repoRoot),
  })),
  comparison,
  thresholds,
  output_dir: outputDir,
};
if (options.dryRun) {
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  process.exit(0);
}

fs.mkdirSync(outputDir, { recursive: true });
writeJson(path.join(outputDir, 'plan.json'), plan);
const rows = [];
let executionSequence = 0;

for (let warmup = 1; warmup <= warmups; warmup += 1) {
  for (const scenario of rotated(scenarios, warmup - 1)) {
    for (const binary of rotated(binaries, warmup - 1)) {
      process.stderr.write(`[warmup ${warmup}/${warmups}] ${scenario.id} ${binary.name}\n`);
      const row = await executeScenario({ scenario, binary, sample: warmup, counted: false });
      rows.push(row);
      if (warmupBlocksComparison(binary.name, row, comparison)) {
        throw new Error(`warmup failed: ${scenario.id} ${binary.name}: ${row.failure_reason}`);
      }
    }
  }
}

for (let sample = 1; sample <= samples; sample += 1) {
  const orderedScenarios = rotated(scenarios, sample - 1);
  for (const scenario of orderedScenarios) {
    const pairId = `${scenario.id}:sample-${sample}`;
    const baselineFirst = baselineRunsFirst(sample, scenarioOrder.get(scenario.id));
    const orderedBinaries = baselineFirst
      ? [binaryNamed(comparison.baseline), binaryNamed(comparison.candidate)]
      : [binaryNamed(comparison.candidate), binaryNamed(comparison.baseline)];
    const pairOrder = baselineFirst ? 'baseline-candidate' : 'candidate-baseline';
    for (const binary of orderedBinaries) {
      process.stderr.write(`[sample ${sample}/${samples}] ${scenario.id} ${binary.name} (${pairOrder})\n`);
      rows.push(await executeScenario({ scenario, binary, sample, counted: true, pairId, pairOrder }));
    }
  }
}

const summary = summarize(rows);
const comparisonSummary = summarizeComparison(rows, comparison, thresholds, samples);
writeJson(path.join(outputDir, 'rows.json'), rows);
writeJson(path.join(outputDir, 'summary.json'), summary);
writeJson(path.join(outputDir, 'comparison.json'), comparisonSummary);
fs.writeFileSync(path.join(outputDir, 'summary.md'), `${renderMarkdown(summary, comparisonSummary)}\n`);
process.stdout.write(`${renderMarkdown(summary, comparisonSummary)}\n\nArtifacts: ${outputDir}\n`);
if (comparisonSummary.verdict === 'execution-failure' || comparisonSummary.verdict === 'regression') {
  process.exitCode = 1;
} else if (comparisonSummary.verdict === 'inconclusive' && !options.allowInconclusive) {
  process.exitCode = 2;
}

function binaryNamed(name) {
  return binaries.find((binary) => binary.name === name);
}

async function executeScenario({ scenario, binary, sample, counted, pairId = null, pairOrder = null }) {
  const runId = `${counted ? `sample-${sample}` : `warmup-${sample}`}-${binary.name}`;
  const artifactDir = path.join(outputDir, safeName(scenario.id), runId);
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), `lpm-runtime-readiness-${safeName(scenario.id)}-`));
  const homeDir = path.join(workRoot, 'home');
  const lpmHome = path.join(workRoot, 'lpm-home');
  const projectRoot = path.join(workRoot, 'project');
  fs.mkdirSync(artifactDir, { recursive: true });
  fs.mkdirSync(homeDir, { recursive: true });
  fs.mkdirSync(lpmHome, { recursive: true });
  fs.mkdirSync(projectRoot, { recursive: true });
  const context = {
    scenario,
    binary,
    sample,
    artifactDir,
    workRoot,
    homeDir,
    lpmHome,
    projectRoot,
    ports: [],
    cleanup: [],
    state: {},
  };
  const row = {
    schema_version: SCHEMA_VERSION,
    scenario: scenario.id,
    kind: scenario.kind,
    binary: binary.name,
    binary_path: binary.path,
    sample,
    counted,
    pair_id: pairId,
    pair_order: pairOrder,
    execution_sequence: ++executionSequence,
    timeout_ms: scenario.timeoutMs ?? timeoutMs,
    started_at: new Date().toISOString(),
  };
  try {
    await scenario.prepare(context);
    const env = benchmarkEnv(context, scenario.allowRuntimeInstall);
    writeJson(path.join(artifactDir, 'env.json'), redactEnv(env));
    const processSpecs = scenario.processes(context).map((spec) => ({
      executable: spec.executable ?? binary.path,
      args: spec.args,
      cwd: spec.cwd ?? projectRoot,
      env: { ...env, ...spec.env },
      label: spec.label ?? 'lpm',
    }));
    const result = await runProcesses(
      context,
      processSpecs,
      scenario,
      scenario.timeoutMs ?? timeoutMs,
    );
    Object.assign(row, result.metrics);
    row.processes = result.processes;
    row.contract = await scenario.validate(context, result);
    if (result.metrics.forced_shutdown) {
      row.contract = {
        ok: false,
        reason: 'lpm exceeded the benchmark shutdown deadline and required SIGKILL',
        inner: row.contract,
      };
    }
    const outputBoundOk = result.processes.every((process) =>
      process.stdout.retained_bytes <= STREAM_RETAIN_BYTES + 48
      && process.stderr.retained_bytes <= STREAM_RETAIN_BYTES + 48,
    );
    if (!outputBoundOk) {
      row.contract = { ok: false, reason: 'the benchmark harness exceeded its retained-output ceiling', inner: row.contract };
    }
    row.exit_ok = result.processes.every((process) =>
      scenario.kind === 'dev'
        ? process.exit_code === 0
          || process.signal === 'SIGTERM'
          || (result.metrics.forced_shutdown && process.signal === 'SIGKILL')
        : process.exit_code === 0,
    );
    row.contract_ok = row.contract.ok;
    row.failure_reason = row.exit_ok && row.contract_ok ? null : row.contract.reason ?? 'process failed';
  } catch (error) {
    row.exit_ok = false;
    row.contract_ok = false;
    row.failure_reason = error instanceof Error ? error.stack ?? error.message : String(error);
  } finally {
    const cleanupErrors = [];
    for (const cleanup of context.cleanup.reverse()) {
      try {
        await withTimeout(Promise.resolve().then(cleanup), 5_000, `${scenario.id} cleanup`);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    if (cleanupErrors.length > 0) {
      row.cleanup_errors = cleanupErrors;
      row.exit_ok = false;
      row.contract_ok = false;
      row.failure_reason = `benchmark cleanup failed: ${cleanupErrors.join('; ')}`;
      row.contract = { ok: false, reason: row.failure_reason, inner: row.contract ?? null };
    }
    writeJson(path.join(artifactDir, 'metrics.json'), row);
    if (options.keepWork) {
      fs.writeFileSync(path.join(artifactDir, 'work-root.txt'), `${workRoot}\n`);
    } else {
      removeTree(workRoot);
    }
  }
  return row;
}

async function runProcesses(context, specs, scenario, timeout) {
  const startedNs = process.hrtime.bigint();
  const children = specs.map((spec, index) => spawnMeasured(spec, context.artifactDir, index));
  const roots = children.map((child) => child.child.pid).filter(Number.isInteger);
  context.state.children = children;
  const samples = [];
  const metricRootSelector = scenario.metricRootPids
    ? (tree) => scenario.metricRootPids(context, tree, roots)
    : () => roots;
  let sampling = true;
  const sampler = (async () => {
    let detailedTick = 0;
    while (sampling) {
      const sample = sampleProcessTree(roots, detailedTick % 5 === 0, metricRootSelector);
      sample.elapsed_ms = elapsedMs(startedNs);
      samples.push(sample);
      detailedTick += 1;
      await delay(SAMPLE_INTERVAL_MS);
    }
  })();
  let readiness = null;
  let shutdownMs = null;
  let preShutdown = [];
  let steadyTreeRssBytes = null;
  let steadyRootRssBytes = null;
  let signalTargets = roots;
  const completion = Promise.all(children.map((child) => child.completion));
  let processCompletedMs = null;
  let forcedShutdown = false;
  try {
    if (scenario.kind === 'dev') {
      readiness = await withTimeout(scenario.waitReady(context, children), timeout, `${scenario.id} readiness`);
      readiness.elapsed_ms = elapsedMs(startedNs);
      await delay(STEADY_WINDOW_MS);
      const snapshot = sampleProcessTree(roots, true, metricRootSelector);
      snapshot.elapsed_ms = elapsedMs(startedNs);
      samples.push(snapshot);
      steadyTreeRssBytes = snapshot.tree_rss_bytes;
      steadyRootRssBytes = snapshot.root_rss_bytes;
      preShutdown = snapshot.processes.map((process) => ({ pid: process.pid, start_identity: process.start_identity }));
      signalTargets = scenario.signalTargets
        ? await scenario.signalTargets(context, snapshot, roots)
        : roots;
      const shutdownStarted = process.hrtime.bigint();
      for (const pid of signalTargets) safeKill(pid, 'SIGTERM');
      const completed = await withTimeout(
        completion,
        benchmarkShutdownTimeoutMs(),
        `${scenario.id} shutdown`,
      )
        .then(() => true)
        .catch(() => false);
      if (!completed) {
        forcedShutdown = true;
        const remaining = sampleProcessTree(roots, false, metricRootSelector).processes.map((process) => ({
          pid: process.pid,
          start_identity: process.start_identity,
        }));
        for (const identity of remaining) {
          if (sameProcess(identity)) safeKill(identity.pid, 'SIGKILL');
        }
        await withTimeout(completion, 1_000, `${scenario.id} forced shutdown`);
      }
      processCompletedMs = elapsedMs(startedNs);
      shutdownMs = elapsedMs(shutdownStarted);
    } else {
      await withTimeout(completion, timeout, `${scenario.id} completion`);
      processCompletedMs = elapsedMs(startedNs);
    }
  } catch (error) {
    const emergencyProcesses = sampleProcessTree(roots, false, metricRootSelector).processes.map((process) => ({
      pid: process.pid,
      start_identity: process.start_identity,
    }));
    for (const pid of roots) safeKill(pid, 'SIGTERM');
    await delay(500);
    for (const identity of emergencyProcesses) {
      if (sameProcess(identity)) safeKill(identity.pid, 'SIGKILL');
    }
    throw error;
  } finally {
    sampling = false;
    await sampler;
  }
  const processResults = await completion;
  const survivors = preShutdown.filter((identity) => sameProcess(identity));
  const survivingPorts = [];
  for (const port of context.ports) {
    if (await canConnect(port)) survivingPorts.push(port);
  }
  for (const survivor of survivors) safeKill(survivor.pid, 'SIGKILL');
  const metrics = summarizeResourceSamples(samples, roots);
  metrics.wall_ms = processCompletedMs ?? elapsedMs(startedNs);
  metrics.startup_ms = readiness?.elapsed_ms ?? null;
  metrics.steady_tree_rss_bytes = steadyTreeRssBytes;
  metrics.steady_root_rss_bytes = steadyRootRssBytes;
  metrics.shutdown_ms = shutdownMs;
  metrics.forced_shutdown = forcedShutdown;
  metrics.readiness = readiness;
  metrics.signal_targets = signalTargets;
  metrics.surviving_processes = survivors;
  metrics.surviving_ports = survivingPorts;
  fs.writeFileSync(
    path.join(context.artifactDir, 'resource-samples.jsonl'),
    samples.map((sample) => JSON.stringify(sample)).join('\n') + '\n',
  );
  writeJson(path.join(context.artifactDir, 'survivors.json'), { survivors, surviving_ports: survivingPorts });
  return { metrics, processes: processResults, readiness, samples };
}

function spawnMeasured(spec, artifactDir, index) {
  const stdout = new BoundedCollector(STREAM_RETAIN_BYTES);
  const stderr = new BoundedCollector(STREAM_RETAIN_BYTES);
  const child = spawn(spec.executable, spec.args, {
    cwd: spec.cwd,
    env: spec.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });
  child.stdout.on('data', (chunk) => stdout.push(chunk));
  child.stderr.on('data', (chunk) => stderr.push(chunk));
  const completion = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => {
      const stdoutResult = stdout.finish();
      const stderrResult = stderr.finish();
      fs.writeFileSync(path.join(artifactDir, `${index}-${spec.label}-stdout.log`), stdoutResult.retained);
      fs.writeFileSync(path.join(artifactDir, `${index}-${spec.label}-stderr.log`), stderrResult.retained);
      const result = {
        label: spec.label,
        pid: child.pid,
        exit_code: code,
        signal,
        stdout: stdoutResult,
        stderr: stderrResult,
      };
      writeJson(path.join(artifactDir, `${index}-${spec.label}-output.json`), result);
      resolve(result);
    });
  });
  return { child, completion, stdout, stderr };
}

function buildScenarios() {
  return [
    runSystemNodeScenario(),
    runDotNodeVersionScenario(),
    runNodeSelectorPrecedenceScenario(),
    runLpmJsonNodeSelectorPrecedenceScenario(),
    runTaskEnvManagedNodeScenario(),
    runWorkspaceNodeBunScenario(),
    taskGraphScenario(10, 'deep'),
    taskGraphScenario(10, 'wide'),
    taskGraphScenario(100, 'deep'),
    taskGraphScenario(100, 'wide'),
    taskGraphScenario(1_000, 'deep', true),
    taskGraphScenario(1_000, 'wide', true),
    cachedTaskChainScenario(10, 'cold'),
    cachedTaskChainScenario(10, 'warm'),
    cachedTaskChainScenario(100, 'cold', true),
    cachedTaskChainScenario(100, 'warm', true),
    cachedTaskChainScenario(1_000, 'cold', true),
    cachedTaskChainScenario(1_000, 'warm', true),
    workspaceCaretChainScenario(10),
    workspaceCaretChainScenario(100, true),
    workspaceCaretChainScenario(1_000, true),
    workspaceTaskCacheScenario(10, 'cold'),
    workspaceTaskCacheScenario(10, 'warm'),
    workspaceTaskCacheScenario(100, 'cold', true),
    workspaceTaskCacheScenario(100, 'warm', true),
    workspaceTaskCacheScenario(1_000, 'cold', true),
    workspaceTaskCacheScenario(1_000, 'warm', true),
    workspaceRootLockCacheScenario(1, 'cold'),
    workspaceRootLockCacheScenario(1, 'warm'),
    workspaceRootLockCacheScenario(10, 'cold', true),
    workspaceRootLockCacheScenario(10, 'warm', true),
    workspaceRootLockCacheScenario(50, 'cold', true),
    workspaceRootLockCacheScenario(50, 'warm', true),
    cacheHitScenario(1),
    cacheHitScenario(128, true),
    cacheManyFileRestoreScenario(),
    cacheDeepPathRestoreScenario(),
    cacheStaleOutputRemovalScenario(),
    concurrentCacheStoreScenario(),
    devSingleScenario(),
    devMultiScenario(),
    devGraphScenario(10, 'deep'),
    devGraphScenario(10, 'wide'),
    devGraphScenario(50, 'deep', true),
    devGraphScenario(50, 'wide', true),
    concurrentDifferentRuntimeScenario(),
    concurrentProjectScaleScenario(4, true),
    concurrentFirstInstallScenario(),
    cleanupDescendantScenario(),
    restartCrashCycleScenario(),
    newlineFreeScenario(),
    largeReadinessResponseScenario(1),
    largeReadinessResponseScenario(10, true),
    largeReadinessResponseScenario(49, true),
    tunnelManagedNodeEnvMultiScenario(),
    tunnelResponseScenario(1),
    tunnelResponseScenario(10, true),
    tunnelResponseScenario(49, true),
    tunnelResponseScenario(49, true, 4),
    tunnelFairnessScenario(),
    tunnelWebSocketLifecycleScenario(),
    tunnelDashboardScenario(),
  ];
}

function runSystemNodeScenario() {
  return runScenario('run/package-system-node-no-lpm-json', async (context) => {
    writePackage(context.projectRoot, {
      name: 'runtime-system-node',
      private: true,
      scripts: { probe: 'node probe.mjs' },
    });
    writeFile(context.projectRoot, 'probe.mjs', resultScript({ scenario: 'system-node', env: [] }));
  }, ['run', 'probe'], (result) => markerContract(result, { scenario: 'system-node' }));
}

function runDotNodeVersionScenario() {
  const version = process.version.slice(1);
  return runScenario('run/package-dot-node-version-no-lpm-json', async (context) => {
    writePackage(context.projectRoot, {
      name: 'runtime-dot-node-version',
      private: true,
      scripts: { probe: 'node probe.mjs' },
    });
    writeFile(context.projectRoot, '.node-version', `${version}\n`);
    writeFile(context.projectRoot, 'probe.mjs', resultScript({ scenario: 'dot-node-version', env: [] }));
    installManagedRuntime(context.lpmHome, 'node', version);
  }, ['run', 'probe'], (result) => markerContract(result, { scenario: 'dot-node-version', selected_runtime: `node@${version}` }));
}

function runNodeSelectorPrecedenceScenario() {
  const version = process.version.slice(1);
  return runScenario('run/nvmrc-precedes-node-version-no-lpm-json', async (context) => {
    writePackage(context.projectRoot, {
      name: 'runtime-selector-precedence',
      private: true,
      scripts: { probe: 'node probe.mjs' },
    });
    writeFile(context.projectRoot, '.nvmrc', `${version}\n`);
    writeFile(context.projectRoot, '.node-version', '99.0.0\n');
    writeFile(context.projectRoot, 'probe.mjs', resultScript({ scenario: 'selector-precedence', env: [] }));
    installManagedRuntime(context.lpmHome, 'node', version);
  }, ['run', 'probe'], (result) => markerContract(result, {
    scenario: 'selector-precedence',
    selected_runtime: `node@${version}`,
  }));
}

function runLpmJsonNodeSelectorPrecedenceScenario() {
  const version = process.version.slice(1);
  return runScenario('run/lpm-json-precedes-file-node-selectors', async (context) => {
    writePackage(context.projectRoot, {
      name: 'runtime-lpm-json-selector-precedence',
      private: true,
      scripts: { probe: 'node probe.mjs' },
    });
    writeJson(path.join(context.projectRoot, 'lpm.json'), { runtime: { node: version } });
    writeFile(context.projectRoot, '.nvmrc', '98.0.0\n');
    writeFile(context.projectRoot, '.node-version', '99.0.0\n');
    writeFile(context.projectRoot, 'probe.mjs', resultScript({ scenario: 'lpm-json-selector-precedence', env: [] }));
    installManagedRuntime(context.lpmHome, 'node', version);
  }, ['run', 'probe'], (result) => markerContract(result, {
    scenario: 'lpm-json-selector-precedence',
    selected_runtime: `node@${version}`,
  }));
}

function runTaskEnvManagedNodeScenario() {
  const version = process.version.slice(1);
  return runScenario('run/lpm-task-env-managed-node', async (context) => {
    writePackage(context.projectRoot, {
      name: 'runtime-task-env',
      private: true,
      scripts: { probe: 'node probe.mjs' },
    });
    writeJson(path.join(context.projectRoot, 'lpm.json'), {
      runtime: { node: version },
      env: { probe: '.env.benchmark' },
    });
    writeFile(context.projectRoot, '.env.benchmark', 'RUNTIME_BENCH_ENV=task-env\n');
    writeFile(context.projectRoot, 'probe.mjs', resultScript({ scenario: 'task-env', env: ['RUNTIME_BENCH_ENV'] }));
    installManagedRuntime(context.lpmHome, 'node', version);
  }, ['run', 'probe'], (result) => markerContract(result, {
    scenario: 'task-env',
    selected_runtime: `node@${version}`,
    env: { RUNTIME_BENCH_ENV: 'task-env' },
  }));
}

function runWorkspaceNodeBunScenario() {
  const nodeVersion = process.version.slice(1);
  const bunVersion = '1.3.14';
  return runScenario('run/workspace-root-node-member-bun', async (context) => {
    writePackage(context.projectRoot, {
      name: 'runtime-workspace-root',
      private: true,
      workspaces: ['packages/*'],
    });
    writeJson(path.join(context.projectRoot, 'lpm.json'), { runtime: { node: nodeVersion } });
    const member = path.join(context.projectRoot, 'packages/app');
    writePackage(member, {
      name: 'runtime-workspace-app',
      private: true,
      scripts: { probe: 'node node-probe.mjs && bun bun-probe.mjs' },
    });
    writeJson(path.join(member, 'lpm.json'), { runtime: { bun: bunVersion } });
    writeFile(member, 'node-probe.mjs', resultScript({ scenario: 'workspace-node', env: [] }));
    writeFile(member, 'bun-probe.mjs', resultScript({ scenario: 'workspace-bun', env: [] }));
    installManagedRuntime(context.lpmHome, 'node', nodeVersion);
    installManagedRuntime(context.lpmHome, 'bun', bunVersion);
  }, ['run', 'probe', '--filter', 'runtime-workspace-app'], (result) => {
    const node = markerContract(result, { scenario: 'workspace-node', selected_runtime: `node@${nodeVersion}` });
    const bun = markerContract(result, {
      scenario: 'workspace-bun',
      engine: 'bun',
      runtime_version: bunVersion,
      selected_runtime: `bun@${bunVersion}`,
    });
    return node.ok && bun.ok ? { ok: true } : { ok: false, reason: node.reason ?? bun.reason };
  });
}

function taskGraphScenario(taskCount, shape, fullOnly = false) {
  const scenarioId = `task/${shape}-${taskCount}`;
  const tasks = {};
  let requestedTask;
  if (shape === 'deep') {
    let dependency = 'leaf';
    for (let index = 1; index < taskCount; index += 1) {
      const name = `task-${index}`;
      tasks[name] = { dependsOn: [dependency] };
      dependency = name;
    }
    requestedTask = dependency;
  } else if (shape === 'wide') {
    const branches = [];
    for (let index = 0; index < taskCount - 2; index += 1) {
      const name = `branch-${index}`;
      tasks[name] = { dependsOn: ['leaf'] };
      branches.push(name);
    }
    requestedTask = 'root';
    tasks[requestedTask] = { dependsOn: branches };
  } else {
    throw new Error(`unknown task graph shape: ${shape}`);
  }

  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: `runtime-task-${shape}-${taskCount}`,
        private: true,
        scripts: { leaf: 'node probe.mjs' },
      });
      writeJson(path.join(context.projectRoot, 'lpm.json'), { tasks });
      writeFile(
        context.projectRoot,
        'probe.mjs',
        `setTimeout(() => {\n${resultScript({ scenario: scenarioId, env: [] })}}, ${TASK_RSS_HOLD_MS});\n`,
      );
    }, shape === 'wide'
      ? ['run', requestedTask, '--parallel']
      : ['run', requestedTask],
    (result) => markerContract(result, { scenario: scenarioId })),
    fullOnly,
  };
}

function cachedTaskChainScenario(taskCount, mode, fullOnly = false) {
  const scenarioId = `task/cache-${mode}-deep-${taskCount}`;
  const tasks = {};
  for (let index = 0; index < taskCount; index += 1) {
    const name = `task-${index}`;
    tasks[name] = {
      command: `mkdir -p dist executions && printf '${index}\\n' > dist/${name}.txt && printf 'run\\n' >> executions/${name}.txt`,
      cache: true,
      outputs: [`dist/${name}.txt`],
      ...(index === 0 ? {} : { dependsOn: [`task-${index - 1}`] }),
    };
  }
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: `runtime-cache-${mode}-deep-${taskCount}`,
        private: true,
      });
      writeJson(path.join(context.projectRoot, 'lpm.json'), { tasks });
      if (mode === 'warm') {
        runPreparationCommand(
          context,
          context.projectRoot,
          ['run', `task-${taskCount - 1}`],
          taskCount >= 1_000 ? 180_000 : 30_000,
        );
        fs.rmSync(path.join(context.projectRoot, 'dist'), { recursive: true, force: true });
      }
    }, ['run', `task-${taskCount - 1}`], () => ({ ok: true })),
    fullOnly,
    timeoutMs: taskCount >= 1_000 ? 180_000 : undefined,
    async validate(context) {
      for (let index = 0; index < taskCount; index += 1) {
        const name = `task-${index}`;
        if (!fs.existsSync(path.join(context.projectRoot, `dist/${name}.txt`))) {
          return { ok: false, reason: `cached task chain did not produce ${name}` };
        }
        const executions = fs.readFileSync(
          path.join(context.projectRoot, `executions/${name}.txt`),
          'utf8',
        );
        if (executions !== 'run\n') {
          return { ok: false, reason: `cached task chain executed ${name} more or less than once` };
        }
      }
      return { ok: true, task_count: taskCount, cache_mode: mode };
    },
  };
}

function workspaceCaretChainScenario(packageCount, fullOnly = false) {
  const scenarioId = `task/workspace-caret-deep-${packageCount}`;
  const targetName = `runtime-workspace-caret-${packageCount - 1}`;
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: `runtime-workspace-caret-root-${packageCount}`,
        private: true,
        workspaces: ['packages/*'],
      });
      for (let index = 0; index < packageCount; index += 1) {
        const name = `runtime-workspace-caret-${index}`;
        const member = path.join(context.projectRoot, `packages/member-${index}`);
        writePackage(member, {
          name,
          private: true,
          ...(index === 0
            ? { scripts: { build: "mkdir -p dist && printf 'run\\n' > dist/executions.txt" } }
            : { dependencies: { [`runtime-workspace-caret-${index - 1}`]: 'workspace:*' } }),
        });
        if (index > 0) {
          writeJson(path.join(member, 'lpm.json'), {
            tasks: { build: { dependsOn: ['^build'] } },
          });
        }
      }
    }, ['run', 'build', '--filter', targetName], () => ({ ok: true })),
    fullOnly,
    async validate(context) {
      const executions = path.join(
        context.projectRoot,
        'packages/member-0/dist/executions.txt',
      );
      if (!fs.existsSync(executions) || fs.readFileSync(executions, 'utf8') !== 'run\n') {
        return { ok: false, reason: 'workspace caret chain did not execute its leaf exactly once' };
      }
      return { ok: true, package_count: packageCount };
    },
  };
}

function workspaceTaskCacheScenario(taskCount, mode, fullOnly = false) {
  const upstreamCount = taskCount <= 10 ? 3 : taskCount <= 100 ? 10 : 50;
  const localTaskCount = taskCount - upstreamCount;
  const scenarioId = `task/workspace-cache-${mode}-wide-deep-${taskCount}`;
  const appName = 'runtime-workspace-cache-app';
  return {
    ...runScenario(scenarioId, async (context) => {
      const dependencies = {};
      const memberDirectories = [];
      const upstreamNames = Array.from(
        { length: upstreamCount },
        (_, index) => `runtime-workspace-cache-upstream-${index}`,
      );
      const rootCount = Math.max(1, Math.floor(upstreamCount / 2));
      for (let index = 0; index < upstreamCount; index += 1) {
        const name = upstreamNames[index];
        const relativeDirectory = `packages/upstream-${index}`;
        const member = path.join(context.projectRoot, relativeDirectory);
        const memberDependencies = {};
        if (index >= rootCount) {
          memberDependencies[upstreamNames[(index - rootCount) % rootCount]] = 'workspace:*';
          dependencies[name] = 'workspace:*';
        }
        memberDirectories.push(member);
        writePackage(member, { name, private: true, dependencies: memberDependencies });
        writeJson(path.join(member, 'lpm.json'), {
          tasks: {
            build: {
              command: `mkdir -p dist && printf '${index}\\n' > dist/value.txt && printf 'run\\n' >> executions.txt`,
              cache: true,
              outputs: ['dist/**'],
            },
          },
        });
      }

      writePackage(context.projectRoot, {
        name: 'runtime-workspace-cache-root',
        private: true,
        workspaces: ['packages/*'],
      });
      const app = path.join(context.projectRoot, 'packages/app');
      memberDirectories.push(app);
      writePackage(app, { name: appName, private: true, dependencies });
      const tasks = { 'stage-0': { dependsOn: ['^build'] } };
      let previous = 'stage-0';
      for (let index = 1; index < localTaskCount - 1; index += 1) {
        const name = `stage-${index}`;
        tasks[name] = { dependsOn: [previous] };
        previous = name;
      }
      tasks.result = {
        dependsOn: [previous],
        command: "mkdir -p dist && printf 'ready\\n' > dist/result.txt && printf 'run\\n' >> executions.txt",
        cache: true,
        outputs: ['dist/**'],
      };
      writeJson(path.join(app, 'lpm.json'), { tasks });
      writeFile(context.projectRoot, 'lpm.lock', 'workspace-cache-contract\n');
      context.state.workspaceTaskCache = { app, memberDirectories, upstreamCount };

      if (mode === 'warm') {
        runPreparationCommand(context, context.projectRoot, ['run', 'result', '--filter', appName]);
        for (const member of memberDirectories) {
          fs.rmSync(path.join(member, 'dist'), { recursive: true, force: true });
        }
      }
    }, ['run', 'result', '--filter', appName], () => ({ ok: true })),
    fullOnly,
    async validate(context) {
      const fixture = context.state.workspaceTaskCache;
      if (!fs.existsSync(path.join(fixture.app, 'dist/result.txt'))) {
        return { ok: false, reason: 'workspace cache graph did not produce the final output' };
      }
      for (const member of fixture.memberDirectories) {
        const executions = path.join(member, 'executions.txt');
        if (!fs.existsSync(executions) || fs.readFileSync(executions, 'utf8') !== 'run\n') {
          return { ok: false, reason: `workspace cache graph executed ${member} more or less than once` };
        }
      }
      return {
        ok: true,
        task_count: taskCount,
        upstream_packages: fixture.upstreamCount,
        local_tasks: taskCount - fixture.upstreamCount,
        cache_mode: mode,
      };
    },
  };
}

function workspaceRootLockCacheScenario(lockMiB, mode, fullOnly = false) {
  const taskCount = 10;
  const scenarioId = `cache/workspace-root-lock-${mode}-${lockMiB}mib-${taskCount}-tasks`;
  const appName = 'runtime-workspace-root-lock-app';
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: 'runtime-workspace-root-lock-root',
        private: true,
        workspaces: ['packages/*'],
      });
      const app = path.join(context.projectRoot, 'packages/app');
      writePackage(app, { name: appName, private: true });
      const tasks = {};
      const taskNames = [];
      for (let index = 0; index < taskCount; index += 1) {
        const name = `task-${index}`;
        taskNames.push(name);
        tasks[name] = {
          command: `mkdir -p dist/${name} executions && printf '${index}\\n' > dist/${name}/value.txt && printf 'run\\n' >> executions/${name}.txt`,
          cache: true,
          outputs: [`dist/${name}/**`],
        };
      }
      writeJson(path.join(app, 'lpm.json'), { tasks });
      fs.writeFileSync(path.join(context.projectRoot, 'lpm.lock'), Buffer.alloc(lockMiB * MiB, 0x78));
      context.state.workspaceRootLockCache = { app, taskNames };
      if (mode === 'warm') {
        runPreparationCommand(context, context.projectRoot, [
          'run',
          ...taskNames,
          '--filter',
          appName,
          '--parallel',
        ]);
        fs.rmSync(path.join(app, 'dist'), { recursive: true, force: true });
      }
    }, (context) => [
      'run',
      ...context.state.workspaceRootLockCache.taskNames,
      '--filter',
      appName,
      '--parallel',
    ], () => ({ ok: true })),
    fullOnly,
    async validate(context) {
      const fixture = context.state.workspaceRootLockCache;
      for (const name of fixture.taskNames) {
        if (!fs.existsSync(path.join(fixture.app, `dist/${name}/value.txt`))) {
          return { ok: false, reason: `root-lock cache scenario did not restore ${name}` };
        }
        const executions = fs.readFileSync(path.join(fixture.app, `executions/${name}.txt`), 'utf8');
        if (executions !== 'run\n') {
          return { ok: false, reason: `root-lock cache scenario re-executed ${name}` };
        }
      }
      return { ok: true, lock_mib: lockMiB, task_count: taskCount, cache_mode: mode };
    },
  };
}

function cacheHitScenario(outputMiB, fullOnly = false) {
  const scenarioId = `cache/hit-${outputMiB}mib`;
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: `runtime-cache-hit-${outputMiB}mib`,
        private: true,
        scripts: { build: 'node build.mjs' },
      });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        tasks: { build: { cache: true, outputs: ['dist/**'] } },
      });
      writeFile(context.projectRoot, 'build.mjs', cachePayloadScript(scenarioId, outputMiB));
      runPreparationCommand(context, context.projectRoot, ['run', 'build']);
      fs.rmSync(path.join(context.projectRoot, 'dist'), { recursive: true, force: true });
      fs.rmSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'), { force: true });
    }, ['run', 'build'], () => ({ ok: true })),
    fullOnly,
    async validate(context, result) {
      const marker = markerContract(result, { scenario: scenarioId, bytes: outputMiB * MiB });
      if (!marker.ok) return marker;
      const payloadPath = path.join(context.projectRoot, 'dist/payload.bin');
      if (!fs.existsSync(payloadPath)) return { ok: false, reason: 'cache hit did not restore dist/payload.bin' };
      if (fs.existsSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'))) {
        return { ok: false, reason: 'cache-hit scenario executed the build script instead of restoring' };
      }
      const payload = await sha256FileStreaming(payloadPath);
      const ok = payload.bytes === outputMiB * MiB && payload.sha256 === marker.actual.sha256;
      return {
        ok,
        reason: ok ? null : `restored payload mismatch: bytes=${payload.bytes}, sha256=${payload.sha256}`,
        restored_bytes: payload.bytes,
        restored_sha256: payload.sha256,
      };
    },
  };
}

function cacheManyFileRestoreScenario() {
  const scenarioId = 'cache/hit-500-files';
  const fileCount = 500;
  const fileBytes = 4 * 1024;
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: 'runtime-cache-hit-many-files',
        private: true,
        scripts: { build: 'node build.mjs' },
      });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        tasks: { build: { cache: true, outputs: ['dist/**'] } },
      });
      writeFile(
        context.projectRoot,
        'build.mjs',
        cacheManyFileScript(scenarioId, fileCount, fileBytes),
      );
      runPreparationCommand(context, context.projectRoot, ['run', 'build']);
      fs.rmSync(path.join(context.projectRoot, 'dist'), { recursive: true, force: true });
      fs.rmSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'), { force: true });
    }, ['run', 'build'], () => ({ ok: true })),
    fullOnly: true,
    async validate(context, result) {
      const marker = markerContract(result, {
        scenario: scenarioId,
        file_count: fileCount,
        file_bytes: fileBytes,
      });
      if (!marker.ok) return marker;
      if (fs.existsSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'))) {
        return { ok: false, reason: 'many-file cache hit executed the build script instead of restoring' };
      }
      const tree = validateManyFileTree(path.join(context.projectRoot, 'dist'), fileCount, fileBytes);
      return {
        ok: tree.ok,
        reason: tree.ok ? null : tree.reason,
        restored_files: tree.files,
        restored_bytes: tree.bytes,
      };
    },
  };
}

function cacheDeepPathRestoreScenario() {
  const scenarioId = 'cache/hit-deep-path';
  const depth = 64;
  const outputBytes = MiB;
  const relativePayload = path.join(
    'dist',
    ...Array.from({ length: depth }, (_, index) => `level-${String(index).padStart(2, '0')}`),
    'payload.bin',
  );
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: 'runtime-cache-hit-deep-path',
        private: true,
        scripts: { build: 'node build.mjs' },
      });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        tasks: { build: { cache: true, outputs: ['dist/**'] } },
      });
      writeFile(
        context.projectRoot,
        'build.mjs',
        cacheDeepPathScript(scenarioId, relativePayload, outputBytes),
      );
      runPreparationCommand(context, context.projectRoot, ['run', 'build']);
      fs.rmSync(path.join(context.projectRoot, 'dist'), { recursive: true, force: true });
      fs.rmSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'), { force: true });
    }, ['run', 'build'], () => ({ ok: true })),
    fullOnly: true,
    async validate(context, result) {
      const marker = markerContract(result, {
        scenario: scenarioId,
        depth,
        bytes: outputBytes,
      });
      if (!marker.ok) return marker;
      if (fs.existsSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'))) {
        return { ok: false, reason: 'deep-path cache hit executed the build script instead of restoring' };
      }
      const payloadPath = path.join(context.projectRoot, relativePayload);
      if (!fs.existsSync(payloadPath)) {
        return { ok: false, reason: `cache hit did not restore ${relativePayload}` };
      }
      const payload = await sha256FileStreaming(payloadPath);
      const ok = payload.bytes === outputBytes && payload.sha256 === marker.actual.sha256;
      return {
        ok,
        reason: ok ? null : `deep-path payload mismatch: bytes=${payload.bytes}, sha256=${payload.sha256}`,
        restored_bytes: payload.bytes,
        restored_sha256: payload.sha256,
      };
    },
  };
}

function cacheStaleOutputRemovalScenario() {
  const scenarioId = 'cache/removes-stale-output';
  return {
    ...runScenario(scenarioId, async (context) => {
      writePackage(context.projectRoot, {
        name: 'runtime-cache-removes-stale-output',
        private: true,
        scripts: { build: 'node build.mjs' },
      });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        tasks: { build: { cache: true, outputs: ['dist/**'] } },
      });
      writeFile(context.projectRoot, 'build.mjs', cacheStaleOutputScript(scenarioId));
      runPreparationCommand(context, context.projectRoot, ['run', 'build']);
      fs.rmSync(path.join(context.projectRoot, 'dist'), { recursive: true, force: true });
      fs.mkdirSync(path.join(context.projectRoot, 'dist'));
      writeFile(context.projectRoot, 'dist/stale.txt', 'must be removed\n');
      fs.rmSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'), { force: true });
    }, ['run', 'build'], () => ({ ok: true })),
    async validate(context, result) {
      const marker = markerContract(result, { scenario: scenarioId });
      if (!marker.ok) return marker;
      if (fs.existsSync(path.join(context.projectRoot, '.lpm-bench-cache-executed'))) {
        return { ok: false, reason: 'stale-output cache scenario executed the build script instead of restoring' };
      }
      const restored = path.join(context.projectRoot, 'dist/restored.txt');
      const stale = path.join(context.projectRoot, 'dist/stale.txt');
      const ok = fs.readFileSync(restored, 'utf8') === 'restored\n' && !fs.existsSync(stale);
      return {
        ok,
        reason: ok ? null : 'cache restore did not replace the declared output tree exactly',
        stale_output_present: fs.existsSync(stale),
      };
    },
  };
}

function concurrentCacheStoreScenario() {
  const scenarioId = 'cache/concurrent-same-key-store';
  return {
    id: scenarioId,
    kind: 'run',
    allowRuntimeInstall: false,
    async prepare(context) {
      context.state.projects = ['first', 'second'].map((producer) => {
        const project = path.join(context.projectRoot, producer);
        writePackage(project, {
          name: 'runtime-concurrent-cache-store',
          private: true,
          scripts: { build: 'node build.mjs' },
        });
        writeJson(path.join(project, 'lpm.json'), {
          tasks: { build: { cache: true, outputs: ['dist/**'] } },
        });
        writeFile(project, 'producer.txt', producer);
        writeFile(project, 'build.mjs', concurrentCachePayloadScript());
        return { producer, project };
      });
      fs.mkdirSync(path.join(context.projectRoot, 'barrier'));
    },
    processes(context) {
      return context.state.projects.map(({ producer, project }) => ({
        label: producer,
        cwd: project,
        args: ['run', 'build'],
      }));
    },
    async validate(context) {
      const cacheRoot = path.join(context.lpmHome, 'cache/tasks');
      const entries = fs.readdirSync(cacheRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && /^[a-f0-9]+$/i.test(entry.name));
      if (entries.length !== 1) {
        return { ok: false, reason: `expected one cache entry, found ${entries.length}` };
      }

      const verifier = context.state.projects[0];
      fs.rmSync(path.join(verifier.project, 'dist'), { recursive: true, force: true });
      const executionCounter = path.join(verifier.project, '.lpm-bench-cache-executed');
      const executionsBefore = fs.statSync(executionCounter).size;
      const restored = runPreparationCommand(context, verifier.project, ['run', 'build']);
      const executionsAfter = fs.statSync(executionCounter).size;
      if (executionsAfter !== executionsBefore) {
        return { ok: false, reason: 'cache verifier executed the build script instead of restoring' };
      }
      const marker = markerContractOutput(`${restored.stdout}\n${restored.stderr}`, { scenario: scenarioId });
      if (!marker.ok) return marker;
      const payloadPath = path.join(verifier.project, 'dist/payload.bin');
      if (!fs.existsSync(payloadPath)) return { ok: false, reason: 'published cache entry did not restore its payload' };
      const expectedByte = marker.actual.producer === 'first' ? 0x31 : marker.actual.producer === 'second' ? 0x32 : -1;
      const payload = expectedByte >= 0
        ? await validateRepeatedByteFile(payloadPath, expectedByte)
        : { bytes: 0, matches: false };
      const ok = payload.bytes === 8 * MiB && payload.matches;
      return {
        ok,
        reason: ok ? null : `published cache payload did not match producer ${marker.actual.producer}`,
        producer: marker.actual.producer,
        restored_bytes: payload.bytes,
      };
    },
  };
}

function devSingleScenario() {
  return devScenario('dev/single-service-no-lpm-json', async (context) => {
    const port = await reservePort();
    context.ports.push(port);
    context.state.port = port;
    writePackage(context.projectRoot, {
      name: 'runtime-dev-single',
      private: true,
      scripts: { dev: 'node server.mjs' },
    });
    writeFile(context.projectRoot, 'server.mjs', httpServerScript('single-dev'));
  }, (context) => ['dev', '--no-open', '--no-install', '--port', String(context.state.port)],
  async (context) => waitForJsonEndpoint(context.state.port, { scenario: 'single-dev' }));
}

function devMultiScenario() {
  return devScenario('dev/multi-service-dependency-readiness', async (context) => {
    const apiPort = await reservePort();
    const webPort = await reservePort();
    context.ports.push(apiPort, webPort);
    Object.assign(context.state, { apiPort, webPort });
    writePackage(context.projectRoot, { name: 'runtime-dev-multi', private: true });
    writeJson(path.join(context.projectRoot, 'lpm.json'), {
      environments: { benchmark: { file: '.env.benchmark' } },
      services: {
        api: { command: 'node service.mjs api', port: apiPort, readyPort: apiPort, env: { SERVICE_ENV: 'api' } },
        web: {
          command: 'node service.mjs web',
          port: webPort,
          readyPort: webPort,
          dependsOn: ['api'],
          env: { SERVICE_ENV: 'web' },
          primary: true,
        },
      },
    });
    writeFile(context.projectRoot, '.env.benchmark', 'RUNTIME_BENCH_ENV=explicit-dev\n');
    writeFile(context.projectRoot, 'service.mjs', multiServiceScript(apiPort));
  }, (context) => ['dev', '--no-open', '--no-install', '--env', 'benchmark'], async (context) => {
    return waitForJsonEndpoint(context.state.webPort, { scenario: 'multi-dev' });
  }, async (_context, result) => {
    const payload = result.readiness;
    const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
    const ok = payload.service === 'web' && payload.env === 'explicit-dev' && payload.service_env === 'web' && payload.api_ready && clean;
    return { ok, reason: ok ? null : `multi-service env, dependency, or cleanup contract failed: ${JSON.stringify(payload)}` };
  });
}

function devGraphScenario(serviceCount, shape, fullOnly = false) {
  const readinessTimeoutMs = graphReadinessTimeoutMs(serviceCount, shape);
  const scenario = devScenario(`dev/${shape}-${serviceCount}-services`, async (context) => {
    const services = {};
    for (let index = 0; index < serviceCount; index += 1) {
      const name = `service-${String(index).padStart(2, '0')}`;
      const port = await reservePort();
      context.ports.push(port);
      services[name] = {
        command: `node graph-service.mjs ${name}`,
        port,
        readyPort: port,
        ...(index === serviceCount - 1 ? { primary: true } : {}),
        ...(shape === 'deep' && index > 0
          ? { dependsOn: [`service-${String(index - 1).padStart(2, '0')}`] }
          : {}),
      };
    }
    context.state.graphServices = Object.entries(services).map(([service, config]) => ({
      service,
      port: config.port,
    }));
    writePackage(context.projectRoot, { name: `runtime-${shape}-${serviceCount}`, private: true });
    writeJson(path.join(context.projectRoot, 'lpm.json'), { services });
    writeFile(context.projectRoot, 'graph-service.mjs', graphServiceScript(shape, serviceCount));
  }, () => ['dev', '--no-open', '--no-install'], async (context) => {
    const ready = await Promise.all(context.state.graphServices.map(({ service, port }) =>
      waitForJsonEndpoint(port, { shape, service_count: serviceCount, service }, readinessTimeoutMs)));
    return { shape, service_count: serviceCount, ready_services: ready.length };
  });
  scenario.fullOnly = fullOnly;
  return scenario;
}

function graphReadinessTimeoutMs(serviceCount, shape) {
  return shape === 'deep' ? Math.max(8_000, serviceCount * 500) : 8_000;
}

function concurrentDifferentRuntimeScenario() {
  const nodeVersion = process.version.slice(1);
  const bunVersion = '1.3.14';
  return {
    id: 'concurrency/two-projects-different-selectors',
    kind: 'run',
    allowRuntimeInstall: false,
    async prepare(context) {
      const nodeProject = path.join(context.projectRoot, 'node-project');
      const bunProject = path.join(context.projectRoot, 'bun-project');
      for (const [project, runtime, version, value] of [
        [nodeProject, 'node', nodeVersion, 'node-project'],
        [bunProject, 'bun', bunVersion, 'bun-project'],
      ]) {
        writePackage(project, { name: value, private: true, scripts: { probe: `${runtime} probe.mjs` } });
        writeJson(path.join(project, 'lpm.json'), { runtime: { [runtime]: version }, env: { probe: '.env.concurrent' } });
        writeFile(project, '.env.concurrent', `RUNTIME_BENCH_ENV=${value}\n`);
        writeFile(project, 'probe.mjs', resultScript({ scenario: value, env: ['RUNTIME_BENCH_ENV'] }));
      }
      installManagedRuntime(context.lpmHome, 'node', nodeVersion);
      installManagedRuntime(context.lpmHome, 'bun', bunVersion);
      Object.assign(context.state, { nodeProject, bunProject });
    },
    processes(context) {
      return [
        { label: 'node-project', cwd: context.state.nodeProject, args: ['run', 'probe'] },
        { label: 'bun-project', cwd: context.state.bunProject, args: ['run', 'probe'] },
      ];
    },
    async validate(_context, result) {
      const node = markerContractForProcess(result, 'node-project', {
        scenario: 'node-project', env: { RUNTIME_BENCH_ENV: 'node-project' }, selected_runtime: `node@${nodeVersion}`,
      });
      const bun = markerContractForProcess(result, 'bun-project', {
        scenario: 'bun-project', env: { RUNTIME_BENCH_ENV: 'bun-project' }, engine: 'bun', runtime_version: bunVersion,
      });
      return node.ok && bun.ok ? { ok: true } : { ok: false, reason: node.reason ?? bun.reason };
    },
  };
}

function concurrentProjectScaleScenario(projectCount, fullOnly = false) {
  const nodeVersion = process.version.slice(1);
  return {
    id: `concurrency/${projectCount}-projects-managed-node-env`,
    kind: 'run',
    fullOnly,
    allowRuntimeInstall: false,
    async prepare(context) {
      installManagedRuntime(context.lpmHome, 'node', nodeVersion);
      context.state.projects = [];
      for (let index = 0; index < projectCount; index += 1) {
        const label = `project-${index}`;
        const project = path.join(context.projectRoot, label);
        writePackage(project, { name: label, private: true, scripts: { probe: 'node probe.mjs' } });
        writeJson(path.join(project, 'lpm.json'), {
          runtime: { node: nodeVersion },
          env: { probe: '.env.concurrent' },
        });
        writeFile(project, '.env.concurrent', `RUNTIME_BENCH_ENV=${label}\n`);
        writeFile(project, 'probe.mjs', resultScript({ scenario: label, env: ['RUNTIME_BENCH_ENV'] }));
        context.state.projects.push({ project, label });
      }
    },
    processes(context) {
      return context.state.projects.map(({ project, label }) => ({
        label,
        cwd: project,
        args: ['run', 'probe'],
      }));
    },
    async validate(context, result) {
      for (const { label } of context.state.projects) {
        const contract = markerContractForProcess(result, label, {
          scenario: label,
          env: { RUNTIME_BENCH_ENV: label },
          selected_runtime: `node@${nodeVersion}`,
        });
        if (!contract.ok) return contract;
      }
      return { ok: true };
    },
  };
}

function concurrentFirstInstallScenario() {
  const version = '99.0.0';
  return {
    id: 'concurrency/shared-home-first-node-install',
    kind: 'run',
    allowRuntimeInstall: true,
    async prepare(context) {
      const archive = createFakeNodeArchive(context.workRoot, version);
      const requests = [];
      const server = http.createServer((request, response) => {
        requests.push({ url: request.url, bytes: 0 });
        if (request.url?.endsWith('/SHASUMS256.txt')) {
          const body = `${archive.sha256}  ${archive.name}\n`;
          response.end(body);
          requests.at(-1).bytes = Buffer.byteLength(body);
        } else if (request.url?.endsWith(`/${archive.name}`)) {
          setTimeout(() => {
            response.end(archive.bytes);
            requests.findLast((entry) => entry.url === request.url && entry.bytes === 0).bytes = archive.bytes.length;
          }, 250);
        } else {
          response.statusCode = 404;
          response.end('unexpected benchmark request');
        }
      });
      await listen(server);
      context.cleanup.push(() => closeServer(server));
      const origin = `http://127.0.0.1:${server.address().port}`;
      fs.mkdirSync(path.join(context.lpmHome, 'runtimes'), { recursive: true });
      writeJson(path.join(context.lpmHome, 'runtimes/index-cache.json'), [{
        version: `v${version}`,
        date: '2099-01-01',
        lts: false,
        dist_base_url: origin,
      }]);
      const first = path.join(context.projectRoot, 'first');
      const second = path.join(context.projectRoot, 'second');
      for (const [project, label] of [[first, 'first-install'], [second, 'second-install']]) {
        writePackage(project, { name: label, private: true, scripts: { probe: 'node --version' } });
        writeJson(path.join(project, 'lpm.json'), { runtime: { node: version } });
      }
      Object.assign(context.state, { first, second, requests, archive });
    },
    processes(context) {
      return [
        { label: 'first-install', cwd: context.state.first, args: ['run', 'probe'] },
        { label: 'second-install', cwd: context.state.second, args: ['run', 'probe'] },
      ];
    },
    async validate(context, result) {
      const archiveRequests = context.state.requests.filter((request) => request.url.endsWith(context.state.archive.name));
      const installed = path.join(context.lpmHome, 'runtimes/node/99.0.0/bin/node');
      const outputs = combinedOutput(result);
      const ok = archiveRequests.length === 1 && fs.existsSync(installed) && outputs.includes('v99.0.0');
      return {
        ok,
        reason: ok ? null : `archive requests=${archiveRequests.length}, installed=${fs.existsSync(installed)}`,
        runtime_requests: context.state.requests,
        runtime_download_count: archiveRequests.length,
        runtime_download_bytes: archiveRequests.reduce((sum, request) => sum + request.bytes, 0),
      };
    },
  };
}

function cleanupDescendantScenario() {
  return devScenario('cleanup/multiservice-descendant-sigterm', async (context) => {
    const port = await reservePort();
    context.ports.push(port);
    context.state.port = port;
    writePackage(context.projectRoot, { name: 'runtime-cleanup', private: true });
    writeJson(path.join(context.projectRoot, 'lpm.json'), {
      services: {
        parent: { command: 'node parent.mjs', port, readyPort: port, primary: true },
      },
    });
    writeFile(context.projectRoot, 'parent.mjs', descendantParentScript());
    writeFile(context.projectRoot, 'descendant.mjs', httpServerScript('descendant'));
  }, () => ['dev', '--no-open', '--no-install'], async (context) => {
    const payload = await waitForJsonEndpoint(context.state.port, { scenario: 'descendant' });
    const pidFile = path.join(context.projectRoot, 'descendant.pid');
    await waitFor(() => fs.existsSync(pidFile), 2_000, 'descendant pid file');
    context.state.descendantPid = Number(fs.readFileSync(pidFile, 'utf8'));
    return payload;
  }, async (context, result) => {
    const identity = result.metrics.surviving_processes.find((process) => process.pid === context.state.descendantPid);
    const portSurvived = result.metrics.surviving_ports.includes(context.state.port);
    return identity || portSurvived
      ? { ok: false, reason: `descendant survived: pid=${Boolean(identity)} port=${portSurvived}` }
      : { ok: true };
  });
}

function restartCrashCycleScenario() {
  return devScenario('recovery/crash-cycles-resistant-descendants', async (context) => {
    const readyPort = await reservePort();
    const descendantPorts = [];
    for (let index = 0; index < 2; index += 1) descendantPorts.push(await reservePort());
    context.ports.push(readyPort, ...descendantPorts);
    Object.assign(context.state, { readyPort, descendantPorts });
    writePackage(context.projectRoot, { name: 'runtime-restart-cycles', private: true });
    writeJson(path.join(context.projectRoot, 'lpm.json'), {
      services: {
        worker: {
          command: `node restart-root.mjs ${readyPort} ${descendantPorts.join(' ')}`,
          port: readyPort,
          readyPort,
          readyTimeout: 10,
          restart: true,
          primary: true,
        },
      },
    });
    writeFile(context.projectRoot, 'restart-root.mjs', restartRootScript());
    writeFile(context.projectRoot, 'resistant-descendant.mjs', resistantDescendantScript());
    context.cleanup.push(() => {
      for (const name of fs.readdirSync(context.projectRoot)) {
        if (!/^descendant-\d+\.pid$/.test(name)) continue;
        const pid = Number(fs.readFileSync(path.join(context.projectRoot, name), 'utf8'));
        if (Number.isInteger(pid)) safeKill(pid, 'SIGKILL');
      }
    });
  }, () => ['dev', '--no-open', '--no-install'], async (context) => {
    const payload = await waitForJsonEndpoint(context.state.readyPort, { scenario: 'restart-cycle' });
    await waitFor(() => fs.existsSync(path.join(context.projectRoot, 'attempt-count')), 2_000, 'restart attempt count');
    context.state.attemptCount = Number(fs.readFileSync(path.join(context.projectRoot, 'attempt-count'), 'utf8'));
    return payload;
  }, async (context, result) => {
    const descendantPids = fs.readdirSync(context.projectRoot)
      .filter((name) => /^descendant-\d+\.pid$/.test(name))
      .map((name) => Number(fs.readFileSync(path.join(context.projectRoot, name), 'utf8')));
    const survivingPids = descendantPids.filter(processExists);
    const clean = result.metrics.surviving_ports.length === 0 && survivingPids.length === 0;
    const ok = context.state.attemptCount >= 3 && descendantPids.length === 2 && clean;
    return {
      ok,
      reason: ok ? null : `restart attempts=${context.state.attemptCount}, descendant pids=${descendantPids}, surviving pids=${survivingPids}`,
      restart_attempts: context.state.attemptCount,
      resistant_descendant_pids: descendantPids,
      surviving_resistant_descendant_pids: survivingPids,
    };
  });
}

function newlineFreeScenario() {
  const outputBytes = 4 * MiB;
  const digest = crypto.createHash('sha256').update(Buffer.alloc(outputBytes, 'x')).digest('hex');
  return devScenario('output/newline-free-ready', async (context) => {
    const port = await reservePort();
    context.ports.push(port);
    context.state.port = port;
    writePackage(context.projectRoot, { name: 'runtime-newline-free', private: true });
    writeJson(path.join(context.projectRoot, 'lpm.json'), {
      services: { noisy: { command: 'node noisy.mjs', port, readyPort: port, primary: true } },
    });
    writeFile(context.projectRoot, 'noisy.mjs', newlineFreeServerScript(outputBytes, digest));
  }, () => ['dev', '--no-open', '--no-install'], async (context) => {
    const payload = await waitForJsonEndpoint(context.state.port, { scenario: 'newline-free' });
    await waitFor(() => fs.existsSync(path.join(context.projectRoot, 'output-proof.json')), 2_000, 'output proof');
    return payload;
  }, async (context, result) => {
    const proof = JSON.parse(fs.readFileSync(path.join(context.projectRoot, 'output-proof.json'), 'utf8'));
    const retained = result.processes.reduce((sum, process) => sum + process.stdout.retained_bytes + process.stderr.retained_bytes, 0);
    const ok = proof.bytes === outputBytes && proof.sha256 === digest && retained <= STREAM_RETAIN_BYTES * 2;
    return { ok, reason: ok ? null : 'newline-free output proof or harness retention limit failed', output_proof: proof, retained_bytes: retained };
  });
}

function largeReadinessResponseScenario(responseMiB, fullOnly = false) {
  const scenario = devScenario(`readiness/http-${responseMiB}-mib-body`, async (context) => {
    const port = await reservePort();
    context.ports.push(port);
    context.state.port = port;
    writePackage(context.projectRoot, { name: `runtime-readiness-${responseMiB}-mib`, private: true });
    writeJson(path.join(context.projectRoot, 'lpm.json'), {
      services: {
        web: {
          command: `node readiness-response.mjs ${responseMiB}`,
          port,
          readyUrl: `http://127.0.0.1:${port}/ready`,
          readyTimeout: 10,
          primary: true,
        },
      },
    });
    writeFile(context.projectRoot, 'readiness-response.mjs', largeReadinessResponseScript());
  }, () => ['dev', '--no-open', '--no-install'], async (context) => {
    return waitForJsonEndpoint(context.state.port, { scenario: 'large-readiness', response_mib: responseMiB });
  });
  scenario.fullOnly = fullOnly;
  return scenario;
}

function tunnelManagedNodeEnvMultiScenario() {
  const nodeVersion = process.version.slice(1);
  return {
    id: 'tunnel/managed-node-env-multi-service',
    kind: 'dev',
    fullOnly: true,
    allowRuntimeInstall: false,
    async prepare(context) {
      const apiPort = await reservePort();
      const webPort = await reservePort();
      context.ports.push(apiPort, webPort);
      Object.assign(context.state, { apiPort, webPort });
      writePackage(context.projectRoot, { name: 'runtime-tunnel-managed-multi', private: true });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        runtime: { node: nodeVersion },
        environments: { benchmark: { file: '.env.benchmark' } },
        services: {
          api: { command: 'node service.mjs api', port: apiPort, readyPort: apiPort, env: { SERVICE_ENV: 'api' } },
          web: {
            command: 'node service.mjs web',
            port: webPort,
            readyPort: webPort,
            dependsOn: ['api'],
            env: { SERVICE_ENV: 'web' },
            primary: true,
          },
        },
      });
      writeFile(context.projectRoot, '.env.benchmark', 'RUNTIME_BENCH_ENV=tunnel-managed-env\n');
      writeFile(context.projectRoot, 'service.mjs', multiServiceScript(apiPort));
      installManagedRuntime(context.lpmHome, 'node', nodeVersion);
      const relay = await startFakeRelay([{ method: 'GET', url: '/' }]);
      context.cleanup.push(relay.close);
      context.state.relay = relay;
    },
    processes(context) {
      return [{
        label: 'tunnel-managed-multi',
        args: ['dev', '--tunnel', '--env', 'benchmark', '--no-inspect', '--no-open', '--no-install'],
        env: {
          LPM_TOKEN: 'runtime-readiness-token',
          LPM_TUNNEL_RELAY: context.state.relay.url,
        },
      }];
    },
    async waitReady(context) {
      const payload = await waitForJsonEndpoint(context.state.webPort, {
        scenario: 'multi-dev',
        service: 'web',
        env: 'tunnel-managed-env',
        service_env: 'web',
        api_ready: true,
      });
      await waitFor(() => context.state.relay.responses === 1, 8_000, 'managed multi-service tunnel response');
      return payload;
    },
    async validate(context, result) {
      const credential = relayCredentialContract(context.state.relay);
      const response = context.state.relay.responseMessages.get('runtime-readiness-0');
      const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
      const ok = credential.ok && response?.status === 200 && clean;
      return {
        ok,
        reason: ok ? null : `managed runtime, env, multi-service tunnel, credential, or cleanup contract failed: credential=${credential.reason}, status=${response?.status}, clean=${clean}`,
        relay_credential: credential,
      };
    },
  };
}

function tunnelResponseScenario(responseMiB, fullOnly = false, responseCount = 1) {
  return {
    id: `tunnel/response-${responseMiB}-mib${responseCount === 1 ? '' : `-${responseCount}-concurrent`}`,
    kind: 'dev',
    fullOnly,
    allowRuntimeInstall: false,
    async prepare(context) {
      const port = await reservePort();
      context.ports.push(port);
      context.state.port = port;
      writePackage(context.projectRoot, { name: `runtime-tunnel-${responseMiB}-mib`, private: true });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        services: { web: { command: `node tunnel-response.mjs ${responseMiB}`, port, readyPort: port, primary: true } },
      });
      writeFile(context.projectRoot, 'tunnel-response.mjs', tunnelResponseScript());
      const relay = await startFakeRelay(Array.from({ length: responseCount }, () => ({ method: 'GET', url: '/large' })));
      context.cleanup.push(relay.close);
      context.state.relay = relay;
    },
    processes(context) {
      return [{
        label: 'tunnel-response',
        args: [
          'dev', '--tunnel', '--no-inspect', '--no-open', '--no-install',
        ],
        env: {
          LPM_TOKEN: 'runtime-readiness-token',
          LPM_TUNNEL_RELAY: context.state.relay.url,
        },
      }];
    },
    async waitReady(context) {
      await waitForJsonEndpoint(context.state.port, { scenario: 'tunnel-response', response_mib: responseMiB });
      await waitFor(() => context.state.relay.responses >= responseCount, 30_000, 'large tunnel responses');
      return { scenario: 'tunnel-response', response_mib: responseMiB, response_count: responseCount, relay_responses: context.state.relay.responses };
    },
    async validate(context, result) {
      const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
      const expectedBytes = responseMiB * 1024 * 1024;
      const expectedDigest = crypto.createHash('sha256').update(Buffer.alloc(expectedBytes, 'x')).digest('hex');
      const responses = Array.from({ length: responseCount }, (_, index) =>
        context.state.relay.responseMessages.get(`runtime-readiness-${index}`));
      const credential = relayCredentialContract(context.state.relay);
      const ok = credential.ok && context.state.relay.responses === responseCount
        && responses.every((response) => response?.status === 200
          && response?.decoded_bytes === expectedBytes
          && response?.sha256 === expectedDigest)
        && clean;
      return {
        ok,
        reason: ok ? null : `large tunnel responses invalid: ${JSON.stringify(responses)}, count=${context.state.relay.responses}, clean=${clean}, credential=${credential.reason}`,
        relay_credential: credential,
      };
    },
  };
}

function tunnelFairnessScenario() {
  return {
    id: 'tunnel/slow-fast-fairness',
    kind: 'dev',
    fullOnly: true,
    allowRuntimeInstall: false,
    async prepare(context) {
      const port = await reservePort();
      context.ports.push(port);
      context.state.port = port;
      writePackage(context.projectRoot, { name: 'runtime-tunnel-fairness', private: true });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        services: { web: { command: 'node tunnel-fairness.mjs', port, readyPort: port, primary: true } },
      });
      writeFile(context.projectRoot, 'tunnel-fairness.mjs', tunnelFairnessScript());
      const relay = await startFakeRelay([
        { method: 'GET', url: '/slow' },
        { method: 'GET', url: '/fast' },
      ]);
      context.cleanup.push(relay.close);
      context.state.relay = relay;
    },
    processes(context) {
      return [{
        label: 'tunnel-fairness',
        args: [
          'dev', '--tunnel', '--no-inspect', '--no-open', '--no-install',
        ],
        env: {
          LPM_TOKEN: 'runtime-readiness-token',
          LPM_TUNNEL_RELAY: context.state.relay.url,
        },
      }];
    },
    async waitReady(context) {
      await waitForJsonEndpoint(context.state.port, { scenario: 'tunnel-fairness' });
      await waitFor(() => context.state.relay.responseIds.includes('runtime-readiness-1'), 4_000, 'fast tunneled response');
      context.state.fastResponseMs = context.state.relay.responseTimes.get('runtime-readiness-1');
      return { scenario: 'tunnel-fairness', fast_response_ms: context.state.fastResponseMs };
    },
    async validate(context, result) {
      const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
      const fastBeforeSlow = context.state.relay.responseIds[0] === 'runtime-readiness-1';
      const promptly = context.state.fastResponseMs < 750;
      const credential = relayCredentialContract(context.state.relay);
      const ok = credential.ok && fastBeforeSlow && promptly && clean;
      return {
        ok,
        reason: ok ? null : `response order=${context.state.relay.responseIds}, fast response=${context.state.fastResponseMs}ms, clean=${clean}, credential=${credential.reason}`,
        response_order: context.state.relay.responseIds,
        fast_response_ms: context.state.fastResponseMs,
        relay_credential: credential,
      };
    },
  };
}

function tunnelWebSocketLifecycleScenario() {
  const token = `runtime-readiness-ws-${crypto.randomBytes(16).toString('hex')}`;
  return {
    id: 'tunnel/websocket-fairness-close-cancellation',
    kind: 'dev',
    fullOnly: true,
    allowRuntimeInstall: false,
    async prepare(context) {
      writePackage(context.projectRoot, { name: 'runtime-tunnel-websocket', private: true });
      const local = await startLocalWebSocketFixture();
      const relay = await startFakeWebSocketRelay();
      context.cleanup.push(local.close, relay.close);
      Object.assign(context.state, { local, relay, token });
    },
    processes(context) {
      return [{
        label: 'tunnel-websocket',
        args: ['tunnel', String(context.state.local.port), '--no-inspect'],
        env: {
          LPM_TOKEN: context.state.token,
          LPM_TUNNEL_RELAY: context.state.relay.url,
        },
      }];
    },
    async waitReady(context) {
      await waitFor(() => {
        const { local, relay } = context.state;
        return relay.localPriorityAt > 0
          && local.activeClosedAt > 0
          && local.pendingConnections === 1;
      }, 8_000, 'WebSocket fairness, relay close, and pending upgrade');
      return {
        scenario: 'tunnel-websocket',
        local_priority_ms: context.state.relay.localPriorityAt - context.state.relay.readyAt,
        relay_close_ms: context.state.local.activeClosedAt - context.state.relay.closeSentAt,
      };
    },
    async validate(context, result) {
      await waitFor(() => context.state.local.pendingConnections === 0, 1_000, 'pending local WebSocket cancellation');
      await waitFor(() => context.state.relay.socketCount === 0, 1_000, 'relay WebSocket shutdown');
      const credential = relayCredentialContract(context.state.relay, context.state.token);
      const clean = result.metrics.surviving_processes.length === 0
        && result.metrics.surviving_ports.length === 0
        && context.state.local.activeConnections === 0
        && context.state.local.pendingConnections === 0
        && context.state.relay.socketCount === 0;
      const localPriorityMs = context.state.relay.localPriorityAt - context.state.relay.readyAt;
      const relayCloseMs = context.state.local.activeClosedAt - context.state.relay.closeSentAt;
      const artifactsClean = !directoryContains(context.artifactDir, Buffer.from(context.state.token));
      const ok = credential.ok
        && context.state.relay.textFrames.includes('local-priority')
        && context.state.relay.binaryFrames.includes('local-binary')
        && context.state.local.relayTextFrames >= 32
        && context.state.local.relayBinaryFrames >= 32
        && localPriorityMs >= 0
        && localPriorityMs < 750
        && relayCloseMs >= 0
        && relayCloseMs < 750
        && context.state.local.pendingClosed === 1
        && artifactsClean
        && clean;
      return {
        ok,
        reason: ok ? null : `WebSocket contract failed: localPriorityMs=${localPriorityMs}, relayCloseMs=${relayCloseMs}, text=${context.state.local.relayTextFrames}, binary=${context.state.local.relayBinaryFrames}, pendingClosed=${context.state.local.pendingClosed}, artifactsClean=${artifactsClean}, clean=${clean}, credential=${credential.reason}`,
        relay_credential: credential,
        local_priority_ms: localPriorityMs,
        relay_close_ms: relayCloseMs,
        pending_upgrade_closed: context.state.local.pendingClosed === 1,
        token_absent_from_artifacts: artifactsClean,
      };
    },
  };
}

function tunnelDashboardScenario() {
  return {
    id: 'tunnel-dashboard/local-relay-burst-pty',
    kind: 'dev',
    fullOnly: true,
    requiresPty: true,
    allowRuntimeInstall: false,
    async prepare(context) {
      const port = await reservePort();
      context.ports.push(port);
      context.state.port = port;
      writePackage(context.projectRoot, { name: 'runtime-tunnel-dashboard', private: true });
      writeJson(path.join(context.projectRoot, 'lpm.json'), {
        services: { web: { command: 'node server.mjs', port, readyPort: port, primary: true } },
      });
      writeFile(context.projectRoot, 'server.mjs', httpServerScript('tunnel-dashboard'));
      const relay = await startFakeRelay(Array.from({ length: 64 }, () => ({ method: 'GET', url: '/' })));
      context.cleanup.push(relay.close);
      context.state.relay = relay;
    },
    processes(context) {
      const command = [
        context.binary.path, 'dev', '--tunnel', '--dashboard',
        '--no-open', '--no-install', '--no-inspect',
      ];
      const script = findExecutable('script');
      if (process.platform === 'darwin') {
        return [{ label: 'dashboard-pty', executable: script, args: ['-q', '/dev/null', ...command], env: { LPM_TOKEN: 'runtime-readiness-token', LPM_TUNNEL_RELAY: context.state.relay.url } }];
      }
      return [{
        label: 'dashboard-pty',
        executable: script,
        args: ['--quiet', '--return', '--command', shellJoin(command), '/dev/null'],
        env: { LPM_TOKEN: 'runtime-readiness-token', LPM_TUNNEL_RELAY: context.state.relay.url },
      }];
    },
    async waitReady(context) {
      await waitForJsonEndpoint(context.state.port, { scenario: 'tunnel-dashboard' });
      await waitFor(() => context.state.relay.responses >= 64, 8_000, 'relay response burst');
      return { scenario: 'tunnel-dashboard', relay_responses: context.state.relay.responses };
    },
    metricRootPids(context, tree) {
      return tree
        .filter((process) => processRunsExecutable(process, context.binary.path))
        .map((process) => process.pid);
    },
    async signalTargets(context, snapshot) {
      const exact = this.metricRootPids(context, snapshot.processes);
      if (exact.length !== 1) throw new Error(`expected one lpm process below PTY, found ${exact.length}`);
      return exact;
    },
    async validate(context, result) {
      const relay = context.state.relay;
      const credential = relayCredentialContract(relay);
      const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
      const statuses = [...relay.responseMessages.values()].map((response) => response.status);
      const successful = statuses.filter((status) => status === 200).length;
      const shed = statuses.filter((status) => status === 503).length;
      return {
        ok: credential.ok && relay.responses === 64 && successful >= 4 && successful + shed === 64 && clean,
        reason: credential.ok && relay.responses === 64 && successful >= 4 && successful + shed === 64 && clean ? null : 'local relay, credential, forwarding-capacity, explicit load-shedding, burst, or cleanup contract failed',
        relay: { request_url: relay.requestUrl, authorization: credential.authorization, responses: relay.responses },
        response_statuses: { successful, shed },
      };
    },
  };
}

function runScenario(id, prepare, args, validate) {
  return {
    id,
    kind: 'run',
    allowRuntimeInstall: false,
    prepare,
    processes: (context) => [{ args: typeof args === 'function' ? args(context) : args }],
    validate: async (_context, result) => validate(result),
  };
}

function devScenario(id, prepare, args, waitReady, validate = null) {
  return {
    id,
    kind: 'dev',
    allowRuntimeInstall: false,
    prepare,
    processes: (context) => [{ args: args(context) }],
    waitReady,
    validate: validate ?? (async (_context, result) => {
      const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
      if (result.metrics.forced_shutdown) {
        return { ok: false, reason: 'lpm exceeded the benchmark shutdown deadline and required SIGKILL' };
      }
      return clean ? { ok: true } : { ok: false, reason: 'process or listener survived lpm shutdown' };
    }),
  };
}

function benchmarkEnv(context, allowRuntimeInstall) {
  const keep = [
    'PATH', 'SHELL', 'LANG', 'LC_ALL', 'TMPDIR', 'TMP', 'TEMP', 'SystemRoot', 'WINDIR',
    'COMSPEC', 'PATHEXT', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS',
  ];
  const env = {};
  for (const key of keep) {
    if (process.env[key] != null) env[key] = process.env[key];
  }
  Object.assign(env, {
    HOME: context.homeDir,
    USERPROFILE: context.homeDir,
    LPM_HOME: context.lpmHome,
    XDG_CACHE_HOME: path.join(context.homeDir, '.cache'),
    XDG_CONFIG_HOME: path.join(context.homeDir, '.config'),
    XDG_DATA_HOME: path.join(context.homeDir, '.local/share'),
    LPM_NO_UPDATE_CHECK: '1',
    CI: '1',
  });
  if (!allowRuntimeInstall) env.LPM_NO_AUTO_INSTALL = '1';
  return env;
}

function runPreparationCommand(context, cwd, args, timeout = 30_000) {
  const result = spawnSync(context.binary.path, args, {
    cwd,
    env: benchmarkEnv(context, false),
    encoding: 'utf8',
    maxBuffer: 4 * MiB,
    timeout,
  });
  if (result.status !== 0) {
    throw new Error(`preparation command failed (${args.join(' ')}):\n${result.stdout ?? ''}\n${result.stderr ?? ''}`);
  }
  return result;
}

function resultScript({ scenario, env }) {
  return `const result = {scenario:${JSON.stringify(scenario)},engine:typeof Bun==='undefined'?'node':'bun',runtime_version:typeof Bun==='undefined'?process.version:Bun.version,selected_runtime:process.env.LPM_BENCH_SELECTED_RUNTIME??null,env:{}};\n${env
    .map((name) => `result.env[${JSON.stringify(name)}] = process.env[${JSON.stringify(name)}] ?? null;`)
    .join('\n')}\nconsole.log('LPM_RUNTIME_RESULT=' + JSON.stringify(result));\n`;
}

function cachePayloadScript(scenario, outputMiB) {
  return `import crypto from 'node:crypto';
import fs from 'node:fs';
const bytes=${outputMiB * MiB};
fs.appendFileSync('.lpm-bench-cache-executed','1');
fs.mkdirSync('dist',{recursive:true});
const file=fs.openSync('dist/payload.bin','w');
const hash=crypto.createHash('sha256');
const chunk=Buffer.alloc(64*1024);
let state=0x12345678;
let written=0;
while(written<bytes){const size=Math.min(chunk.length,bytes-written);for(let index=0;index<size;index+=1){state^=state<<13;state^=state>>>17;state^=state<<5;chunk[index]=state&255;}const slice=chunk.subarray(0,size);fs.writeSync(file,slice);hash.update(slice);written+=size;}
fs.closeSync(file);
console.log('LPM_RUNTIME_RESULT='+JSON.stringify({scenario:${JSON.stringify(scenario)},bytes,sha256:hash.digest('hex')}));
`;
}

function cacheManyFileScript(scenario, fileCount, fileBytes) {
  return `import fs from 'node:fs';
const fileCount=${fileCount};
const fileBytes=${fileBytes};
fs.appendFileSync('.lpm-bench-cache-executed','1');
for(let index=0;index<fileCount;index+=1){const shard=String(Math.floor(index/100)).padStart(2,'0');const name=String(index).padStart(4,'0');if(index%100===0)fs.mkdirSync('dist/'+shard,{recursive:true});fs.writeFileSync('dist/'+shard+'/file-'+name+'.bin',Buffer.alloc(fileBytes,index%251));}
console.log('LPM_RUNTIME_RESULT='+JSON.stringify({scenario:${JSON.stringify(scenario)},file_count:fileCount,file_bytes:fileBytes}));
`;
}

function cacheDeepPathScript(scenario, relativePayload, outputBytes) {
  return `import crypto from 'node:crypto';
import fs from 'node:fs';
const relativePayload=${JSON.stringify(relativePayload)};
const bytes=${outputBytes};
const payload=Buffer.alloc(bytes,0x5a);
fs.appendFileSync('.lpm-bench-cache-executed','1');
fs.mkdirSync(relativePayload.slice(0,relativePayload.lastIndexOf(${JSON.stringify(path.sep)})),{recursive:true});
fs.writeFileSync(relativePayload,payload);
console.log('LPM_RUNTIME_RESULT='+JSON.stringify({scenario:${JSON.stringify(scenario)},depth:${relativePayload.split(path.sep).length - 2},bytes,sha256:crypto.createHash('sha256').update(payload).digest('hex')}));
`;
}

function cacheStaleOutputScript(scenario) {
  return `import fs from 'node:fs';
fs.appendFileSync('.lpm-bench-cache-executed','1');
fs.mkdirSync('dist',{recursive:true});
fs.writeFileSync('dist/restored.txt','restored\\n');
console.log('LPM_RUNTIME_RESULT='+JSON.stringify({scenario:${JSON.stringify(scenario)}}));
`;
}

function validateManyFileTree(root, fileCount, fileBytes) {
  if (!fs.existsSync(root)) return { ok: false, reason: 'many-file cache hit did not restore dist', files: 0, bytes: 0 };
  const stack = [root];
  let files = 0;
  let bytes = 0;
  while (stack.length > 0) {
    const directory = stack.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        stack.push(entryPath);
        continue;
      }
      if (!entry.isFile()) {
        return { ok: false, reason: `unexpected non-file cache output: ${entryPath}`, files, bytes };
      }
      const expectedIndex = Number.parseInt(entry.name.slice(5, -4), 10);
      const content = fs.readFileSync(entryPath);
      files += 1;
      bytes += content.length;
      if (!Number.isInteger(expectedIndex)
        || content.length !== fileBytes
        || content[0] !== expectedIndex % 251
        || content[content.length - 1] !== expectedIndex % 251) {
        return { ok: false, reason: `invalid many-file cache output: ${entryPath}`, files, bytes };
      }
    }
  }
  const ok = files === fileCount && bytes === fileCount * fileBytes;
  return {
    ok,
    reason: ok ? null : `many-file output mismatch: files=${files}, bytes=${bytes}`,
    files,
    bytes,
  };
}

function concurrentCachePayloadScript() {
  return `import fs from 'node:fs';
const producer=fs.readFileSync('producer.txt','utf8').trim();
fs.appendFileSync('.lpm-bench-cache-executed','1');
const barrier='../barrier';
fs.writeFileSync(barrier+'/'+producer,'ready');
const deadline=Date.now()+5000;
while(fs.readdirSync(barrier).length<2){if(Date.now()>deadline)throw new Error('cache benchmark barrier timed out');await new Promise(resolve=>setTimeout(resolve,10));}
fs.mkdirSync('dist',{recursive:true});
const byte=producer==='first'?0x31:0x32;
fs.writeFileSync('dist/payload.bin',Buffer.alloc(8*1024*1024,byte));
console.log('LPM_RUNTIME_RESULT='+JSON.stringify({scenario:'cache/concurrent-same-key-store',producer}));
`;
}

function httpServerScript(scenario) {
  return `import http from 'node:http';\nconst scenario=${JSON.stringify(scenario)};\nconst server=http.createServer((_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario,pid:process.pid}));});\nserver.listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function multiServiceScript(apiPort) {
  return `import http from 'node:http';\nconst service=process.argv[2];\nconst port=Number(process.env.PORT);\nconst server=http.createServer(async (_req,res)=>{let apiReady=true;if(service==='web'){try{const response=await fetch('http://127.0.0.1:${apiPort}');apiReady=response.ok;}catch{apiReady=false;}}res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario:'multi-dev',service,env:process.env.RUNTIME_BENCH_ENV,service_env:process.env.SERVICE_ENV,api_ready:apiReady,pid:process.pid}));});\nserver.listen(port,'127.0.0.1');\n`;
}

function graphServiceScript(shape, serviceCount) {
  return `import http from 'node:http';\nconst shape=${JSON.stringify(shape)};\nconst serviceCount=${serviceCount};\nconst service=process.argv[2];\nhttp.createServer((_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({shape,service_count:serviceCount,service,pid:process.pid}));}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function descendantParentScript() {
  return `import {spawn} from 'node:child_process';\nimport fs from 'node:fs';\nconst child=spawn(process.execPath,['descendant.mjs'],{env:process.env,stdio:'inherit'});\nfs.writeFileSync('descendant.pid',String(child.pid));\nsetInterval(()=>{},1000);\n`;
}

function newlineFreeServerScript(outputBytes, digest) {
  return `import crypto from 'node:crypto';\nimport fs from 'node:fs';\nimport http from 'node:http';\nconst bytes=${outputBytes};\nconst block=Buffer.alloc(64*1024,'x');\nconst hash=crypto.createHash('sha256');\nlet written=0;\nwhile(written<bytes){const chunk=block.subarray(0,Math.min(block.length,bytes-written));process.stdout.write(chunk);hash.update(chunk);written+=chunk.length;}\nconst sha256=hash.digest('hex');\nfs.writeFileSync('output-proof.json',JSON.stringify({bytes:written,sha256,expected:${JSON.stringify(digest)}}));\nhttp.createServer((_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario:'newline-free',bytes:written,sha256}));}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function largeReadinessResponseScript() {
  return `import http from 'node:http';\nconst responseMiB=Number(process.argv[2]);\nconst chunk=Buffer.alloc(64*1024,'x');\nhttp.createServer((request,response)=>{response.statusCode=200;if(request.url==='/ready'){let remaining=responseMiB*1024*1024;const write=()=>{while(remaining>0){const bytes=Math.min(chunk.length,remaining);remaining-=bytes;if(!response.write(chunk.subarray(0,bytes))){response.once('drain',write);return;}}response.end();};write();return;}response.setHeader('content-type','application/json');response.end(JSON.stringify({scenario:'large-readiness',response_mib:responseMiB,pid:process.pid}));}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function restartRootScript() {
  return `import {spawn} from 'node:child_process';\nimport fs from 'node:fs';\nimport http from 'node:http';\nconst [readyPort,...descendantPorts]=process.argv.slice(2).map(Number);\nlet attempt=0;try{attempt=Number(fs.readFileSync('attempt-count','utf8'));}catch{}attempt+=1;fs.writeFileSync('attempt-count',String(attempt));\nif(attempt<=descendantPorts.length){const child=spawn(process.execPath,['resistant-descendant.mjs',String(descendantPorts[attempt-1])],{stdio:'ignore',detached:false});fs.writeFileSync('descendant-'+attempt+'.pid',String(child.pid));setTimeout(()=>process.exit(1),100);}\nelse{http.createServer((_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario:'restart-cycle',attempt,pid:process.pid}));}).listen(readyPort,'127.0.0.1');}\n`;
}

function resistantDescendantScript() {
  return `import http from 'node:http';\nprocess.on('SIGTERM',()=>{});\nhttp.createServer((_req,res)=>res.end('old')).listen(Number(process.argv[2]),'127.0.0.1');\n`;
}

function tunnelResponseScript() {
  return `import http from 'node:http';\nconst responseMiB=Number(process.argv[2]);\nconst bodyBytes=responseMiB*1024*1024;\nconst chunk=Buffer.alloc(64*1024,'x');\nhttp.createServer((request,response)=>{if(request.url==='/large'){response.setHeader('content-length',String(bodyBytes));let remaining=bodyBytes;const write=()=>{while(remaining>0){const bytes=Math.min(chunk.length,remaining);remaining-=bytes;if(!response.write(chunk.subarray(0,bytes))){response.once('drain',write);return;}}response.end();};write();return;}response.setHeader('content-type','application/json');response.end(JSON.stringify({scenario:'tunnel-response',response_mib:responseMiB,pid:process.pid}));}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function tunnelFairnessScript() {
  return `import http from 'node:http';\nhttp.createServer((request,response)=>{if(request.url==='/slow'){setTimeout(()=>response.end('slow'),1500);return;}if(request.url==='/fast'){response.end('fast');return;}response.setHeader('content-type','application/json');response.end(JSON.stringify({scenario:'tunnel-fairness',pid:process.pid}));}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function installManagedRuntime(lpmHome, runtime, version) {
  const binDir = path.join(lpmHome, 'runtimes', runtime, version, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const executable = path.join(binDir, runtime);
  const host = runtime === 'node' ? process.execPath : findExecutable('bun');
  if (!host) throw new Error(`${runtime} is required for the runtime-readiness fixture`);
  fs.writeFileSync(executable, `#!/bin/sh\nexport LPM_BENCH_SELECTED_RUNTIME=${shellQuote(`${runtime}@${version}`)}\nexec ${shellQuote(host)} \"$@\"\n`, { mode: 0o755 });
}

function createFakeNodeArchive(workRoot, version) {
  if (process.platform === 'win32') throw new Error('fake runtime archive supports Unix benchmark hosts');
  const suffix = nodePlatformSuffix();
  const top = `node-v${version}-${suffix}`;
  const archiveRoot = path.join(workRoot, 'fake-node-archive');
  const source = path.join(archiveRoot, top, 'bin');
  fs.mkdirSync(source, { recursive: true });
  fs.writeFileSync(path.join(source, 'node'), `#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo v${version}; else exec ${shellQuote(process.execPath)} \"$@\"; fi\n`, { mode: 0o755 });
  const archivePath = path.join(workRoot, `node-v${version}-${suffix}.tar.gz`);
  const tar = spawnSync('tar', ['-czf', archivePath, '-C', archiveRoot, top], {
    encoding: 'utf8',
    env: { ...process.env, COPYFILE_DISABLE: '1' },
  });
  if (tar.status !== 0) throw new Error(`failed to create fake Node archive: ${tar.stderr}`);
  const listing = spawnSync('tar', ['-tzf', archivePath], { encoding: 'utf8' });
  if (listing.status !== 0 || !listing.stdout.split('\n').some((entry) => entry === `${top}/`)) {
    throw new Error(`fake Node archive lacks an explicit top-level directory: ${listing.stderr || listing.stdout}`);
  }
  const bytes = fs.readFileSync(archivePath);
  return { name: path.basename(archivePath), bytes, sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
}

function nodePlatformSuffix() {
  const platform = process.platform === 'darwin' ? 'darwin' : process.platform;
  const arch = process.arch === 'arm64' ? 'arm64' : process.arch === 'x64' ? 'x64' : process.arch;
  return `${platform}-${arch}`;
}

function writePackage(directory, value) {
  fs.mkdirSync(directory, { recursive: true });
  writeJson(path.join(directory, 'package.json'), value);
}

function writeFile(directory, name, content) {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, name), content);
}

function markerContract(result, expected) {
  const processResult = result.processes[0];
  return markerContractOutput(`${processResult.stdout.retained}\n${processResult.stderr.retained}`, expected);
}

function markerContractForProcess(result, label, expected) {
  const processResult = result.processes.find((process) => process.label === label);
  if (!processResult) return { ok: false, reason: `missing process result for ${label}` };
  return markerContractOutput(`${processResult.stdout.retained}\n${processResult.stderr.retained}`, expected);
}

function markerContractOutput(output, expected) {
  const line = output.split(/\r?\n/).find((candidate) => {
    if (!candidate.startsWith('LPM_RUNTIME_RESULT=')) return false;
    if (expected.scenario == null) return true;
    try {
      return JSON.parse(candidate.slice('LPM_RUNTIME_RESULT='.length)).scenario === expected.scenario;
    } catch {
      return true;
    }
  });
  if (!line) return { ok: false, reason: `missing runtime result marker in ${output.slice(0, 1000)}` };
  let actual;
  try {
    actual = JSON.parse(line.slice('LPM_RUNTIME_RESULT='.length));
  } catch (error) {
    return { ok: false, reason: `invalid runtime result marker: ${error}` };
  }
  try {
    for (const [key, value] of Object.entries(expected)) assert.deepEqual(actual[key], value);
    return { ok: true, actual };
  } catch (error) {
    return { ok: false, reason: String(error), actual, expected };
  }
}

function combinedOutput(result) {
  return result.processes.map((process) => `${process.stdout.retained}\n${process.stderr.retained}`).join('\n');
}

async function waitForJsonEndpoint(port, expected, timeoutMs = 8_000) {
  return waitFor(async () => {
    try {
      const payload = await httpGetJson(port);
      for (const [key, value] of Object.entries(expected)) {
        if (payload[key] !== value) return false;
      }
      return payload;
    } catch {
      return false;
    }
  }, timeoutMs, `http://127.0.0.1:${port} readiness`);
}

function httpGetJson(port) {
  return new Promise((resolve, reject) => {
    const request = http.get({ hostname: '127.0.0.1', port, path: '/', timeout: 500 }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.once('timeout', () => request.destroy(new Error('endpoint timeout')));
    request.once('error', reject);
  });
}

async function reservePort() {
  const server = net.createServer();
  await listen(server);
  const port = server.address().port;
  await closeServer(server);
  return port;
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

function canConnect(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const done = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(250, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

async function startFakeRelay(requests) {
  let authorization = null;
  let requestUrl = '';
  let responses = 0;
  const responseIds = [];
  const responseTimes = new Map();
  const responseMessages = new Map();
  let requestsSentAt = 0;
  const server = http.createServer();
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.once('end', () => socket.destroy());
    socket.once('error', () => socket.destroy());
  });
  server.on('upgrade', (request, socket) => {
    authorization = request.headers.authorization ?? null;
    requestUrl = request.url ?? '';
    const key = request.headers['sec-websocket-key'];
    const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.write(webSocketTextFrame(JSON.stringify({
      type: 'hello',
      subdomain: 'runtime-readiness.local',
      tunnel_url: 'http://runtime-readiness.local',
      session_id: 'runtime-readiness-session',
      plan: 'free',
      base_domain: 'local',
      domain_kind: 'random',
    })));
    requestsSentAt = performance.now();
    for (const [index, relayRequest] of requests.entries()) {
      socket.write(webSocketTextFrame(JSON.stringify({
        type: 'http_request',
        id: `runtime-readiness-${index}`,
        method: relayRequest.method,
        url: relayRequest.url,
        headers: {},
        body: '',
      })));
    }
    const parser = new WebSocketFrameParser((payload, opcode) => {
      if (opcode !== 0x1 || !payload.includes(Buffer.from('"type":"http_response"'))) return;
      responses += 1;
      try {
        const message = JSON.parse(payload.toString('utf8'));
        responseIds.push(message.id);
        responseTimes.set(message.id, performance.now() - requestsSentAt);
        const body = Buffer.from(message.body ?? '', 'base64');
        responseMessages.set(message.id, {
          status: message.status,
          decoded_bytes: body.length,
          sha256: crypto.createHash('sha256').update(body).digest('hex'),
        });
      } catch {
        // A malformed response still counts toward the relay contract and is
        // diagnosed by the scenario's missing response ID.
      }
    });
    socket.on('data', (data) => {
      parser.push(data);
    });
  });
  await listen(server);
  return {
    url: `ws://127.0.0.1:${server.address().port}/connect`,
    get authorization() { return authorization; },
    get requestUrl() { return requestUrl; },
    get responses() { return responses; },
    get responseIds() { return responseIds; },
    get responseTimes() { return responseTimes; },
    get responseMessages() { return responseMessages; },
    get socketCount() { return sockets.size; },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await closeServer(server);
    },
  };
}

async function startLocalWebSocketFixture() {
  const server = http.createServer((_request, response) => {
    response.statusCode = 426;
    response.end('WebSocket upgrade required');
  });
  const sockets = new Set();
  let activeConnections = 0;
  let pendingConnections = 0;
  let pendingClosed = 0;
  let activeClosedAt = 0;
  let relayTextFrames = 0;
  let relayBinaryFrames = 0;

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.once('end', () => socket.destroy());
    socket.once('error', () => socket.destroy());
  });
  server.on('upgrade', (request, socket) => {
    if (request.url === '/pending') {
      pendingConnections += 1;
      socket.once('close', () => {
        pendingConnections -= 1;
        pendingClosed += 1;
      });
      socket.once('end', () => socket.destroy());
      socket.once('error', () => socket.destroy());
      socket.resume();
      return;
    }
    if (request.url !== '/active') {
      socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
      return;
    }

    acceptWebSocketUpgrade(request, socket);
    activeConnections += 1;
    let publishedLocalFrames = false;
    const parser = new WebSocketFrameParser((payload, opcode) => {
      if (opcode === 0x8) {
        socket.write(webSocketFrame(Buffer.alloc(0), 0x8));
        socket.end();
        return;
      }
      if (opcode !== 0x1 && opcode !== 0x2) return;
      if (!publishedLocalFrames) {
        publishedLocalFrames = true;
        socket.write(webSocketFrame(Buffer.from('local-priority'), 0x1));
        socket.write(webSocketFrame(Buffer.from('local-binary'), 0x2));
      }
      if (opcode === 0x1) relayTextFrames += 1;
      else relayBinaryFrames += 1;
      socket.write(webSocketFrame(payload, opcode));
    });
    socket.on('data', (data) => parser.push(data));
    socket.once('close', () => {
      activeConnections -= 1;
      activeClosedAt = performance.now();
    });
  });
  await listen(server);

  return {
    port: server.address().port,
    get activeConnections() { return activeConnections; },
    get pendingConnections() { return pendingConnections; },
    get pendingClosed() { return pendingClosed; },
    get activeClosedAt() { return activeClosedAt; },
    get relayTextFrames() { return relayTextFrames; },
    get relayBinaryFrames() { return relayBinaryFrames; },
    get socketCount() { return sockets.size; },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await closeServer(server);
    },
  };
}

async function startFakeWebSocketRelay() {
  let authorization = null;
  let requestUrl = '';
  let readyAt = 0;
  let localPriorityAt = 0;
  let closeSentAt = 0;
  const textFrames = [];
  const binaryFrames = [];
  const sockets = new Set();
  const server = http.createServer();

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.once('end', () => socket.destroy());
    socket.once('error', () => socket.destroy());
  });
  server.on('upgrade', (request, socket) => {
    authorization = request.headers.authorization ?? null;
    requestUrl = request.url ?? '';
    acceptWebSocketUpgrade(request, socket);
    socket.write(webSocketTextFrame(JSON.stringify({
      type: 'hello',
      subdomain: 'runtime-readiness.local',
      tunnel_url: 'http://runtime-readiness.local',
      session_id: 'runtime-readiness-websocket-session',
      plan: 'free',
      base_domain: 'local',
      domain_kind: 'random',
    })));
    socket.write(webSocketTextFrame(JSON.stringify({
      type: 'ws_upgrade',
      id: 'runtime-readiness-active',
      url: '/active',
      headers: {},
    })));

    const maybeCloseActive = () => {
      if (closeSentAt > 0
        || !textFrames.includes('local-priority')
        || !binaryFrames.includes('local-binary')
        || textFrames.filter((frame) => frame.startsWith('relay-text-')).length < 32
        || binaryFrames.filter((frame) => frame.startsWith('relay-binary-')).length < 32) return;
      closeSentAt = performance.now();
      socket.write(webSocketTextFrame(JSON.stringify({
        type: 'ws_close',
        id: 'runtime-readiness-active',
        code: 1000,
        reason: 'benchmark close',
      })));
      socket.write(webSocketTextFrame(JSON.stringify({
        type: 'ws_upgrade',
        id: 'runtime-readiness-pending',
        url: '/pending',
        headers: {},
      })));
    };
    const parser = new WebSocketFrameParser((payload, opcode) => {
      if (opcode !== 0x1) return;
      let message;
      try {
        message = JSON.parse(payload.toString('utf8'));
      } catch {
        return;
      }
      if (message.type === 'ws_ready' && message.id === 'runtime-readiness-active') {
        readyAt = performance.now();
        for (let index = 0; index < 64; index += 1) {
          const isBinary = index % 2 === 1;
          const value = `${isBinary ? 'relay-binary' : 'relay-text'}-${index}`;
          socket.write(webSocketTextFrame(JSON.stringify({
            type: 'ws_frame',
            id: 'runtime-readiness-active',
            data: Buffer.from(value).toString('base64'),
            is_binary: isBinary,
          })));
        }
        return;
      }
      if (message.type !== 'ws_frame' || message.id !== 'runtime-readiness-active') return;
      const decoded = Buffer.from(message.data ?? '', 'base64').toString('utf8');
      if (message.is_binary) binaryFrames.push(decoded);
      else textFrames.push(decoded);
      if (decoded === 'local-priority' && localPriorityAt === 0) localPriorityAt = performance.now();
      maybeCloseActive();
    });
    socket.on('data', (data) => parser.push(data));
  });
  await listen(server);

  return {
    url: `ws://127.0.0.1:${server.address().port}/connect`,
    get authorization() { return authorization; },
    get requestUrl() { return requestUrl; },
    get readyAt() { return readyAt; },
    get localPriorityAt() { return localPriorityAt; },
    get closeSentAt() { return closeSentAt; },
    get textFrames() { return textFrames; },
    get binaryFrames() { return binaryFrames; },
    get socketCount() { return sockets.size; },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await closeServer(server);
    },
  };
}

function acceptWebSocketUpgrade(request, socket) {
  const key = request.headers['sec-websocket-key'];
  if (typeof key !== 'string') {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return;
  }
  const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
}

function relayCredentialContract(relay, token = 'runtime-readiness-token') {
  const authOk = relay.authorization === `Bearer ${token}`;
  const urlOk = !relay.requestUrl.includes('token')
    && !relay.requestUrl.includes('auth=')
    && !relay.requestUrl.includes(token);
  return {
    ok: authOk && urlOk,
    reason: authOk && urlOk ? null : 'bearer token was missing from the header or leaked into the relay URL',
    request_url: relay.requestUrl,
    authorization: authOk ? '<redacted-valid-bearer>' : '<invalid>',
  };
}

function webSocketTextFrame(text) {
  return webSocketFrame(Buffer.from(text), 0x1);
}

function webSocketFrame(payload, opcode) {
  if (payload.length < 126) return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
  if (payload.length <= 0xffff) {
    const header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
    return Buffer.concat([header, payload]);
  }
  const header = Buffer.alloc(10);
  header[0] = 0x80 | opcode;
  header[1] = 127;
  header.writeBigUInt64BE(BigInt(payload.length), 2);
  return Buffer.concat([header, payload]);
}

function maskedWebSocketTextFrame(text, force64BitLength = false) {
  const payload = Buffer.from(text);
  const mask = Buffer.from([0x12, 0x34, 0x56, 0x78]);
  let header;
  if (force64BitLength) {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 0xff;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  } else if (payload.length < 126) {
    header = Buffer.from([0x81, 0x80 | payload.length]);
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0xfe;
    header.writeUInt16BE(payload.length, 2);
  }
  const masked = Buffer.from(payload);
  for (let index = 0; index < masked.length; index += 1) masked[index] ^= mask[index % 4];
  return Buffer.concat([header, mask, masked]);
}

function sampleProcessTree(rootPids, detailed, metricRootSelector = () => rootPids) {
  const processes = process.platform === 'linux' ? linuxProcesses() : macProcesses();
  const tree = descendantProcesses(processes, rootPids);
  if (detailed) enrichProcessDetails(tree);
  const metricRootPids = metricRootSelector(tree);
  return {
    process_count: tree.length,
    tree_rss_bytes: tree.reduce((sum, process) => sum + process.rss_bytes, 0),
    root_rss_bytes: metricRootPids.length > 0
      ? tree.filter((process) => metricRootPids.includes(process.pid)).reduce((sum, process) => sum + process.rss_bytes, 0)
      : null,
    fd_count: detailed ? tree.reduce((sum, process) => sum + (process.fd_count ?? 0), 0) : null,
    thread_count: detailed ? tree.reduce((sum, process) => sum + (process.thread_count ?? 0), 0) : null,
    metric_root_pids: metricRootPids,
    processes: tree,
  };
}

function linuxProcesses() {
  const processes = [];
  for (const entry of fs.readdirSync('/proc', { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) continue;
    try {
      const status = fs.readFileSync(`/proc/${entry.name}/status`, 'utf8');
      const stat = fs.readFileSync(`/proc/${entry.name}/stat`, 'utf8');
      const pid = Number(entry.name);
      const ppid = Number(/^PPid:\s+(\d+)/m.exec(status)?.[1] ?? 0);
      const rssKb = Number(/^VmRSS:\s+(\d+)/m.exec(status)?.[1] ?? 0);
      const threads = Number(/^Threads:\s+(\d+)/m.exec(status)?.[1] ?? 0);
      const closingParen = stat.lastIndexOf(')');
      const fields = stat.slice(closingParen + 2).split(' ');
      const startIdentity = fields[19];
      let command = '';
      let executable = '';
      try {
        command = fs.readFileSync(`/proc/${entry.name}/cmdline`).toString('utf8').replaceAll('\0', ' ').trim();
      } catch {
        // The status and stat files are enough for sampling.
      }
      try {
        executable = fs.readlinkSync(`/proc/${entry.name}/exe`);
      } catch {
        // Executable identity is best-effort because the process can exit.
      }
      processes.push({ pid, ppid, rss_bytes: rssKb * 1024, thread_count: threads, start_identity: startIdentity, command, executable });
    } catch {
      // A process can exit during the /proc walk.
    }
  }
  return processes;
}

function macProcesses() {
  const result = spawnSync('ps', ['-axo', 'pid=,ppid=,rss=,lstart=,command='], { encoding: 'utf8' });
  if (result.status !== 0) return [];
  const rows = [];
  for (const line of result.stdout.split('\n')) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+(.*)$/.exec(line);
    if (!match) continue;
    rows.push({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      rss_bytes: Number(match[3]) * 1024,
      start_identity: match[4],
      command: match[5],
    });
  }
  return rows;
}

function descendantProcesses(processes, roots) {
  const wanted = new Set(roots);
  let changed = true;
  while (changed) {
    changed = false;
    for (const process of processes) {
      if (!wanted.has(process.pid) && wanted.has(process.ppid)) {
        wanted.add(process.pid);
        changed = true;
      }
    }
  }
  return processes.filter((process) => wanted.has(process.pid));
}

function processRunsExecutable(process, executable) {
  const expected = canonicalPath(executable);
  if (process.executable && canonicalPath(process.executable) === expected) return true;
  const command = process.command?.trim() ?? '';
  return [executable, shellQuote(executable), JSON.stringify(executable)]
    .some((prefix) => command === prefix || command.startsWith(`${prefix} `));
}

function canonicalPath(value) {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return path.resolve(value);
  }
}

function enrichProcessDetails(processes) {
  for (const process of processes) {
    if (process.platform === 'linux' || fs.existsSync(`/proc/${process.pid}`)) {
      try { process.fd_count = fs.readdirSync(`/proc/${process.pid}/fd`).length; } catch { process.fd_count = 0; }
      if (process.thread_count == null) {
        try { process.thread_count = fs.readdirSync(`/proc/${process.pid}/task`).length; } catch { process.thread_count = 0; }
      }
      continue;
    }
    const lsof = spawnSync('/usr/sbin/lsof', ['-nP', '-p', String(process.pid)], { encoding: 'utf8' });
    process.fd_count = lsof.status === 0 ? Math.max(0, lsof.stdout.trim().split('\n').length - 1) : 0;
    const threads = spawnSync('ps', ['-M', '-p', String(process.pid), '-o', 'pid='], { encoding: 'utf8' });
    process.thread_count = threads.status === 0 ? threads.stdout.split('\n').filter((line) => line.trim()).length : 0;
  }
}

function sameProcess(identity) {
  const current = process.platform === 'linux'
    ? linuxProcesses().find((process) => process.pid === identity.pid)
    : macProcesses().find((process) => process.pid === identity.pid);
  return current?.start_identity === identity.start_identity;
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function summarizeResourceSamples(samples, roots) {
  const detailed = samples.filter((sample) => sample.fd_count != null);
  const ready = samples.at(-1);
  const elapsed = samples.map((sample) => sample.elapsed_ms).filter(Number.isFinite);
  return {
    tree_peak_rss_bytes: maximum(samples.map((sample) => sample.tree_rss_bytes)),
    root_peak_rss_bytes: maximum(samples.map((sample) => sample.root_rss_bytes)),
    steady_tree_rss_bytes: ready?.tree_rss_bytes ?? 0,
    peak_process_count: maximum(samples.map((sample) => sample.process_count)),
    maximum_observed_fd_count: maximum(detailed.map((sample) => sample.fd_count)),
    maximum_observed_thread_count: maximum(detailed.map((sample) => sample.thread_count)),
    resource_sample_count: samples.length,
    resource_sample_span_ms: elapsed.length > 1 ? Math.max(...elapsed) - Math.min(...elapsed) : 0,
    detailed_sample_count: detailed.length,
    root_pids: roots,
  };
}

function maximum(values) {
  const finite = values.filter(Number.isFinite);
  return finite.length > 0 ? Math.max(...finite) : 0;
}

function summarize(rows) {
  const groups = new Map();
  for (const row of rows.filter((candidate) => candidate.counted)) {
    const key = `${row.scenario}\0${row.binary}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  return [...groups.entries()].map(([key, group]) => {
    const [scenario, binary] = key.split('\0');
    const successful = group.filter((row) => !executionFailed(row));
    return {
      scenario,
      binary,
      samples: group.length,
      successful_samples: successful.length,
      contract_passes: group.filter((row) => row.contract_ok).length,
      wall_ms: distribution(successful.map((row) => row.wall_ms)),
      startup_ms: distribution(successful.map((row) => row.startup_ms).filter(Number.isFinite)),
      shutdown_ms: distribution(successful.map((row) => row.shutdown_ms).filter(Number.isFinite)),
      tree_peak_rss_bytes: distribution(successful.map((row) => row.tree_peak_rss_bytes)),
      root_peak_rss_bytes: distribution(successful.map((row) => row.root_peak_rss_bytes)),
      steady_tree_rss_bytes: distribution(successful.map((row) => row.steady_tree_rss_bytes)),
      steady_root_rss_bytes: distribution(successful.map((row) => row.steady_root_rss_bytes)),
      peak_process_count: distribution(successful.map((row) => row.peak_process_count)),
      maximum_observed_fd_count: distribution(successful.map((row) => row.maximum_observed_fd_count)),
      maximum_observed_thread_count: distribution(successful.map((row) => row.maximum_observed_thread_count)),
    };
  }).sort((a, b) => `${a.scenario}\0${a.binary}`.localeCompare(`${b.scenario}\0${b.binary}`));
}

function summarizeComparison(rows, comparison, thresholds, expectedSamples) {
  const groups = [];
  let executionFailure = false;
  let regression = false;
  let inconclusive = false;
  for (const scenario of [...new Set(rows.filter((row) => row.counted).map((row) => row.scenario))].sort()) {
    const scenarioRows = rows.filter((row) => row.counted && row.scenario === scenario);
    const observedPairs = [];
    const performancePairs = [];
    const failures = [];
    for (let sample = 1; sample <= expectedSamples; sample += 1) {
      const baseline = scenarioRows.find((row) => row.sample === sample && row.binary === comparison.baseline);
      const candidate = scenarioRows.find((row) => row.sample === sample && row.binary === comparison.candidate);
      if (!baseline || !candidate) {
        failures.push({ sample, baseline: rowStatus(baseline), candidate: rowStatus(candidate) });
        continue;
      }
      if (baseline.pair_id !== candidate.pair_id || Math.abs(baseline.execution_sequence - candidate.execution_sequence) !== 1) {
        failures.push({ sample, baseline: 'not adjacent', candidate: 'not adjacent' });
        continue;
      }
      const pair = { sample, baseline, candidate };
      observedPairs.push(pair);
      if (runFailed(candidate)) {
        failures.push({ sample, baseline: rowStatus(baseline), candidate: rowStatus(candidate) });
        continue;
      }
      if (!runFailed(baseline)) performancePairs.push(pair);
    }
    const orders = {
      'baseline-candidate': observedPairs.filter((pair) => pair.baseline.pair_order === 'baseline-candidate').length,
      'candidate-baseline': observedPairs.filter((pair) => pair.baseline.pair_order === 'candidate-baseline').length,
    };
    const correctness = {
      baseline_failures: observedPairs.filter((pair) => runFailed(pair.baseline)).length,
      candidate_failures: observedPairs.filter((pair) => runFailed(pair.candidate)).length,
      baseline_contract_failures: observedPairs.filter((pair) => pair.baseline.contract_ok !== true).length,
      candidate_contract_failures: observedPairs.filter((pair) => pair.candidate.contract_ok !== true).length,
    };
    const performanceGates = correctness.baseline_failures === 0;
    if (correctness.baseline_failures > 0
      && correctness.candidate_failures < correctness.baseline_failures) {
      inconclusive = true;
    }
    if (Math.abs(orders['baseline-candidate'] - orders['candidate-baseline']) > 1) failures.push({ sample: 'schedule', baseline: 'imbalanced AB/BA', candidate: 'imbalanced AB/BA' });
    const kind = scenarioRows[0]?.kind;
    const metrics = {};
    const metricsForKind = kind === 'dev'
      ? [
          'startup_ms',
          'shutdown_ms',
          'tree_peak_rss_bytes',
          'root_peak_rss_bytes',
          'steady_tree_rss_bytes',
          'steady_root_rss_bytes',
          'peak_process_count',
          'maximum_observed_fd_count',
          'maximum_observed_thread_count',
        ]
      : [
          'wall_ms',
          'tree_peak_rss_bytes',
          'root_peak_rss_bytes',
          'peak_process_count',
          'maximum_observed_fd_count',
          'maximum_observed_thread_count',
        ];
    for (const metric of metricsForKind) {
      const presentPairs = performancePairs.filter((pair) => metricHasValue(pair.baseline, metric)
        && metricHasValue(pair.candidate, metric));
      if (presentPairs.length !== performancePairs.length || performancePairs.length === 0) {
        metrics[metric] = {
          verdict: 'inconclusive',
          reason: `metric is present in ${presentPairs.length}/${performancePairs.length} successful pairs`,
        };
      } else {
        const sampledPairs = presentPairs.filter((pair) => metricHasSamplingCoverage(pair.baseline, metric)
          && metricHasSamplingCoverage(pair.candidate, metric));
        metrics[metric] = sampledPairs.length === presentPairs.length
          ? compareMetric(presentPairs, metric, thresholds[metric])
          : {
              verdict: 'advisory-insufficient-sampling',
              reason: `metric has sufficient temporal sampling in ${sampledPairs.length}/${presentPairs.length} successful pairs`,
            };
      }
      if (performanceGates && metrics[metric]?.verdict === 'regression') regression = true;
      if (performanceGates && metrics[metric]?.verdict === 'inconclusive') inconclusive = true;
    }
    if (failures.length > 0) executionFailure = true;
    groups.push({
      scenario,
      expected_pairs: expectedSamples,
      observed_pairs: observedPairs.length,
      successful_pairs: performancePairs.length,
      pair_orders: orders,
      correctness,
      performance_gates: performanceGates,
      failures,
      metrics,
    });
  }
  return {
    baseline: comparison.baseline,
    candidate: comparison.candidate,
    thresholds,
    verdict: executionFailure ? 'execution-failure' : regression ? 'regression' : inconclusive ? 'inconclusive' : 'pass',
    groups,
  };
}

function metricHasValue(row, metric) {
  const value = row[metric];
  if (!Number.isFinite(value)) return false;
  if (metric === 'maximum_observed_fd_count'
    || metric === 'maximum_observed_thread_count') return value >= 0;
  return value > 0;
}

function metricHasSamplingCoverage(row, metric) {
  if (!metricHasValue(row, metric)) return false;
  if (metric === 'tree_peak_rss_bytes'
    || metric === 'root_peak_rss_bytes'
    || metric === 'peak_process_count') {
    return row.resource_sample_count >= 3
      && row.resource_sample_span_ms >= SAMPLE_INTERVAL_MS * 2;
  }
  if (metric === 'maximum_observed_fd_count'
    || metric === 'maximum_observed_thread_count') {
    return row.detailed_sample_count >= 2;
  }
  return true;
}

function compareMetric(pairs, metric, limits) {
  const baseline = distribution(pairs.map((pair) => pair.baseline[metric]));
  const candidate = distribution(pairs.map((pair) => pair.candidate[metric]));
  const deltas = pairs.map((pair) => pair.candidate[metric] - pair.baseline[metric]);
  const percentages = pairs.map((pair) => ((pair.candidate[metric] - pair.baseline[metric]) / pair.baseline[metric]) * 100);
  const delta = distribution(deltas);
  const percentage = distribution(percentages);
  const medianDelta = candidate.median - baseline.median;
  const p95Delta = candidate.p95 - baseline.p95;
  const medianPct = relativeDelta(baseline.median, candidate.median);
  const p95Pct = relativeDelta(baseline.p95, candidate.p95);
  const medianRegression = medianDelta > limits.median_abs && medianPct > limits.median_pct && delta.median - delta.mad > limits.median_abs && percentage.median - percentage.mad > limits.median_pct;
  const p95Regression = p95Delta > limits.p95_abs && p95Pct > limits.p95_pct && delta.p95 - delta.iqr > limits.p95_abs && percentage.p95 - percentage.iqr > limits.p95_pct;
  const within = (medianDelta <= limits.median_abs || medianPct <= limits.median_pct) && (p95Delta <= limits.p95_abs || p95Pct <= limits.p95_pct);
  return {
    baseline,
    candidate,
    median_delta: round(medianDelta),
    p95_delta: round(p95Delta),
    median_delta_pct: round(medianPct),
    p95_delta_pct: round(p95Pct),
    paired_delta: delta,
    paired_delta_pct: percentage,
    verdict: medianRegression || p95Regression ? 'regression' : within ? 'pass' : 'inconclusive',
  };
}

function distribution(values) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  const median = percentile(sorted, 0.5);
  const deviations = sorted.map((value) => Math.abs(value - median)).sort((a, b) => a - b);
  return {
    min: round(sorted[0]),
    median: round(median),
    p95: round(percentile(sorted, 0.95)),
    max: round(sorted.at(-1)),
    iqr: round(percentile(sorted, 0.75) - percentile(sorted, 0.25)),
    mad: round(percentile(deviations, 0.5)),
  };
}

function percentile(sorted, probability) {
  const index = (sorted.length - 1) * probability;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  return lower === upper ? sorted[lower] : sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

function relativeDelta(baseline, candidate) {
  return baseline === 0 ? 0 : ((candidate - baseline) / baseline) * 100;
}

function renderMarkdown(summary, comparison) {
  const lines = [
    '# Runtime readiness',
    '',
    `Verdict: **${comparison.verdict}**`,
    '',
    `Baseline: \`${comparison.baseline}\`. Candidate: \`${comparison.candidate}\`.`,
    '',
    '| Scenario | Performance/observed/expected pairs | Metric | Baseline median/p95 | Candidate median/p95 | Delta median/p95 | Result |',
    '| --- | ---: | --- | ---: | ---: | ---: | --- |',
  ];
  for (const group of comparison.groups) {
    for (const [metric, result] of Object.entries(group.metrics)) {
      const metricVerdict = group.performance_gates ? result.verdict : 'advisory: baseline correctness failed';
      if (!result.baseline || !result.candidate) {
        lines.push(`| ${group.scenario} | ${group.successful_pairs}/${group.observed_pairs}/${group.expected_pairs} | ${metric} | n/a | n/a | n/a | ${metricVerdict}: ${result.reason} |`);
        continue;
      }
      lines.push(`| ${group.scenario} | ${group.successful_pairs}/${group.observed_pairs}/${group.expected_pairs} | ${metric} | ${formatMetric(metric, result.baseline.median)}/${formatMetric(metric, result.baseline.p95)} | ${formatMetric(metric, result.candidate.median)}/${formatMetric(metric, result.candidate.p95)} | ${result.median_delta_pct}%/${result.p95_delta_pct}% | ${metricVerdict} |`);
    }
  }
  const transitions = comparison.groups.filter((group) => group.correctness.baseline_failures > 0);
  if (transitions.length > 0) {
    lines.push('', '## Correctness transitions', '');
    for (const group of transitions) {
      lines.push(`- ${group.scenario}: baseline failures ${group.correctness.baseline_failures}/${group.observed_pairs}; candidate failures ${group.correctness.candidate_failures}/${group.observed_pairs}. Performance deltas are advisory.`);
    }
  }
  const failures = comparison.groups.flatMap((group) => group.failures.map((failure) => ({ group, failure })));
  if (failures.length > 0) {
    lines.push('', '## Execution failures', '');
    for (const { group, failure } of failures) lines.push(`- ${group.scenario} sample ${failure.sample}: baseline=${failure.baseline}; candidate=${failure.candidate}.`);
  }
  lines.push(
    '',
    '## Distributions',
    '',
    '| Scenario | Binary | Samples | Wall | Startup | Shutdown | Tree peak RSS | Root peak RSS | Tree steady RSS | Root steady RSS | Processes | FDs | Threads |',
    '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  );
  for (const group of summary) {
    lines.push(`| ${group.scenario} | ${group.binary} | ${group.successful_samples}/${group.samples} | ${formatDistribution(group.wall_ms, 'ms')} | ${formatDistribution(group.startup_ms, 'ms')} | ${formatDistribution(group.shutdown_ms, 'ms')} | ${formatDistribution(group.tree_peak_rss_bytes, 'bytes')} | ${formatDistribution(group.root_peak_rss_bytes, 'bytes')} | ${formatDistribution(group.steady_tree_rss_bytes, 'bytes')} | ${formatDistribution(group.steady_root_rss_bytes, 'bytes')} | ${formatDistribution(group.peak_process_count, 'count')} | ${formatDistribution(group.maximum_observed_fd_count, 'count')} | ${formatDistribution(group.maximum_observed_thread_count, 'count')} |`);
  }
  return lines.join('\n');
}

function formatMetric(metric, value) {
  if (metric.endsWith('_bytes')) return formatBytes(value);
  if (metric.endsWith('_ms')) return `${value} ms`;
  return String(value);
}

function formatDistribution(value, kind) {
  if (!value) return 'n/a';
  if (kind === 'bytes') return `${formatBytes(value.median)}/${formatBytes(value.p95)}`;
  if (kind === 'ms') return `${value.median}/${value.p95} ms`;
  return `${value.median}/${value.p95}`;
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return 'n/a';
  return `${round(value / MiB)} MiB`;
}

function parseArgs(argv) {
  const parsed = { binaries: [], profile: 'pr' };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const [flag, inline] = token.split('=', 2);
    const value = () => inline ?? argv[++index];
    switch (flag) {
      case '--lpm-binary': parsed.binaries.push(value()); break;
      case '--compare': parsed.compare = value(); break;
      case '--samples': parsed.samples = value(); break;
      case '--warmups': parsed.warmups = value(); break;
      case '--scenarios': parsed.scenarios = value(); break;
      case '--profile': parsed.profile = value(); break;
      case '--timeout-ms': parsed.timeoutMs = value(); break;
      case '--output': parsed.output = value(); break;
      case '--median-regression-pct': parsed.wallMedianPct = value(); parsed.startupMedianPct = parsed.wallMedianPct; break;
      case '--p95-regression-pct': parsed.wallP95Pct = value(); parsed.startupP95Pct = parsed.wallP95Pct; break;
      case '--median-regression-ms': parsed.wallMedianAbs = value(); parsed.startupMedianAbs = parsed.wallMedianAbs; break;
      case '--p95-regression-ms': parsed.wallP95Abs = value(); parsed.startupP95Abs = parsed.wallP95Abs; break;
      case '--wall-median-regression-pct': parsed.wallMedianPct = value(); break;
      case '--wall-p95-regression-pct': parsed.wallP95Pct = value(); break;
      case '--wall-median-regression-ms': parsed.wallMedianAbs = value(); break;
      case '--wall-p95-regression-ms': parsed.wallP95Abs = value(); break;
      case '--startup-median-regression-pct': parsed.startupMedianPct = value(); break;
      case '--startup-p95-regression-pct': parsed.startupP95Pct = value(); break;
      case '--startup-median-regression-ms': parsed.startupMedianAbs = value(); break;
      case '--startup-p95-regression-ms': parsed.startupP95Abs = value(); break;
      case '--rss-median-regression-pct': parsed.rssMedianPct = value(); break;
      case '--rss-p95-regression-pct': parsed.rssP95Pct = value(); break;
      case '--rss-median-regression-mb': parsed.rssMedianAbs = Number(value()) * MiB; break;
      case '--rss-p95-regression-mb': parsed.rssP95Abs = Number(value()) * MiB; break;
      case '--root-rss-median-regression-pct': parsed.rootRssMedianPct = value(); break;
      case '--root-rss-p95-regression-pct': parsed.rootRssP95Pct = value(); break;
      case '--root-rss-median-regression-mb': parsed.rootRssMedianAbs = Number(value()) * MiB; break;
      case '--root-rss-p95-regression-mb': parsed.rootRssP95Abs = Number(value()) * MiB; break;
      case '--shutdown-median-regression-pct': parsed.shutdownMedianPct = value(); break;
      case '--shutdown-p95-regression-pct': parsed.shutdownP95Pct = value(); break;
      case '--shutdown-median-regression-ms': parsed.shutdownMedianAbs = value(); break;
      case '--shutdown-p95-regression-ms': parsed.shutdownP95Abs = value(); break;
      case '--steady-rss-median-regression-pct': parsed.steadyRssMedianPct = value(); break;
      case '--steady-rss-p95-regression-pct': parsed.steadyRssP95Pct = value(); break;
      case '--steady-rss-median-regression-mb': parsed.steadyRssMedianAbs = Number(value()) * MiB; break;
      case '--steady-rss-p95-regression-mb': parsed.steadyRssP95Abs = Number(value()) * MiB; break;
      case '--steady-root-rss-median-regression-pct': parsed.steadyRootRssMedianPct = value(); break;
      case '--steady-root-rss-p95-regression-pct': parsed.steadyRootRssP95Pct = value(); break;
      case '--steady-root-rss-median-regression-mb': parsed.steadyRootRssMedianAbs = Number(value()) * MiB; break;
      case '--steady-root-rss-p95-regression-mb': parsed.steadyRootRssP95Abs = Number(value()) * MiB; break;
      case '--process-median-regression-pct': parsed.processMedianPct = value(); break;
      case '--process-p95-regression-pct': parsed.processP95Pct = value(); break;
      case '--process-median-regression-count': parsed.processMedianAbs = value(); break;
      case '--process-p95-regression-count': parsed.processP95Abs = value(); break;
      case '--fd-median-regression-pct': parsed.fdMedianPct = value(); break;
      case '--fd-p95-regression-pct': parsed.fdP95Pct = value(); break;
      case '--fd-median-regression-count': parsed.fdMedianAbs = value(); break;
      case '--fd-p95-regression-count': parsed.fdP95Abs = value(); break;
      case '--thread-median-regression-pct': parsed.threadMedianPct = value(); break;
      case '--thread-p95-regression-pct': parsed.threadP95Pct = value(); break;
      case '--thread-median-regression-count': parsed.threadMedianAbs = value(); break;
      case '--thread-p95-regression-count': parsed.threadP95Abs = value(); break;
      case '--allow-inconclusive': parsed.allowInconclusive = true; break;
      case '--keep-work': parsed.keepWork = true; break;
      case '--dry-run': parsed.dryRun = true; break;
      case '--self-test': parsed.selfTest = true; break;
      case '--help': case '-h': parsed.help = true; break;
      default: throw new Error(`unknown option: ${token}`);
    }
  }
  if (!['pr', 'full'].includes(parsed.profile)) throw new Error('--profile must be pr or full');
  return parsed;
}

function parseBinaries(values) {
  if (values.length === 0) throw new Error('pass two explicit --lpm-binary NAME=PATH values');
  const binaries = values.map((value) => {
    const split = value.indexOf('=');
    if (split < 1) throw new Error(`invalid --lpm-binary: ${value}`);
    return { name: value.slice(0, split), path: path.resolve(value.slice(split + 1)) };
  });
  validateUnique(binaries.map((binary) => binary.name), 'binary');
  return binaries;
}

function parseComparison(raw, parsedBinaries) {
  const names = raw ? parseList(raw, '--compare') : parsedBinaries.map((binary) => binary.name);
  if (names.length !== 2) throw new Error('--compare requires exactly baseline,candidate');
  for (const name of names) if (!parsedBinaries.some((binary) => binary.name === name)) throw new Error(`comparison binary is missing: ${name}`);
  return { baseline: names[0], candidate: names[1] };
}

function threshold(parsed, prefix, medianPct, p95Pct, medianAbs, p95Abs) {
  return {
    median_pct: nonNegativeNumber(parsed[`${prefix}MedianPct`], medianPct, `--${prefix}-median-pct`),
    p95_pct: nonNegativeNumber(parsed[`${prefix}P95Pct`], p95Pct, `--${prefix}-p95-pct`),
    median_abs: nonNegativeNumber(parsed[`${prefix}MedianAbs`], medianAbs, `--${prefix}-median-abs`),
    p95_abs: nonNegativeNumber(parsed[`${prefix}P95Abs`], p95Abs, `--${prefix}-p95-abs`),
  };
}

function positiveInt(raw, fallback, flag) {
  if (raw == null) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) throw new Error(`${flag} must be a positive integer`);
  return value;
}

function balancedPairCount(raw, fallback, flag) {
  const value = positiveInt(raw, fallback, flag);
  if (value % 2 !== 0) {
    throw new Error(`${flag} must be even so baseline/candidate order is balanced`);
  }
  return value;
}

function nonNegativeInt(raw, fallback, flag) {
  if (raw == null) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0) throw new Error(`${flag} must be a non-negative integer`);
  return value;
}

function nonNegativeNumber(raw, fallback, flag) {
  if (raw == null) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) throw new Error(`${flag} must be a non-negative number`);
  return value;
}

function parseList(raw, flag) {
  const values = raw.split(',').map((value) => value.trim()).filter(Boolean);
  if (values.length === 0) throw new Error(`${flag} must not be empty`);
  return values;
}

function validateUnique(values, label) {
  if (new Set(values).size !== values.length) throw new Error(`duplicate ${label}`);
}

function redactEnv(env) {
  return Object.fromEntries(Object.entries(env).map(([key, value]) => [key, /token|secret|password|key/i.test(key) ? '<redacted>' : value]));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, jsonFiniteReplacer, 2)}\n`);
}

function jsonFiniteReplacer(_key, value) {
  return typeof value === 'number' && !Number.isFinite(value) ? null : value;
}

function defaultOutputDir() {
  const stamp = new Date().toISOString().replace(/[-:.]/g, '').replace('Z', 'Z');
  return path.join(os.tmpdir(), `lpm-runtime-readiness-${stamp}-${process.pid}`);
}

function safeName(value) {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '-');
}

function rotated(values, offset) {
  if (values.length < 2) return [...values];
  const shift = offset % values.length;
  return values.slice(shift).concat(values.slice(0, shift));
}

function baselineRunsFirst(sample, scenarioPosition) {
  return (sample + scenarioPosition) % 2 === 1;
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

async function sha256FileStreaming(file) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  for await (const chunk of fs.createReadStream(file)) {
    bytes += chunk.length;
    hash.update(chunk);
  }
  return { bytes, sha256: hash.digest('hex') };
}

async function validateRepeatedByteFile(file, expectedByte) {
  let bytes = 0;
  let matches = true;
  for await (const chunk of fs.createReadStream(file)) {
    bytes += chunk.length;
    if (!chunk.every((byte) => byte === expectedByte)) matches = false;
  }
  return { bytes, matches };
}

function commandOutput(command, args, cwd = repoRoot) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

function hostMetadata() {
  const memory = process.platform === 'darwin'
    ? Number(commandOutput('sysctl', ['-n', 'hw.memsize'], repoRoot))
    : os.totalmem();
  const cpu = process.platform === 'darwin'
    ? commandOutput('sysctl', ['-n', 'machdep.cpu.brand_string'], repoRoot)
    : os.cpus()[0]?.model ?? null;
  return {
    platform: process.platform,
    architecture: process.arch,
    kernel: os.release(),
    cpu,
    logical_cpus: os.cpus().length,
    memory_bytes: memory,
    node: process.version,
  };
}

function isExecutable(file) {
  try { fs.accessSync(file, fs.constants.X_OK); return true; } catch { return false; }
}

function findExecutable(name) {
  if (name.includes(path.sep)) return isExecutable(name) ? name : null;
  for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
    const candidate = path.join(directory, name);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function shellJoin(values) {
  return values.map(shellQuote).join(' ');
}

function safeKill(pid, signal) {
  try { process.kill(pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}

function removeTree(target) {
  fs.rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

function directoryContains(directory, needle) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (directoryContains(fullPath, needle)) return true;
    } else if (entry.isFile() && fs.readFileSync(fullPath).includes(needle)) {
      return true;
    }
  }
  return false;
}

function elapsedMs(startedNs) {
  return Number(process.hrtime.bigint() - startedNs) / 1_000_000;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(operation, timeout, description) {
  const deadline = Date.now() + timeout;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await operation();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await delay(25);
  }
  throw new Error(`timed out waiting for ${description}${lastError ? `: ${lastError}` : ''}`);
}

function withTimeout(promise, timeout, description) {
  return new Promise((resolve, reject) => {
    const timeoutHandle = setTimeout(
      () => reject(new Error(`${description} timed out after ${timeout} ms`)),
      timeout,
    );
    Promise.resolve(promise).then(
      (value) => {
        clearTimeout(timeoutHandle);
        resolve(value);
      },
      (error) => {
        clearTimeout(timeoutHandle);
        reject(error);
      },
    );
  });
}

function rowStatus(row) {
  if (!row) return 'missing';
  if (executionFailed(row)) return row.failure_reason ?? 'execution failed';
  return row.contract_ok === true ? 'ok' : `contract failed: ${row.failure_reason ?? 'unknown'}`;
}

function runFailed(row) {
  return executionFailed(row) || row.contract_ok !== true;
}

function warmupBlocksComparison(binaryName, row, comparison) {
  return binaryName === comparison.candidate && runFailed(row);
}

function executionFailed(row) {
  return row.exit_ok !== true || !Number.isFinite(row.wall_ms);
}

function round(value) {
  return Math.round(value * 100) / 100;
}

function printHelp() {
  process.stdout.write(`Usage: node bench/scripts/run-runtime-readiness.mjs [options]\n\n` +
    `Required:\n` +
    `  --lpm-binary NAME=PATH   Explicit prebuilt binary; pass baseline and candidate\n` +
    `\nOptions:\n` +
    `  --compare BASE,CANDIDATE  Binary names to compare (default: first two)\n` +
    `  --profile pr|full         Fixed PR suite or suite including PTY tunnel/dashboard\n` +
    `  --samples N               Even number of measured adjacent AB/BA pairs (PR default: 4)\n` +
    `  --warmups N               Warmup rounds (default: 1)\n` +
    `  --scenarios IDS           Comma-separated fixed scenario IDs\n` +
    `  --timeout-ms N            Per-scenario hard timeout\n` +
    `  --output DIR              JSON, Markdown, bounded logs, and raw samples\n` +
    `  --*-median-regression-*   Override wall/startup/shutdown/tree/root RSS/process/FD/thread gates\n` +
    `  --allow-inconclusive      Exit zero for an inconclusive performance comparison\n` +
    `  --keep-work               Preserve isolated fixture directories\n` +
    `  --dry-run                 Print the plan without execution\n` +
    `  --self-test               Run scheduler, collector, parser, and summary tests\n`);
}

async function runSelfTests() {
  assert.equal(defaultTimeoutMs('pr'), 15_000);
  assert.equal(defaultTimeoutMs('full'), 60_000);
  assert.equal(benchmarkShutdownTimeoutMs(), 10_000);
  assert.equal(graphReadinessTimeoutMs(10, 'deep'), 8_000);
  assert.equal(graphReadinessTimeoutMs(50, 'deep'), 25_000);
  assert.equal(graphReadinessTimeoutMs(50, 'wide'), 8_000);
  assert.equal(balancedPairCount(undefined, 4, '--samples'), 4);
  assert.throws(() => balancedPairCount(3, 4, '--samples'), /even/);
  const collector = new BoundedCollector(16);
  collector.push(Buffer.from('hello '));
  collector.push(Buffer.from([0xf0, 0x9f]));
  collector.push(Buffer.from([0x98, 0x80]));
  collector.push(Buffer.alloc(32, 'x'));
  const collected = collector.finish();
  assert.equal(collected.total_bytes, 42);
  assert.equal(collected.truncated, true);
  assert.ok(collected.retained_bytes <= 16 + 48);
  const nonTruncatedCollector = new BoundedCollector(16);
  nonTruncatedCollector.push(Buffer.from('twelve-bytes'));
  const nonTruncated = nonTruncatedCollector.finish();
  assert.equal(nonTruncated.truncated, false);
  assert.equal(nonTruncated.retained, 'twelve-bytes');

  assert.deepEqual(rotated(['a', 'b', 'c'], 1), ['b', 'c', 'a']);
  const schedules = new Map([['a', []], ['b', []], ['c', []]]);
  const stablePositions = new Map([...schedules.keys()].map((scenario, index) => [scenario, index]));
  for (let sample = 1; sample <= 3; sample += 1) {
    for (const scenario of rotated([...schedules.keys()], sample - 1)) {
      schedules.get(scenario).push(baselineRunsFirst(sample, stablePositions.get(scenario)));
    }
  }
  for (const orders of schedules.values()) {
    assert.ok(Math.abs(orders.filter(Boolean).length - orders.filter((order) => !order).length) <= 1);
  }
  const processes = [
    { pid: 1, ppid: 0, rss_bytes: 1 },
    { pid: 2, ppid: 1, rss_bytes: 2 },
    { pid: 3, ppid: 2, rss_bytes: 3 },
    { pid: 4, ppid: 0, rss_bytes: 4 },
  ];
  assert.deepEqual(descendantProcesses(processes, [1]).map((process) => process.pid), [1, 2, 3]);
  const executable = '/tmp/lpm-rs';
  const ptyTree = [
    { pid: 10, command: `script -q /dev/null ${executable} dev` },
    { pid: 11, command: `/bin/sh -c '${executable} dev'` },
    { pid: 12, command: `${executable} dev --dashboard` },
    { pid: 13, command: 'node service.mjs' },
  ];
  assert.deepEqual(ptyTree.filter((process) => processRunsExecutable(process, executable)).map((process) => process.pid), [12]);
  assert.deepEqual(distribution([1, 2, 3, 4]), { min: 1, median: 2.5, p95: 3.85, max: 4, iqr: 1.5, mad: 1 });

  const frameText = JSON.stringify({ type: 'http_response', body: 'x'.repeat(256) });
  for (const force64BitLength of [false, true]) {
    const frame = maskedWebSocketTextFrame(frameText, force64BitLength);
    for (let split = 0; split <= frame.length; split += 1) {
      const parsed = [];
      const parser = new WebSocketFrameParser((payload, opcode) => {
        assert.equal(opcode, 0x1);
        parsed.push(payload.toString('utf8'));
      });
      parser.push(frame.subarray(0, split));
      parser.push(frame.subarray(split));
      assert.deepEqual(parsed, [frameText], `WebSocket frame split failed at byte ${split}`);
      assert.equal(parser.totalBytes, 0);
    }
  }
  const concatenatedTexts = ['first', 'second', 'third'];
  const concatenatedFrames = Buffer.concat(concatenatedTexts.map((text) => maskedWebSocketTextFrame(text)));
  const parsedConcatenated = [];
  const concatenatedParser = new WebSocketFrameParser((payload, opcode) => {
    assert.equal(opcode, 0x1);
    parsedConcatenated.push(payload.toString('utf8'));
  });
  for (let offset = 0; offset < concatenatedFrames.length; offset += 3) {
    concatenatedParser.push(concatenatedFrames.subarray(offset, offset + 3));
  }
  assert.deepEqual(parsedConcatenated, concatenatedTexts);

  const relay = await startFakeRelay([]);
  const relaySocket = net.connect(Number(new URL(relay.url).port), '127.0.0.1');
  await new Promise((resolve, reject) => {
    relaySocket.once('connect', resolve);
    relaySocket.once('error', reject);
  });
  relaySocket.write('GET /connect HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');
  await new Promise((resolve, reject) => {
    const onData = (data) => {
      if (!data.includes(Buffer.from('101 Switching Protocols'))) return;
      relaySocket.off('error', reject);
      resolve();
    };
    relaySocket.on('data', onData);
    relaySocket.once('error', reject);
  });
  const relaySocketClosed = new Promise((resolve) => relaySocket.once('close', resolve));
  await withTimeout(relay.close(), 500, 'fake relay cleanup');
  await withTimeout(relaySocketClosed, 500, 'fake relay socket close');
  assert.equal(relay.socketCount, 0);

  const localWebSocket = await startLocalWebSocketFixture();
  const pendingSocket = net.connect(localWebSocket.port, '127.0.0.1');
  await new Promise((resolve, reject) => {
    pendingSocket.once('connect', resolve);
    pendingSocket.once('error', reject);
  });
  pendingSocket.write('GET /pending HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');
  await waitFor(() => localWebSocket.pendingConnections === 1, 500, 'pending local WebSocket fixture');
  pendingSocket.end();
  await waitFor(() => localWebSocket.pendingConnections === 0, 500, 'pending local WebSocket fixture close');
  assert.equal(localWebSocket.pendingClosed, 1);
  await withTimeout(localWebSocket.close(), 500, 'local WebSocket fixture cleanup');
  assert.equal(localWebSocket.socketCount, 0);

  const baseline = {
    binary: 'main', sample: 1, counted: true, pair_id: 'x', pair_order: 'baseline-candidate',
    execution_sequence: 1, scenario: 's', kind: 'run', wall_ms: 100, tree_peak_rss_bytes: 100,
    root_peak_rss_bytes: 50, steady_tree_rss_bytes: 100, steady_root_rss_bytes: 50,
    peak_process_count: 2, maximum_observed_fd_count: 10,
    maximum_observed_thread_count: 4, resource_sample_count: 3,
    resource_sample_span_ms: 100, detailed_sample_count: 2,
    exit_ok: true, contract_ok: true,
  };
  const candidate = {
    ...baseline, binary: 'candidate', execution_sequence: 2, wall_ms: 101,
    tree_peak_rss_bytes: 101, root_peak_rss_bytes: 51,
    steady_tree_rss_bytes: 101, steady_root_rss_bytes: 51,
  };
  const countLimit = { median_pct: 10, p95_pct: 20, median_abs: 1, p95_abs: 2 };
  const limits = {
    wall_ms: { median_pct: 5, p95_pct: 10, median_abs: 20, p95_abs: 50 },
    startup_ms: { median_pct: 5, p95_pct: 10, median_abs: 20, p95_abs: 50 },
    shutdown_ms: { median_pct: 10, p95_pct: 20, median_abs: 50, p95_abs: 100 },
    tree_peak_rss_bytes: { median_pct: 5, p95_pct: 10, median_abs: 16, p95_abs: 32 },
    root_peak_rss_bytes: { median_pct: 5, p95_pct: 10, median_abs: 8, p95_abs: 16 },
    steady_tree_rss_bytes: { median_pct: 5, p95_pct: 10, median_abs: 16, p95_abs: 32 },
    steady_root_rss_bytes: { median_pct: 5, p95_pct: 10, median_abs: 8, p95_abs: 16 },
    peak_process_count: countLimit,
    maximum_observed_fd_count: { median_pct: 10, p95_pct: 20, median_abs: 8, p95_abs: 16 },
    maximum_observed_thread_count: { median_pct: 10, p95_pct: 20, median_abs: 2, p95_abs: 4 },
  };
  assert.equal(summarizeComparison([baseline, candidate], { baseline: 'main', candidate: 'candidate' }, limits, 1).verdict, 'pass');
  const zeroCandidateDetail = { ...candidate, maximum_observed_fd_count: 0 };
  const zeroDetailComparison = summarizeComparison(
    [baseline, zeroCandidateDetail],
    { baseline: 'main', candidate: 'candidate' },
    limits,
    1,
  );
  assert.equal(zeroDetailComparison.verdict, 'pass');
  assert.equal(zeroDetailComparison.groups[0].metrics.maximum_observed_fd_count.verdict, 'pass');
  const missingCandidateDetail = { ...candidate, maximum_observed_fd_count: null };
  const missingDetailComparison = summarizeComparison(
    [baseline, missingCandidateDetail],
    { baseline: 'main', candidate: 'candidate' },
    limits,
    1,
  );
  assert.equal(missingDetailComparison.verdict, 'inconclusive');
  assert.equal(missingDetailComparison.groups[0].metrics.maximum_observed_fd_count.verdict, 'inconclusive');
  const underSampledCandidate = {
    ...candidate,
    root_peak_rss_bytes: 100,
    maximum_observed_fd_count: 43,
    resource_sample_count: 1,
    resource_sample_span_ms: 0,
    detailed_sample_count: 1,
  };
  const underSampledComparison = summarizeComparison(
    [baseline, underSampledCandidate],
    { baseline: 'main', candidate: 'candidate' },
    limits,
    1,
  );
  assert.equal(underSampledComparison.verdict, 'pass');
  assert.equal(underSampledComparison.groups[0].metrics.root_peak_rss_bytes.verdict, 'advisory-insufficient-sampling');
  assert.equal(underSampledComparison.groups[0].metrics.maximum_observed_fd_count.verdict, 'advisory-insufficient-sampling');
  const failedCandidate = {
    ...candidate,
    exit_ok: false,
    contract_ok: false,
    wall_ms: null,
    failure_reason: 'candidate readiness timeout',
  };
  const candidateFailureComparison = summarizeComparison(
    [baseline, failedCandidate],
    { baseline: 'main', candidate: 'candidate' },
    limits,
    1,
  );
  assert.equal(candidateFailureComparison.verdict, 'execution-failure');
  assert.equal(candidateFailureComparison.groups[0].correctness.candidate_failures, 1);
  assert.equal(candidateFailureComparison.groups[0].correctness.candidate_contract_failures, 1);
  const correctedCandidate = { ...candidate };
  const brokenBaselineContract = { ...baseline, contract_ok: false };
  assert.equal(summarizeComparison(
    [brokenBaselineContract, correctedCandidate],
    { baseline: 'main', candidate: 'candidate' },
    limits,
    1,
  ).verdict, 'inconclusive');
  const failedBaselineExecution = {
    ...baseline,
    exit_ok: false,
    contract_ok: false,
    wall_ms: null,
    failure_reason: 'readiness timeout',
  };
  const executionImprovement = summarizeComparison(
    [failedBaselineExecution, correctedCandidate],
    { baseline: 'main', candidate: 'candidate' },
    limits,
    1,
  );
  assert.equal(executionImprovement.verdict, 'inconclusive');
  assert.equal(executionImprovement.groups[0].correctness.baseline_failures, 1);
  assert.equal(executionImprovement.groups[0].correctness.candidate_failures, 0);
  assert.deepEqual(executionImprovement.groups[0].failures, []);
  const broken = { ...candidate, execution_sequence: 4 };
  assert.equal(summarizeComparison([baseline, broken], { baseline: 'main', candidate: 'candidate' }, limits, 1).verdict, 'execution-failure');
  const failedCandidateWarmup = { ...candidate, exit_ok: false, failure_reason: 'fixture failed' };
  assert.equal(warmupBlocksComparison('main', brokenBaselineContract, { baseline: 'main', candidate: 'candidate' }), false);
  assert.equal(warmupBlocksComparison('candidate', failedCandidateWarmup, { baseline: 'main', candidate: 'candidate' }), true);
  assert.equal(warmupBlocksComparison('candidate', candidate, { baseline: 'main', candidate: 'candidate' }), false);
  assert.doesNotThrow(() => JSON.stringify({ value: Number.POSITIVE_INFINITY }, jsonFiniteReplacer));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'run/package-system-node-no-lpm-json'));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'task/deep-1000' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'task/wide-100'));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'task/cache-warm-deep-1000' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'task/workspace-caret-deep-1000' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'task/workspace-cache-cold-wide-deep-10' && !scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'task/workspace-cache-warm-wide-deep-1000' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/workspace-root-lock-cold-1mib-10-tasks' && !scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/workspace-root-lock-warm-50mib-10-tasks' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/hit-128mib' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/hit-500-files' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/hit-deep-path' && scenario.fullOnly));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/removes-stale-output'));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'cache/concurrent-same-key-store'));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'tunnel/websocket-fairness-close-cancellation'));
  process.stdout.write('run-runtime-readiness self-test passed\n');
}
