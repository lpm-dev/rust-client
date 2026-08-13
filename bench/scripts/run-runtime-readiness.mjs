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
const SCHEMA_VERSION = 1;
const STREAM_RETAIN_BYTES = 64 * 1024;
const SAMPLE_INTERVAL_MS = 50;
const STEADY_WINDOW_MS = 350;
const DEFAULT_TIMEOUT_MS = 15_000;
const MiB = 1024 * 1024;

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
    const retained = truncated ? Buffer.concat([this.prefix, separator, this.tail]) : this.prefix;
    return {
      total_bytes: this.total,
      retained_bytes: retained.length,
      truncated,
      sha256: this.hash.digest('hex'),
      retained: retained.toString('utf8'),
    };
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

const samples = positiveInt(options.samples, options.profile === 'full' ? 10 : 3, '--samples');
const warmups = nonNegativeInt(options.warmups, 1, '--warmups');
const timeoutMs = positiveInt(options.timeoutMs, DEFAULT_TIMEOUT_MS, '--timeout-ms');
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
  tree_peak_rss_bytes: threshold(options, 'rss', 5, 10, 16 * MiB, 32 * MiB),
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
      if (executionFailed(row) || (binary.name === comparison.candidate && row.contract_ok !== true)) {
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
    const result = await runProcesses(context, processSpecs, scenario, timeoutMs);
    Object.assign(row, result.metrics);
    row.processes = result.processes;
    row.contract = await scenario.validate(context, result);
    const outputBoundOk = result.processes.every((process) =>
      process.stdout.retained_bytes <= STREAM_RETAIN_BYTES + 48
      && process.stderr.retained_bytes <= STREAM_RETAIN_BYTES + 48,
    );
    if (!outputBoundOk) {
      row.contract = { ok: false, reason: 'the benchmark harness exceeded its retained-output ceiling', inner: row.contract };
    }
    row.exit_ok = result.processes.every((process) =>
      scenario.kind === 'dev'
        ? process.exit_code === 0 || process.signal === 'SIGTERM'
        : process.exit_code === 0,
    );
    row.contract_ok = row.contract.ok;
    row.failure_reason = row.exit_ok && row.contract_ok ? null : row.contract.reason ?? 'process failed';
    writeJson(path.join(artifactDir, 'metrics.json'), row);
  } catch (error) {
    row.exit_ok = false;
    row.contract_ok = false;
    row.failure_reason = error instanceof Error ? error.stack ?? error.message : String(error);
    writeJson(path.join(artifactDir, 'metrics.json'), row);
  } finally {
    for (const cleanup of context.cleanup.reverse()) {
      try {
        await cleanup();
      } catch (error) {
        row.cleanup_error = String(error);
      }
    }
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
  let sampling = true;
  const sampler = (async () => {
    let detailedTick = 1;
    while (sampling) {
      const sample = sampleProcessTree(roots, detailedTick % 5 === 0);
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
  let signalTargets = roots;
  const completion = Promise.all(children.map((child) => child.completion));
  let processCompletedMs = null;
  try {
    if (scenario.kind === 'dev') {
      readiness = await withTimeout(scenario.waitReady(context, children), timeout, `${scenario.id} readiness`);
      readiness.elapsed_ms = elapsedMs(startedNs);
      await delay(STEADY_WINDOW_MS);
      const snapshot = sampleProcessTree(roots, true);
      snapshot.elapsed_ms = elapsedMs(startedNs);
      samples.push(snapshot);
      steadyTreeRssBytes = snapshot.tree_rss_bytes;
      preShutdown = snapshot.processes.map((process) => ({ pid: process.pid, start_identity: process.start_identity }));
      signalTargets = scenario.signalTargets
        ? await scenario.signalTargets(context, snapshot, roots)
        : roots;
      const shutdownStarted = process.hrtime.bigint();
      for (const pid of signalTargets) safeKill(pid, 'SIGTERM');
      const completed = await withTimeout(completion, 5_000, `${scenario.id} shutdown`)
        .then(() => true)
        .catch(() => false);
      if (!completed) {
        const remaining = sampleProcessTree(roots, false).processes.map((process) => ({
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
    const emergencyProcesses = sampleProcessTree(roots, false).processes.map((process) => ({
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
  metrics.steady_tree_rss_bytes = steadyTreeRssBytes ?? samples.findLast((sample) => sample.process_count > 0)?.tree_rss_bytes ?? 0;
  metrics.shutdown_ms = shutdownMs;
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
    runTaskEnvManagedNodeScenario(),
    runWorkspaceNodeBunScenario(),
    devSingleScenario(),
    devMultiScenario(),
    concurrentDifferentRuntimeScenario(),
    concurrentFirstInstallScenario(),
    cleanupDescendantScenario(),
    newlineFreeScenario(),
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
      const relay = await startFakeRelay(64);
      context.cleanup.push(relay.close);
      context.state.relay = relay;
    },
    processes(context) {
      const command = [
        context.binary.path, '--token', 'runtime-readiness-token', 'dev', '--tunnel', '--dashboard',
        '--no-open', '--no-install', '--no-inspect',
      ];
      const script = findExecutable('script');
      if (process.platform === 'darwin') {
        return [{ label: 'dashboard-pty', executable: script, args: ['-q', '/dev/null', ...command], env: { LPM_TUNNEL_RELAY: context.state.relay.url } }];
      }
      return [{
        label: 'dashboard-pty',
        executable: script,
        args: ['--quiet', '--return', '--command', shellJoin(command), '/dev/null'],
        env: { LPM_TUNNEL_RELAY: context.state.relay.url },
      }];
    },
    async waitReady(context) {
      await waitForJsonEndpoint(context.state.port, { scenario: 'tunnel-dashboard' });
      await waitFor(() => context.state.relay.responses >= 64, 8_000, 'relay response burst');
      return { scenario: 'tunnel-dashboard', relay_responses: context.state.relay.responses };
    },
    async signalTargets(context, snapshot) {
      const exact = snapshot.processes.filter((process) => process.command?.includes(context.binary.path));
      if (exact.length !== 1) throw new Error(`expected one lpm process below PTY, found ${exact.length}`);
      return [exact[0].pid];
    },
    async validate(context, result) {
      const relay = context.state.relay;
      const authOk = relay.authorization === 'Bearer runtime-readiness-token';
      const urlOk = !relay.requestUrl.includes('token') && !relay.requestUrl.includes('auth=');
      const clean = result.metrics.surviving_processes.length === 0 && result.metrics.surviving_ports.length === 0;
      return {
        ok: authOk && urlOk && relay.responses === 64 && clean,
        reason: authOk && urlOk && relay.responses === 64 && clean ? null : 'local relay, credential, burst, or cleanup contract failed',
        relay: { request_url: relay.requestUrl, authorization: authOk ? '<redacted-valid-bearer>' : '<invalid>', responses: relay.responses },
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

function resultScript({ scenario, env }) {
  return `const result = {scenario:${JSON.stringify(scenario)},engine:typeof Bun==='undefined'?'node':'bun',runtime_version:typeof Bun==='undefined'?process.version:Bun.version,selected_runtime:process.env.LPM_BENCH_SELECTED_RUNTIME??null,env:{}};\n${env
    .map((name) => `result.env[${JSON.stringify(name)}] = process.env[${JSON.stringify(name)}] ?? null;`)
    .join('\n')}\nconsole.log('LPM_RUNTIME_RESULT=' + JSON.stringify(result));\n`;
}

function httpServerScript(scenario) {
  return `import http from 'node:http';\nconst scenario=${JSON.stringify(scenario)};\nconst server=http.createServer((_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario,pid:process.pid}));});\nserver.listen(Number(process.env.PORT),'127.0.0.1');\n`;
}

function multiServiceScript(apiPort) {
  return `import http from 'node:http';\nconst service=process.argv[2];\nconst port=Number(process.env.PORT);\nconst server=http.createServer(async (_req,res)=>{let apiReady=true;if(service==='web'){try{const response=await fetch('http://127.0.0.1:${apiPort}');apiReady=response.ok;}catch{apiReady=false;}}res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario:'multi-dev',service,env:process.env.RUNTIME_BENCH_ENV,service_env:process.env.SERVICE_ENV,api_ready:apiReady,pid:process.pid}));});\nserver.listen(port,'127.0.0.1');\n`;
}

function descendantParentScript() {
  return `import {spawn} from 'node:child_process';\nimport fs from 'node:fs';\nconst child=spawn(process.execPath,['descendant.mjs'],{env:process.env,stdio:'inherit'});\nfs.writeFileSync('descendant.pid',String(child.pid));\nsetInterval(()=>{},1000);\n`;
}

function newlineFreeServerScript(outputBytes, digest) {
  return `import crypto from 'node:crypto';\nimport fs from 'node:fs';\nimport http from 'node:http';\nconst bytes=${outputBytes};\nconst block=Buffer.alloc(64*1024,'x');\nconst hash=crypto.createHash('sha256');\nlet written=0;\nwhile(written<bytes){const chunk=block.subarray(0,Math.min(block.length,bytes-written));process.stdout.write(chunk);hash.update(chunk);written+=chunk.length;}\nconst sha256=hash.digest('hex');\nfs.writeFileSync('output-proof.json',JSON.stringify({bytes:written,sha256,expected:${JSON.stringify(digest)}}));\nhttp.createServer((_req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({scenario:'newline-free',bytes:written,sha256}));}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
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

async function waitForJsonEndpoint(port, expected) {
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
  }, 8_000, `http://127.0.0.1:${port} readiness`);
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

async function startFakeRelay(burstCount) {
  let authorization = null;
  let requestUrl = '';
  let responses = 0;
  const server = http.createServer();
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
    for (let index = 0; index < burstCount; index += 1) {
      socket.write(webSocketTextFrame(JSON.stringify({
        type: 'http_request',
        id: `runtime-readiness-${index}`,
        method: 'GET',
        url: '/',
        headers: {},
        body: '',
      })));
    }
    socket.on('data', (data) => {
      responses += countWebSocketTextFrames(data, 'http_response');
    });
  });
  await listen(server);
  return {
    url: `ws://127.0.0.1:${server.address().port}/connect`,
    get authorization() { return authorization; },
    get requestUrl() { return requestUrl; },
    get responses() { return responses; },
    close: () => closeServer(server),
  };
}

function webSocketTextFrame(text) {
  const payload = Buffer.from(text);
  if (payload.length < 126) return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  const header = Buffer.alloc(4);
  header[0] = 0x81;
  header[1] = 126;
  header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

function countWebSocketTextFrames(buffer, type) {
  let offset = 0;
  let count = 0;
  while (offset + 2 <= buffer.length) {
    const masked = (buffer[offset + 1] & 0x80) !== 0;
    let length = buffer[offset + 1] & 0x7f;
    let header = 2;
    if (length === 126) {
      if (offset + 4 > buffer.length) break;
      length = buffer.readUInt16BE(offset + 2);
      header = 4;
    } else if (length === 127) {
      break;
    }
    const maskBytes = masked ? 4 : 0;
    if (offset + header + maskBytes + length > buffer.length) break;
    const payload = Buffer.from(buffer.subarray(offset + header + maskBytes, offset + header + maskBytes + length));
    if (masked) {
      const mask = buffer.subarray(offset + header, offset + header + 4);
      for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
    }
    if (payload.toString('utf8').includes(`\"type\":\"${type}\"`)) count += 1;
    offset += header + maskBytes + length;
  }
  return count;
}

function sampleProcessTree(rootPids, detailed) {
  const processes = process.platform === 'linux' ? linuxProcesses() : macProcesses();
  const tree = descendantProcesses(processes, rootPids);
  if (detailed) enrichProcessDetails(tree);
  return {
    process_count: tree.length,
    tree_rss_bytes: tree.reduce((sum, process) => sum + process.rss_bytes, 0),
    root_rss_bytes: tree.filter((process) => rootPids.includes(process.pid)).reduce((sum, process) => sum + process.rss_bytes, 0),
    fd_count: detailed ? tree.reduce((sum, process) => sum + (process.fd_count ?? 0), 0) : null,
    thread_count: detailed ? tree.reduce((sum, process) => sum + (process.thread_count ?? 0), 0) : null,
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
      try {
        command = fs.readFileSync(`/proc/${entry.name}/cmdline`).toString('utf8').replaceAll('\0', ' ').trim();
      } catch {
        // The status and stat files are enough for sampling.
      }
      processes.push({ pid, ppid, rss_bytes: rssKb * 1024, thread_count: threads, start_identity: startIdentity, command });
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

function summarizeResourceSamples(samples, roots) {
  const detailed = samples.filter((sample) => sample.fd_count != null);
  const ready = samples.at(-1);
  return {
    tree_peak_rss_bytes: maximum(samples.map((sample) => sample.tree_rss_bytes)),
    root_peak_rss_bytes: maximum(samples.map((sample) => sample.root_rss_bytes)),
    steady_tree_rss_bytes: ready?.tree_rss_bytes ?? 0,
    peak_process_count: maximum(samples.map((sample) => sample.process_count)),
    maximum_observed_fd_count: maximum(detailed.map((sample) => sample.fd_count)),
    maximum_observed_thread_count: maximum(detailed.map((sample) => sample.thread_count)),
    resource_sample_count: samples.length,
    detailed_sample_count: detailed.length,
    root_pids: roots,
  };
}

function maximum(values) {
  return values.length > 0 ? Math.max(...values.filter(Number.isFinite)) : 0;
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
      tree_peak_rss_bytes: distribution(successful.map((row) => row.tree_peak_rss_bytes)),
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
    const pairs = [];
    const failures = [];
    for (let sample = 1; sample <= expectedSamples; sample += 1) {
      const baseline = scenarioRows.find((row) => row.sample === sample && row.binary === comparison.baseline);
      const candidate = scenarioRows.find((row) => row.sample === sample && row.binary === comparison.candidate);
      if (!baseline || !candidate || executionFailed(baseline) || candidate.contract_ok !== true || executionFailed(candidate)) {
        failures.push({ sample, baseline: rowStatus(baseline), candidate: rowStatus(candidate) });
        continue;
      }
      if (baseline.pair_id !== candidate.pair_id || Math.abs(baseline.execution_sequence - candidate.execution_sequence) !== 1) {
        failures.push({ sample, baseline: 'not adjacent', candidate: 'not adjacent' });
        continue;
      }
      pairs.push({ sample, baseline, candidate });
    }
    const orders = {
      'baseline-candidate': pairs.filter((pair) => pair.baseline.pair_order === 'baseline-candidate').length,
      'candidate-baseline': pairs.filter((pair) => pair.baseline.pair_order === 'candidate-baseline').length,
    };
    const correctness = {
      baseline_contract_failures: pairs.filter((pair) => pair.baseline.contract_ok !== true).length,
      candidate_contract_failures: pairs.filter((pair) => pair.candidate.contract_ok !== true).length,
    };
    const performanceGates = correctness.baseline_contract_failures === 0;
    if (Math.abs(orders['baseline-candidate'] - orders['candidate-baseline']) > 1) failures.push({ sample: 'schedule', baseline: 'imbalanced AB/BA', candidate: 'imbalanced AB/BA' });
    const kind = scenarioRows[0]?.kind;
    const metrics = {};
    for (const metric of kind === 'dev' ? ['startup_ms', 'tree_peak_rss_bytes'] : ['wall_ms', 'tree_peak_rss_bytes']) {
      const metricPairs = pairs.filter((pair) => Number.isFinite(pair.baseline[metric]) && Number.isFinite(pair.candidate[metric]) && pair.baseline[metric] > 0);
      if (metricPairs.length > 0) metrics[metric] = compareMetric(metricPairs, metric, thresholds[metric]);
      if (performanceGates && metrics[metric]?.verdict === 'regression') regression = true;
      if (performanceGates && metrics[metric]?.verdict === 'inconclusive') inconclusive = true;
    }
    if (failures.length > 0) executionFailure = true;
    groups.push({
      scenario,
      expected_pairs: expectedSamples,
      successful_pairs: pairs.length,
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
    '| Scenario | Pairs | Metric | Baseline median/p95 | Candidate median/p95 | Delta median/p95 | Result |',
    '| --- | ---: | --- | ---: | ---: | ---: | --- |',
  ];
  for (const group of comparison.groups) {
    for (const [metric, result] of Object.entries(group.metrics)) {
      const metricVerdict = group.performance_gates ? result.verdict : 'advisory: baseline contract failed';
      lines.push(`| ${group.scenario} | ${group.successful_pairs}/${group.expected_pairs} | ${metric} | ${formatMetric(metric, result.baseline.median)}/${formatMetric(metric, result.baseline.p95)} | ${formatMetric(metric, result.candidate.median)}/${formatMetric(metric, result.candidate.p95)} | ${result.median_delta_pct}%/${result.p95_delta_pct}% | ${metricVerdict} |`);
    }
  }
  const transitions = comparison.groups.filter((group) => group.correctness.baseline_contract_failures > 0);
  if (transitions.length > 0) {
    lines.push('', '## Correctness transitions', '');
    for (const group of transitions) {
      lines.push(`- ${group.scenario}: baseline contract failures ${group.correctness.baseline_contract_failures}/${group.successful_pairs}; candidate failures ${group.correctness.candidate_contract_failures}/${group.successful_pairs}. Performance deltas are advisory.`);
    }
  }
  const failures = comparison.groups.flatMap((group) => group.failures.map((failure) => ({ group, failure })));
  if (failures.length > 0) {
    lines.push('', '## Execution failures', '');
    for (const { group, failure } of failures) lines.push(`- ${group.scenario} sample ${failure.sample}: baseline=${failure.baseline}; candidate=${failure.candidate}.`);
  }
  lines.push('', '## Distributions', '', '| Scenario | Binary | Samples | Wall median/p95 | Startup median/p95 | Tree RSS median/p95 |', '| --- | --- | ---: | ---: | ---: | ---: |');
  for (const group of summary) {
    lines.push(`| ${group.scenario} | ${group.binary} | ${group.successful_samples}/${group.samples} | ${formatDistribution(group.wall_ms, 'ms')} | ${formatDistribution(group.startup_ms, 'ms')} | ${formatDistribution(group.tree_peak_rss_bytes, 'bytes')} |`);
  }
  return lines.join('\n');
}

function formatMetric(metric, value) {
  return metric.endsWith('_bytes') ? formatBytes(value) : `${value} ms`;
}

function formatDistribution(value, kind) {
  if (!value) return 'n/a';
  return kind === 'bytes' ? `${formatBytes(value.median)}/${formatBytes(value.p95)}` : `${value.median}/${value.p95} ms`;
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
      case '--rss-median-regression-pct': parsed.rssMedianPct = value(); break;
      case '--rss-p95-regression-pct': parsed.rssP95Pct = value(); break;
      case '--rss-median-regression-mb': parsed.rssMedianAbs = Number(value()) * MiB; break;
      case '--rss-p95-regression-mb': parsed.rssP95Abs = Number(value()) * MiB; break;
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
  return Promise.race([
    promise,
    delay(timeout).then(() => { throw new Error(`${description} timed out after ${timeout} ms`); }),
  ]);
}

function rowStatus(row) {
  if (!row) return 'missing';
  if (executionFailed(row)) return row.failure_reason ?? 'execution failed';
  return row.contract_ok === true ? 'ok' : `contract failed: ${row.failure_reason ?? 'unknown'}`;
}

function runFailed(row) {
  return executionFailed(row) || row.contract_ok !== true;
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
    `  --samples N               Measured adjacent AB/BA pairs\n` +
    `  --warmups N               Warmup rounds (default: 1)\n` +
    `  --scenarios IDS           Comma-separated fixed scenario IDs\n` +
    `  --timeout-ms N            Per-scenario hard timeout\n` +
    `  --output DIR              JSON, Markdown, bounded logs, and raw samples\n` +
    `  --allow-inconclusive      Exit zero for an inconclusive performance comparison\n` +
    `  --keep-work               Preserve isolated fixture directories\n` +
    `  --dry-run                 Print the plan without execution\n` +
    `  --self-test               Run scheduler, collector, parser, and summary tests\n`);
}

async function runSelfTests() {
  const collector = new BoundedCollector(16);
  collector.push(Buffer.from('hello '));
  collector.push(Buffer.from([0xf0, 0x9f]));
  collector.push(Buffer.from([0x98, 0x80]));
  collector.push(Buffer.alloc(32, 'x'));
  const collected = collector.finish();
  assert.equal(collected.total_bytes, 42);
  assert.equal(collected.truncated, true);
  assert.ok(collected.retained_bytes <= 16 + 48);

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
  assert.deepEqual(distribution([1, 2, 3, 4]), { min: 1, median: 2.5, p95: 3.85, max: 4, iqr: 1.5, mad: 1 });

  const baseline = { binary: 'main', sample: 1, counted: true, pair_id: 'x', pair_order: 'baseline-candidate', execution_sequence: 1, scenario: 's', kind: 'run', wall_ms: 100, tree_peak_rss_bytes: 100, exit_ok: true, contract_ok: true };
  const candidate = { ...baseline, binary: 'candidate', execution_sequence: 2, wall_ms: 101, tree_peak_rss_bytes: 101 };
  const limits = { wall_ms: { median_pct: 5, p95_pct: 10, median_abs: 20, p95_abs: 50 }, startup_ms: { median_pct: 5, p95_pct: 10, median_abs: 20, p95_abs: 50 }, tree_peak_rss_bytes: { median_pct: 5, p95_pct: 10, median_abs: 16, p95_abs: 32 } };
  assert.equal(summarizeComparison([baseline, candidate], { baseline: 'main', candidate: 'candidate' }, limits, 1).verdict, 'pass');
  const broken = { ...candidate, execution_sequence: 4 };
  assert.equal(summarizeComparison([baseline, broken], { baseline: 'main', candidate: 'candidate' }, limits, 1).verdict, 'execution-failure');
  assert.doesNotThrow(() => JSON.stringify({ value: Number.POSITIVE_INFINITY }, jsonFiniteReplacer));
  assert.ok(buildScenarios().some((scenario) => scenario.id === 'run/package-system-node-no-lpm-json'));
  process.stdout.write('run-runtime-readiness self-test passed\n');
}
