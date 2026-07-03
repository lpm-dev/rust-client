#!/usr/bin/env node

import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, "../..");
const RESULTS_DIR = path.join(ROOT, "bench", "perf-results");
const TIMESTAMP = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
const ITERATIONS = positiveInt(process.env.ITERATIONS, 30);
const WARMUP_ITERATIONS = nonNegativeInt(process.env.WARMUP_ITERATIONS, 2);
const COMMAND_TIMEOUT_MS = positiveInt(process.env.COMMAND_TIMEOUT_MS, 30_000);
const ESBUILD_VERSION = process.env.ESBUILD_VERSION || "0.28.1";
const TYPESCRIPT_VERSION = process.env.TYPESCRIPT_VERSION || "6.0.3";
const EXPLICIT_LPM_BIN = Boolean(process.env.LPM_BIN);
const LPM_BIN = resolveToolBin(process.env.LPM_BIN || path.join(ROOT, "target/release/lpm-rs"));
const NODE_BIN = resolveToolBin(process.env.NODE_BIN) || process.execPath;
const NPM_BIN = resolveToolBin(process.env.NPM_BIN || "npm");
const NPX_BIN = resolveToolBin(process.env.NPX_BIN || "npx");
const PNPM_BIN = resolveToolBin(process.env.PNPM_BIN || "pnpm");
const BUN_BIN = resolveToolBin(process.env.BUN_BIN || "bun");
const BUNX_BIN = resolveToolBin(process.env.BUNX_BIN || "bunx");
const NUB_BIN = resolveToolBin(process.env.NUB_BIN || "nub");
const NUBX_BIN = resolveToolBin(process.env.NUBX_BIN || "nubx");
const MARKDOWN_OUT = path.resolve(
  process.env.OUT || process.env.MARKDOWN_OUT || path.join(RESULTS_DIR, `run-bin-suite-${TIMESTAMP}.md`),
);
const JSON_OUT = path.resolve(
  process.env.JSON_OUT || path.join(RESULTS_DIR, `${path.basename(MARKDOWN_OUT, ".md")}.json`),
);
const KEEP_WORK = truthy(process.env.KEEP_BENCH_WORK);
const SCENARIO_FILTER = process.env.SCENARIOS ? new RegExp(process.env.SCENARIOS) : null;
const RUNNER_FILTER = process.env.RUNNERS ? new Set(csvList(process.env.RUNNERS)) : null;
const GROUP_FILTER = process.env.GROUPS ? new Set(csvList(process.env.GROUPS)) : null;
const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

if (args.selfTest) {
  runSelfTests();
  process.exit(0);
}

if (args.list) {
  printCaseList();
  process.exit(0);
}

if (!executable(NODE_BIN)) {
  throw new Error(`Node binary is not executable: ${NODE_BIN}`);
}

if (EXPLICIT_LPM_BIN) {
  if (!executable(LPM_BIN)) {
    throw new Error(`explicit LPM_BIN is not executable: ${LPM_BIN}`);
  }
} else {
  runChecked("cargo", ["build", "--release", "--locked", "-p", "lpm-cli", "--bin", "lpm-rs"], {
    cwd: ROOT,
    stdio: "inherit",
  });
  if (!executable(LPM_BIN)) {
    throw new Error(`release lpm-rs binary was not built at ${LPM_BIN}`);
  }
}

fs.mkdirSync(RESULTS_DIR, { recursive: true });
const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-run-bin-bench-"));

try {
  const projectDir = path.join(workRoot, "project");
  createFixtureProject(projectDir);
  const setup = installFixtureDependencies(projectDir);
  const metadata = collectMetadata(setup);
  const cases = filteredCases(buildBenchmarkCases());
  const results = [];

  for (const benchCase of cases) {
    const result = measureCase(benchCase, projectDir);
    results.push(result);
    printProgress(result);
  }

  const report = {
    metadata,
    fixture: fixtureMetadata(projectDir, setup),
    results,
  };
  fs.writeFileSync(JSON_OUT, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(MARKDOWN_OUT, renderMarkdown(report));
  console.log(`Wrote ${MARKDOWN_OUT}`);
  console.log(`Wrote ${JSON_OUT}`);
  if (KEEP_WORK) {
    console.log(`Kept benchmark work directory: ${workRoot}`);
  }
} finally {
  if (!KEEP_WORK) {
    removeTree(workRoot);
  }
}

function buildBenchmarkCases() {
  const scriptScenarios = [
    {
      scenario: "noop",
      label: "script noop",
      expected: containsExpected("hi"),
    },
    {
      scenario: "node-noop",
      label: "script node-noop",
      expected: containsExpected("node-noop"),
    },
    {
      scenario: "esbuild-version",
      label: "script invokes local native bin",
      expected: containsExpected(ESBUILD_VERSION),
    },
  ];
  const localBinScenarios = [
    {
      scenario: "esbuild-version",
      label: "native CLI local bin",
      bin: "esbuild",
      args: ["--version"],
      expected: exactLineExpected(ESBUILD_VERSION),
    },
    {
      scenario: "tsc-version",
      label: "Node CLI local bin",
      bin: "tsc",
      args: ["--version"],
      expected: containsExpected(`Version ${TYPESCRIPT_VERSION}`),
    },
  ];

  const cases = [];
  for (const scenario of scriptScenarios) {
    cases.push(
      scriptCase("lpm-run", "lpm run", scenario, LPM_BIN, ["run", scenario.scenario]),
      scriptCase("lpm-shortcut", "lpm script shortcut", scenario, LPM_BIN, [scenario.scenario], {
        skipOnCorrectnessFailure: true,
      }),
      scriptCase("nub-run", "nub run", scenario, NUB_BIN, ["run", scenario.scenario]),
      scriptCase("npm-run", "npm run", scenario, NPM_BIN, ["run", scenario.scenario]),
      scriptCase("pnpm-run", "pnpm run", scenario, PNPM_BIN, ["run", scenario.scenario]),
      scriptCase("bun-run", "bun run", scenario, BUN_BIN, ["run", scenario.scenario]),
    );
  }

  for (const scenario of localBinScenarios) {
    cases.push(
      localBinCase("lpm-exec", "lpm exec", scenario, LPM_BIN, ["exec", scenario.bin, ...scenario.args]),
      localBinCase("lpm-shorthand", "lpm local-bin shorthand", scenario, LPM_BIN, [
        scenario.bin,
        ...scenario.args,
      ], {
        skipOnCorrectnessFailure: true,
      }),
      localBinCase("nub-exec", "nub exec", scenario, NUB_BIN, ["exec", scenario.bin, ...scenario.args]),
      localBinCase("nubx", "nubx", scenario, NUBX_BIN, [scenario.bin, ...scenario.args]),
      localBinCase("pnpm-exec", "pnpm exec", scenario, PNPM_BIN, ["exec", scenario.bin, ...scenario.args]),
      localBinCase("npx-no-install", "npx --no-install", scenario, NPX_BIN, [
        "--no-install",
        scenario.bin,
        ...scenario.args,
      ]),
      localBinCase("npm-exec", "npm exec", scenario, NPM_BIN, [
        "exec",
        "--",
        scenario.bin,
        ...scenario.args,
      ]),
      localBinCase("bunx-no-install", "bunx --no-install", scenario, BUNX_BIN, [
        "--no-install",
        scenario.bin,
        ...scenario.args,
      ], {
        skipOnCorrectnessFailure: true,
      }),
    );
  }
  return cases;
}

function scriptCase(runnerKey, runner, scenario, program, commandArgs, options = {}) {
  return {
    id: `script-${scenario.scenario}-${runnerKey}`,
    group: "script-runner",
    runnerKey,
    runner,
    scenario: scenario.scenario,
    label: scenario.label,
    command: makeCommand(program, commandArgs),
    expected: scenario.expected,
    skipOnCorrectnessFailure: Boolean(options.skipOnCorrectnessFailure),
  };
}

function localBinCase(runnerKey, runner, scenario, program, commandArgs, options = {}) {
  return {
    id: `local-bin-${scenario.scenario}-${runnerKey}`,
    group: "local-bin-runner",
    runnerKey,
    runner,
    scenario: scenario.scenario,
    label: scenario.label,
    command: makeCommand(program, commandArgs),
    targetBin: scenario.bin,
    expected: scenario.expected,
    skipOnCorrectnessFailure: Boolean(options.skipOnCorrectnessFailure),
  };
}

function filteredCases(cases) {
  return cases.filter((benchCase) => {
    if (SCENARIO_FILTER && !SCENARIO_FILTER.test(benchCase.scenario) && !SCENARIO_FILTER.test(benchCase.id)) {
      return false;
    }
    if (RUNNER_FILTER && !RUNNER_FILTER.has(benchCase.runnerKey) && !RUNNER_FILTER.has(benchCase.runner)) {
      return false;
    }
    return !(GROUP_FILTER && !GROUP_FILTER.has(benchCase.group));
  });
}

function measureCase(benchCase, projectDir) {
  const unavailableReason = runnerUnavailableReason(benchCase);
  if (unavailableReason) {
    return skippedResult(benchCase, unavailableReason);
  }

  const envRoot = path.join(workRoot, "env", sanitizeName(benchCase.id));
  removeTree(envRoot);
  const env = benchmarkEnv(envRoot, projectDir);
  const correctness = runBenchCommand(benchCase.command, projectDir, env);
  const correctnessFailure = correctnessRunFailure(correctness, benchCase);
  if (correctnessFailure) {
    if (benchCase.skipOnCorrectnessFailure) {
      return skippedResult(benchCase, correctnessFailure);
    }
    return failedResult(benchCase, `correctness check failed: ${correctnessFailure}`);
  }
  const mismatch = expectedMismatch(benchCase.expected, correctness.stdout);
  if (mismatch) {
    return failedResult(benchCase, `correctness check failed: ${mismatch}`);
  }

  for (let warmup = 0; warmup < WARMUP_ITERATIONS; warmup += 1) {
    const run = runBenchCommand(benchCase.command, projectDir, env);
    const failure = correctnessRunFailure(run, benchCase);
    if (failure) {
      return failedResult(benchCase, `warmup failed: ${failure}`);
    }
    const warmupMismatch = expectedMismatch(benchCase.expected, run.stdout);
    if (warmupMismatch) {
      return failedResult(benchCase, `warmup failed: ${warmupMismatch}`);
    }
  }

  const samples = [];
  for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
    const started = process.hrtime.bigint();
    const run = runBenchCommand(benchCase.command, projectDir, env);
    const elapsedNs = process.hrtime.bigint() - started;
    const failure = correctnessRunFailure(run, benchCase);
    if (failure) {
      return failedResult(benchCase, failure, samples);
    }
    const runMismatch = expectedMismatch(benchCase.expected, run.stdout);
    if (runMismatch) {
      return failedResult(benchCase, runMismatch, samples);
    }
    samples.push(Number(elapsedNs) / 1_000_000);
  }

  return passedResult(benchCase, samples);
}

function runBenchCommand(command, cwd, env) {
  return childProcess.spawnSync(command.program, command.args, {
    cwd,
    env,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: COMMAND_TIMEOUT_MS,
    windowsHide: true,
  });
}

function correctnessRunFailure(run, benchCase) {
  if (!run.error && run.status === 0) {
    return "";
  }
  return failureDetail(run, benchCase.command.display);
}

function runnerUnavailableReason(benchCase) {
  if (!executable(benchCase.command.program)) {
    return `${path.basename(benchCase.command.program)} binary was not found or is not executable`;
  }
  return "";
}

function createFixtureProject(projectDir) {
  removeTree(projectDir);
  fs.mkdirSync(projectDir, { recursive: true });
  writeJson(projectDir, "package.json", {
    name: "lpm-run-bin-benchmark-fixture",
    version: "0.0.0",
    private: true,
    scripts: {
      noop: "echo hi",
      "node-noop": "node -e \"process.stdout.write('node-noop\\\\n')\"",
      "esbuild-version": "esbuild --version",
    },
    dependencies: {
      esbuild: ESBUILD_VERSION,
      typescript: TYPESCRIPT_VERSION,
    },
  });
}

function installFixtureDependencies(projectDir) {
  const setup = chooseSetupTool(projectDir);
  const env = setupEnv(path.join(workRoot, "setup-env"));
  if (setup.storeDir) {
    env.npm_config_store_dir = setup.storeDir;
  }
  console.log(`[setup] installing fixture dependencies with ${setup.manager}`);
  runChecked(setup.program, setup.args, {
    cwd: projectDir,
    env,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return setup;
}

function chooseSetupTool(projectDir) {
  const explicit = process.env.SETUP_MANAGER || "";
  if (explicit === "pnpm") {
    if (!executable(PNPM_BIN)) {
      throw new Error("SETUP_MANAGER=pnpm but pnpm was not found");
    }
    return pnpmSetup(projectDir);
  }
  if (explicit === "npm") {
    if (!executable(NPM_BIN)) {
      throw new Error("SETUP_MANAGER=npm but npm was not found");
    }
    return npmSetup();
  }
  if (explicit) {
    throw new Error("SETUP_MANAGER must be pnpm or npm");
  }
  if (executable(PNPM_BIN)) {
    return pnpmSetup(projectDir);
  }
  if (executable(NPM_BIN)) {
    return npmSetup();
  }
  throw new Error("npm or pnpm is required for fixture setup");
}

function pnpmSetup(projectDir) {
  const storeDir = path.join(projectDir, ".pnpm-store");
  return {
    manager: "pnpm",
    program: PNPM_BIN,
    args: [
      "install",
      "--no-frozen-lockfile",
      "--config.dangerously-allow-all-builds=true",
      "--store-dir",
      storeDir,
    ],
    display: shellDisplay([
      PNPM_BIN,
      "install",
      "--no-frozen-lockfile",
      "--config.dangerously-allow-all-builds=true",
      "--store-dir",
      storeDir,
    ]),
    storeDir,
  };
}

function npmSetup() {
  return {
    manager: "npm",
    program: NPM_BIN,
    args: ["install", "--no-audit", "--no-fund"],
    display: shellDisplay([NPM_BIN, "install", "--no-audit", "--no-fund"]),
  };
}

function setupEnv(envRoot) {
  const env = { ...process.env };
  const home = path.join(envRoot, "home");
  const cache = path.join(envRoot, "cache");
  const tmp = path.join(envRoot, "tmp");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(cache, { recursive: true });
  fs.mkdirSync(tmp, { recursive: true });
  env.HOME = home;
  env.XDG_CACHE_HOME = cache;
  env.TMPDIR = tmp;
  env.TEMP = tmp;
  env.TMP = tmp;
  env.NO_COLOR = "1";
  env.FORCE_COLOR = "0";
  env.COREPACK_ENABLE_DOWNLOAD_PROMPT = "0";
  env.npm_config_audit = "false";
  env.npm_config_fund = "false";
  env.npm_config_update_notifier = "false";
  env.PATH = path.dirname(NODE_BIN) + path.delimiter + String(env.PATH || "");
  return env;
}

function benchmarkEnv(envRoot, projectDir) {
  const env = setupEnv(envRoot);
  const lpmHome = path.join(envRoot, "lpm-home");
  const bunInstallCache = path.join(envRoot, "bun-install-cache");
  fs.mkdirSync(lpmHome, { recursive: true });
  fs.mkdirSync(bunInstallCache, { recursive: true });
  delete env.NODE_OPTIONS;
  delete env.CI;
  delete env.GITHUB_ACTIONS;
  env.LPM_HOME = lpmHome;
  env.LPM_NO_UPDATE_CHECK = "1";
  env.BUN_INSTALL_CACHE_DIR = bunInstallCache;
  env.npm_config_offline = "true";
  env.npm_config_prefer_offline = "true";
  env.npm_config_store_dir = path.join(projectDir, ".pnpm-store");
  env.PATH = [
    path.join(projectDir, "node_modules", ".bin"),
    path.dirname(NODE_BIN),
    String(process.env.PATH || ""),
  ]
    .filter(Boolean)
    .join(path.delimiter);
  return env;
}

function collectMetadata(setup) {
  const gitStatus = commandOutput("git", ["status", "--porcelain"], ROOT);
  const cpu = os.cpus()[0] || null;
  return {
    generatedAt: new Date().toISOString(),
    gitSha: commandOutput("git", ["rev-parse", "--short", "HEAD"], ROOT) || "unknown",
    gitBranch: commandOutput("git", ["branch", "--show-current"], ROOT) || "unknown",
    gitDirty: Boolean(gitStatus.trim()),
    gitStatus: gitStatus ? gitStatus.split(/\r?\n/).slice(0, 40) : [],
    iterations: ITERATIONS,
    warmupIterations: WARMUP_ITERATIONS,
    commandTimeoutMs: COMMAND_TIMEOUT_MS,
    fixtureDependencies: {
      esbuild: ESBUILD_VERSION,
      typescript: TYPESCRIPT_VERSION,
    },
    setup: {
      manager: setup.manager,
      command: setup.display,
    },
    binaries: {
      lpm: binaryMetadata(LPM_BIN, ["--version"], EXPLICIT_LPM_BIN ? "LPM_BIN" : "rebuilt release binary"),
      nub: binaryMetadata(NUB_BIN, ["--version"], process.env.NUB_BIN ? "NUB_BIN" : "PATH"),
      nubx: binaryMetadata(NUBX_BIN, ["--version"], process.env.NUBX_BIN ? "NUBX_BIN" : "PATH"),
      node: binaryMetadata(NODE_BIN, ["--version"], process.env.NODE_BIN ? "NODE_BIN" : "current Node process"),
      npm: binaryMetadata(NPM_BIN, ["--version"], process.env.NPM_BIN ? "NPM_BIN" : "PATH"),
      npx: binaryMetadata(NPX_BIN, ["--version"], process.env.NPX_BIN ? "NPX_BIN" : "PATH"),
      pnpm: binaryMetadata(PNPM_BIN, ["--version"], process.env.PNPM_BIN ? "PNPM_BIN" : "PATH"),
      bun: binaryMetadata(BUN_BIN, ["--version"], process.env.BUN_BIN ? "BUN_BIN" : "PATH"),
      bunx: binaryMetadata(BUNX_BIN, ["--version"], process.env.BUNX_BIN ? "BUNX_BIN" : "PATH"),
    },
    host: {
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      cpuModel: cpu ? cpu.model : "unknown",
      cpuCount: os.cpus().length,
      totalMemoryBytes: os.totalmem(),
    },
    filters: {
      scenarios: process.env.SCENARIOS || null,
      runners: process.env.RUNNERS || null,
      groups: process.env.GROUPS || null,
    },
    output: {
      markdown: MARKDOWN_OUT,
      json: JSON_OUT,
    },
  };
}

function binaryMetadata(program, versionArgs, source) {
  const available = executable(program);
  return {
    path: program || null,
    source,
    available,
    version: available ? versionOutput(program, versionArgs, ROOT) : null,
  };
}

function fixtureMetadata(projectDir, setup) {
  const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, "package.json"), "utf8"));
  return {
    packageJson: pkg,
    setupManager: setup.manager,
    setupCommand: setup.display,
    sameProjectForEveryRunner: true,
  };
}

function passedResult(benchCase, samples) {
  return {
    ...baseResult(benchCase),
    status: "pass",
    iterations: ITERATIONS,
    ...statsFor(samples),
  };
}

function failedResult(benchCase, reason, samples = []) {
  return {
    ...baseResult(benchCase),
    status: "failed",
    reason,
    iterations: samples.length,
    samplesMs: samples.map(round),
  };
}

function skippedResult(benchCase, reason) {
  return {
    ...baseResult(benchCase),
    status: "skipped",
    reason,
    iterations: 0,
  };
}

function baseResult(benchCase) {
  return {
    id: benchCase.id,
    group: benchCase.group,
    runner: benchCase.runner,
    runnerKey: benchCase.runnerKey,
    scenario: benchCase.scenario,
    label: benchCase.label,
    targetBin: benchCase.targetBin || null,
    command: {
      program: benchCase.command.program,
      args: benchCase.command.args,
      display: benchCase.command.display,
    },
    expectedStdout: benchCase.expected.description,
  };
}

function statsFor(samples) {
  const sorted = samples.slice().sort((a, b) => a - b);
  const total = samples.reduce((sum, value) => sum + value, 0);
  return {
    p50Ms: round(percentile(sorted, 0.5)),
    p95Ms: round(percentile(sorted, 0.95)),
    avgMs: round(total / samples.length),
    minMs: round(sorted[0]),
    maxMs: round(sorted[sorted.length - 1]),
    samplesMs: samples.map(round),
  };
}

function percentile(sorted, p) {
  const index = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1));
  return sorted[index];
}

function containsExpected(value) {
  return {
    description: `stdout contains ${JSON.stringify(value)}`,
    matches(stdout) {
      return String(stdout).includes(value);
    },
  };
}

function exactLineExpected(value) {
  return {
    description: `stdout has a line exactly ${JSON.stringify(value)}`,
    matches(stdout) {
      return String(stdout)
        .split(/\r?\n/)
        .map((line) => line.trim())
        .includes(value);
    },
  };
}

function expectedMismatch(expected, stdout) {
  if (expected.matches(stdout)) {
    return "";
  }
  return `expected ${expected.description}; stdout was ${JSON.stringify(tail(String(stdout || "").trim(), 400))}`;
}

function renderMarkdown(report) {
  const metadata = report.metadata;
  const lines = [];
  lines.push("# lpm run/bin benchmark suite", "");
  lines.push(`- Date: \`${metadata.generatedAt}\``);
  lines.push(`- Git: \`${metadata.gitSha}\` on \`${metadata.gitBranch}\` (${metadata.gitDirty ? "dirty" : "clean"})`);
  lines.push(`- Iterations: \`${metadata.iterations}\``);
  lines.push(`- Warmup iterations: \`${metadata.warmupIterations}\``);
  lines.push(`- Timeout per command: \`${metadata.commandTimeoutMs} ms\``);
  lines.push(`- Setup: \`${metadata.setup.command}\``);
  lines.push(`- Fixture dependencies: \`esbuild ${ESBUILD_VERSION}\`, \`typescript ${TYPESCRIPT_VERSION}\``);
  lines.push(`- Host: \`${metadata.host.platform} ${metadata.host.release} ${metadata.host.arch}\``);
  lines.push(`- CPU: \`${metadata.host.cpuModel} (${metadata.host.cpuCount} logical)\``);
  lines.push("");
  lines.push("## Tool versions", "");
  lines.push("| Tool | Available | Version | Binary |");
  lines.push("| --- | --- | --- | --- |");
  for (const [tool, info] of Object.entries(metadata.binaries)) {
    lines.push(
      [
        tool,
        info.available ? "yes" : "no",
        info.version || "-",
        info.path || "-",
      ]
        .map(escapeCell)
        .join(" | ")
        .replace(/^/, "| ")
        .replace(/$/, " |"),
    );
  }
  lines.push("");
  lines.push("## Methodology", "");
  lines.push(
    "All rows use the same generated project. Dependency installation is setup-only and is not measured; timed rows run only local scripts or already-installed local bins.",
  );
  lines.push(
    `Warm policy: each row runs one correctness check plus ${metadata.warmupIterations} unmeasured warmup iteration(s), then records ${metadata.iterations} measured iterations without clearing package-manager caches.`,
  );
  lines.push(
    "Native CLI and Node CLI local-bin rows are reported separately because wrapper overhead ratios differ once the target process has its own startup cost.",
  );
  lines.push("");
  lines.push("## Results", "");
  lines.push(
    "| Group | Scenario | Runner | Command | Status | Iterations | P50 ms | P95 ms | Avg ms | Min ms | Max ms | Reason |",
  );
  lines.push("| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |");
  for (const result of report.results) {
    lines.push(renderResultRow(result));
  }
  lines.push("");
  lines.push("Skipped rows mean the comparison tool or optional shorthand was unavailable in this environment.");
  return `${lines.join("\n")}\n`;
}

function renderResultRow(result) {
  const metric = (name) => (result.status === "pass" ? result[name].toFixed(2) : "-");
  return [
    result.group,
    result.scenario,
    result.runner,
    result.command.display,
    result.status,
    result.iterations,
    metric("p50Ms"),
    metric("p95Ms"),
    metric("avgMs"),
    metric("minMs"),
    metric("maxMs"),
    result.reason || "",
  ]
    .map(escapeCell)
    .join(" | ")
    .replace(/^/, "| ")
    .replace(/$/, " |");
}

function printProgress(result) {
  if (result.status === "pass") {
    console.log(
      `${result.group}/${result.scenario}/${result.runnerKey}: p50=${result.p50Ms.toFixed(2)}ms p95=${result.p95Ms.toFixed(2)}ms avg=${result.avgMs.toFixed(2)}ms`,
    );
    return;
  }
  console.log(`${result.group}/${result.scenario}/${result.runnerKey}: ${result.status} (${result.reason})`);
}

function makeCommand(program, args) {
  return {
    program,
    args,
    display: shellDisplay([program, ...args]),
  };
}

function shellDisplay(parts) {
  return parts.map(shellQuote).join(" ");
}

function shellQuote(value) {
  const raw = String(value);
  if (/^[A-Za-z0-9_/@%+=:,.-]+$/.test(raw)) {
    return raw;
  }
  return JSON.stringify(raw);
}

function writeJson(root, relativePath, value) {
  writeFile(root, relativePath, `${JSON.stringify(value, null, 2)}\n`);
}

function writeFile(root, relativePath, contents) {
  const file = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function nonNegativeInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function csvList(value) {
  return String(value || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function truthy(value) {
  return ["1", "true", "TRUE", "yes", "YES", "on", "ON"].includes(String(value || ""));
}

function resolveToolBin(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }
  if (path.isAbsolute(raw) || raw.startsWith(".") || raw.includes("/") || raw.includes("\\")) {
    return path.resolve(raw);
  }
  return commandPath(raw) || raw;
}

function commandPath(command) {
  const searchPath = String(process.env.PATH || "");
  const pathExt = process.platform === "win32" ? String(process.env.PATHEXT || ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of searchPath.split(path.delimiter)) {
    if (!dir) {
      continue;
    }
    for (const ext of pathExt) {
      const candidate = path.join(dir, `${command}${ext}`);
      if (executable(candidate)) {
        return candidate;
      }
    }
  }
  return "";
}

function executable(file) {
  if (!file) {
    return false;
  }
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch (_error) {
    return false;
  }
}

function runChecked(command, commandArgs, options) {
  const result = childProcess.spawnSync(command, commandArgs, options);
  if (result.status !== 0 || result.error) {
    throw new Error(failureDetail(result, shellDisplay([command, ...commandArgs])));
  }
}

function commandOutput(command, commandArgs, cwd) {
  const result = childProcess.spawnSync(command, commandArgs, {
    cwd,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: COMMAND_TIMEOUT_MS,
    windowsHide: true,
  });
  if (result.status !== 0 || result.error) {
    return "";
  }
  return String(result.stdout || "").trim();
}

function versionOutput(command, commandArgs, cwd) {
  return commandOutput(command, commandArgs, cwd).replace(/\s+/g, " ") || "unavailable";
}

function failureDetail(result, command) {
  if (result.error) {
    return `${command}: ${result.error.message}`;
  }
  const stderr = String(result.stderr || "").trim();
  const stdout = String(result.stdout || "").trim();
  const detail = stderr || stdout || `exit status ${result.status}`;
  return `${command}: ${tail(detail, 1200)}`;
}

function tail(value, maxChars) {
  return value.length > maxChars ? value.slice(value.length - maxChars) : value;
}

function round(value) {
  return Math.round(value * 100) / 100;
}

function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function sanitizeName(value) {
  return String(value).replace(/[^A-Za-z0-9_.-]/g, "-");
}

function removeTree(target) {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      fs.rmSync(target, {
        recursive: true,
        force: true,
      });
      return;
    } catch (error) {
      if (!["ENOTEMPTY", "EBUSY", "EPERM"].includes(error?.code) || attempt === 5) {
        if (process.platform !== "win32") {
          childProcess.spawnSync("rm", ["-rf", target]);
          if (!fs.existsSync(target)) {
            return;
          }
        }
        throw error;
      }
      sleep(100);
    }
  }
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function parseArgs(argv) {
  const parsed = {
    help: false,
    selfTest: false,
    list: false,
  };
  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
    } else if (arg === "--self-test") {
      parsed.selfTest = true;
    } else if (arg === "--list") {
      parsed.list = true;
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return parsed;
}

function printCaseList() {
  const cases = filteredCases(buildBenchmarkCases()).map((benchCase) => ({
    id: benchCase.id,
    group: benchCase.group,
    scenario: benchCase.scenario,
    runner: benchCase.runner,
    runnerKey: benchCase.runnerKey,
    command: benchCase.command,
    expectedStdout: benchCase.expected.description,
  }));
  console.log(
    JSON.stringify(
      {
        fixture: {
          scripts: ["noop", "node-noop", "esbuild-version"],
          dependencies: {
            esbuild: ESBUILD_VERSION,
            typescript: TYPESCRIPT_VERSION,
          },
        },
        cases,
      },
      null,
      2,
    ),
  );
}

function runSelfTests() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-run-bin-bench-self-test-"));
  try {
    createFixtureProject(tmp);
    const pkg = JSON.parse(fs.readFileSync(path.join(tmp, "package.json"), "utf8"));
    assert.equal(pkg.scripts.noop, "echo hi");
    assert.equal(pkg.scripts["esbuild-version"], "esbuild --version");
    assert.equal(pkg.dependencies.esbuild, ESBUILD_VERSION);
    assert.equal(pkg.dependencies.typescript, TYPESCRIPT_VERSION);

    const cases = buildBenchmarkCases();
    assertCommand(cases, "script-noop-lpm-run", ["run", "noop"]);
    assertCommand(cases, "script-noop-lpm-shortcut", ["noop"]);
    assertCommand(cases, "local-bin-esbuild-version-lpm-exec", ["exec", "esbuild", "--version"]);
    assertCommand(cases, "local-bin-esbuild-version-lpm-shorthand", ["esbuild", "--version"]);
    assertCommand(cases, "local-bin-esbuild-version-npx-no-install", [
      "--no-install",
      "esbuild",
      "--version",
    ]);
    assertCommand(cases, "local-bin-esbuild-version-npm-exec", ["exec", "--", "esbuild", "--version"]);
    assert.equal(exactLineExpected(ESBUILD_VERSION).matches(`wrapper\n${ESBUILD_VERSION}\n`), true);
    assert.notEqual(expectedMismatch(exactLineExpected(ESBUILD_VERSION), "11.0.0"), "");
  } finally {
    removeTree(tmp);
  }
  console.log("run-bin-benchmark self-test passed");
}

function assertCommand(cases, id, expectedArgs) {
  const benchCase = cases.find((candidate) => candidate.id === id);
  assert.ok(benchCase, `missing benchmark case ${id}`);
  assert.deepEqual(benchCase.command.args, expectedArgs);
}

function printHelp() {
  console.log(`Usage: node bench/scripts/run-bin-benchmark.mjs [options]

Options:
  --list       Print generated benchmark cases without building, installing, or timing
  --self-test  Validate fixture generation and command construction
  -h, --help   Show this help

Environment:
  ITERATIONS=30
  WARMUP_ITERATIONS=2
  COMMAND_TIMEOUT_MS=30000
  LPM_BIN=/path/to/lpm-rs
  NUB_BIN=/path/to/nub
  NUBX_BIN=/path/to/nubx
  NODE_BIN=/path/to/node
  NPM_BIN=/path/to/npm
  NPX_BIN=/path/to/npx
  PNPM_BIN=/path/to/pnpm
  BUN_BIN=/path/to/bun
  BUNX_BIN=/path/to/bunx
  SETUP_MANAGER=pnpm|npm
  SCENARIOS=noop|node-noop|esbuild-version|tsc-version
  RUNNERS=lpm-run,lpm-shortcut,npm-run,pnpm-run,lpm-exec,npx-no-install
  GROUPS=script-runner,local-bin-runner
  OUT=bench/perf-results/run-bin-suite-name.md
  JSON_OUT=bench/perf-results/run-bin-suite-name.json
  KEEP_BENCH_WORK=1
`);
}
