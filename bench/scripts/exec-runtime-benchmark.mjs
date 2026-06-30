#!/usr/bin/env node

import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(SCRIPT_DIR, "../..");
const BENCH_DIR = path.join(ROOT, "bench");
const RESULTS_DIR = path.join(BENCH_DIR, "perf-results");
const TIMESTAMP = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
const ITERATIONS = positiveInt(process.env.ITERATIONS, 30);
const WARMUP_ITERATIONS = positiveInt(process.env.WARMUP_ITERATIONS, 1);
const MODULE_COUNTS = numberList(process.env.MODULE_COUNTS, [1, 10, 100]);
const TRANSFORM_PROTOCOL_VERSION = 1;
const MAX_TRANSFORM_OUTPUT_BYTES = 64 * 1024 * 1024;
const EXPLICIT_LPM_BIN = Boolean(process.env.LPM_BIN);
const LPM_BIN = path.resolve(process.env.LPM_BIN || path.join(ROOT, "target/release/lpm-rs"));
const EXPLICIT_NODE_BIN = Boolean(process.env.NODE_BIN);
const NODE_BIN = resolveToolBin(process.env.NODE_BIN) || process.execPath;
const BUN_BIN = resolveToolBin(process.env.BUN_BIN || "bun");
const BUN_BIN_SOURCE = process.env.BUN_BIN ? "BUN_BIN" : executable(BUN_BIN) ? "PATH" : null;
const NUB_BIN = resolveToolBin(process.env.NUB_BIN);
const TSX_BIN_SOURCE = process.env.TSX_BIN ? "TSX_BIN" : process.env.LOCAL_TSX_BIN ? "LOCAL_TSX_BIN" : null;
const TSX_BIN = resolveToolBin(process.env.TSX_BIN || process.env.LOCAL_TSX_BIN);
const MARKDOWN_OUT = path.resolve(
  process.env.OUT || process.env.MARKDOWN_OUT || path.join(RESULTS_DIR, `exec-runtime-suite-${TIMESTAMP}.md`),
);
const JSON_OUT = path.resolve(
  process.env.JSON_OUT || path.join(RESULTS_DIR, `${path.basename(MARKDOWN_OUT, ".md")}.json`),
);
const KEEP_WORK = truthy(process.env.KEEP_BENCH_WORK);
const SCENARIO_FILTER = process.env.SCENARIOS ? new RegExp(process.env.SCENARIOS) : null;

if (!executable(NODE_BIN)) {
  throw new Error(`${EXPLICIT_NODE_BIN ? "explicit NODE_BIN" : "current Node binary"} is not executable: ${NODE_BIN}`);
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
const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-exec-runtime-bench-"));

try {
  const metadata = collectMetadata();
  const scenarios = buildScenarios().filter(
    (scenario) =>
      !SCENARIO_FILTER || SCENARIO_FILTER.test(scenario.id) || SCENARIO_FILTER.test(scenario.fixture),
  );
  const results = [];

  for (const scenario of scenarios) {
    const projectDir = path.join(workRoot, "projects", scenario.id);
    removeTree(projectDir);
    scenario.createProject(projectDir);

    for (const cacheMode of scenario.cacheModes) {
      const result = measureScenario(scenario, projectDir, cacheMode);
      results.push(result);
      printProgress(result);
    }
  }

  const report = { metadata, results };
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

function collectMetadata() {
  return {
    generatedAt: new Date().toISOString(),
    sourceGitSha: commandOutput("git", ["rev-parse", "--short", "HEAD"], ROOT) || "unknown",
    lpmBinarySource: EXPLICIT_LPM_BIN ? "explicit LPM_BIN" : "rebuilt release binary",
    iterations: ITERATIONS,
    warmupIterations: WARMUP_ITERATIONS,
    moduleCounts: MODULE_COUNTS,
    nodeBinary: NODE_BIN,
    nodeBinarySource: EXPLICIT_NODE_BIN ? "explicit NODE_BIN" : "current Node process",
    nodeVersion: versionOutput(NODE_BIN, ["--version"], ROOT),
    npmVersion: versionOutput("npm", ["--version"], ROOT),
    lpmBinary: LPM_BIN,
    lpmVersion: versionOutput(LPM_BIN, ["--version"], ROOT),
    bunBin: BUN_BIN && executable(BUN_BIN) ? BUN_BIN : null,
    bunBinSource: BUN_BIN_SOURCE,
    bunAvailable: Boolean(BUN_BIN && executable(BUN_BIN)),
    bunVersion: BUN_BIN && executable(BUN_BIN) ? versionOutput(BUN_BIN, ["--version"], ROOT) : null,
    nubBin: NUB_BIN || null,
    nubAvailable: Boolean(NUB_BIN && executable(NUB_BIN)),
    nubVersion: NUB_BIN && executable(NUB_BIN) ? versionOutput(NUB_BIN, ["--version"], ROOT) : null,
    tsxBin: TSX_BIN || null,
    tsxBinSource: TSX_BIN_SOURCE,
    tsxAvailable: Boolean(TSX_BIN && executable(TSX_BIN)),
    tsxVersion: TSX_BIN && executable(TSX_BIN) ? versionOutput(TSX_BIN, ["--version"], ROOT) : null,
    markdownOut: MARKDOWN_OUT,
    jsonOut: JSON_OUT,
    scenarioFilter: process.env.SCENARIOS || null,
  };
}

function buildScenarios() {
  const scenarios = [];

  for (const moduleCount of MODULE_COUNTS) {
    addTsComparisonScenarios(scenarios, {
      fixture: `ts-cjs-modules-${moduleCount}`,
      label: "TS CJS",
      format: "commonjs",
      projectMode: "commonjs-omitted",
      moduleCount,
      tsEntry: "scripts/entry.ts",
      jsEntry: "scripts/entry.js",
      createProject: (projectDir) =>
        createTsProject(projectDir, {
          ext: ".ts",
          format: "commonjs",
          projectMode: "commonjs-omitted",
          moduleCount,
          jsBaseline: true,
        }),
    });

    addTsComparisonScenarios(scenarios, {
      fixture: `ts-esm-modules-${moduleCount}`,
      label: "TS ESM",
      format: "module",
      projectMode: "module",
      moduleCount,
      tsEntry: "scripts/entry.ts",
      jsEntry: "scripts/entry.js",
      createProject: (projectDir) =>
        createTsProject(projectDir, {
          ext: ".ts",
          format: "module",
          projectMode: "module",
          moduleCount,
          jsBaseline: true,
        }),
    });

    addTsComparisonScenarios(scenarios, {
      fixture: `tsx-esm-modules-${moduleCount}`,
      label: "TSX ESM",
      format: "module",
      projectMode: "module",
      moduleCount,
      tsEntry: "scripts/entry.tsx",
      jsEntry: "scripts/entry.js",
      createProject: (projectDir) =>
        createTsxProject(projectDir, {
          projectMode: "module",
          moduleCount,
          jsBaseline: true,
        }),
    });

    addOxcHelperScenario(scenarios, {
      fixture: `oxc-helper-ts-cjs-files-${moduleCount}`,
      label: "LPM OXC helper TS CJS",
      entryKind: "ts",
      format: "commonjs",
      projectMode: "commonjs-omitted",
      moduleCount,
      ext: ".ts",
      createProject: (projectDir) =>
        createTsProject(projectDir, {
          ext: ".ts",
          format: "commonjs",
          projectMode: "commonjs-omitted",
          moduleCount,
        }),
    });

    addOxcHelperScenario(scenarios, {
      fixture: `oxc-helper-ts-esm-files-${moduleCount}`,
      label: "LPM OXC helper TS ESM",
      entryKind: "ts",
      format: "module",
      projectMode: "module",
      moduleCount,
      ext: ".ts",
      createProject: (projectDir) =>
        createTsProject(projectDir, {
          ext: ".ts",
          format: "module",
          projectMode: "module",
          moduleCount,
        }),
    });

    addOxcHelperScenario(scenarios, {
      fixture: `oxc-helper-tsx-esm-files-${moduleCount}`,
      label: "LPM OXC helper TSX ESM",
      entryKind: "tsx",
      format: "module",
      projectMode: "module",
      moduleCount,
      ext: ".tsx",
      createProject: (projectDir) =>
        createTsxProject(projectDir, {
          projectMode: "module",
          moduleCount,
        }),
    });
  }

  scenarios.push({
    id: "lpm-mts-esm-modules-10",
    runner: "lpm",
    fixture: "mts-esm-modules-10",
    label: "MTS ESM",
    entryKind: "mts",
    format: "module",
    projectMode: "commonjs-omitted",
    moduleCount: 10,
    cacheModes: ["cold", "warm"],
    createProject: (projectDir) =>
      createTsProject(projectDir, {
        ext: ".mts",
        format: "module",
        projectMode: "commonjs-omitted",
        moduleCount: 10,
      }),
    entry: "scripts/entry.mts",
  });
  scenarios.push({
    id: "lpm-cts-cjs-modules-10",
    runner: "lpm",
    fixture: "cts-cjs-modules-10",
    label: "CTS CJS",
    entryKind: "cts",
    format: "commonjs",
    projectMode: "module",
    moduleCount: 10,
    cacheModes: ["cold", "warm"],
    createProject: (projectDir) =>
      createTsProject(projectDir, {
        ext: ".cts",
        format: "commonjs",
        projectMode: "module",
        moduleCount: 10,
      }),
    entry: "scripts/entry.cts",
  });

  return scenarios;
}

function addTsComparisonScenarios(scenarios, options) {
  for (const runner of ["node", "bun", "lpm", "nub", "tsx"]) {
    scenarios.push({
      id: `${runner}-${options.fixture}`,
      runner,
      fixture: options.fixture,
      label: options.label,
      entryKind: runner === "node" ? "js" : path.extname(options.tsEntry).slice(1),
      format: options.format,
      projectMode: options.projectMode,
      moduleCount: options.moduleCount,
      cacheModes: ["cold", "warm"],
      createProject: options.createProject,
      entry: runner === "node" ? options.jsEntry : options.tsEntry,
    });
  }
}

function addOxcHelperScenario(scenarios, options) {
  for (const runner of ["lpm-oxc-helper", "lpm-oxc-helper-persistent"]) {
    scenarios.push({
      id: runner === "lpm-oxc-helper" ? `lpm-${options.fixture}` : `lpm-persistent-${options.fixture}`,
      runner,
      fixture: options.fixture,
      label: options.label,
      entryKind: options.entryKind,
      format: options.format,
      projectMode: options.projectMode,
      moduleCount: options.moduleCount,
      helperInvocations: options.moduleCount,
      cacheModes: ["none"],
      createProject: options.createProject,
      entry: runner === "lpm-oxc-helper" ? "internal-ts-transform" : "internal-ts-transform --persistent",
      helperFiles: (projectDir) => helperModuleFiles(projectDir, options.ext, options.moduleCount),
    });
  }
}

function runnerUnavailableReason(runner) {
  if (runner === "bun" && !executable(BUN_BIN)) {
    return "BUN_BIN is unset or bun was not found on PATH";
  }
  if (runner === "nub" && !executable(NUB_BIN)) {
    return "NUB_BIN is unset or not executable";
  }
  if (runner === "tsx" && !executable(TSX_BIN)) {
    return "TSX_BIN/LOCAL_TSX_BIN is unset or not executable";
  }
  return "";
}

function measureScenario(scenario, projectDir, cacheMode) {
  const unavailableReason = runnerUnavailableReason(scenario.runner);
  if (unavailableReason) {
    return skippedResult(scenario, cacheMode, unavailableReason);
  }
  if (scenario.runner === "lpm-oxc-helper" || scenario.runner === "lpm-oxc-helper-persistent") {
    return measureOxcHelperScenario(scenario, projectDir, cacheMode);
  }

  const envRoot = path.join(workRoot, "env", `${scenario.id}-${cacheMode}`);
  removeTree(envRoot);
  const env = benchmarkEnv(envRoot);
  const command = commandForScenario(scenario, projectDir);

  try {
    prepareCacheState(scenario, cacheMode, projectDir, envRoot, env, command);
  } catch (error) {
    return failedResult(scenario, cacheMode, `warmup failed: ${error.message}`);
  }

  const samples = [];
  for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
    if (cacheMode === "cold") {
      resetColdCache(scenario, envRoot);
    }
    const started = process.hrtime.bigint();
    const run = childProcess.spawnSync(command.program, command.args, {
      cwd: projectDir,
      env,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    const elapsedNs = process.hrtime.bigint() - started;
    if (run.status !== 0 || run.error) {
      return failedResult(
        scenario,
        cacheMode,
        failureDetail(run, `${command.program} ${command.args.join(" ")}`),
        samples,
      );
    }
    samples.push(Number(elapsedNs) / 1_000_000);
  }

  return passedResult(scenario, cacheMode, samples);
}

function measureOxcHelperScenario(scenario, projectDir, cacheMode) {
  const envRoot = path.join(workRoot, "env", `${scenario.id}-${cacheMode}`);
  removeTree(envRoot);
  const env = benchmarkEnv(envRoot);
  const inputs = helperTransformInputs(scenario, projectDir);
  const runHelperInputs =
    scenario.runner === "lpm-oxc-helper-persistent" ? runHelperInputsPersistentOnce : runHelperInputsOnce;
  if (inputs.length === 0) {
    return failedResult(scenario, cacheMode, "helper scenario did not produce transform inputs");
  }

  try {
    for (let i = 0; i < WARMUP_ITERATIONS; i += 1) {
      const failed = runHelperInputs(inputs, projectDir, env);
      if (failed) {
        throw new Error(failed);
      }
    }
  } catch (error) {
    return failedResult(scenario, cacheMode, `warmup failed: ${error.message}`);
  }

  const samples = [];
  for (let iteration = 0; iteration < ITERATIONS; iteration += 1) {
    const started = process.hrtime.bigint();
    const failed = runHelperInputs(inputs, projectDir, env);
    const elapsedNs = process.hrtime.bigint() - started;
    if (failed) {
      return failedResult(scenario, cacheMode, failed, samples);
    }
    samples.push(Number(elapsedNs) / 1_000_000);
  }

  return passedResult(scenario, cacheMode, samples);
}

function helperTransformInputs(scenario, projectDir) {
  return scenario.helperFiles(projectDir).map((filename) => {
    const source = fs.readFileSync(filename, "utf8");
    return JSON.stringify({
      schemaVersion: TRANSFORM_PROTOCOL_VERSION,
      filename,
      source,
      format: scenario.format,
      sourceMap: true,
      options: {
        format: scenario.format,
        jsx: {
          runtime: "automatic",
          development: false,
          importSource: "react",
        },
      },
    });
  });
}

function runHelperInputsOnce(inputs, projectDir, env) {
  for (const input of inputs) {
    const run = childProcess.spawnSync(LPM_BIN, ["internal-ts-transform"], {
      cwd: projectDir,
      env,
      input,
      encoding: "utf8",
      maxBuffer: MAX_TRANSFORM_OUTPUT_BYTES,
      windowsHide: true,
    });
    if (run.status !== 0 || run.error) {
      return failureDetail(run, `${LPM_BIN} internal-ts-transform`);
    }
  }
  return "";
}

function runHelperInputsPersistentOnce(inputs, projectDir, env) {
  const run = childProcess.spawnSync(LPM_BIN, ["internal-ts-transform", "--persistent"], {
    cwd: projectDir,
    env,
    input: `${inputs.join("\n")}\n`,
    encoding: "utf8",
    maxBuffer: MAX_TRANSFORM_OUTPUT_BYTES,
    windowsHide: true,
  });
  if (run.status !== 0 || run.error) {
    return failureDetail(run, `${LPM_BIN} internal-ts-transform --persistent`);
  }

  const lines = String(run.stdout || "")
    .split(/\r?\n/)
    .filter(Boolean);
  if (lines.length !== inputs.length) {
    return `expected ${inputs.length} persistent helper responses, got ${lines.length}`;
  }
  for (const line of lines) {
    let response;
    try {
      response = JSON.parse(line);
    } catch (error) {
      return `persistent helper returned invalid JSON: ${error.message}`;
    }
    if (response.error) {
      return `persistent helper returned error: ${response.error}`;
    }
    if (response.schemaVersion !== TRANSFORM_PROTOCOL_VERSION || typeof response.code !== "string") {
      return "persistent helper returned an invalid response envelope";
    }
  }
  return "";
}

function prepareCacheState(scenario, cacheMode, projectDir, envRoot, env, command) {
  if (cacheMode === "none") {
    return;
  }
  if (cacheMode === "cold") {
    runScenarioOnce(command, projectDir, env);
    resetColdCache(scenario, envRoot);
    return;
  }
  resetColdCache(scenario, envRoot);
  for (let i = 0; i < WARMUP_ITERATIONS; i += 1) {
    runScenarioOnce(command, projectDir, env);
  }
}

function resetColdCache(scenario, envRoot) {
  if (scenario.runner === "lpm") {
    removeTree(path.join(envRoot, "lpm-home/cache/exec-ts-runtime/v3/transform-cache"));
    return;
  }
  if (scenario.runner === "nub") {
    removeTree(path.join(envRoot, "xdg-cache/nub/transpile"));
    removeTree(path.join(envRoot, "home/.cache/nub/transpile"));
    return;
  }
  for (const dir of ["home", "xdg-cache", "tmp", "bun-install-cache"]) {
    removeTree(path.join(envRoot, dir));
  }
  for (const dir of ["home", "xdg-cache", "tmp", "bun-install-cache"]) {
    fs.mkdirSync(path.join(envRoot, dir), { recursive: true });
  }
}

function runScenarioOnce(command, projectDir, env) {
  const run = childProcess.spawnSync(command.program, command.args, {
    cwd: projectDir,
    env,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (run.status !== 0 || run.error) {
    throw new Error(failureDetail(run, `${command.program} ${command.args.join(" ")}`));
  }
}

function commandForScenario(scenario, projectDir) {
  if (scenario.runner === "node") {
    return {
      program: NODE_BIN,
      args: [scenario.entry],
    };
  }
  if (scenario.runner === "bun") {
    return {
      program: BUN_BIN,
      args: [scenario.entry],
    };
  }
  if (scenario.runner === "nub") {
    return {
      program: NUB_BIN,
      args: [scenario.entry],
    };
  }
  if (scenario.runner === "tsx") {
    return {
      program: TSX_BIN,
      args: [scenario.entry],
    };
  }
  return {
    program: LPM_BIN,
    args: ["exec", scenario.entry],
  };
}

function benchmarkEnv(envRoot) {
  const lpmHome = path.join(envRoot, "lpm-home");
  const home = path.join(envRoot, "home");
  const xdgCache = path.join(envRoot, "xdg-cache");
  const tmp = path.join(envRoot, "tmp");
  const bunInstallCache = path.join(envRoot, "bun-install-cache");
  fs.mkdirSync(lpmHome, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(xdgCache, { recursive: true });
  fs.mkdirSync(tmp, { recursive: true });
  fs.mkdirSync(bunInstallCache, { recursive: true });
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  env.LPM_HOME = lpmHome;
  env.HOME = home;
  env.XDG_CACHE_HOME = xdgCache;
  env.TMPDIR = tmp;
  env.TEMP = tmp;
  env.TMP = tmp;
  env.BUN_INSTALL_CACHE_DIR = bunInstallCache;
  env.PATH = env.PATH ? `${path.dirname(NODE_BIN)}${path.delimiter}${env.PATH}` : path.dirname(NODE_BIN);
  env.NO_COLOR = "1";
  env.FORCE_COLOR = "0";
  env.CI = "1";
  return env;
}

function helperModuleFiles(projectDir, ext, moduleCount) {
  const files = [];
  for (let i = 0; i < moduleCount; i += 1) {
    files.push(path.join(projectDir, `scripts/module-${i}${ext}`));
  }
  return files;
}

function createTsProject(projectDir, options) {
  createBaseProject(projectDir, options.projectMode, false);
  if (options.jsBaseline) {
    createJsModules(projectDir, options.format, options.moduleCount);
  }
  if (options.format === "commonjs") {
    createCommonJsTsModules(projectDir, options.ext, options.moduleCount);
  } else {
    createModuleTsModules(projectDir, options.ext, options.moduleCount);
  }
}

function createTsxProject(projectDir, options) {
  createBaseProject(projectDir, options.projectMode, true);
  createFakeReactRuntime(projectDir);
  if (options.jsBaseline) {
    createJsxBaselineModules(projectDir, options.moduleCount);
  }
  for (let i = 0; i < options.moduleCount; i += 1) {
    writeFile(
      projectDir,
      `scripts/module-${i}.tsx`,
      [
        `export function view${i}(): JSX.Element {`,
        `  return <span data-index="${i}">module-${i}</span>;`,
        "}",
        "",
      ].join("\n"),
    );
  }
  const imports = [];
  const calls = [];
  for (let i = 0; i < options.moduleCount; i += 1) {
    imports.push(`import { view${i} } from "./module-${i}.tsx";`);
    calls.push(`view${i}()`);
  }
  writeFile(
    projectDir,
    "scripts/entry.tsx",
    [
      ...imports,
      "",
      `const nodes: JSX.Element[] = [${calls.join(", ")}];`,
      `if (nodes.length !== ${options.moduleCount}) process.exit(9);`,
      "console.log(nodes.length);",
      "",
    ].join("\n"),
  );
}

function createJsModules(projectDir, format, moduleCount) {
  if (format === "commonjs") {
    createCommonJsModules(projectDir, ".js", moduleCount, {
      moduleLine: (i) => `const value = ${i + 1};`,
      requireLine: (i) => `const mod${i} = require("./module-${i}.js");`,
      entry: "scripts/entry.js",
    });
  } else {
    createModuleJsModules(projectDir, moduleCount);
  }
}

function createJsxBaselineModules(projectDir, moduleCount) {
  for (let i = 0; i < moduleCount; i += 1) {
    writeFile(
      projectDir,
      `scripts/module-${i}.js`,
      [
        'import { jsx as _jsx } from "react/jsx-runtime";',
        `export function view${i}() {`,
        `  return _jsx("span", { "data-index": "${i}", children: "module-${i}" });`,
        "}",
        "",
      ].join("\n"),
    );
  }
  const imports = [];
  const calls = [];
  for (let i = 0; i < moduleCount; i += 1) {
    imports.push(`import { view${i} } from "./module-${i}.js";`);
    calls.push(`view${i}()`);
  }
  writeFile(
    projectDir,
    "scripts/entry.js",
    [
      ...imports,
      "",
      `const nodes = [${calls.join(", ")}];`,
      `if (nodes.length !== ${moduleCount}) process.exit(9);`,
      "console.log(nodes.length);",
      "",
    ].join("\n"),
  );
}

function createCommonJsTsModules(projectDir, ext, moduleCount) {
  createCommonJsModules(projectDir, ext, moduleCount, {
    moduleLine: (i) => `const value: number = ${i + 1};`,
    requireLine: (i) => `const mod${i}: { value: number } = require("./module-${i}${ext}");`,
    entry: `scripts/entry${ext}`,
  });
}

function createCommonJsModules(projectDir, ext, moduleCount, options) {
  for (let i = 0; i < moduleCount; i += 1) {
    writeFile(
      projectDir,
      `scripts/module-${i}${ext}`,
      [options.moduleLine(i), "module.exports = { value };", ""].join("\n"),
    );
  }
  const requires = [];
  const terms = [];
  for (let i = 0; i < moduleCount; i += 1) {
    requires.push(options.requireLine(i));
    terms.push(`mod${i}.value`);
  }
  writeFile(
    projectDir,
    options.entry,
    [
      ...requires,
      "",
      `const total${ext === ".js" ? "" : ": number"} = ${terms.join(" + ")};`,
      `if (total !== ${sumOneTo(moduleCount)}) process.exit(8);`,
      "console.log(total);",
      "",
    ].join("\n"),
  );
}

function createModuleJsModules(projectDir, moduleCount) {
  for (let i = 0; i < moduleCount; i += 1) {
    writeFile(projectDir, `scripts/module-${i}.js`, `export const value${i} = ${i + 1};\n`);
  }
  const imports = [];
  const terms = [];
  for (let i = 0; i < moduleCount; i += 1) {
    imports.push(`import { value${i} } from "./module-${i}.js";`);
    terms.push(`value${i}`);
  }
  writeFile(
    projectDir,
    "scripts/entry.js",
    [
      ...imports,
      "",
      `const total = ${terms.join(" + ")};`,
      `if (total !== ${sumOneTo(moduleCount)}) process.exit(8);`,
      "console.log(total);",
      "",
    ].join("\n"),
  );
}

function createModuleTsModules(projectDir, ext, moduleCount) {
  for (let i = 0; i < moduleCount; i += 1) {
    writeFile(projectDir, `scripts/module-${i}${ext}`, `export const value${i}: number = ${i + 1};\n`);
  }
  const imports = [];
  const terms = [];
  for (let i = 0; i < moduleCount; i += 1) {
    imports.push(`import { value${i} } from "./module-${i}${ext}";`);
    terms.push(`value${i}`);
  }
  writeFile(
    projectDir,
    `scripts/entry${ext}`,
    [
      ...imports,
      "",
      `const total: number = ${terms.join(" + ")};`,
      `if (total !== ${sumOneTo(moduleCount)}) process.exit(8);`,
      "console.log(total);",
      "",
    ].join("\n"),
  );
}

function createBaseProject(projectDir, projectMode, jsx) {
  fs.mkdirSync(path.join(projectDir, "scripts"), { recursive: true });
  const pkg = {
    name: "lpm-exec-runtime-bench",
    version: "0.0.0",
  };
  if (projectMode === "module") {
    pkg.type = "module";
  }
  writeJson(projectDir, "package.json", pkg);
  writeJson(projectDir, "tsconfig.json", {
    compilerOptions: {
      target: "ES2022",
      moduleResolution: "bundler",
      jsx: jsx ? "react-jsx" : "preserve",
      jsxImportSource: "react",
      baseUrl: ".",
    },
  });
}

function createFakeReactRuntime(projectDir) {
  writeJson(projectDir, "node_modules/react/package.json", {
    name: "react",
    version: "0.0.0",
    type: "commonjs",
    exports: {
      "./jsx-runtime": {
        import: "./jsx-runtime.mjs",
        require: "./jsx-runtime.js",
      },
      "./jsx-dev-runtime": {
        import: "./jsx-dev-runtime.mjs",
        require: "./jsx-dev-runtime.js",
      },
    },
  });
  writeFile(
    projectDir,
    "node_modules/react/jsx-runtime.js",
    [
      "function jsx(type, props, key) {",
      "  return { type, props: props || {}, key: key ?? null };",
      "}",
      'exports.Fragment = "Fragment";',
      "exports.jsx = jsx;",
      "exports.jsxs = jsx;",
      "",
    ].join("\n"),
  );
  writeFile(
    projectDir,
    "node_modules/react/jsx-runtime.mjs",
    [
      'export const Fragment = "Fragment";',
      "export function jsx(type, props, key) {",
      "  return { type, props: props || {}, key: key ?? null };",
      "}",
      "export const jsxs = jsx;",
      "",
    ].join("\n"),
  );
  writeFile(
    projectDir,
    "node_modules/react/jsx-dev-runtime.js",
    [
      "function jsxDEV(type, props, key) {",
      "  return { type, props: props || {}, key: key ?? null };",
      "}",
      'exports.Fragment = "Fragment";',
      "exports.jsxDEV = jsxDEV;",
      "",
    ].join("\n"),
  );
  writeFile(
    projectDir,
    "node_modules/react/jsx-dev-runtime.mjs",
    [
      'export const Fragment = "Fragment";',
      "export function jsxDEV(type, props, key) {",
      "  return { type, props: props || {}, key: key ?? null };",
      "}",
      "",
    ].join("\n"),
  );
  writeFile(projectDir, "scripts/jsx.d.ts", "declare namespace JSX { interface Element {} }\n");
}

function passedResult(scenario, cacheMode, samples) {
  const stats = statsFor(samples);
  const helperInvocations = scenario.helperInvocations || 0;
  return {
    runner: scenario.runner,
    scenario: scenario.id,
    fixture: scenario.fixture,
    label: scenario.label,
    status: "pass",
    cacheMode,
    moduleCount: scenario.moduleCount,
    format: scenario.format,
    projectMode: scenario.projectMode,
    entryKind: scenario.entryKind,
    entry: scenario.entry,
    helperInvocations,
    iterations: ITERATIONS,
    ...(helperInvocations > 0
      ? {
          avgPerHelperInvocationMs: round(stats.avgMs / helperInvocations),
          p50PerHelperInvocationMs: round(stats.p50Ms / helperInvocations),
          p95PerHelperInvocationMs: round(stats.p95Ms / helperInvocations),
        }
      : {}),
    ...stats,
  };
}

function failedResult(scenario, cacheMode, reason, samples = []) {
  const helperInvocations = scenario.helperInvocations || 0;
  return {
    runner: scenario.runner,
    scenario: scenario.id,
    fixture: scenario.fixture,
    label: scenario.label,
    status: "failed",
    reason,
    cacheMode,
    moduleCount: scenario.moduleCount,
    format: scenario.format,
    projectMode: scenario.projectMode,
    entryKind: scenario.entryKind,
    entry: scenario.entry,
    helperInvocations,
    iterations: samples.length,
  };
}

function skippedResult(scenario, cacheMode, reason) {
  const helperInvocations = scenario.helperInvocations || 0;
  return {
    runner: scenario.runner,
    scenario: scenario.id,
    fixture: scenario.fixture,
    label: scenario.label,
    status: "skipped",
    reason,
    cacheMode,
    moduleCount: scenario.moduleCount,
    format: scenario.format,
    projectMode: scenario.projectMode,
    entryKind: scenario.entryKind,
    entry: scenario.entry,
    helperInvocations,
    iterations: 0,
  };
}

function statsFor(samples) {
  const sorted = samples.slice().sort((a, b) => a - b);
  const total = samples.reduce((sum, value) => sum + value, 0);
  return {
    avgMs: round(total / samples.length),
    minMs: round(sorted[0]),
    p50Ms: round(percentile(sorted, 0.5)),
    p95Ms: round(percentile(sorted, 0.95)),
    maxMs: round(sorted[sorted.length - 1]),
    samplesMs: samples.map(round),
  };
}

function percentile(sorted, p) {
  const index = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1));
  return sorted[index];
}

function renderMarkdown(report) {
  const lines = [];
  const metadata = report.metadata;
  lines.push("# lpm exec runtime benchmark suite", "");
  lines.push(`- Date: \`${metadata.generatedAt}\``);
  lines.push(`- Source Git SHA: \`${metadata.sourceGitSha}\``);
  lines.push(`- Iterations: \`${metadata.iterations}\``);
  lines.push(`- Warmup iterations: \`${metadata.warmupIterations}\``);
  lines.push(`- Module counts: \`${metadata.moduleCounts.join(", ")}\``);
  lines.push(`- Binary: \`${metadata.lpmBinary}\``);
  lines.push(`- Binary source: \`${metadata.lpmBinarySource}\``);
  lines.push(`- LPM: \`${metadata.lpmVersion}\``);
  lines.push(`- Node: \`${metadata.nodeVersion}\` via \`${metadata.nodeBinary}\``);
  lines.push(`- Node source: \`${metadata.nodeBinarySource}\``);
  lines.push(`- Bun: \`${metadata.bunAvailable ? metadata.bunVersion : "skipped"}\``);
  lines.push(`- Bun binary: \`${metadata.bunAvailable ? metadata.bunBin : "set BUN_BIN or put bun on PATH to enable"}\``);
  lines.push(`- Nub: \`${metadata.nubAvailable ? metadata.nubVersion : "skipped"}\``);
  lines.push(`- Nub binary: \`${metadata.nubAvailable ? metadata.nubBin : "set NUB_BIN to enable"}\``);
  lines.push(
    `- tsx: \`${metadata.tsxAvailable ? metadata.tsxVersion : "skipped"}\``,
  );
  lines.push(
    `- tsx binary: \`${metadata.tsxAvailable ? metadata.tsxBin : "set TSX_BIN or LOCAL_TSX_BIN to enable"}\``,
  );
  lines.push("");
  lines.push(
    "Each comparison fixture uses the same generated module graph: `node` runs the JS baseline, while `bun`, `lpm`, `nub`, and `tsx` run the matching TS/TSX source.",
  );
  lines.push(
    `Cold clears the runner's transform cache before every measured run. Warm runs ${metadata.warmupIterations} unmeasured warmup iteration(s) and then reuses that cache.`,
  );
  lines.push(
    "`lpm-oxc-helper` rows run one transform helper process per file. `lpm-oxc-helper-persistent` rows run one `internal-ts-transform --persistent` process for the whole module set.",
  );
  lines.push("");
  lines.push(
    "| Runner | Fixture | Entry | Cache | Modules | Helper calls | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P50/call ms | P95 ms | Max ms |",
  );
  lines.push("| --- | --- | --- | --- | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const result of report.results) {
    lines.push(renderResultRow(result));
  }
  lines.push("");
  lines.push(
    "Skipped Bun/Nub/tsx rows are benchmark-only comparisons; the harness never installs or fetches comparison tools.",
  );
  return `${lines.join("\n")}\n`;
}

function renderResultRow(result) {
  if (result.status !== "pass") {
    return [
      result.runner,
      result.fixture,
      result.entry,
      result.cacheMode,
      result.moduleCount,
      result.helperInvocations || "-",
      result.format,
      result.projectMode,
      `${result.status}: ${escapeCell(result.reason || "")}`,
      result.iterations,
      "-",
      "-",
      "-",
      "-",
      "-",
      "-",
    ].join(" | ").replace(/^/, "| ").replace(/$/, " |");
  }
  return [
    result.runner,
    result.fixture,
    result.entry,
    result.cacheMode,
    result.moduleCount,
    result.helperInvocations || "-",
    result.format,
    result.projectMode,
    result.status,
    result.iterations,
    result.avgMs.toFixed(2),
    result.minMs.toFixed(2),
    result.p50Ms.toFixed(2),
    result.p50PerHelperInvocationMs ? result.p50PerHelperInvocationMs.toFixed(2) : "-",
    result.p95Ms.toFixed(2),
    result.maxMs.toFixed(2),
  ].join(" | ").replace(/^/, "| ").replace(/$/, " |");
}

function printProgress(result) {
  if (result.status === "pass") {
    const helperSuffix = result.p50PerHelperInvocationMs
      ? ` p50/call=${result.p50PerHelperInvocationMs.toFixed(2)}ms`
      : "";
    console.log(
      `${result.scenario} ${result.cacheMode}: avg=${result.avgMs.toFixed(2)}ms p50=${result.p50Ms.toFixed(2)}ms p95=${result.p95Ms.toFixed(2)}ms${helperSuffix}`,
    );
    return;
  }
  console.log(`${result.scenario} ${result.cacheMode}: ${result.status} (${result.reason})`);
}

function writeJson(root, relativePath, value) {
  writeFile(root, relativePath, `${JSON.stringify(value, null, 2)}\n`);
}

function writeFile(root, relativePath, contents) {
  const file = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

function sumOneTo(count) {
  return (count * (count + 1)) / 2;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function numberList(value, fallback) {
  if (!value) {
    return fallback;
  }
  const parsed = value
    .split(",")
    .map((part) => Number.parseInt(part.trim(), 10))
    .filter((part) => Number.isFinite(part) && part > 0);
  return parsed.length > 0 ? parsed : fallback;
}

function truthy(value) {
  return ["1", "true", "TRUE", "yes", "YES"].includes(String(value || ""));
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

function runChecked(command, args, options) {
  const result = childProcess.spawnSync(command, args, options);
  if (result.status !== 0 || result.error) {
    throw new Error(failureDetail(result, `${command} ${args.join(" ")}`));
  }
}

function commandOutput(command, args, cwd) {
  const result = childProcess.spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  if (result.status !== 0 || result.error) {
    return "";
  }
  return String(result.stdout || "").trim();
}

function versionOutput(command, args, cwd) {
  return commandOutput(command, args, cwd).replace(/\s+/g, " ") || "unavailable";
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
