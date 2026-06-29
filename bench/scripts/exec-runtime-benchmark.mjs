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
const ITERATIONS = positiveInt(process.env.ITERATIONS, 10);
const WARMUP_ITERATIONS = positiveInt(process.env.WARMUP_ITERATIONS, 1);
const MODULE_COUNTS = numberList(process.env.MODULE_COUNTS, [1, 10, 100]);
const LPM_BIN = path.resolve(process.env.LPM_BIN || path.join(ROOT, "target/release/lpm-rs"));
const MARKDOWN_OUT = path.resolve(
  process.env.OUT || process.env.MARKDOWN_OUT || path.join(RESULTS_DIR, `exec-runtime-suite-${TIMESTAMP}.md`),
);
const JSON_OUT = path.resolve(
  process.env.JSON_OUT || path.join(RESULTS_DIR, `${path.basename(MARKDOWN_OUT, ".md")}.json`),
);
const LOCAL_TSX_BIN = process.env.LOCAL_TSX_BIN ? path.resolve(process.env.LOCAL_TSX_BIN) : "";
const KEEP_WORK = truthy(process.env.KEEP_BENCH_WORK);
const SCENARIO_FILTER = process.env.SCENARIOS ? new RegExp(process.env.SCENARIOS) : null;

if (!fs.existsSync(LPM_BIN)) {
  runChecked("cargo", ["build", "--release", "--locked", "-p", "lpm-cli", "--bin", "lpm-rs"], {
    cwd: ROOT,
    stdio: "inherit",
  });
}

fs.mkdirSync(RESULTS_DIR, { recursive: true });
const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-exec-runtime-bench-"));

try {
  const metadata = collectMetadata();
  const scenarios = buildScenarios().filter((scenario) => !SCENARIO_FILTER || SCENARIO_FILTER.test(scenario.id));
  const results = [];

  for (const scenario of scenarios) {
    const projectDir = path.join(workRoot, "projects", scenario.id);
    removeTree(projectDir);
    scenario.createProject(projectDir);
    if (scenario.runner === "local-tsx") {
      installLocalTsxBaseline(projectDir);
    }

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
    gitSha: commandOutput("git", ["rev-parse", "--short", "HEAD"], ROOT) || "unknown",
    iterations: ITERATIONS,
    warmupIterations: WARMUP_ITERATIONS,
    moduleCounts: MODULE_COUNTS,
    nodeVersion: commandOutput("node", ["--version"], ROOT) || "unavailable",
    npmVersion: commandOutput("npm", ["--version"], ROOT) || "unavailable",
    lpmBinary: LPM_BIN,
    lpmVersion: commandOutput(LPM_BIN, ["--version"], ROOT) || "unavailable",
    localTsxBin: LOCAL_TSX_BIN || null,
    localTsxAvailable: Boolean(LOCAL_TSX_BIN && executable(LOCAL_TSX_BIN)),
    markdownOut: MARKDOWN_OUT,
    jsonOut: JSON_OUT,
    scenarioFilter: process.env.SCENARIOS || null,
  };
}

function buildScenarios() {
  const scenarios = [
    {
      id: "lpm-js-cjs-modules-1",
      runner: "lpm",
      label: "JS CJS startup",
      entryKind: "js",
      format: "commonjs",
      projectMode: "commonjs-omitted",
      moduleCount: 1,
      cacheModes: ["none"],
      createProject: (projectDir) => createJsProject(projectDir),
      entry: "scripts/entry.js",
    },
  ];

  for (const moduleCount of MODULE_COUNTS) {
    scenarios.push({
      id: `lpm-ts-cjs-modules-${moduleCount}`,
      runner: "lpm",
      label: "TS CJS",
      entryKind: "ts",
      format: "commonjs",
      projectMode: "commonjs-omitted",
      moduleCount,
      cacheModes: ["cold", "warm"],
      createProject: (projectDir) =>
        createTsProject(projectDir, {
          ext: ".ts",
          format: "commonjs",
          projectMode: "commonjs-omitted",
          moduleCount,
        }),
      entry: "scripts/entry.ts",
    });
    scenarios.push({
      id: `lpm-ts-esm-modules-${moduleCount}`,
      runner: "lpm",
      label: "TS ESM",
      entryKind: "ts",
      format: "module",
      projectMode: "module",
      moduleCount,
      cacheModes: ["cold", "warm"],
      createProject: (projectDir) =>
        createTsProject(projectDir, {
          ext: ".ts",
          format: "module",
          projectMode: "module",
          moduleCount,
        }),
      entry: "scripts/entry.ts",
    });
    scenarios.push({
      id: `lpm-tsx-esm-modules-${moduleCount}`,
      runner: "lpm",
      label: "TSX ESM",
      entryKind: "tsx",
      format: "module",
      projectMode: "module",
      moduleCount,
      cacheModes: ["cold", "warm"],
      createProject: (projectDir) =>
        createTsxProject(projectDir, {
          projectMode: "module",
          moduleCount,
        }),
      entry: "scripts/entry.tsx",
    });
    scenarios.push({
      id: `local-tsx-tsx-esm-modules-${moduleCount}`,
      runner: "local-tsx",
      label: "project-local tsx TSX ESM",
      entryKind: "tsx",
      format: "module",
      projectMode: "module",
      moduleCount,
      cacheModes: ["cold", "warm"],
      createProject: (projectDir) =>
        createTsxProject(projectDir, {
          projectMode: "module",
          moduleCount,
        }),
      entry: "scripts/entry.tsx",
    });
  }

  scenarios.push({
    id: "lpm-mts-esm-modules-10",
    runner: "lpm",
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

function measureScenario(scenario, projectDir, cacheMode) {
  if (scenario.runner === "local-tsx" && !executable(LOCAL_TSX_BIN)) {
    return skippedResult(scenario, cacheMode, "LOCAL_TSX_BIN is unset or not executable");
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
    removeTree(path.join(envRoot, "lpm-home/cache/exec-ts-runtime/v2/transform-cache"));
    return;
  }
  removeTree(path.join(envRoot, "home"));
  removeTree(path.join(envRoot, "xdg-cache"));
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
  if (scenario.runner === "local-tsx") {
    return {
      program: path.join(projectDir, "node_modules/.bin/tsx"),
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
  fs.mkdirSync(lpmHome, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(xdgCache, { recursive: true });
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  env.LPM_HOME = lpmHome;
  env.HOME = home;
  env.XDG_CACHE_HOME = xdgCache;
  env.NO_COLOR = "1";
  env.FORCE_COLOR = "0";
  env.CI = "1";
  return env;
}

function installLocalTsxBaseline(projectDir) {
  if (!executable(LOCAL_TSX_BIN)) {
    return;
  }
  const binDir = path.join(projectDir, "node_modules/.bin");
  fs.mkdirSync(binDir, { recursive: true });
  const linkPath = path.join(binDir, "tsx");
  removeTree(linkPath);
  fs.symlinkSync(LOCAL_TSX_BIN, linkPath);
}

function createJsProject(projectDir) {
  createBaseProject(projectDir, "commonjs-omitted", false);
  writeFile(projectDir, "scripts/module-0.js", "exports.value = 1;\n");
  writeFile(
    projectDir,
    "scripts/entry.js",
    [
      'const mod0 = require("./module-0.js");',
      "if (mod0.value !== 1) process.exit(7);",
      "console.log(mod0.value);",
      "",
    ].join("\n"),
  );
}

function createTsProject(projectDir, options) {
  createBaseProject(projectDir, options.projectMode, false);
  if (options.format === "commonjs") {
    createCommonJsTsModules(projectDir, options.ext, options.moduleCount);
  } else {
    createModuleTsModules(projectDir, options.ext, options.moduleCount);
  }
}

function createTsxProject(projectDir, options) {
  createBaseProject(projectDir, options.projectMode, true);
  createFakeReactRuntime(projectDir);
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

function createCommonJsTsModules(projectDir, ext, moduleCount) {
  for (let i = 0; i < moduleCount; i += 1) {
    writeFile(
      projectDir,
      `scripts/module-${i}${ext}`,
      [`const value: number = ${i + 1};`, "module.exports = { value };", ""].join("\n"),
    );
  }
  const requires = [];
  const terms = [];
  for (let i = 0; i < moduleCount; i += 1) {
    requires.push(`const mod${i}: { value: number } = require("./module-${i}${ext}");`);
    terms.push(`mod${i}.value`);
  }
  writeFile(
    projectDir,
    `scripts/entry${ext}`,
    [
      ...requires,
      "",
      `const total: number = ${terms.join(" + ")};`,
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
  writeFile(projectDir, "scripts/jsx.d.ts", "declare namespace JSX { interface Element {} }\n");
}

function passedResult(scenario, cacheMode, samples) {
  const stats = statsFor(samples);
  return {
    runner: scenario.runner,
    scenario: scenario.id,
    label: scenario.label,
    status: "pass",
    cacheMode,
    moduleCount: scenario.moduleCount,
    format: scenario.format,
    projectMode: scenario.projectMode,
    entryKind: scenario.entryKind,
    entry: scenario.entry,
    iterations: ITERATIONS,
    ...stats,
  };
}

function failedResult(scenario, cacheMode, reason, samples = []) {
  return {
    runner: scenario.runner,
    scenario: scenario.id,
    label: scenario.label,
    status: "failed",
    reason,
    cacheMode,
    moduleCount: scenario.moduleCount,
    format: scenario.format,
    projectMode: scenario.projectMode,
    entryKind: scenario.entryKind,
    entry: scenario.entry,
    iterations: samples.length,
  };
}

function skippedResult(scenario, cacheMode, reason) {
  return {
    runner: scenario.runner,
    scenario: scenario.id,
    label: scenario.label,
    status: "skipped",
    reason,
    cacheMode,
    moduleCount: scenario.moduleCount,
    format: scenario.format,
    projectMode: scenario.projectMode,
    entryKind: scenario.entryKind,
    entry: scenario.entry,
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
  lines.push(`- Git SHA: \`${metadata.gitSha}\``);
  lines.push(`- Iterations: \`${metadata.iterations}\``);
  lines.push(`- Warmup iterations: \`${metadata.warmupIterations}\``);
  lines.push(`- Module counts: \`${metadata.moduleCounts.join(", ")}\``);
  lines.push(`- Binary: \`${metadata.lpmBinary}\``);
  lines.push(`- LPM: \`${metadata.lpmVersion}\``);
  lines.push(`- Node: \`${metadata.nodeVersion}\``);
  lines.push(
    `- Local tsx baseline: \`${metadata.localTsxAvailable ? metadata.localTsxBin : "skipped"}\``,
  );
  lines.push("");
  lines.push("Cold clears the LPM TS runtime transform cache before every measured run. Warm runs one unmeasured warmup and then reuses that transform cache.");
  lines.push("");
  lines.push(
    "| Runner | Scenario | Cache | Modules | Format | Project mode | Status | Iterations | Avg ms | Min ms | P50 ms | P95 ms | Max ms |",
  );
  lines.push("| --- | --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const result of report.results) {
    lines.push(renderResultRow(result));
  }
  lines.push("");
  lines.push("Skipped local tsx rows are benchmark-only comparisons; the harness never installs or fetches tsx.");
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function renderResultRow(result) {
  if (result.status !== "pass") {
    return [
      result.runner,
      result.scenario,
      result.cacheMode,
      result.moduleCount,
      result.format,
      result.projectMode,
      `${result.status}: ${escapeCell(result.reason || "")}`,
      result.iterations,
      "-",
      "-",
      "-",
      "-",
      "-",
    ].join(" | ").replace(/^/, "| ").replace(/$/, " |");
  }
  return [
    result.runner,
    result.scenario,
    result.cacheMode,
    result.moduleCount,
    result.format,
    result.projectMode,
    result.status,
    result.iterations,
    result.avgMs.toFixed(2),
    result.minMs.toFixed(2),
    result.p50Ms.toFixed(2),
    result.p95Ms.toFixed(2),
    result.maxMs.toFixed(2),
  ].join(" | ").replace(/^/, "| ").replace(/$/, " |");
}

function printProgress(result) {
  if (result.status === "pass") {
    console.log(
      `${result.scenario} ${result.cacheMode}: avg=${result.avgMs.toFixed(2)}ms p50=${result.p50Ms.toFixed(2)}ms p95=${result.p95Ms.toFixed(2)}ms`,
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
