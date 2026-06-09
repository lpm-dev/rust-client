import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import {
  LpmWrapperError,
  platformKey,
  resolveNativeBinary,
} from "../bin/native.js";

const repoPackageDir = path.dirname(fileURLToPath(import.meta.url));
const wrapperRoot = path.resolve(repoPackageDir, "..");

test("platformKey joins node platform and architecture", () => {
  assert.equal(platformKey("darwin", "arm64"), "darwin-arm64");
  assert.equal(platformKey("linux", "x64"), "linux-x64");
  assert.equal(platformKey("win32", "x64"), "win32-x64");
});

test("published wrapper manifest stays dependency-free", () => {
  const manifestPath = path.join(wrapperRoot, "package.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  assert.equal(manifest.dependencies, undefined);
  assert.equal(manifest.devDependencies, undefined);
  assert.equal(manifest.scripts?.preinstall, undefined);
  assert.equal(manifest.scripts?.install, undefined);
  assert.equal(manifest.scripts?.postinstall, undefined);
  assert.deepEqual(Object.keys(manifest.optionalDependencies).sort(), [
    "@lpm-registry/cli-darwin-arm64",
    "@lpm-registry/cli-darwin-x64",
    "@lpm-registry/cli-linux-arm64",
    "@lpm-registry/cli-linux-x64",
    "@lpm-registry/cli-win32-x64",
  ]);
});

test("resolveNativeBinary finds lpm in the matching optional dependency", () => {
  const root = makePackageTree("linux-x64");
  const requireFn = createFakeRequire(root);

  const resolved = resolveNativeBinary({
    command: "lpm",
    platform: "linux",
    arch: "x64",
    requireFn,
    env: {},
  });

  assert.equal(
    resolved.path,
    path.join(
      root,
      "node_modules",
      "@lpm-registry",
      "cli-linux-x64",
      "lpm",
    ),
  );
  assert.equal(resolved.source, "@lpm-registry/cli-linux-x64");
  assert.deepEqual(resolved.argsPrefix, []);
});

test("resolveNativeBinary finds lpx separately from lpm", () => {
  const root = makePackageTree("darwin-arm64");
  const requireFn = createFakeRequire(root);

  const resolved = resolveNativeBinary({
    command: "lpx",
    platform: "darwin",
    arch: "arm64",
    requireFn,
    env: {},
  });

  assert.equal(
    resolved.path,
    path.join(
      root,
      "node_modules",
      "@lpm-registry",
      "cli-darwin-arm64",
      "lpx",
    ),
  );
  assert.deepEqual(resolved.argsPrefix, []);
});

test("LPM_BINARY_PATH bypasses package resolution", () => {
  const resolved = resolveNativeBinary({
    command: "lpm",
    platform: "linux",
    arch: "x64",
    env: { LPM_BINARY_PATH: "/tmp/lpm-dev-binary" },
    requireFn: createThrowingRequire(),
  });

  assert.equal(resolved.path, "/tmp/lpm-dev-binary");
  assert.equal(resolved.source, "env");
  assert.deepEqual(resolved.argsPrefix, []);
});

test("LPM_BINARY_PATH preserves lpx behavior by prepending dlx", () => {
  const resolved = resolveNativeBinary({
    command: "lpx",
    platform: "linux",
    arch: "x64",
    env: { LPM_BINARY_PATH: "/tmp/lpm-dev-binary" },
    requireFn: createThrowingRequire(),
  });

  assert.equal(resolved.path, "/tmp/lpm-dev-binary");
  assert.deepEqual(resolved.argsPrefix, ["dlx"]);
});

test("missing optional dependency surfaces a reinstall hint", () => {
  assert.throws(
    () =>
      resolveNativeBinary({
        command: "lpm",
        platform: "linux",
        arch: "arm64",
        requireFn: createThrowingRequire(),
        env: {},
      }),
    error => {
      assert.ok(error instanceof LpmWrapperError);
      assert.match(error.message, /cli-linux-arm64/);
      assert.ok(
        error.hints.some(hint => hint.includes("npm install -g @lpm-registry/cli")),
      );
      return true;
    },
  );
});

test("unsupported platforms fail before package resolution", () => {
  assert.throws(
    () =>
      resolveNativeBinary({
        command: "lpm",
        platform: "freebsd",
        arch: "x64",
        requireFn: createThrowingRequire(),
        env: {},
      }),
    /Unsupported platform: freebsd-x64/,
  );
});

test("lpm wrapper forwards argv to LPM_BINARY_PATH", () => {
  const recorder = makeRecorderBinary();
  const result = spawnSync(process.execPath, ["bin/lpm.js", "self-update", "--json"], {
    cwd: wrapperRoot,
    env: {
      ...process.env,
      LPM_BINARY_PATH: recorder.binaryPath,
      LPM_RECORDER_OUTPUT: recorder.outputPath,
    },
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(fs.readFileSync(recorder.outputPath, "utf8"));
  assert.deepEqual(payload.argv, ["self-update", "--json"]);
});

test("lpx wrapper runs custom LPM_BINARY_PATH through dlx", () => {
  const recorder = makeRecorderBinary();
  const result = spawnSync(process.execPath, ["bin/lpx.js", "cowsay", "hello"], {
    cwd: wrapperRoot,
    env: {
      ...process.env,
      LPM_BINARY_PATH: recorder.binaryPath,
      LPM_RECORDER_OUTPUT: recorder.outputPath,
    },
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(fs.readFileSync(recorder.outputPath, "utf8"));
  assert.deepEqual(payload.argv, ["dlx", "cowsay", "hello"]);
});

function makePackageTree(platform) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-wrapper-"));
  const pkgDir = path.join(
    root,
    "node_modules",
    "@lpm-registry",
    `cli-${platform}`,
  );
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify({ name: `@lpm-registry/cli-${platform}`, version: "1.0.0" }),
  );
  for (const name of ["lpm", "lpx", "lpm.exe", "lpx.exe"]) {
    fs.writeFileSync(path.join(pkgDir, name), "");
  }
  return root;
}

function createFakeRequire(root) {
  return {
    resolve(specifier) {
      const packageName = specifier.replace(/\/package\.json$/, "");
      const packagePath = path.join(root, "node_modules", ...packageName.split("/"));
      const packageJsonPath = path.join(packagePath, "package.json");
      if (!fs.existsSync(packageJsonPath)) {
        throw new Error(`Cannot find module ${specifier}`);
      }
      return packageJsonPath;
    },
  };
}

function createThrowingRequire() {
  return {
    resolve(specifier) {
      throw new Error(`Cannot find module ${specifier}`);
    },
  };
}

function makeRecorderBinary() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-recorder-"));
  const binaryPath = path.join(dir, "record-argv.mjs");
  const outputPath = path.join(dir, "argv.json");
  fs.writeFileSync(
    binaryPath,
    [
      "#!/usr/bin/env node",
      "import fs from 'node:fs';",
      "fs.writeFileSync(process.env.LPM_RECORDER_OUTPUT, JSON.stringify({ argv: process.argv.slice(2) }));",
    ].join("\n"),
  );
  fs.chmodSync(binaryPath, 0o755);
  return { binaryPath, outputPath };
}
