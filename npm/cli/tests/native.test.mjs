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
import { installNativeBinaries } from "../scripts/install-binary.js";

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
  assert.equal(manifest.scripts?.postinstall, "node scripts/install-binary.js");
  assert.ok(manifest.files.includes("scripts"));
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

test("postinstall validates and hard-links unix binaries into bin targets", () => {
  const tree = makeInstallTree("linux-x64", {
    version: "1.2.3",
    packageBinaryNames: ["lpm", "lpx"],
  });

  const result = installNativeBinaries({
    wrapperRoot: tree.wrapperRoot,
    platform: "linux",
    arch: "x64",
    requireFn: createFakeRequire(tree.root),
    spawnSyncFn: createVersionSpawn("lpm 1.2.3"),
    logFn() {},
  });

  assert.equal(result.status, "installed");
  assert.deepEqual(
    result.optimized.map(entry => [entry.command, entry.action]),
    [
      ["lpm", "link"],
      ["lpx", "link"],
    ],
  );
  assert.equal(
    fs.statSync(path.join(tree.packageDir, "lpm")).ino,
    fs.statSync(path.join(tree.wrapperRoot, "bin", "lpm.js")).ino,
  );
  assert.equal(
    fs.statSync(path.join(tree.packageDir, "lpx")).ino,
    fs.statSync(path.join(tree.wrapperRoot, "bin", "lpx.js")).ino,
  );
});

test("postinstall copies unix binaries when hard-linking is unavailable", () => {
  const tree = makeInstallTree("darwin-arm64", {
    version: "2.0.0",
    packageBinaryNames: ["lpm", "lpx"],
  });
  const fsModule = {
    ...fs,
    linkSync() {
      const error = new Error("cross-device link");
      error.code = "EXDEV";
      throw error;
    },
  };

  const result = installNativeBinaries({
    wrapperRoot: tree.wrapperRoot,
    platform: "darwin",
    arch: "arm64",
    requireFn: createFakeRequire(tree.root),
    spawnSyncFn: createVersionSpawn("lpm 2.0.0"),
    fsModule,
    logFn() {},
  });

  assert.equal(result.status, "installed");
  assert.deepEqual(
    result.optimized.map(entry => [entry.command, entry.action]),
    [
      ["lpm", "copy"],
      ["lpx", "copy"],
    ],
  );
  assert.equal(
    fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpm.js"), "utf8"),
    fs.readFileSync(path.join(tree.packageDir, "lpm"), "utf8"),
  );
});

test("postinstall keeps windows JS shims and stages local exe binaries", () => {
  const tree = makeInstallTree("win32-x64", {
    version: "3.0.0",
    packageBinaryNames: ["lpm.exe", "lpx.exe"],
  });
  const lpmShim = fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpm.js"), "utf8");
  const lpxShim = fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpx.js"), "utf8");

  const result = installNativeBinaries({
    wrapperRoot: tree.wrapperRoot,
    platform: "win32",
    arch: "x64",
    requireFn: createFakeRequire(tree.root),
    spawnSyncFn: createVersionSpawn("lpm 3.0.0"),
    logFn() {},
  });

  assert.equal(result.status, "installed");
  assert.deepEqual(
    result.optimized.map(entry => [entry.command, entry.action]),
    [
      ["lpm", "copy"],
      ["lpx", "copy"],
    ],
  );
  assert.equal(fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpm.js"), "utf8"), lpmShim);
  assert.equal(fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpx.js"), "utf8"), lpxShim);
  assert.equal(
    fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpm.exe"), "utf8"),
    fs.readFileSync(path.join(tree.packageDir, "lpm.exe"), "utf8"),
  );
});

test("postinstall validation failure leaves JS shims in place", () => {
  const tree = makeInstallTree("linux-x64", {
    version: "4.0.0",
    packageBinaryNames: ["lpm", "lpx"],
  });
  const shim = fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpm.js"), "utf8");

  assert.throws(
    () =>
      installNativeBinaries({
        wrapperRoot: tree.wrapperRoot,
        platform: "linux",
        arch: "x64",
        requireFn: createFakeRequire(tree.root),
        spawnSyncFn: createVersionSpawn("lpm 3.9.9"),
        logFn() {},
      }),
    /reported version/,
  );

  assert.equal(fs.readFileSync(path.join(tree.wrapperRoot, "bin", "lpm.js"), "utf8"), shim);
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

function makeInstallTree(platform, { version, packageBinaryNames }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-install-wrapper-"));
  const wrapperRoot = path.join(root, "node_modules", "@lpm-registry", "cli");
  const packageDir = path.join(
    root,
    "node_modules",
    "@lpm-registry",
    `cli-${platform}`,
  );
  fs.mkdirSync(path.join(wrapperRoot, "bin"), { recursive: true });
  fs.mkdirSync(packageDir, { recursive: true });
  fs.writeFileSync(
    path.join(wrapperRoot, "package.json"),
    JSON.stringify({ name: "@lpm-registry/cli", version }),
  );
  fs.writeFileSync(path.join(wrapperRoot, "bin", "lpm.js"), "#!/usr/bin/env node\n");
  fs.writeFileSync(path.join(wrapperRoot, "bin", "lpx.js"), "#!/usr/bin/env node\n");
  fs.writeFileSync(
    path.join(packageDir, "package.json"),
    JSON.stringify({ name: `@lpm-registry/cli-${platform}`, version }),
  );
  for (const name of packageBinaryNames) {
    fs.writeFileSync(path.join(packageDir, name), `native ${name} ${version}\n`);
    fs.chmodSync(path.join(packageDir, name), 0o755);
  }
  return { root, wrapperRoot, packageDir };
}

function createVersionSpawn(stdout) {
  return () => ({
    status: 0,
    signal: null,
    error: undefined,
    stdout,
    stderr: "",
  });
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
