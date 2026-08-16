import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PLATFORM_PACKAGES,
  assertCliVersion,
  expectedPackedFiles,
  manifestForRelease,
  parseReleaseVersion,
  runtimePlatformKey,
} from "../release-artifacts.mjs";
import { npmInvocation } from "../npm-invocation.mjs";
import { prepareReleasePackages } from "../prepare-packages.mjs";
import { smokeInstall, windowsCommandInvocation } from "../smoke-install.mjs";

function releaseTargetTimeout(releaseWorkflow, target) {
  const targetMarker = `          - target: ${target}`;
  const targetStart = releaseWorkflow.indexOf(targetMarker);

  assert.notEqual(targetStart, -1, `missing ${target} release target`);

  const nextTarget = releaseWorkflow.indexOf(
    "\n          - target:",
    targetStart + targetMarker.length,
  );

  const targetSource = releaseWorkflow.slice(
    targetStart,
    nextTarget === -1 ? releaseWorkflow.length : nextTarget,
  );
  const timeout = targetSource.match(/^\s+timeout_minutes:\s*(\d+)\s*$/m);

  assert.ok(timeout, `missing ${target} release timeout`);
  return Number(timeout[1]);
}

test("release versions accept stable and prerelease semver values", () => {
  assert.equal(parseReleaseVersion("0.69.0"), "0.69.0");
  assert.equal(parseReleaseVersion("1.0.0-beta.2"), "1.0.0-beta.2");
});

test("release versions reject tags, traversal, and incomplete versions", () => {
  for (const value of ["v0.69.0", "../0.69.0", "0.69", "0.69.0 latest", ""]) {
    assert.throws(() => parseReleaseVersion(value), /valid npm semver/);
  }
});

test("CI and release Alpine smokes share one immutable Node image pin", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const imagePattern = /node:22-alpine@sha256:[0-9a-f]{64}/g;
  const ciPins =
    fs.readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8").match(imagePattern) ?? [];
  const releasePins =
    fs
      .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
      .match(imagePattern) ?? [];

  assert.equal(ciPins.length, 1);
  assert.equal(releasePins.length, 1);
  assert.deepEqual(releasePins, ciPins);
});

test("Windows release builds keep enough timeout headroom for signing", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const timeout = releaseTargetTimeout(releaseWorkflow, "x86_64-pc-windows-msvc");

  assert.ok(
    timeout >= 60,
    `Windows release timeout must be at least 60 minutes, found ${timeout}`,
  );
});

test("Apple Silicon release builds keep enough timeout headroom for cold builds", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const timeout = releaseTargetTimeout(releaseWorkflow, "aarch64-apple-darwin");

  assert.ok(
    timeout >= 60,
    `Apple Silicon release timeout must be at least 60 minutes, found ${timeout}`,
  );
});

test("Windows filesystem gate isolates file-count stress from lock timing tests", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/windows-filesystem-gate.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const regularStart = workflow.indexOf("      - name: Windows filesystem crate tests\n");
  const stressStart = workflow.indexOf("      - name: Windows extractor file-count stress tests\n");

  assert.notEqual(regularStart, -1, "missing regular Windows filesystem test step");
  assert.ok(stressStart > regularStart, "extractor stress tests must run after regular crate tests");
  const regularStep = workflow.slice(regularStart, stressStart);
  const stressStep = workflow.slice(stressStart);
  assert.match(
    regularStep,
    /not \(test\(extract_accepts_exact_max_file_count\) \|\s+test\(extract_rejects_more_than_max_file_count\)\)/,
  );
  assert.match(
    stressStep,
    /test\(extract_accepts_exact_max_file_count\) \|\s+test\(extract_rejects_more_than_max_file_count\)/,
  );
  assert.match(stressStep, /--test-threads=1/);
});

test("npm publish workflow treats release tarballs as local filesystem paths", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );
  const publishSpecs = [...releaseWorkflow.matchAll(/npx npm@11\.12\.1 publish "([^"]+)"/g)].map(
    match => match[1],
  );

  assert.deepEqual(publishSpecs, [
    "./npm-release-packages/$tarball",
    "./npm-release-packages/$TARBALL",
  ]);
});

test("OIDC publish jobs verify release archives before consuming them", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const jobSource = (job, nextJob) => {
    const start = releaseWorkflow.indexOf(`\n  ${job}:\n`);
    const end = releaseWorkflow.indexOf(`\n  ${nextJob}:\n`, start + 1);
    assert.notEqual(start, -1, `missing ${job} job`);
    assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
    return releaseWorkflow.slice(start, end);
  };
  const platformJob = jobSource("publish-npm-platform", "publish-npm-wrapper");
  const wrapperJob = jobSource("publish-npm-wrapper", "update-homebrew");
  for (const [job, firstConsumer] of [
    [platformJob, "npx npm@11.12.1 publish"],
    [wrapperJob, "npm install --prefix"],
  ]) {
    const verification = job.indexOf("node npm/release/verify-packages.mjs");
    const consumption = job.indexOf(firstConsumer);
    assert.notEqual(verification, -1, "release package verification is missing");
    assert.notEqual(consumption, -1, `release package consumer is missing: ${firstConsumer}`);
    assert.ok(verification < consumption, "release packages must be verified before consumption");
  }
});

test("immutable npm versions are accepted only after registry verification", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const jobSource = (job, nextJob) => {
    const start = releaseWorkflow.indexOf(`\n  ${job}:\n`);
    const end = releaseWorkflow.indexOf(`\n  ${nextJob}:\n`, start + 1);
    assert.notEqual(start, -1, `missing ${job} job`);
    assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
    return releaseWorkflow.slice(start, end);
  };

  const platform = jobSource("publish-npm-platform", "publish-npm-wrapper");
  const wrapper = jobSource("publish-npm-wrapper", "update-homebrew");
  const assertImmutableBranch = (source, packageArgument, tarballArgument) => {
    const start = source.indexOf(
      'if grep -q "cannot publish over the previously published" /tmp/npm-publish.log; then',
    );
    assert.notEqual(start, -1, "missing immutable-version branch");
    const branchLength = source.slice(start).search(/\n\s+else\s*$/m);
    assert.notEqual(branchLength, -1, "missing immutable-version failure branch");
    const branch = source.slice(start, start + branchLength);
    assert.match(branch, /node npm\/release\/verify-published-package\.mjs/);
    assert.match(branch, /--manifest "\$MANIFEST"/);
    assert.ok(branch.includes(`--package ${packageArgument}`));
    assert.match(branch, /--tag "\$NPM_TAG"/);
    assert.match(branch, /--source-sha "\$EXPECTED_SOURCE_SHA"/);
    assert.match(branch, /--source-run-id "\$EXPECTED_SOURCE_RUN_ID"/);
    assert.ok(branch.includes(`--tarball ${tarballArgument}`));
  };
  assertImmutableBranch(platform, '"$package"', '"./npm-release-packages/$tarball"');
  assertImmutableBranch(wrapper, '"@lpm-registry/cli"', '"./npm-release-packages/$TARBALL"');
  assert.doesNotMatch(releaseWorkflow, /Already published — skipping/);
});

function assertNpmPublishRecoveryWorkflow(workflowSource) {
  const releaseWorkflow = workflowSource.replaceAll("\r\n", "\n");
  const jobSource = (job, nextJob) => {
    const start = releaseWorkflow.indexOf(`\n  ${job}:\n`);
    const end = releaseWorkflow.indexOf(`\n  ${nextJob}:\n`, start + 1);
    assert.notEqual(start, -1, `missing ${job} job`);
    assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
    return releaseWorkflow.slice(start, end);
  };

  assert.match(releaseWorkflow, /^\s+- npm-publish-only$/m);
  assert.match(
    releaseWorkflow,
    /if \[ "\$MODE" != "full" \] && \[ "\$GITHUB_REF" != "refs\/heads\/main" \]; then/,
  );
  const platformSource = jobSource("publish-npm-platform", "publish-npm-wrapper");
  const wrapperSource = jobSource("publish-npm-wrapper", "update-homebrew");
  for (const source of [platformSource, wrapperSource]) {
    assert.match(source, /inputs\.mode == 'npm-publish-only'/);
    assert.match(source, /node npm\/release\/validate-recovery-source\.mjs/);
    assert.match(source, /--purpose (?:npm-publish|"\$RECOVERY_PURPOSE")/);
    assert.match(source, /artifact-ids: \$\{\{ steps\.source\.outputs\.artifact_id \}\}/);
    assert.match(source, /run-id: \$\{\{ inputs\.source_run_id \}\}/);
    assert.match(source, /repository: \$\{\{ github\.repository \}\}/);
    assert.match(source, /github-token: \$\{\{ github\.token \}\}/);
    assert.match(source, /test "\$ARTIFACT_VERSION" = "\$INPUT_VERSION"/);
  }
  assert.match(wrapperSource, /inputs\.mode == 'wrapper-only'/);
  assert.match(wrapperSource, /'wrapper-publish'/);
  assert.doesNotMatch(wrapperSource, /--wrapper-only/);
}

test("npm publish recovery reuses exact source-run artifacts for platforms and wrapper", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );

  assertNpmPublishRecoveryWorkflow(releaseWorkflow);
});

test("npm publish recovery assertions accept Windows CRLF workflow files", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n")
    .replaceAll("\n", "\r\n");

  assertNpmPublishRecoveryWorkflow(releaseWorkflow);
});

test("Windows artifact recovery validates the source run before selecting its artifact ID", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = releaseWorkflow.indexOf("\n  smoke-windows-recovery:\n");
  const end = releaseWorkflow.indexOf("\n  release:\n", start + 1);

  assert.notEqual(start, -1, "missing Windows recovery job");
  assert.notEqual(end, -1, "missing release job after Windows recovery");
  const recovery = releaseWorkflow.slice(start, end);
  assert.match(recovery, /node npm\/release\/validate-recovery-source\.mjs/);
  assert.match(recovery, /--purpose windows-smoke/);
  assert.match(recovery, /artifact-ids: \$\{\{ steps\.source\.outputs\.artifact_id \}\}/);
  assert.match(recovery, /shell: bash/);
});

test("published wrapper verification tolerates five minutes of registry propagation", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = releaseWorkflow.indexOf("\n  publish-npm-wrapper:\n");
  const end = releaseWorkflow.indexOf("\n  update-homebrew:\n", start + 1);

  assert.notEqual(start, -1, "missing publish-npm-wrapper job");
  assert.notEqual(end, -1, "missing update-homebrew job after publish-npm-wrapper");

  const wrapperJob = releaseWorkflow.slice(start, end);
  assert.match(wrapperJob, /REGISTRY_PROPAGATION_TIMEOUT_SECONDS=300/);
  assert.match(
    wrapperJob,
    /deadline=\$\(\(SECONDS \+ REGISTRY_PROPAGATION_TIMEOUT_SECONDS\)\)/,
  );
  assert.match(wrapperJob, /NPM_CACHE=\$\(mktemp -d\)/);
  assert.match(wrapperJob, /--cache "\$NPM_CACHE" --prefer-online/);
  assert.match(wrapperJob, /BACKOFF_SECONDS=\$\(\(5 \* \(1 << \(attempt - 1\)\)\)\)/);
  assert.match(wrapperJob, /if \[ "\$BACKOFF_SECONDS" -gt 30 \]; then/);
  assert.doesNotMatch(wrapperJob, /for attempt in 1 2 3 4 5/);
});

test("Windows npm invocation runs npm CLI through Node without a command shell", () => {
  const nodeExecutable = path.join(os.tmpdir(), "node-fixture", "node.exe");

  assert.deepEqual(npmInvocation({ platform: "win32", nodeExecutable }), {
    command: nodeExecutable,
    argsPrefix: [
      path.join(path.dirname(nodeExecutable), "node_modules", "npm", "bin", "npm-cli.js"),
    ],
  });
});

test(
  "Windows npm invocation executes the installed npm CLI",
  { skip: process.platform !== "win32" },
  () => {
    const invocation = npmInvocation();
    const result = spawnSync(invocation.command, [...invocation.argsPrefix, "--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+/);
  },
);

test("Windows command shims use structured cmd arguments without escaped quotes", () => {
  const command = path.join("C:\\", "release smoke ü", "lpm.cmd");

  assert.deepEqual(windowsCommandInvocation(command, ["--version"]), {
    command: "cmd.exe",
    args: ["/D", "/S", "/C", "call", command, "--version"],
  });
});

test(
  "Windows command invocation executes an npm-generated shim in a path with spaces and Unicode",
  { skip: process.platform !== "win32" },
  t => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lpm command smoke ü-"));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const packageDirectory = path.join(directory, "fixture package");
    const binDirectory = path.join(packageDirectory, "bin");
    const installPrefix = path.join(directory, "install prefix");
    fs.mkdirSync(binDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(packageDirectory, "package.json"),
      `${JSON.stringify({
        name: "lpm-command-shim-fixture",
        version: "1.0.0",
        bin: { "lpm-command-shim-fixture": "bin/cli.js" },
      })}\n`,
    );
    fs.writeFileSync(
      path.join(binDirectory, "cli.js"),
      '#!/usr/bin/env node\nconsole.log(process.argv[2] === "--version" ? "lpm 0.69.0" : "unexpected args");\n',
    );

    const npm = npmInvocation();
    const install = spawnSync(
      npm.command,
      [
        ...npm.argsPrefix,
        "install",
        "--prefix",
        installPrefix,
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--no-package-lock",
        "--no-save",
        packageDirectory,
      ],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    assert.ifError(install.error);
    assert.equal(install.status, 0, install.stderr);

    const command = path.join(
      installPrefix,
      "node_modules",
      ".bin",
      "lpm-command-shim-fixture.cmd",
    );
    const invocation = windowsCommandInvocation(command, ["--version"]);
    const result = spawnSync(invocation.command, invocation.args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), "lpm 0.69.0");
  },
);

test("wrapper release manifest pins every platform package and keeps the lifecycle contract", () => {
  const source = {
    name: "@lpm-registry/cli",
    version: "0.1.0",
    bin: { lpm: "bin/lpm", lpx: "bin/lpx" },
    files: ["bin", "scripts", "README.md"],
    scripts: { postinstall: "node scripts/install-binary.js" },
    optionalDependencies: {},
  };

  const manifest = manifestForRelease(source, "0.69.0");

  assert.equal(manifest.version, "0.69.0");
  assert.equal(manifest.dependencies, undefined);
  assert.equal(manifest.scripts.postinstall, "node scripts/install-binary.js");
  assert.deepEqual(
    manifest.optionalDependencies,
    Object.fromEntries(
      PLATFORM_PACKAGES.map(platform => [platform.packageName, "0.69.0"]),
    ),
  );
});

test("wrapper release manifest rejects install-time dependency and script drift", () => {
  const valid = {
    name: "@lpm-registry/cli",
    version: "0.1.0",
    bin: { lpm: "bin/lpm", lpx: "bin/lpx" },
    files: ["bin", "scripts"],
    scripts: { postinstall: "node scripts/install-binary.js" },
    optionalDependencies: {},
  };

  assert.throws(
    () => manifestForRelease({ ...valid, dependencies: { kleur: "1.0.0" } }, "0.69.0"),
    /must not publish runtime dependencies/,
  );
  assert.throws(
    () =>
      manifestForRelease(
        { ...valid, scripts: { ...valid.scripts, preinstall: "node preinstall.js" } },
        "0.69.0",
      ),
    /must not publish preinstall\/install lifecycle scripts/,
  );
});

test("platform release manifest must match its declared operating system and architecture", () => {
  const platform = PLATFORM_PACKAGES.find(entry => entry.key === "win32-x64");
  const source = {
    name: platform.packageName,
    version: "0.1.0",
    os: ["win32"],
    cpu: ["x64"],
    files: ["lpm.exe", "lpx.exe", "lpm-sandbox-helper.exe"],
  };

  assert.equal(manifestForRelease(source, "0.69.0", platform).version, "0.69.0");
  assert.throws(
    () => manifestForRelease({ ...source, os: ["linux"] }, "0.69.0", platform),
    /operating-system contract/,
  );
});

test("packed-file inventory expands declared directories without allowing traversal", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-files-"));
  fs.mkdirSync(path.join(root, "bin"));
  fs.writeFileSync(path.join(root, "bin", "lpm"), "binary");
  fs.writeFileSync(path.join(root, "README.md"), "readme");
  fs.writeFileSync(path.join(root, "package.json"), "{}");

  assert.deepEqual(expectedPackedFiles(root, { files: ["bin", "README.md"] }), [
    "README.md",
    "bin/lpm",
    "package.json",
  ]);
  assert.throws(
    () => expectedPackedFiles(root, { files: ["../secret"] }),
    /unsafe package file path/,
  );
});

test("packed-file inventory rejects paths that require PAX metadata", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-pax-path-"));
  const longName = "x".repeat(101);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, longName), "long path");
  fs.writeFileSync(path.join(root, "package.json"), "{}");

  assert.throws(
    () => expectedPackedFiles(root, { files: [longName] }),
    /requires unsupported PAX metadata/,
  );
});

test("packed-file inventory accepts paths that fit the USTAR prefix field", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-ustar-prefix-"));
  const directory = "a".repeat(80);
  const file = "b".repeat(30);
  const relative = `${directory}/${file}`;
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, directory));
  fs.writeFileSync(path.join(root, relative), "prefixed path");
  fs.writeFileSync(path.join(root, "package.json"), "{}");

  assert.deepEqual(expectedPackedFiles(root, { files: [relative] }), [relative, "package.json"]);
});

test("runtime platform selection distinguishes glibc and musl", () => {
  assert.equal(runtimePlatformKey("linux", "x64", "glibc"), "linux-x64");
  assert.equal(runtimePlatformKey("linux", "x64", "musl"), "linux-x64-musl");
  assert.equal(runtimePlatformKey("win32", "x64"), "win32-x64");
});

test("CLI version verification requires an exact final version token", () => {
  assert.equal(assertCliVersion("lpm 0.69.0\n", "0.69.0"), "0.69.0");
  assert.throws(() => assertCliVersion("lpm 0.69.01\n", "0.69.0"), /expected 0.69.0/);
  assert.throws(() => assertCliVersion("", "0.69.0"), /reported no version/);
});

test("release packaging emits one hash-bound tarball for every published package", t => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const binaries = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-binaries-"));
  const output = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-output-parent-"));
  fs.rmdirSync(output);
  t.after(() => {
    fs.rmSync(binaries, { recursive: true, force: true });
    fs.rmSync(output, { recursive: true, force: true });
  });

  for (const platform of PLATFORM_PACKAGES) {
    for (const mapping of platform.binaries) {
      const artifact = path.join(binaries, mapping.artifact);
      if (!fs.existsSync(artifact)) fs.writeFileSync(artifact, `fixture:${mapping.artifact}\n`);
    }
  }

  const manifest = prepareReleasePackages({
    repoRoot,
    binariesDir: binaries,
    outputDir: output,
    version: "0.69.0",
  });

  assert.equal(manifest.packages.length, PLATFORM_PACKAGES.length + 1);
  for (const pkg of manifest.packages) {
    assert.match(pkg.sha256, /^[0-9a-f]{64}$/);
    assert.equal(fs.existsSync(path.join(output, pkg.tarball)), true);
    assert.equal(pkg.version, "0.69.0");
  }
  assert.equal(fs.existsSync(path.join(output, ".staging")), false);
});

test("release packaging rejects a symlinked output directory", t => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const outputTarget = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-output-target-"));
  const outputLink = path.join(os.tmpdir(), `lpm-release-output-link-${process.pid}-${Date.now()}`);
  fs.symlinkSync(outputTarget, outputLink, process.platform === "win32" ? "junction" : undefined);
  t.after(() => {
    fs.rmSync(outputLink, { recursive: true, force: true });
    fs.rmSync(outputTarget, { recursive: true, force: true });
  });

  assert.throws(
    () =>
      prepareReleasePackages({
        repoRoot,
        outputDir: outputLink,
        version: "0.69.0",
        wrapperOnly: true,
      }),
    /must not be a symbolic link/,
  );
});

test(
  "packed wrapper and Linux platform tarballs install and execute without registry access",
  { skip: process.platform !== "linux" || process.arch !== "x64" },
  t => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
    const binaries = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-smoke-binaries-"));
    const output = path.join(os.tmpdir(), `lpm-smoke-packages-${process.pid}-${Date.now()}`);
    t.after(() => {
      fs.rmSync(binaries, { recursive: true, force: true });
      fs.rmSync(output, { recursive: true, force: true });
    });

    for (const platform of PLATFORM_PACKAGES) {
      for (const mapping of platform.binaries) {
        const artifact = path.join(binaries, mapping.artifact);
        if (!fs.existsSync(artifact)) fs.writeFileSync(artifact, `fixture:${mapping.artifact}\n`);
      }
    }
    const linuxBinary = path.join(binaries, "lpm-linux-x64");
    fs.writeFileSync(
      linuxBinary,
      '#!/bin/sh\ncase "$1" in --version) echo "lpm 0.69.0" ;; --help) exit 0 ;; *) exit 0 ;; esac\n',
    );
    fs.chmodSync(linuxBinary, 0o755);

    prepareReleasePackages({
      repoRoot,
      binariesDir: binaries,
      outputDir: output,
      version: "0.69.0",
    });
    const result = smokeInstall({
      tarballsDir: output,
      expectedPlatform: "linux-x64",
      expectedVersion: "0.69.0",
    });

    assert.equal(result.platform, "linux-x64");
    assert.equal(result.version, "0.69.0");
  },
);
