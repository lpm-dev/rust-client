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

function releaseJobSource(releaseWorkflow, job, nextJob) {
  const start = releaseWorkflow.indexOf(`\n  ${job}:\n`);
  const end = nextJob
    ? releaseWorkflow.indexOf(`\n  ${nextJob}:\n`, start + 1)
    : releaseWorkflow.length;

  assert.notEqual(start, -1, `missing ${job} job`);
  assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
  return releaseWorkflow.slice(start, end);
}

function releaseJobTimeout(releaseWorkflow, job, nextJob) {
  const source = releaseJobSource(releaseWorkflow, job, nextJob);
  const timeout = source.match(/^ {4}timeout-minutes:\s*(\d+)\s*$/m);

  assert.ok(timeout, `missing ${job} timeout`);
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
  const buildTimeout = releaseJobTimeout(releaseWorkflow, "build-windows", "sign-windows");
  const signingTimeout = releaseJobTimeout(
    releaseWorkflow,
    "sign-windows",
    "pack-npm-packages",
  );

  assert.ok(
    buildTimeout >= 60,
    `Windows build timeout must be at least 60 minutes, found ${buildTimeout}`,
  );
  assert.ok(
    signingTimeout >= 20,
    `Windows signing timeout must be at least 20 minutes, found ${signingTimeout}`,
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

test("macOS CLI releases use the shared LPM Vault Keychain access group", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const entitlementPath = path.join(repoRoot, "macos/lpm.entitlements");
  const entitlements = fs.readFileSync(entitlementPath, "utf8");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );

  assert.match(entitlements, /<key>keychain-access-groups<\/key>/);
  assert.match(entitlements, /823S8YKMRW\.dev\.lpm\.vault\.shared/);
  assert.match(entitlements, /<key>com\.apple\.application-identifier<\/key>/);
  assert.doesNotMatch(entitlements, /com\.apple\.security\.app-sandbox/);
  assert.match(releaseWorkflow, /--entitlements "\$APPLE_CODESIGN_ENTITLEMENTS"/);
  assert.match(releaseWorkflow, /codesign -d --entitlements :-/);
});

test("raw macOS compatibility assets reuse dependencies while preserving separate binaries", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );
  const cliManifest = fs.readFileSync(
    path.join(repoRoot, "crates/lpm-cli/Cargo.toml"),
    "utf8",
  );
  const vaultManifest = fs.readFileSync(
    path.join(repoRoot, "crates/lpm-vault/Cargo.toml"),
    "utf8",
  );

  assert.match(cliManifest, /legacy-macos-keychain = \["lpm-vault\/legacy-macos-keychain"\]/);
  assert.match(vaultManifest, /legacy-macos-keychain = \[\]/);
  assert.doesNotMatch(releaseWorkflow, /--target-dir target\/legacy-macos-keychain/);
  assert.match(
    releaseWorkflow,
    /cp "target\/\$\{\{ matrix\.target \}\}\/release\/lpm-rs" "\$RUNNER_TEMP\/lpm-rs-provisioned"/,
  );
  assert.match(releaseWorkflow, /--features legacy-macos-keychain/);
  assert.match(
    releaseWorkflow,
    /cp target\/\$\{\{ matrix\.target \}\}\/release\/lpm-rs \$\{\{ matrix\.binary \}\}/,
  );
  assert.match(
    releaseWorkflow,
    /cp "\$RUNNER_TEMP\/lpm-rs-provisioned" "\$APP_BUNDLE\/Contents\/MacOS\/lpm-rs"/,
  );
  assert.match(releaseWorkflow, /env set LPM_RELEASE_SMOKE=verified/);
  assert.match(releaseWorkflow, /env get LPM_RELEASE_SMOKE >\/dev\/null/);
  assert.match(releaseWorkflow, /env delete LPM_RELEASE_SMOKE/);
});

test("macOS release packaging preserves a provisioned app bundle", () => {
  const darwinPackages = PLATFORM_PACKAGES.filter(platform => platform.os === "darwin");

  assert.equal(darwinPackages.length, 2);
  for (const platform of darwinPackages) {
    assert.equal(platform.bundleSource, `${platform.key}/LPM CLI.app`);
    assert.deepEqual(
      platform.binaries.map(binary => binary.destination),
      ["LPM CLI.app/Contents/MacOS/lpm-rs"],
    );
    const source = JSON.parse(
      fs.readFileSync(
        path.resolve(
          path.dirname(fileURLToPath(import.meta.url)),
          "../..",
          `cli-${platform.key}/package.json`,
        ),
        "utf8",
      ),
    );
    assert.deepEqual(source.files, ["LPM CLI.app"]);
    assert.equal(manifestForRelease(source, "0.69.0", platform).version, "0.69.0");
  }
});

test("macOS release workflow provisions, notarizes, staples, and executes the bundle", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );
  const infoPlist = fs.readFileSync(path.join(repoRoot, "macos/LPMCLI-Info.plist"), "utf8");
  const localBuild = fs.readFileSync(
    path.join(repoRoot, "scripts/build-signed-macos.sh"),
    "utf8",
  );

  assert.match(infoPlist, /<key>LSMinimumSystemVersion<\/key>\s*<string>11\.0<\/string>/);
  assert.match(localBuild, /Entitlements:com\.apple\.application-identifier/);
  assert.match(localBuild, /EXPECTED_PROFILE_ACCESS_GROUP="\$EXPECTED_TEAM_ID\.\*"/);
  assert.match(releaseWorkflow, /Contents\/embedded\.provisionprofile/);
  assert.match(releaseWorkflow, /xcrun stapler staple/);
  assert.match(releaseWorkflow, /xcrun stapler validate/);
  assert.equal(
    [...releaseWorkflow.matchAll(/ditto -c -k --keepParent --norsrc/g)].length,
    3,
    "every public or notarization ZIP must exclude AppleDouble metadata",
  );
  assert.match(releaseWorkflow, /unzip -q "\$archive" -d "binaries\/\$\{platform\}" -x '\*\/\._\*'/);
  assert.match(releaseWorkflow, /LPM CLI\.app\/Contents\/MacOS\/lpm-rs/);
  assert.match(localBuild, /Contents\/embedded\.provisionprofile/);
  assert.doesNotMatch(releaseWorkflow, /--entitlements "\$APPLE_CODESIGN_ENTITLEMENTS"\s*\\\s*--sign[^\n]+\s*\\\s*"\$\{\{ matrix\.binary \}\}"/);
});

test("release workflow smoke-tests standalone macOS bundle installation on both architectures", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );

  assert.match(releaseWorkflow, /Smoke standalone installer on macOS \(arm64\)/);
  assert.match(releaseWorkflow, /Smoke standalone installer on macOS \(x64\)/);
  assert.match(releaseWorkflow, /\.lpm\/libexec\/LPM CLI\.app\/Contents\/MacOS\/lpm-rs/);
  assert.match(releaseWorkflow, /test -L "\$HOME\/.lpm\/bin\/lpm"/);
  assert.match(releaseWorkflow, /codesign --verify --strict --verbose=4/);
  assert.match(releaseWorkflow, /stapler validate/);
  assert.match(
    releaseWorkflow,
    /printf '\{"tag_name":"v%s","published_at":"%s"\}\\n' "\$version" "\$published_at"/,
    "the mocked release response must bind metadata to the requested tag",
  );

  const npmSmoke = fs.readFileSync(
    path.join(repoRoot, "npm/release/smoke-install.mjs"),
    "utf8",
  );
  assert.match(npmSmoke, /Contents", "CodeResources"/);
  assert.match(npmSmoke, /"\/usr\/bin\/xcrun", \["stapler", "validate"/);
  assert.match(npmSmoke, /"\/usr\/sbin\/spctl"/);
});

test("macOS vault storage never delegates secret access to the security utility", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const keychainSource = ["keychain.rs", "macos_keychain.rs"]
    .map(file =>
      fs.readFileSync(path.join(repoRoot, "crates/lpm-vault/src", file), "utf8"),
    )
    .join("\n");

  assert.doesNotMatch(keychainSource, /Command::new\("security"\)/);
  assert.doesNotMatch(keychainSource, /\["-A"\]/);
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

test("release workflow grants write permissions only to jobs that use them", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const topLevelPermissions = releaseWorkflow.slice(
    releaseWorkflow.indexOf("\npermissions:\n"),
    releaseWorkflow.indexOf("\nenv:\n"),
  );
  const writePermissions = source =>
    [...source.matchAll(/^ {6}([a-z-]+): write(?:\s+#.*)?$/gm)].map(match => match[1]);

  assert.equal(topLevelPermissions, "\npermissions:\n  contents: read\n");

  const jobs = [
    ["release-metadata", "verify", []],
    ["verify", "verify-candidate-source", []],
    ["verify-candidate-source", "release-preflight", []],
    ["release-preflight", "verify-windows-filesystem", []],
    ["verify-windows-filesystem", "build", []],
    ["build", "notarize-macos", []],
    ["notarize-macos", "build-windows", []],
    ["build-windows", "sign-windows", []],
    ["sign-windows", "pack-npm-packages", ["id-token"]],
    ["pack-npm-packages", "smoke-npm-packages", []],
    ["smoke-npm-packages", "smoke-windows-recovery", []],
    ["smoke-windows-recovery", "release", []],
    ["release", "smoke-standalone-installer", ["contents", "id-token", "attestations"]],
    ["smoke-standalone-installer", "seal-candidate", []],
    ["seal-candidate", "prepare-promotion", []],
    ["prepare-promotion", "stage-promotion-release", []],
    ["stage-promotion-release", "publish-promotion-platform", ["attestations", "id-token"]],
    ["publish-promotion-platform", "finalize-promotion-release", ["id-token"]],
    ["finalize-promotion-release", "publish-release", ["contents"]],
    ["publish-release", "publish-npm-platform", ["contents"]],
    ["publish-npm-platform", "publish-npm-wrapper", ["id-token"]],
    ["publish-npm-wrapper", "update-homebrew", ["id-token"]],
    ["update-homebrew", undefined, []],
  ];

  for (const [job, nextJob, expected] of jobs) {
    assert.deepEqual(
      writePermissions(releaseJobSource(releaseWorkflow, job, nextJob)),
      expected,
      `${job} has unexpected write permissions`,
    );
  }

  const windowsSigningJob = releaseJobSource(
    releaseWorkflow,
    "sign-windows",
    "pack-npm-packages",
  );
  assert.doesNotMatch(windowsSigningJob, /actions\/checkout|\bcargo\b|--version/);
});

test("npm publish workflow treats release tarballs as local filesystem paths", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const releaseWorkflow = fs.readFileSync(
    path.join(repoRoot, ".github/workflows/release.yml"),
    "utf8",
  );
  const publishSpecs = [...releaseWorkflow.matchAll(/npm publish "([^"]+)"/g)].map(
    match => match[1],
  );

  assert.deepEqual(publishSpecs, [
    "$packages/$tarball",
    "$packages/$tarball",
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
    [platformJob, "npm publish"],
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

  assert.match(releaseWorkflow, /^\s+- npm-publish-only$/m);
  assert.match(
    releaseWorkflow,
    /if \[ "\$GITHUB_REF" != "refs\/heads\/main" \]; then/,
  );
  const platformSource = releaseJobSource(
    releaseWorkflow,
    "publish-npm-platform",
    "publish-npm-wrapper",
  );
  const wrapperSource = releaseJobSource(
    releaseWorkflow,
    "publish-npm-wrapper",
    "update-homebrew",
  );
  for (const source of [platformSource, wrapperSource]) {
    assert.match(source, /inputs\.mode == 'npm-publish-only'/);
    assert.match(source, /node npm\/release\/validate-recovery-source\.mjs/);
    assert.match(source, /--purpose (?:npm-publish|"\$RECOVERY_PURPOSE")/);
    assert.match(source, /ARTIFACT_ID: \$\{\{ steps\.source\.outputs\.artifact_id \}\}/);
    assert.match(source, /ARTIFACT_DIGEST: \$\{\{ steps\.source\.outputs\.artifact_digest \}\}/);
    assert.match(source, /scripts\/ci\/download-verified-artifact\.sh/);
    assert.match(source, /GH_TOKEN: \$\{\{ github\.token \}\}/);
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
  assert.match(recovery, /ARTIFACT_ID: \$\{\{ steps\.source\.outputs\.artifact_id \}\}/);
  assert.match(recovery, /ARTIFACT_DIGEST: \$\{\{ steps\.source\.outputs\.artifact_digest \}\}/);
  assert.match(recovery, /scripts\/ci\/download-verified-artifact\.sh/);
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
    stagePlatformFixture(binaries, platform);
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

test("release packaging rejects AppleDouble files in an npm app bundle", t => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const binaries = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-appledouble-"));
  const output = path.join(os.tmpdir(), `lpm-release-output-${process.pid}-${Date.now()}`);
  t.after(() => {
    fs.rmSync(binaries, { recursive: true, force: true });
    fs.rmSync(output, { recursive: true, force: true });
  });

  for (const platform of PLATFORM_PACKAGES) {
    stagePlatformFixture(binaries, platform);
  }
  fs.writeFileSync(
    path.join(binaries, "darwin-arm64/LPM CLI.app/Contents/MacOS/._lpm-rs"),
    "AppleDouble metadata",
  );

  assert.throws(
    () =>
      prepareReleasePackages({
        repoRoot,
        binariesDir: binaries,
        outputDir: output,
        version: "0.69.0",
      }),
    /file inventory drifted[\s\S]*\._lpm-rs/,
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
      stagePlatformFixture(binaries, platform);
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

function stagePlatformFixture(binaries, platform) {
  if (platform.bundleSource) {
    for (const entry of platform.bundleFiles) {
      const artifact = path.join(
        binaries,
        platform.bundleSource,
        path.relative("LPM CLI.app", entry.path),
      );
      fs.mkdirSync(path.dirname(artifact), { recursive: true });
      fs.writeFileSync(artifact, `fixture:${entry.path}\n`);
      fs.chmodSync(artifact, entry.mode);
    }
    return;
  }

  for (const mapping of platform.binaries) {
    const artifact = path.join(binaries, mapping.artifact);
    fs.mkdirSync(path.dirname(artifact), { recursive: true });
    if (!fs.existsSync(artifact)) fs.writeFileSync(artifact, `fixture:${mapping.artifact}\n`);
  }
}
