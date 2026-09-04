import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("scheduled releases publish a separate acceptance-hook Linux artifact", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const buildStart = workflow.indexOf("\n  build:\n");
  const buildEnd = workflow.indexOf("\n  notarize-macos:\n", buildStart + 1);

  assert.notEqual(buildStart, -1, "missing release build job");
  assert.notEqual(buildEnd, -1, "missing job after release build");
  const build = workflow.slice(buildStart, buildEnd);
  const productUpload = build.indexOf("Upload non-macOS artifact");
  const acceptanceBuild = build.indexOf("Build scheduled acceptance binary");
  const acceptanceUpload = build.indexOf("Upload scheduled acceptance artifact");

  assert.ok(productUpload >= 0 && productUpload < acceptanceBuild);
  assert.ok(acceptanceBuild < acceptanceUpload);
  assert.match(
    build,
    /github\.event_name == 'schedule' && matrix\.target == 'x86_64-unknown-linux-gnu'/,
  );
  assert.match(build, /--features portable-linux,acceptance-test-hooks/);
  assert.match(build, /name: lpm-linux-x64-acceptance/);
  assert.match(build, /retention-days: 30/);
  assert.match(build, /SHA256SUMS\.txt/);
  assert.match(build, /manifest\.json/);
});

test("scheduled acceptance artifacts cannot enter public release downloads", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const publicArtifacts = [
    "lpm-darwin-arm64",
    "lpm-darwin-x64",
    "lpm-linux-arm64",
    "lpm-linux-x64",
    "lpm-linux-x64-musl",
    "lpm-sandbox-helper-win32-x64.exe",
    "lpm-win32-x64.exe",
  ];

  for (const [job, nextJob] of [
    ["pack-npm-packages", "smoke-npm-packages"],
    ["release", "smoke-standalone-installer"],
  ]) {
    const start = workflow.indexOf(`\n  ${job}:\n`);
    const end = workflow.indexOf(`\n  ${nextJob}:\n`, start + 1);

    assert.notEqual(start, -1, `missing ${job} job`);
    assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
    const jobSource = workflow.slice(start, end);
    const pattern = jobSource.match(/^\s+pattern:\s+(\S+)\s*$/m)?.[1];

    assert.ok(pattern, `${job} must select release artifacts with a static pattern`);
    assert.equal(
      path.matchesGlob("lpm-linux-x64-acceptance", pattern),
      false,
      `${job} must exclude the internal acceptance artifact`,
    );
    for (const artifact of publicArtifacts) {
      assert.equal(path.matchesGlob(artifact, pattern), true, `${job} must include ${artifact}`);
    }
  }
});
