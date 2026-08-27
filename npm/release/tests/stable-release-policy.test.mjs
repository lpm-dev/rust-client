import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("stable full releases require the exact tag and recreate stale drafts", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const metadataStart = workflow.indexOf("\n  release-metadata:\n");
  const metadataEnd = workflow.indexOf("\n  verify:\n", metadataStart + 1);
  const releaseStart = workflow.indexOf("\n  release:\n");
  const releaseEnd = workflow.indexOf("\n  smoke-standalone-installer:\n", releaseStart + 1);

  assert.notEqual(metadataStart, -1, "missing release metadata job");
  assert.notEqual(metadataEnd, -1, "missing job after release metadata");
  assert.notEqual(releaseStart, -1, "missing release job");
  assert.notEqual(releaseEnd, -1, "missing job after release");

  const metadata = workflow.slice(metadataStart, metadataEnd);
  assert.match(
    workflow,
    /group: release-\$\{\{ .*'nightly' \|\| github\.ref \}\}/,
    "tag pushes and manual dispatches for the same stable ref must serialize together",
  );
  assert.match(metadata, /EXPECTED_REF="refs\/tags\/v\$\{VERSION\}"/);
  assert.match(metadata, /if \[ "\$GITHUB_REF" != "\$EXPECTED_REF" \]; then/);

  const release = workflow.slice(releaseStart, releaseEnd);
  assert.match(release, /^\s+overwrite_files: false$/m);
  assert.match(release, /^\s+fail_on_unmatched_files: true$/m);
  assert.match(release, /A published release already exists for \$RELEASE_TAG/);
  assert.match(release, /gh api --method DELETE/);
  assert.match(release, /Multiple stale drafts exist/);
  assert.ok(
    release.indexOf("Remove stale draft release for the exact tag") <
      release.indexOf("Create draft GitHub Release"),
    "stale draft cleanup must finish before a new draft uploads assets",
  );
});

test("release inputs are uploaded before any staged binary executes natively", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const jobSource = (job, nextJob) => {
    const start = workflow.indexOf(`\n  ${job}:\n`);
    const end = workflow.indexOf(`\n  ${nextJob}:\n`, start + 1);
    assert.notEqual(start, -1, `missing ${job} job`);
    assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
    return workflow.slice(start, end);
  };

  const build = jobSource("build", "build-windows");
  const macUpload = build.indexOf("Upload macOS bundle and compatibility artifact");
  const macExecute = build.indexOf("Execute release app bundle and compatibility binary");
  const linuxUpload = build.indexOf("Upload non-macOS artifact");
  const linuxExecute = build.indexOf("Execute release binary (Linux glibc)");
  assert.ok(macUpload >= 0 && macUpload < macExecute, "macOS upload must precede execution");
  assert.ok(linuxUpload >= 0 && linuxUpload < linuxExecute, "Linux upload must precede execution");

  const windows = jobSource("build-windows", "sign-windows");
  assert.ok(
    windows.indexOf("Upload immutable unsigned binaries") <
      windows.indexOf("Execute release binary"),
    "Windows upload must precede execution",
  );
});

test("every macOS release retains the pre-bundle standalone updater bridge", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");

  assert.doesNotMatch(workflow, /MACOS_RAW_BRIDGE_VERSION/);
  assert.match(
    workflow,
    /assets\+=\(lpm-darwin-arm64 lpm-darwin-x64\)/,
    "post-0.76 releases must checksum and publish the raw updater bridge",
  );
  assert.doesNotMatch(workflow, /Remove non-bridge raw macOS artifact/);
});
