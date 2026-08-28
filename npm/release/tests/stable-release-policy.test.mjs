import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("stable releases require candidate promotion and do not start from a tag", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const metadataStart = workflow.indexOf("\n  release-metadata:\n");
  const metadataEnd = workflow.indexOf("\n  verify:\n", metadataStart + 1);
  const promotionStart = workflow.indexOf("\n  prepare-promotion:\n");
  const promotionEnd = workflow.indexOf("\n  publish-release:\n", promotionStart + 1);

  assert.notEqual(metadataStart, -1, "missing release metadata job");
  assert.notEqual(metadataEnd, -1, "missing job after release metadata");
  assert.notEqual(promotionStart, -1, "missing promotion preparation job");
  assert.notEqual(promotionEnd, -1, "missing job after stable promotion jobs");

  const metadata = workflow.slice(metadataStart, metadataEnd);
  assert.match(
    workflow,
    /group: release-\$\{\{ .*inputs\.version \|\| github\.ref \}\}/,
    "candidate and promotion runs for a stable version must serialize together",
  );
  assert.match(metadata, /Stable releases use candidate followed by promote/);
  assert.match(metadata, /Tag v\$\{VERSION\} already exists/);
  assert.doesNotMatch(workflow, /^\s+tags:\s*$/m);

  const promotion = workflow.slice(promotionStart, promotionEnd);
  assert.match(promotion, /^\s+overwrite_files: false$/m);
  assert.match(promotion, /^\s+fail_on_unmatched_files: true$/m);
  assert.match(promotion, /Resolve idempotent release state/);
  assert.match(promotion, /Multiple releases exist for \$RELEASE_TAG/);
  assert.match(promotion, /Tag \$RELEASE_TAG exists without its exact published release/);
  assert.match(promotion, /existing \$RELEASE_TAG release is marked as a prerelease/);
  assert.match(promotion, /missing published_at/);
  assert.match(promotion, /releases\/latest/);
  assert.equal(
    [...promotion.matchAll(/gh api --paginate --slurp/g)].length,
    2,
    "both promotion release listings must slurp paginated JSON before filtering",
  );
  assert.doesNotMatch(promotion, /releases=\$\(gh api --paginate/);
  assert.match(promotion, /^\s+draft: true$/m);
  assert.match(promotion, /-F draft=false/);
  assert.match(promotion, /draft_target.*SOURCE_SHA/s);
  assert.match(promotion, /appeared while the draft was being verified/);
  assert.ok(
    promotion.indexOf("Create draft and upload exact assets") <
      promotion.indexOf("Verify exact draft and publish stable release"),
    "release assets must be uploaded to a draft before that draft is published",
  );
  assert.ok(
    promotion.indexOf("Reverify candidate and promotion asset inventory") <
      promotion.indexOf("Create draft and upload exact assets"),
    "candidate and release assets must be reverified before publication",
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

  const build = jobSource("build", "notarize-macos");
  const linuxUpload = build.indexOf("Upload non-macOS artifact");
  const linuxExecute = build.indexOf("Execute release binary (Linux glibc)");
  assert.ok(linuxUpload >= 0 && linuxUpload < linuxExecute, "Linux upload must precede execution");

  const macos = jobSource("notarize-macos", "build-windows");
  const macUpload = macos.indexOf("Upload macOS bundle and compatibility artifact");
  const macExecute = macos.indexOf("Execute notarized app bundle and compatibility binary");
  assert.ok(macUpload >= 0 && macUpload < macExecute, "macOS upload must precede execution");

  const windows = jobSource("build-windows", "sign-windows");
  assert.ok(
    windows.indexOf("Upload immutable unsigned binaries") <
      windows.indexOf("Execute release binary"),
    "Windows upload must precede execution",
  );
});

test("macOS release smoke isolates LPM state without hiding the login Keychain", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = workflow.indexOf(
    "- name: Execute notarized app bundle and compatibility binary",
  );
  const end = workflow.indexOf(
    "\n  build-windows:\n",
    start + 1,
  );

  assert.notEqual(start, -1, "missing macOS release smoke step");
  assert.notEqual(end, -1, "missing step after macOS release smoke");

  const smoke = workflow.slice(start, end);
  assert.match(smoke, /LPM_HOME="\$raw_smoke_home"/);
  assert.doesNotMatch(smoke, /(?:^|\s)HOME="\$raw_smoke_home"/m);
});

test("macOS release signing preserves the login Keychain search list", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = workflow.indexOf("- name: Import Developer ID certificate (macOS)");
  const end = workflow.indexOf("- name: Sign legacy binary and provisioned app bundle", start + 1);

  assert.notEqual(start, -1, "missing macOS certificate import step");
  assert.notEqual(end, -1, "missing macOS signing step after certificate import");

  const certificateImport = workflow.slice(start, end);
  assert.doesNotMatch(
    certificateImport,
    /security list-keychains\s+-d user\s+-s/,
    "a temporary signing Keychain must not replace the login Keychain search list",
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
