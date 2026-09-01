import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function read(relative) {
  return fs.readFileSync(path.join(repoRoot, relative), "utf8").replaceAll("\r\n", "\n");
}

function jobSource(workflow, job, nextJob) {
  const start = workflow.indexOf(`\n  ${job}:\n`);
  const end = workflow.indexOf(`\n  ${nextJob}:\n`, start + 1);
  assert.notEqual(start, -1, `missing ${job} job`);
  assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
  return workflow.slice(start, end);
}

test("nightly and candidate construction survives the unused verification branch being skipped", () => {
  const workflow = read(".github/workflows/release.yml");
  const constructionJobs = [
    ["build", "notarize-macos", ["release-metadata", "release-preflight", "verify-windows-filesystem"]],
    ["notarize-macos", "build-windows", ["build", "release-metadata"]],
    ["build-windows", "sign-windows", ["release-metadata", "release-preflight", "verify-windows-filesystem"]],
    ["sign-windows", "pack-npm-packages", ["build-windows", "release-metadata"]],
    ["pack-npm-packages", "smoke-npm-packages", ["build", "notarize-macos", "sign-windows", "release-metadata"]],
    ["smoke-npm-packages", "smoke-windows-recovery", ["pack-npm-packages", "release-metadata"]],
    ["release", "smoke-standalone-installer", ["build", "smoke-npm-packages", "release-metadata"]],
    ["smoke-standalone-installer", "seal-candidate", ["release", "release-metadata"]],
  ];

  for (const [job, nextJob, requiredJobs] of constructionJobs) {
    const source = jobSource(workflow, job, nextJob);
    assert.match(
      source,
      /if: >-\n\s+(?:always\(\)|!cancelled\(\)) &&/,
      `${job} must override the implicit skipped-ancestor status check`,
    );
    for (const requiredJob of requiredJobs) {
      assert.match(
        source,
        new RegExp(`needs\\.${requiredJob}\\.result == 'success'`),
        `${job} must fail closed unless ${requiredJob} succeeds`,
      );
    }
  }

  for (const job of ["build", "build-windows"]) {
    const source = jobSource(
      workflow,
      job,
      job === "build" ? "notarize-macos" : "sign-windows",
    );
    assert.match(source, /mode == 'full' && needs\.verify\.result == 'success'/);
    assert.match(
      source,
      /mode == 'candidate' && needs\.verify-candidate-source\.result == 'success'/,
    );
  }
});

test("stable releases build a candidate before promotion creates the tag", () => {
  const workflow = read(".github/workflows/release.yml");
  const downloader = read("scripts/ci/download-verified-artifact.sh");
  const promotionStart = workflow.indexOf("\n  prepare-promotion:\n");
  const promotionEnd = workflow.indexOf("\n  publish-release:\n", promotionStart + 1);
  assert.notEqual(promotionStart, -1);
  assert.notEqual(promotionEnd, -1);
  const promotion = workflow.slice(promotionStart, promotionEnd);

  assert.doesNotMatch(workflow, /^\s+tags:\s*$/m);
  assert.match(workflow, /^\s+- candidate$/m);
  assert.match(workflow, /^\s+- promote$/m);
  assert.match(workflow, /name: Seal stable release candidate/);
  assert.match(workflow, /name: stable-release-candidate-\$\{\{ needs\.release-metadata\.outputs\.version \}\}/);
  assert.match(workflow, /name: stable-release-candidate-[\s\S]*?retention-days: 7/);

  assert.match(promotion, /validate-release-candidate-source\.mjs/);
  assert.match(promotion, /verify-release-candidate\.mjs/);
  assert.match(promotion, /artifact_digest: \$\{\{ steps\.source\.outputs\.artifact_digest \}\}/);
  assert.match(
    promotion,
    /artifact_digest: sha256:\$\{\{ steps\.github-assets\.outputs\['artifact-digest'\] \}\}/,
  );
  assert.match(promotion, /scripts\/ci\/download-verified-artifact\.sh/);
  assert.match(downloader, /actual_digest="sha256:\$\(sha256sum/);
  assert.match(downloader, /actual_digest" != "\$expected_digest/);
  assert.match(promotion, /Create draft and upload exact assets/);
  assert.match(promotion, /Verify exact draft and publish stable release/);
  assert.match(promotion, /Create fresh promotion-time Sigstore proof/);
  assert.match(promotion, /files: promotion-github-release\/\*/);
  assert.match(promotion, /cosign verify-blob/);
  assert.match(promotion, /refs\/heads\/main\$/);
  assert.match(promotion, /releases\/latest/);
  assert.match(promotion, /--source-run-id trusted/);
  assert.match(promotion, /stable promotion recovery/i);
  assert.match(workflow, /Keep .*main.*until GitHub, npm, and Homebrew promotion all succeed/);
  assert.match(promotion, /one-day scoped-artifact retention window/);
  assert.doesNotMatch(promotion, /cargo (?:build|rustc)/);
  assert.ok(
    promotion.indexOf("Verify sealed candidate") < promotion.indexOf("Create draft and upload exact assets"),
    "promotion must verify the complete candidate before creating a tag",
  );
});

test("macOS release builds reuse dependency artifacts", () => {
  const workflow = read(".github/workflows/release.yml");
  const start = workflow.indexOf("\n  build:\n");
  const end = workflow.indexOf("\n  build-windows:\n", start + 1);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const build = workflow.slice(start, end);

  assert.doesNotMatch(build, /--target-dir target\/legacy-macos-keychain/);
  assert.match(build, /Preserve provisioned macOS binary/);
  assert.match(build, /--features legacy-macos-keychain/);
});

test("candidate runs require the fast macOS release preflight", () => {
  const workflow = read(".github/workflows/release.yml");
  const preflight = read(".github/workflows/release-preflight.yml");

  assert.match(workflow, /uses: \.\/\.github\/workflows\/release-preflight\.yml/);
  assert.match(preflight, /APPLE_DEVELOPER_ID_P12_BASE64/);
  assert.match(preflight, /APPLE_CLI_PROVISIONING_PROFILE_BASE64/);
  assert.match(preflight, /test-macos-keychain-search-list\.sh/);
  assert.match(preflight, /notarytool history/);
  assert.match(preflight, /release-api-contract\.test\.mjs/);
});

test("macOS notarization retries submissions and resumes polling by submission ID", () => {
  const workflow = read(".github/workflows/release.yml");
  const helper = read("scripts/ci/notarize-with-retry.sh");

  assert.match(workflow, /scripts\/ci\/notarize-with-retry\.sh/);
  assert.match(helper, /notarytool submit/);
  assert.match(helper, /notarytool info/);
  assert.match(helper, /submission_id/);
  assert.match(helper, /MAX_SUBMIT_ATTEMPTS/);
  assert.match(workflow, /Persist notarization submission IDs before polling/);
  assert.match(workflow, /notarization-state-\$\{\{ matrix\.binary \}\}-\$\{\{ github\.run_attempt \}\}/);
  assert.ok(
    workflow.indexOf("LPM_NOTARY_MODE=submit") <
      workflow.indexOf("Persist notarization submission IDs before polling"),
  );
  assert.ok(
    workflow.indexOf("Persist notarization submission IDs before polling") <
      workflow.indexOf("LPM_NOTARY_MODE=poll"),
  );
  assert.doesNotMatch(workflow, /notarytool submit .*--wait/);
  const packStart = workflow.indexOf("\n  pack-npm-packages:\n");
  const packEnd = workflow.indexOf("\n  smoke-npm-packages:\n", packStart + 1);
  const pack = workflow.slice(packStart, packEnd);
  assert.match(pack, /needs:[\s\S]*?- notarize-macos/);
});

test("candidate smoke and sealing hard-enforce uploaded artifact digests", () => {
  const workflow = read(".github/workflows/release.yml");
  for (const [jobName, nextJob] of [
    ["smoke-npm-packages", "smoke-windows-recovery"],
    ["smoke-standalone-installer", "seal-candidate"],
    ["seal-candidate", "prepare-promotion"],
  ]) {
    const start = workflow.indexOf(`\n  ${jobName}:\n`);
    const next = workflow.indexOf(`\n  ${nextJob}:\n`, start + 4);
    assert.notEqual(start, -1, `missing ${jobName}`);
    assert.notEqual(next, -1, `missing ${nextJob}`);
    const job = workflow.slice(start, next);
    assert.match(job, /scripts\/ci\/download-verified-artifact\.sh/);
    assert.match(job, /ARTIFACT_DIGEST:/);
  }
});

test("macOS standalone smoke keeps its bounded server-start counter", () => {
  const workflow = read(".github/workflows/release.yml");
  const start = workflow.indexOf("python3 -m http.server 8765 --bind 127.0.0.1");
  const end = workflow.indexOf("# Exercise the real compatibility path", start + 1);
  const serverWait = workflow.slice(start, end);
  assert.match(serverWait, /for attempt in \{1\.\.30\}; do/);
  assert.match(serverWait, /if \[ "\$attempt" -eq 30 \]; then/);
});

test("promotion waits for the correlated Homebrew update", () => {
  const promotion = read(".github/workflows/release.yml");

  assert.match(promotion, /correlation_id/);
  assert.match(promotion, /Await correlated Homebrew workflow/);
  assert.match(promotion, /actions\/runs/);
  assert.match(promotion, /conclusion.*success/);
});
