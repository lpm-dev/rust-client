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
