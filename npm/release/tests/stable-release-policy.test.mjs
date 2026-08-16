import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("stable full releases require the exact tag and never overwrite assets", () => {
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
  assert.match(metadata, /EXPECTED_REF="refs\/tags\/v\$\{VERSION\}"/);
  assert.match(metadata, /if \[ "\$GITHUB_REF" != "\$EXPECTED_REF" \]; then/);

  const release = workflow.slice(releaseStart, releaseEnd);
  assert.match(release, /^\s+overwrite_files: false$/m);
  assert.match(release, /^\s+fail_on_unmatched_files: true$/m);
});
