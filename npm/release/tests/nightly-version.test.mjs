import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { nightlyVersion, workspaceStableVersion } from "../nightly-version.mjs";

test("nightly version advances the workspace minor and embeds reproducible run identity", () => {
  assert.equal(
    nightlyVersion({
      stableVersion: "0.70.0",
      date: "20260728",
      runNumber: "42",
      commitSha: "D82CEEA4B9235B973AA25BD8653909646F9F45AF",
    }),
    "0.71.0-nightly.20260728.42.d82ceea",
  );
});

test("nightly version resets patch after a stable patch release", () => {
  assert.equal(
    nightlyVersion({
      stableVersion: "2.9.7",
      date: "20261201",
      runNumber: 9001,
      commitSha: "1234567890abcdef",
    }),
    "2.10.0-nightly.20261201.9001.1234567",
  );
});

test("nightly version keeps an all-numeric leading-zero SHA semver-valid", () => {
  assert.equal(
    nightlyVersion({
      stableVersion: "0.70.0",
      date: "20260728",
      runNumber: "42",
      commitSha: "0123456789abcdef",
    }),
    "0.71.0-nightly.20260728.42.g0123456",
  );
});

test("nightly version rejects malformed inputs", () => {
  const valid = {
    stableVersion: "0.70.0",
    date: "20260728",
    runNumber: "42",
    commitSha: "d82ceea4",
  };
  for (const override of [
    { stableVersion: "0.70.0-rc.1" },
    { date: "20260230" },
    { date: "2026728" },
    { runNumber: "0" },
    { runNumber: "04" },
    { commitSha: "not-a-sha" },
  ]) {
    assert.throws(() => nightlyVersion({ ...valid, ...override }));
  }
});

test("workspace stable version comes from Cargo workspace metadata", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  assert.match(workspaceStableVersion(repoRoot), /^\d+\.\d+\.\d+$/);
});

test("step-one nightly publishing is manual and preserves stable release routing", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const workflow = fs.readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8");

  assert.doesNotMatch(workflow, /^\s+schedule:\s*$/m);
  assert.match(workflow, /^\s+- "!v\*-\*"\s*$/m);
  assert.match(workflow, /^\s+channel:\s*$/m);
  assert.match(workflow, /LPM_BUILD_VERSION: \$\{\{ needs\.release-metadata\.outputs\.version \}\}/);
  assert.equal(workflow.match(/--tag "\$NPM_TAG"/g)?.length, 2);
  assert.match(workflow, /prerelease: \$\{\{ needs\.release-metadata\.outputs\.prerelease \}\}/);
  assert.match(workflow, /make_latest: \$\{\{ needs\.release-metadata\.outputs\.channel == 'stable' \}\}/);
  assert.match(
    workflow,
    /needs\.release-metadata\.outputs\.channel == 'stable' &&\s+\(github\.event_name == 'push' \|\| inputs\.mode == 'full'\)/,
  );
});
