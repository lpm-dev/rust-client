import assert from "node:assert/strict";
import test from "node:test";

import {
  NIGHTLY_PACKAGES,
  resolveNightlyReleaseState,
} from "../nightly-release-state.mjs";

const VERSION = "0.71.0-nightly.20260727.121.c83ea7b";
const PREVIOUS_SHA = "c83ea7b15c4d989b52ac98c756d99fef55a7fe1b";
const CURRENT_SHA = "d82ceea4b9235b973aa25bd8653909646f9f45af";

function npmVersions(version = VERSION) {
  return Object.fromEntries(NIGHTLY_PACKAGES.map((packageName) => [packageName, version]));
}

function releaseState(overrides = {}) {
  return {
    currentSha: CURRENT_SHA,
    tagSha: PREVIOUS_SHA,
    relationship: "ancestor",
    npmVersions: npmVersions(),
    githubRelease: {
      tagName: `v${VERSION}`,
      prerelease: true,
      draft: false,
      publishedAt: "2026-07-27T23:01:02Z",
    },
    ...overrides,
  };
}

test("scheduled nightly is a no-op when the published tag targets current main", () => {
  const state = resolveNightlyReleaseState(
    releaseState({
      currentSha: PREVIOUS_SHA,
      tagSha: PREVIOUS_SHA,
      relationship: "same",
    }),
  );

  assert.equal(state.shouldRelease, false);
  assert.match(state.reason, /already targets current main commit/);
});

test("scheduled nightly publishes when main advanced from the published tag", () => {
  const state = resolveNightlyReleaseState(releaseState());

  assert.equal(state.shouldRelease, true);
  assert.equal(state.tag, `v${VERSION}`);
  assert.match(state.reason, /main advanced/);
});

test("scheduled nightly rejects malformed published state", () => {
  assert.throws(
    () =>
      resolveNightlyReleaseState(
        releaseState({
          npmVersions: npmVersions("0.71.0-nightly.20260230.121.c83ea7b"),
        }),
      ),
    /invalid version/,
  );

  const missingPackage = npmVersions();
  delete missingPackage["@lpm-registry/cli-linux-arm64"];
  assert.throws(
    () => resolveNightlyReleaseState(releaseState({ npmVersions: missingPackage })),
    /package set is inconsistent/,
  );
});

test("scheduled nightly fails closed when npm and GitHub disagree", () => {
  const mismatchedVersions = npmVersions();
  mismatchedVersions["@lpm-registry/cli-win32-x64"] =
    "0.71.0-nightly.20260728.122.d82ceea";
  assert.throws(
    () => resolveNightlyReleaseState(releaseState({ npmVersions: mismatchedVersions })),
    /dist-tags do not all point to the same version/,
  );

  assert.throws(
    () =>
      resolveNightlyReleaseState(
        releaseState({
          githubRelease: {
            ...releaseState().githubRelease,
            tagName: "v0.71.0-nightly.20260728.122.d82ceea",
          },
        }),
      ),
    /GitHub release tag/,
  );
});

test("scheduled nightly fails closed when the published tag diverged from main", () => {
  assert.throws(
    () => resolveNightlyReleaseState(releaseState({ relationship: "diverged" })),
    /is not an ancestor of current main/,
  );
});
