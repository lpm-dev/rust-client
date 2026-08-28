import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { sealReleaseCandidate, verifyReleaseCandidate } from "../release-candidate.mjs";

const IDENTITY = {
  repository: "lpm-dev/rust-client",
  sourceSha: "a".repeat(40),
  sourceRunId: "33150000000",
  version: "0.76.6",
};

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-candidate-"));
  const githubReleaseDirectory = path.join(root, "release");
  const npmPackagesDirectory = path.join(root, "npm");
  const outputDirectory = path.join(root, "candidate");
  fs.mkdirSync(githubReleaseDirectory);
  fs.mkdirSync(npmPackagesDirectory);
  fs.writeFileSync(path.join(githubReleaseDirectory, "SHA256SUMS.txt"), "hash  lpm-linux-x64\n");
  fs.writeFileSync(path.join(githubReleaseDirectory, "SHA256SUMS.txt.sigstore"), "{}\n");
  fs.writeFileSync(path.join(githubReleaseDirectory, "lpm-linux-x64"), "binary");
  fs.writeFileSync(path.join(npmPackagesDirectory, "release-packages.json"), "{}\n");
  fs.writeFileSync(path.join(npmPackagesDirectory, "cli.tgz"), "package");
  return { root, githubReleaseDirectory, npmPackagesDirectory, outputDirectory };
}

test("sealed candidate round-trips with immutable source identity", t => {
  const dirs = fixture();
  t.after(() => fs.rmSync(dirs.root, { force: true, recursive: true }));

  sealReleaseCandidate({ ...dirs, ...IDENTITY });
  const manifest = verifyReleaseCandidate({
    candidateDirectory: dirs.outputDirectory,
    ...IDENTITY,
  });

  assert.equal(manifest.tag, "v0.76.6");
  assert.equal(manifest.files.length, 5);
});

test("candidate verification rejects changed added and symbolic-link payloads", t => {
  for (const mutation of ["changed", "added", "symlink"]) {
    const dirs = fixture();
    t.after(() => fs.rmSync(dirs.root, { force: true, recursive: true }));
    sealReleaseCandidate({ ...dirs, ...IDENTITY });
    if (mutation === "changed") {
      fs.appendFileSync(path.join(dirs.outputDirectory, "github-release/lpm-linux-x64"), "changed");
    } else if (mutation === "added") {
      fs.writeFileSync(path.join(dirs.outputDirectory, "github-release/unsealed"), "extra");
    } else {
      fs.symlinkSync("lpm-linux-x64", path.join(dirs.outputDirectory, "github-release/link"));
    }

    assert.throws(
      () => verifyReleaseCandidate({ candidateDirectory: dirs.outputDirectory, ...IDENTITY }),
      /inventory|symbolic link/,
      mutation,
    );
  }
});

test("candidate verification rejects promotion identity mismatches", t => {
  const dirs = fixture();
  t.after(() => fs.rmSync(dirs.root, { force: true, recursive: true }));
  sealReleaseCandidate({ ...dirs, ...IDENTITY });

  for (const identity of [
    { ...IDENTITY, repository: "attacker/fork" },
    { ...IDENTITY, sourceSha: "b".repeat(40) },
    { ...IDENTITY, sourceRunId: "33150000001" },
    { ...IDENTITY, version: "0.76.7" },
  ]) {
    assert.throws(
      () => verifyReleaseCandidate({ candidateDirectory: dirs.outputDirectory, ...identity }),
      /mismatch/,
    );
  }
});

test("candidate verification accepts only an exact sealed payload scope", t => {
  const dirs = fixture();
  t.after(() => fs.rmSync(dirs.root, { force: true, recursive: true }));
  sealReleaseCandidate({ ...dirs, ...IDENTITY });

  for (const scope of ["github-release", "npm-release-packages"]) {
    const scoped = path.join(dirs.root, `scoped-${scope}`);
    fs.mkdirSync(scoped);
    fs.copyFileSync(
      path.join(dirs.outputDirectory, "release-candidate.json"),
      path.join(scoped, "release-candidate.json"),
    );
    fs.cpSync(path.join(dirs.outputDirectory, scope), path.join(scoped, scope), { recursive: true });
    assert.doesNotThrow(() =>
      verifyReleaseCandidate({ candidateDirectory: scoped, scope, ...IDENTITY })
    );
    fs.writeFileSync(path.join(scoped, scope, "unsealed"), "unexpected");
    assert.throws(
      () => verifyReleaseCandidate({ candidateDirectory: scoped, scope, ...IDENTITY }),
      /sealed file inventory/,
    );
  }
});
