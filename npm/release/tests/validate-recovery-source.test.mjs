import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  RECOVERY_REQUIRED_JOBS,
  validateRecoverySource,
} from "../validate-recovery-source.mjs";

const REPOSITORY = "lpm-dev/rust-client";
const RUN_ID = 31925614412;
const SOURCE_SHA = "226f5767297ff843c999d06076baec0be7c40f7d";
const ARTIFACT_DIGEST = `sha256:${"a".repeat(64)}`;

const PUBLISH_JOBS = [
  "Resolve release metadata",
  "Release verification",
  "verify-windows-filesystem / Windows filesystem release gate",
  "Build aarch64-apple-darwin",
  "Build aarch64-unknown-linux-gnu",
  "Build x86_64-apple-darwin",
  "Build x86_64-pc-windows-msvc",
  "Build x86_64-unknown-linux-gnu",
  "Build x86_64-unknown-linux-musl",
  "Pack exact npm release artifacts",
  "Smoke npm artifacts (darwin-arm64)",
  "Smoke npm artifacts (darwin-x64)",
  "Smoke npm artifacts (linux-arm64)",
  "Smoke npm artifacts (linux-x64)",
  "Smoke npm artifacts (linux-x64-musl)",
  "Smoke npm artifacts (win32-x64)",
  "Stage Draft Release",
  "Smoke standalone installer on Debian 12 (arm64)",
  "Smoke standalone installer on Debian 12 (x64)",
  "Smoke standalone installer on macOS (arm64)",
  "Smoke standalone installer on macOS (x64)",
  "Publish Smoke-Verified Release",
];

function workflowJobNames(source, repoRoot) {
  const names = new Set();
  const jobs = source.matchAll(
    /^  ([a-z0-9-]+):\n([\s\S]*?)(?=^  [a-z0-9-]+:|(?![\s\S]))/gm,
  );
  for (const [, jobId, body] of jobs) {
    const name = /^    name: (.+)$/m.exec(body)?.[1];
    if (!name) {
      const reusablePath = /^    uses: \.\/(.+)$/m.exec(body)?.[1];
      if (reusablePath) {
        const reusable = fs.readFileSync(path.join(repoRoot, reusablePath), "utf8");
        const reusableJobNames = [...reusable.matchAll(/^    name: (.+)$/gm)].map(
          match => match[1],
        );
        assert.ok(reusableJobNames.length > 0, `reusable workflow ${reusablePath} must name its jobs`);
        for (const reusableJobName of reusableJobNames) {
          names.add(`${jobId} / ${reusableJobName}`);
        }
      }
      continue;
    }
    const countBefore = names.size;
    if (name === "Build ${{ matrix.target }}") {
      for (const match of body.matchAll(/^          - target: (.+)$/gm)) {
        names.add(`Build ${match[1]}`);
      }
    } else if (name === "Smoke npm artifacts (${{ matrix.platform }})") {
      for (const match of body.matchAll(/^          - platform: (.+)$/gm)) {
        names.add(`Smoke npm artifacts (${match[1]})`);
      }
    } else if (name === "${{ matrix.name }}") {
      for (const match of body.matchAll(/^          - name: (.+)$/gm)) names.add(match[1]);
    } else {
      names.add(name);
    }
    assert.ok(names.size > countBefore, `workflow job ${jobId} must resolve to a unique name`);
  }
  return names;
}

test("every recovery prerequisite matches a current release workflow job name", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const workflow = fs.readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8");
  const actualJobNames = workflowJobNames(workflow.replaceAll("\r\n", "\n"), repoRoot);

  for (const [purpose, requiredJobs] of Object.entries(RECOVERY_REQUIRED_JOBS)) {
    for (const requiredJob of requiredJobs) {
      assert.ok(
        actualJobNames.has(requiredJob),
        `${purpose} recovery requires missing workflow job ${requiredJob}`,
      );
    }
  }
});

function stableFixture() {
  const run = {
    id: RUN_ID,
    path: ".github/workflows/release.yml",
    event: "push",
    status: "completed",
    conclusion: "failure",
    head_branch: "v0.74.1",
    head_sha: SOURCE_SHA,
    run_number: 140,
    created_at: "2026-08-10T22:28:50Z",
    repository: { id: 1189082766, full_name: REPOSITORY },
    head_repository: { id: 1189082766, full_name: REPOSITORY },
  };
  const jobs = PUBLISH_JOBS.map((name, index) => ({
    id: index + 1,
    name,
    status: "completed",
    conclusion: "success",
    head_sha: SOURCE_SHA,
  }));
  const artifacts = [
    {
      id: 9258360160,
      name: "npm-release-packages",
      expired: false,
      size_in_bytes: 291663482,
      digest: ARTIFACT_DIGEST,
      workflow_run: {
        id: RUN_ID,
        head_sha: SOURCE_SHA,
        repository_id: 1189082766,
        head_repository_id: 1189082766,
      },
    },
  ];
  return {
    repository: REPOSITORY,
    runId: String(RUN_ID),
    version: "0.74.1",
    channel: "stable",
    purpose: "npm-publish",
    run,
    jobs,
    artifacts,
    tagCommitSha: SOURCE_SHA,
  };
}

test("npm recovery accepts a failed release run only after every publish prerequisite succeeded", () => {
  const fixture = stableFixture();

  assert.deepEqual(validateRecoverySource(fixture), {
    artifactId: 9258360160,
    artifactDigest: ARTIFACT_DIGEST,
    sourceSha: SOURCE_SHA,
  });
});

test("stable recovery rejects a source outside the release workflow tag and commit", () => {
  const cases = [
    ["workflow", fixture => (fixture.run.path = ".github/workflows/ci.yml")],
    ["repository", fixture => (fixture.run.head_repository.full_name = "fork/rust-client")],
    ["event", fixture => (fixture.run.event = "schedule")],
    ["tag", fixture => (fixture.run.head_branch = "main")],
    ["commit", fixture => (fixture.tagCommitSha = "f".repeat(40))],
  ];

  for (const [label, mutate] of cases) {
    const fixture = stableFixture();
    mutate(fixture);
    assert.throws(
      () => validateRecoverySource(fixture),
      /workflow|not from|tag/,
      label,
    );
  }
});

test("stable recovery accepts a full release manually dispatched from its exact tag", () => {
  const fixture = stableFixture();
  fixture.run.event = "workflow_dispatch";

  assert.equal(validateRecoverySource(fixture).sourceSha, SOURCE_SHA);
});

test("npm recovery rejects a missing failed duplicate or cross-commit prerequisite job", () => {
  for (const mutation of ["missing", "failed", "duplicate", "cross-commit"]) {
    const fixture = stableFixture();
    const index = fixture.jobs.findIndex(job => job.name === "Smoke npm artifacts (win32-x64)");
    if (mutation === "missing") fixture.jobs.splice(index, 1);
    if (mutation === "failed") fixture.jobs[index].conclusion = "failure";
    if (mutation === "duplicate") fixture.jobs.push({ ...fixture.jobs[index], id: 999 });
    if (mutation === "cross-commit") fixture.jobs[index].head_sha = "f".repeat(40);

    assert.throws(() => validateRecoverySource(fixture), /job/, mutation);
  }
});

test("npm recovery rejects an ambiguous expired empty or mismatched artifact", () => {
  const cases = [
    fixture => fixture.artifacts.push({ ...fixture.artifacts[0], id: 2 }),
    fixture => (fixture.artifacts[0].expired = true),
    fixture => (fixture.artifacts[0].size_in_bytes = 0),
    fixture => (fixture.artifacts[0].digest = "sha256:invalid"),
    fixture => (fixture.artifacts[0].workflow_run.head_sha = "f".repeat(40)),
    fixture => (fixture.artifacts[0].workflow_run.repository_id = 42),
  ];

  for (const mutate of cases) {
    const fixture = stableFixture();
    mutate(fixture);
    assert.throws(() => validateRecoverySource(fixture), /artifact/);
  }
});

test("nightly recovery binds the source date run number branch and short commit", () => {
  const fixture = stableFixture();
  fixture.version = "0.75.0-nightly.20260816.145.226f576";
  fixture.channel = "nightly";
  fixture.tagCommitSha = undefined;
  fixture.run.event = "schedule";
  fixture.run.head_branch = "main";
  fixture.run.run_number = 145;
  fixture.run.created_at = "2026-08-16T04:01:00Z";

  assert.equal(validateRecoverySource(fixture).sourceSha, SOURCE_SHA);

  for (const mutate of [
    value => (value.run.event = "push"),
    value => (value.run.head_branch = "feature"),
    value => (value.run.run_number = 146),
    value => (value.run.created_at = "2026-08-15T04:01:00Z"),
    value => (value.run.head_sha = "f".repeat(40)),
  ]) {
    const invalid = structuredClone(fixture);
    mutate(invalid);
    assert.throws(() => validateRecoverySource(invalid), /nightly source run identity/);
  }
});

test("wrapper recovery requires the original platform publication to have succeeded", () => {
  const fixture = stableFixture();
  fixture.purpose = "wrapper-publish";

  assert.throws(() => validateRecoverySource(fixture), /Publish npm Platform Packages job/);

  fixture.jobs.push({
    id: 100,
    name: "Publish npm Platform Packages",
    status: "completed",
    conclusion: "success",
    head_sha: SOURCE_SHA,
  });
  assert.equal(validateRecoverySource(fixture).artifactId, 9258360160);
});

test("Windows smoke recovery requires the signed package artifact but not prior npm smokes", () => {
  const fixture = stableFixture();
  fixture.purpose = "windows-smoke";
  fixture.jobs = fixture.jobs.filter(job => !job.name.startsWith("Smoke npm artifacts"));
  fixture.jobs = fixture.jobs.filter(
    job =>
      job.name !== "Stage Draft Release" &&
      job.name !== "Publish Smoke-Verified Release" &&
      !job.name.startsWith("Smoke standalone installer"),
  );

  assert.equal(validateRecoverySource(fixture).artifactId, 9258360160);
});

test("recovery rejects run IDs that cannot be represented exactly", () => {
  const fixture = stableFixture();
  fixture.runId = "9007199254740993";

  assert.throws(() => validateRecoverySource(fixture), /positive GitHub Actions run ID/);
});
