import assert from "node:assert/strict";
import test from "node:test";

import {
  resolveReleaseCandidateSource,
  validateReleaseCandidateSource,
} from "../validate-release-candidate-source.mjs";

const RUN_ID = 33150000000;
const SHA = "a".repeat(40);
const REPOSITORY_ID = 1189082766;

function fixture() {
  const run = {
    id: RUN_ID,
    path: ".github/workflows/release.yml",
    event: "workflow_dispatch",
    head_branch: "main",
    head_sha: SHA,
    status: "completed",
    conclusion: "success",
    repository: { id: REPOSITORY_ID, full_name: "lpm-dev/rust-client" },
    head_repository: { id: REPOSITORY_ID, full_name: "lpm-dev/rust-client" },
  };
  const artifacts = [{
    id: 42,
    name: "stable-release-candidate-0.76.6",
    expired: false,
    size_in_bytes: 1024,
    digest: `sha256:${"b".repeat(64)}`,
    workflow_run: {
      id: RUN_ID,
      head_sha: SHA,
      repository_id: REPOSITORY_ID,
      head_repository_id: REPOSITORY_ID,
    },
  }];
  return {
    repository: "lpm-dev/rust-client",
    runId: String(RUN_ID),
    version: "0.76.6",
    run,
    artifacts,
  };
}

test("promotion accepts one successful same-repository candidate from main", () => {
  assert.deepEqual(validateReleaseCandidateSource(fixture()), {
    artifactId: 42,
    artifactDigest: `sha256:${"b".repeat(64)}`,
    sourceSha: SHA,
  });
});

test("promotion rejects untrusted run identities", () => {
  for (const mutate of [
    value => (value.run.path = ".github/workflows/ci.yml"),
    value => (value.run.event = "push"),
    value => (value.run.head_branch = "feature"),
    value => (value.run.conclusion = "failure"),
    value => (value.run.head_repository.full_name = "attacker/fork"),
  ]) {
    const value = fixture();
    mutate(value);
    assert.throws(() => validateReleaseCandidateSource(value), /workflow|successful|not from/);
  }
});

test("promotion rejects ambiguous expired empty and cross-run artifacts", () => {
  for (const mutate of [
    value => value.artifacts.push({ ...value.artifacts[0], id: 43 }),
    value => (value.artifacts[0].expired = true),
    value => (value.artifacts[0].size_in_bytes = 0),
    value => (value.artifacts[0].digest = "invalid"),
    value => (value.artifacts[0].workflow_run.head_sha = "c".repeat(40)),
  ]) {
    const value = fixture();
    mutate(value);
    assert.throws(() => validateReleaseCandidateSource(value), /candidate artifact|exactly one/);
  }
});

test("promotion source resolution accepts an absent tag or the exact candidate tag", async () => {
  for (const tagSha of [null, SHA]) {
    const value = fixture();
    const result = await resolveReleaseCandidateSource({
      repository: value.repository,
      runId: value.runId,
      version: value.version,
      token: "token",
      fetchImpl: candidateFetch(value, tagSha),
    });
    assert.equal(result.sourceSha, SHA);
  }
});

test("promotion source resolution rejects a tag at a different commit", async () => {
  const value = fixture();
  await assert.rejects(
    resolveReleaseCandidateSource({
      repository: value.repository,
      runId: value.runId,
      version: value.version,
      token: "token",
      fetchImpl: candidateFetch(value, "c".repeat(40)),
    }),
    /does not resolve to the candidate source commit/,
  );
});

function candidateFetch(value, tagSha) {
  return async url => {
    const endpoint = String(url);
    if (endpoint.endsWith(`/actions/runs/${value.runId}`)) return jsonResponse(value.run);
    if (endpoint.includes(`/actions/runs/${value.runId}/artifacts?`)) {
      return jsonResponse({ total_count: value.artifacts.length, artifacts: value.artifacts });
    }
    if (endpoint.includes("/git/ref/tags/")) {
      return tagSha === null ? new Response("not found", { status: 404 }) : jsonResponse({});
    }
    if (endpoint.includes("/commits/")) return jsonResponse({ sha: tagSha });
    throw new Error(`unexpected test request: ${endpoint}`);
  };
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
