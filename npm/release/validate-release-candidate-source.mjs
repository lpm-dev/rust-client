#!/usr/bin/env node

import fs from "node:fs";
import { pathToFileURL } from "node:url";

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function validateReleaseCandidateSource({ repository, runId, version, run, artifacts }) {
  validateInputs({ repository, runId, version });
  if (run?.id !== Number(runId)) throw new Error("candidate run ID mismatch");
  if (run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) {
    throw new Error(`candidate run is not from ${repository}`);
  }
  if (run.path !== ".github/workflows/release.yml") {
    throw new Error("candidate run used an unexpected workflow");
  }
  if (
    run.event !== "workflow_dispatch" ||
    run.head_branch !== "main" ||
    run.status !== "completed" ||
    run.conclusion !== "success"
  ) {
    throw new Error("candidate run must be a successful manual run from main");
  }
  if (!SHA_PATTERN.test(run.head_sha ?? "")) throw new Error("candidate run has an invalid SHA");
  if (
    !Number.isSafeInteger(run.repository?.id) ||
    run.repository.id <= 0 ||
    run.head_repository?.id !== run.repository.id
  ) {
    throw new Error("candidate run has an invalid repository identity");
  }

  const artifactName = `stable-release-candidate-${version}`;
  const matching = artifacts.filter(artifact => artifact?.name === artifactName);
  if (matching.length !== 1) {
    throw new Error(`candidate run must contain exactly one ${artifactName} artifact`);
  }
  const artifact = matching[0];
  if (!Number.isSafeInteger(artifact.id) || artifact.id <= 0) {
    throw new Error("candidate artifact has an invalid ID");
  }
  if (artifact.expired !== false || !Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes <= 0) {
    throw new Error("candidate artifact is expired or empty");
  }
  if (!DIGEST_PATTERN.test(artifact.digest ?? "")) {
    throw new Error("candidate artifact has an invalid digest");
  }
  if (
    artifact.workflow_run?.id !== run.id ||
    artifact.workflow_run?.head_sha !== run.head_sha ||
    artifact.workflow_run?.repository_id !== run.repository.id ||
    artifact.workflow_run?.head_repository_id !== run.repository.id
  ) {
    throw new Error("candidate artifact identity does not match its workflow run");
  }

  return Object.freeze({
    artifactId: artifact.id,
    artifactDigest: artifact.digest,
    sourceSha: run.head_sha,
  });
}

export async function resolveReleaseCandidateSource({
  repository,
  runId,
  version,
  token,
  fetchImpl = fetch,
}) {
  validateInputs({ repository, runId, version });
  if (!token) throw new Error("GH_TOKEN is required");
  const base = `https://api.github.com/repos/${repository}`;
  const run = await githubJson(fetchImpl, token, `${base}/actions/runs/${runId}`);
  const artifacts = await githubCollection(
    fetchImpl,
    token,
    `${base}/actions/runs/${runId}/artifacts`,
    "artifacts",
  );
  const candidate = validateReleaseCandidateSource({ repository, runId, version, run, artifacts });
  const tagResponse = await fetchImpl(`${base}/git/ref/tags/${encodeURIComponent(`v${version}`)}`, {
    headers: githubHeaders(token),
  });
  if (tagResponse.ok) {
    const taggedCommit = await githubJson(
      fetchImpl,
      token,
      `${base}/commits/${encodeURIComponent(`v${version}`)}`,
    );
    if (taggedCommit?.sha !== candidate.sourceSha) {
      throw new Error(`tag v${version} does not resolve to the candidate source commit`);
    }
  } else if (tagResponse.status !== 404) {
    throw new Error(`GitHub tag preflight failed with ${tagResponse.status}`);
  }
  return candidate;
}

function validateInputs({ repository, runId, version }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "")) {
    throw new Error("invalid GitHub repository");
  }
  if (!/^[1-9]\d*$/.test(String(runId)) || !Number.isSafeInteger(Number(runId))) {
    throw new Error("source_run_id must be a positive GitHub Actions run ID");
  }
  if (!VERSION_PATTERN.test(version ?? "")) throw new Error("invalid stable release version");
}

async function githubCollection(fetchImpl, token, endpoint, key) {
  const first = await githubJson(fetchImpl, token, `${endpoint}?per_page=100&page=1`);
  if (!Array.isArray(first[key]) || !Number.isSafeInteger(first.total_count)) {
    throw new Error(`GitHub returned an invalid ${key} response`);
  }
  const values = [...first[key]];
  const pages = Math.ceil(first.total_count / 100);
  for (let page = 2; page <= pages; page += 1) {
    const response = await githubJson(fetchImpl, token, `${endpoint}?per_page=100&page=${page}`);
    if (!Array.isArray(response[key])) throw new Error(`GitHub returned an invalid ${key} page`);
    values.push(...response[key]);
  }
  if (values.length !== first.total_count) throw new Error(`GitHub ${key} pagination is incomplete`);
  return values;
}

async function githubJson(fetchImpl, token, endpoint) {
  const response = await fetchImpl(endpoint, { headers: githubHeaders(token) });
  if (!response.ok) throw new Error(`GitHub API request failed with ${response.status}: ${endpoint}`);
  return response.json();
}

function githubHeaders(token) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "User-Agent": "lpm-release-candidate-validator",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) throw new Error("invalid arguments");
    options[name.slice(2)] = value;
  }
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const result = await resolveReleaseCandidateSource({
    repository: options.repository,
    runId: options["run-id"],
    version: options.version,
    token: process.env.GH_TOKEN,
  });
  if (options["github-output"]) {
    fs.appendFileSync(
      options["github-output"],
      `artifact_id=${result.artifactId}\nartifact_digest=${result.artifactDigest}\nsource_sha=${result.sourceSha}\n`,
    );
  } else {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
