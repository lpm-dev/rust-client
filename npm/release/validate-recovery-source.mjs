#!/usr/bin/env node

import fs from "node:fs";
import { fileURLToPath } from "node:url";

const STABLE_VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const NIGHTLY_VERSION_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.0-nightly\.(\d{8})\.([1-9]\d*)\.([0-9a-f]{7}|g0\d{6})$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const RELEASE_WORKFLOW_PATH = ".github/workflows/release.yml";
const RELEASE_ARTIFACT_NAME = "npm-release-packages";

const BUILD_JOBS = [
  "Build aarch64-apple-darwin",
  "Build aarch64-unknown-linux-gnu",
  "Build x86_64-apple-darwin",
  "Build x86_64-pc-windows-msvc",
  "Build x86_64-unknown-linux-gnu",
  "Build x86_64-unknown-linux-musl",
];

const NPM_SMOKE_JOBS = [
  "Smoke npm artifacts (darwin-arm64)",
  "Smoke npm artifacts (darwin-x64)",
  "Smoke npm artifacts (linux-arm64)",
  "Smoke npm artifacts (linux-x64)",
  "Smoke npm artifacts (linux-x64-musl)",
  "Smoke npm artifacts (win32-x64)",
];

const COMMON_REQUIRED_JOBS = [
  "Resolve release metadata",
  "Release verification",
  "verify-windows-filesystem / Windows filesystem release gate",
  ...BUILD_JOBS,
  "Pack exact npm release artifacts",
];

const PUBLISH_REQUIRED_JOBS = [
  ...COMMON_REQUIRED_JOBS,
  ...NPM_SMOKE_JOBS,
  "Create Release",
  "Smoke standalone installer on Debian 12 (arm64)",
  "Smoke standalone installer on Debian 12 (x64)",
];

const REQUIRED_JOBS = Object.freeze({
  "npm-publish": PUBLISH_REQUIRED_JOBS,
  "windows-smoke": COMMON_REQUIRED_JOBS,
  "wrapper-publish": [...PUBLISH_REQUIRED_JOBS, "Publish npm Platform Packages"],
});

export function validateRecoverySource({
  repository,
  runId,
  version,
  channel,
  purpose,
  run,
  jobs,
  artifacts,
  tagCommitSha,
}) {
  validateInputs({ repository, runId, version, channel, purpose });
  if (!run || typeof run !== "object") throw new Error("source run response is missing");
  if (run.id !== Number(runId)) {
    throw new Error(`source run ID mismatch: expected ${runId}, got ${run.id}`);
  }
  if (run.repository?.full_name !== repository || run.head_repository?.full_name !== repository) {
    throw new Error(`source run is not from ${repository}`);
  }
  if (run.path !== RELEASE_WORKFLOW_PATH) {
    throw new Error(`source run used ${run.path ?? "an unknown workflow"}, not ${RELEASE_WORKFLOW_PATH}`);
  }
  if (run.status !== "completed") {
    throw new Error(`source run is not completed: ${run.status ?? "unknown"}`);
  }
  if (!SHA_PATTERN.test(run.head_sha ?? "")) {
    throw new Error("source run has an invalid head SHA");
  }
  if (
    !Number.isSafeInteger(run.repository?.id) ||
    run.repository.id <= 0 ||
    run.head_repository?.id !== run.repository.id
  ) {
    throw new Error("source run has an invalid repository identity");
  }

  validateVersionIdentity({ version, channel, run, tagCommitSha });
  validateRequiredJobs({ jobs, purpose, headSha: run.head_sha });

  const matchingArtifacts = artifacts.filter(artifact => artifact?.name === RELEASE_ARTIFACT_NAME);
  if (matchingArtifacts.length !== 1) {
    throw new Error(
      `source run must contain exactly one ${RELEASE_ARTIFACT_NAME} artifact, found ${matchingArtifacts.length}`,
    );
  }
  const artifact = matchingArtifacts[0];
  if (!Number.isSafeInteger(artifact.id) || artifact.id <= 0) {
    throw new Error("release artifact has an invalid ID");
  }
  if (artifact.expired !== false) throw new Error("release artifact is expired");
  if (!Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes <= 0) {
    throw new Error("release artifact is empty or has an invalid size");
  }
  if (!DIGEST_PATTERN.test(artifact.digest ?? "")) {
    throw new Error("release artifact has an invalid SHA-256 digest");
  }
  if (
    artifact.workflow_run?.id !== run.id ||
    artifact.workflow_run?.head_sha !== run.head_sha ||
    artifact.workflow_run?.repository_id !== run.repository.id ||
    artifact.workflow_run?.head_repository_id !== run.repository.id
  ) {
    throw new Error("release artifact identity does not match the validated source run");
  }

  return Object.freeze({
    artifactId: artifact.id,
    artifactDigest: artifact.digest,
    sourceSha: run.head_sha,
  });
}

export async function resolveRecoverySource({
  repository,
  runId,
  version,
  channel,
  purpose,
  token,
  fetchImpl = fetch,
}) {
  validateInputs({ repository, runId, version, channel, purpose });
  if (!token) throw new Error("GH_TOKEN is required");

  const base = `https://api.github.com/repos/${repository}`;
  const run = await githubJson(fetchImpl, token, `${base}/actions/runs/${runId}`);
  const jobs = await githubCollection(fetchImpl, token, `${base}/actions/runs/${runId}/jobs`, "jobs");
  const artifacts = await githubCollection(
    fetchImpl,
    token,
    `${base}/actions/runs/${runId}/artifacts`,
    "artifacts",
  );
  const tagCommit =
    channel === "stable"
      ? await githubJson(fetchImpl, token, `${base}/commits/${encodeURIComponent(`v${version}`)}`)
      : undefined;

  return validateRecoverySource({
    repository,
    runId,
    version,
    channel,
    purpose,
    run,
    jobs,
    artifacts,
    tagCommitSha: tagCommit?.sha,
  });
}

function validateInputs({ repository, runId, version, channel, purpose }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "")) {
    throw new Error(`invalid GitHub repository: ${repository ?? ""}`);
  }
  const numericRunId = Number(runId);
  if (!/^[1-9]\d*$/.test(String(runId)) || !Number.isSafeInteger(numericRunId)) {
    throw new Error("source_run_id must be a positive GitHub Actions run ID");
  }
  if (channel !== "stable" && channel !== "nightly") {
    throw new Error(`invalid release channel: ${channel ?? ""}`);
  }
  if (!Object.hasOwn(REQUIRED_JOBS, purpose)) {
    throw new Error(`invalid recovery purpose: ${purpose ?? ""}`);
  }
  const pattern = channel === "stable" ? STABLE_VERSION_PATTERN : NIGHTLY_VERSION_PATTERN;
  if (!pattern.test(version ?? "")) {
    throw new Error(`invalid ${channel} release version: ${version ?? ""}`);
  }
}

function validateVersionIdentity({ version, channel, run, tagCommitSha }) {
  if (channel === "stable") {
    if (
      (run.event !== "push" && run.event !== "workflow_dispatch") ||
      run.head_branch !== `v${version}`
    ) {
      throw new Error(`stable source run must use the v${version} tag`);
    }
    if (!SHA_PATTERN.test(tagCommitSha ?? "") || tagCommitSha !== run.head_sha) {
      throw new Error(`stable source run SHA does not match the v${version} tag`);
    }
    return;
  }

  const match = NIGHTLY_VERSION_PATTERN.exec(version);
  const expectedDate = run.created_at?.slice(0, 10).replaceAll("-", "");
  const expectedSha = match[5].startsWith("g") ? match[5].slice(1) : match[5];
  if (
    (run.event !== "schedule" && run.event !== "workflow_dispatch") ||
    run.head_branch !== "main" ||
    String(run.run_number) !== match[4] ||
    expectedDate !== match[3] ||
    !run.head_sha.startsWith(expectedSha)
  ) {
    throw new Error("nightly source run identity does not match the requested version");
  }
}

function validateRequiredJobs({ jobs, purpose, headSha }) {
  if (!Array.isArray(jobs)) throw new Error("source run jobs response is invalid");
  const jobsByName = new Map();
  for (const job of jobs) {
    const existing = jobsByName.get(job?.name) ?? [];
    existing.push(job);
    jobsByName.set(job?.name, existing);
  }
  for (const name of REQUIRED_JOBS[purpose]) {
    const matches = jobsByName.get(name) ?? [];
    if (matches.length !== 1) {
      throw new Error(`source run must contain exactly one ${name} job, found ${matches.length}`);
    }
    const job = matches[0];
    if (job.status !== "completed" || job.conclusion !== "success" || job.head_sha !== headSha) {
      throw new Error(`source run job did not succeed for the validated SHA: ${name}`);
    }
  }
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
  if (values.length !== first.total_count) {
    throw new Error(`GitHub ${key} pagination returned ${values.length} of ${first.total_count} entries`);
  }
  return values;
}

async function githubJson(fetchImpl, token, endpoint) {
  const response = await fetchImpl(endpoint, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "lpm-release-recovery-validator",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) {
    throw new Error(`GitHub API request failed with ${response.status}: ${endpoint}`);
  }
  return response.json();
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument sequence at ${name ?? "<end>"}`);
    }
    options[name.slice(2)] = value;
  }
  for (const required of [
    "repository",
    "run-id",
    "version",
    "channel",
    "purpose",
    "github-output",
  ]) {
    if (!options[required]) throw new Error(`--${required} is required`);
  }
  return options;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = await resolveRecoverySource({
      repository: options.repository,
      runId: options["run-id"],
      version: options.version,
      channel: options.channel,
      purpose: options.purpose,
      token: process.env.GH_TOKEN,
    });
    fs.appendFileSync(
      options["github-output"],
      `artifact_id=${result.artifactId}\nartifact_digest=${result.artifactDigest}\nsource_sha=${result.sourceSha}\n`,
    );
  } catch (error) {
    console.error(`validate-recovery-source: ${error.message}`);
    process.exit(1);
  }
}
