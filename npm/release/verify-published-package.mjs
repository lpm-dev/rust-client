#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseReleaseVersion } from "./release-artifacts.mjs";

const REGISTRY_ORIGIN = "https://registry.npmjs.org";
const MANIFEST_LIMIT = 1024 * 1024;
const PACKUMENT_LIMIT = 8 * 1024 * 1024;
const ATTESTATION_LIMIT = 2 * 1024 * 1024;
const NPM_AUDIT_OUTPUT_LIMIT = 8 * 1024 * 1024;
const TARBALL_LIMIT = 500 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;
const NPM_CLI_VERSION = "11.12.1";
const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const IN_TOTO_PUBLISH_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1";
const IN_TOTO_PROVENANCE_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PUBLISH_PREDICATE = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";
const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
const RELEASE_REPOSITORY = "https://github.com/lpm-dev/rust-client";
const RELEASE_WORKFLOW = ".github/workflows/release.yml";
const RELEASE_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1";
const RELEASE_BUILDER = "https://github.com/actions/runner/github-hosted";
const RELEASE_REPOSITORY_ID = "1189082766";
const RELEASE_OWNER_ID = "261638357";
const ARGUMENT_NAMES = Object.freeze([
  "manifest",
  "package",
  "tag",
  "source-sha",
  "source-run-id",
  "source-ref",
  "tarball",
]);
const REQUIRED_ARGUMENT_NAMES = Object.freeze(ARGUMENT_NAMES.filter(name => name !== "source-ref"));

export async function verifyPublishedPackage({
  releaseManifest,
  packageName,
  expectedTag,
  expectedSourceRunId,
  expectedSourceSha,
  expectedSourceRef,
  fetchImpl = fetch,
  githubFetchImpl = fetch,
  githubToken = process.env.GH_TOKEN,
  tarballPath,
  verifySignaturesImpl = verifyNpmSignatures,
  verifySourceRunImpl = verifyGitHubSourceRun,
  verifyTarballImpl = verifyLocalTarball,
}) {
  assertPlainObject(releaseManifest, "release manifest");
  const version = parseReleaseVersion(releaseManifest.version);
  if (expectedTag !== "latest" && expectedTag !== "nightly") {
    throw new Error(`The npm dist-tag is not supported: ${format(expectedTag)}`);
  }
  assertLowerHex(expectedSourceSha, 40, "release source SHA");
  const defaultSourceRef = expectedTag === "latest" ? `refs/tags/v${version}` : "refs/heads/main";
  const sourceRef = expectedSourceRef ?? defaultSourceRef;
  if (
    sourceRef !== "refs/heads/main" &&
    !(expectedTag === "latest" && sourceRef === `refs/tags/v${version}`)
  ) {
    throw new Error(`The release source ref is not valid: ${format(sourceRef)}`);
  }
  const sourceRunId = String(expectedSourceRunId ?? "");
  if (
    sourceRunId !== "trusted" &&
    (!/^[1-9]\d*$/.test(sourceRunId) || !Number.isSafeInteger(Number(sourceRunId)))
  ) {
    throw new Error("The release source run ID is not valid");
  }
  if (!Array.isArray(releaseManifest.packages)) {
    throw new Error("The release manifest packages value must be an array");
  }

  const records = releaseManifest.packages.filter(record => record?.name === packageName);
  if (records.length !== 1) {
    throw new Error(`The release manifest must contain one record for ${packageName}`);
  }
  const record = records[0];
  assertPlainObject(record, `release record for ${packageName}`);
  if (record.version !== version) {
    throw new Error(`The release record version does not match for ${packageName}`);
  }
  assertLowerHex(record.shasum, 40, `SHA-1 shasum for ${packageName}`);
  assertLowerHex(record.sha256, 64, `SHA-256 digest for ${packageName}`);
  const expectedSha512 = integritySha512Hex(record.integrity, packageName);
  await verifyTarballImpl({ tarballPath, record, packageName });

  const encodedPackage = encodeURIComponent(packageName);
  const packument = await registryJson(
    fetchImpl,
    `${REGISTRY_ORIGIN}/${encodedPackage}`,
    PACKUMENT_LIMIT,
    `npm package metadata for ${packageName}`,
  );
  validateRegistryVersion({
    packument,
    packageName,
    version,
    expectedTag,
    record,
  });

  const attestations = await verifySignaturesImpl({ packageName, version });
  const sourceRun = validateAttestations({
    document: attestations,
    packageName,
    version,
    expectedTag,
    expectedSha512,
    expectedSourceRunId: sourceRunId,
    expectedSourceSha,
    expectedSourceRef: sourceRef,
  });
  if (sourceRunId === "trusted") {
    await verifySourceRunImpl({
      expectedSourceSha,
      fetchImpl: githubFetchImpl,
      runAttempt: sourceRun.runAttempt,
      runId: sourceRun.runId,
      token: githubToken,
    });
  }

  return Object.freeze({ packageName, version, tag: expectedTag });
}

export async function verifyGitHubSourceRun({
  expectedSourceSha,
  fetchImpl = fetch,
  runAttempt,
  runId,
  token = process.env.GH_TOKEN,
}) {
  if (
    !/^[1-9]\d*$/.test(String(runId)) ||
    !Number.isSafeInteger(Number(runId)) ||
    !/^[1-9]\d*$/.test(String(runAttempt)) ||
    !Number.isSafeInteger(Number(runAttempt))
  ) {
    throw new Error("The attested GitHub Actions invocation is not valid");
  }
  assertLowerHex(expectedSourceSha, 40, "release source SHA");
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("GH_TOKEN is required to verify a prior npm publication run");
  }
  const run = await registryJson(
    fetchImpl,
    `https://api.github.com/repos/lpm-dev/rust-client/actions/runs/${runId}/attempts/${runAttempt}`,
    1024 * 1024,
    "GitHub Actions source run",
    {
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  );
  if (
    run?.id !== Number(runId) ||
    run?.run_attempt !== Number(runAttempt) ||
    run?.path !== RELEASE_WORKFLOW ||
    run?.event !== "workflow_dispatch" ||
    run?.head_branch !== "main" ||
    run?.head_sha !== expectedSourceSha ||
    run?.status !== "completed" ||
    typeof run?.conclusion !== "string" ||
    run.repository?.full_name !== "lpm-dev/rust-client" ||
    String(run.repository?.id) !== RELEASE_REPOSITORY_ID ||
    run.head_repository?.full_name !== "lpm-dev/rust-client" ||
    String(run.head_repository?.id) !== RELEASE_REPOSITORY_ID
  ) {
    throw new Error("The attested npm publication run is not a trusted release invocation");
  }
}

export function verifyLocalTarball({ tarballPath, record, packageName }) {
  if (typeof tarballPath !== "string" || tarballPath.length === 0) {
    throw new Error(`The local tarball path is missing for ${packageName}`);
  }
  const metadata = fs.lstatSync(tarballPath, { throwIfNoEntry: false });
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`The local tarball is missing or is not a regular file for ${packageName}`);
  }
  if (metadata.size > TARBALL_LIMIT) {
    throw new Error(`The local tarball is too large for ${packageName}`);
  }

  const descriptor = fs.openSync(tarballPath, "r");
  const sha1 = crypto.createHash("sha1");
  const sha256 = crypto.createHash("sha256");
  const sha512 = crypto.createHash("sha512");
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let total = 0;
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.size !== metadata.size) {
      throw new Error(`The local tarball changed before verification for ${packageName}`);
    }
    for (;;) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > TARBALL_LIMIT) {
        throw new Error(`The local tarball is too large for ${packageName}`);
      }
      const chunk = buffer.subarray(0, bytesRead);
      sha1.update(chunk);
      sha256.update(chunk);
      sha512.update(chunk);
    }
    if (total !== metadata.size || fs.fstatSync(descriptor).size !== metadata.size) {
      throw new Error(`The local tarball changed during verification for ${packageName}`);
    }
  } finally {
    fs.closeSync(descriptor);
  }

  const actualShasum = sha1.digest("hex");
  const actualSha256 = sha256.digest("hex");
  const actualIntegrity = `sha512-${sha512.digest("base64")}`;
  if (
    actualShasum !== record.shasum ||
    actualSha256 !== record.sha256 ||
    actualIntegrity !== record.integrity
  ) {
    throw new Error(`The local tarball digests do not match for ${packageName}`);
  }
  return Object.freeze({ shasum: actualShasum, sha256: actualSha256, integrity: actualIntegrity });
}

export function verifyNpmSignatures({
  packageName,
  version,
  spawnImpl = spawnSync,
  npmCliPath = trustedNpmCliPath(),
}) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-npm-signatures-"));
  const cache = path.join(workspace, "cache");
  const userNpmrc = path.join(workspace, "user.npmrc");
  const globalNpmrc = path.join(workspace, "global.npmrc");
  fs.writeFileSync(
    path.join(workspace, "package.json"),
    `${JSON.stringify({ name: "lpm-publication-verification", version: "1.0.0", private: true })}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(userNpmrc, "", { mode: 0o600 });
  fs.writeFileSync(globalNpmrc, "", { mode: 0o600 });

  try {
    runPinnedNpm(
      spawnImpl,
      workspace,
      userNpmrc,
      globalNpmrc,
      npmCliPath,
      [
        "install",
        "--prefix",
        workspace,
        "--cache",
        cache,
        "--ignore-scripts",
        "--force",
        "--no-audit",
        "--no-fund",
        "--omit=optional",
        "--save-exact",
        `--registry=${REGISTRY_ORIGIN}`,
        "--",
        `${packageName}@${version}`,
      ],
      `installation for signature verification of ${packageName}@${version}`,
    );
    const stdout = runPinnedNpm(
      spawnImpl,
      workspace,
      userNpmrc,
      globalNpmrc,
      npmCliPath,
      [
        "audit",
        "signatures",
        "--prefix",
        workspace,
        "--cache",
        cache,
        "--json",
        "--include-attestations",
        `--registry=${REGISTRY_ORIGIN}`,
      ],
      `signature verification of ${packageName}@${version}`,
    );
    const report = parseJson(stdout, `npm signature report for ${packageName}@${version}`);
    if (
      !Array.isArray(report.invalid) ||
      report.invalid.length !== 0 ||
      !Array.isArray(report.missing) ||
      report.missing.length !== 0 ||
      !Array.isArray(report.verified) ||
      report.verified.length !== 1
    ) {
      throw new Error(`npm did not verify every signature for ${packageName}@${version}`);
    }
    const matches = report.verified.filter(
      entry =>
        entry?.name === packageName &&
        entry?.version === version &&
        entry?.registry === `${REGISTRY_ORIGIN}/`,
    );
    if (matches.length !== 1 || !Array.isArray(matches[0].attestationBundles)) {
      throw new Error(`npm did not verify the expected package ${packageName}@${version}`);
    }
    return Object.freeze({ attestations: matches[0].attestationBundles });
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

function runPinnedNpm(
  spawnImpl,
  workspace,
  userNpmrc,
  globalNpmrc,
  npmCliPath,
  args,
  label,
) {
  const result = spawnImpl(process.execPath, [npmCliPath, ...args], {
    cwd: workspace,
    encoding: "utf8",
    env: npmVerificationEnvironment(workspace, userNpmrc, globalNpmrc),
    maxBuffer: NPM_AUDIT_OUTPUT_LIMIT,
    windowsHide: true,
  });
  if (result.error) {
    throw new Error(`The npm ${label} command failed`, { cause: result.error });
  }
  if (result.status !== 0) {
    throw new Error(`The npm ${label} command exited with status ${result.status ?? "unknown"}`);
  }
  if (typeof result.stdout !== "string" || Buffer.byteLength(result.stdout) > NPM_AUDIT_OUTPUT_LIMIT) {
    throw new Error(`The npm ${label} output is not valid`);
  }
  return result.stdout;
}

function npmVerificationEnvironment(workspace, userNpmrc, globalNpmrc) {
  const env = {
    HOME: workspace,
    NO_COLOR: "1",
    PATH: path.dirname(process.execPath),
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_CACHE: path.join(workspace, "cache"),
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_GLOBALCONFIG: globalNpmrc,
    NPM_CONFIG_IGNORE_SCRIPTS: "true",
    NPM_CONFIG_REGISTRY: REGISTRY_ORIGIN,
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
    NPM_CONFIG_USERCONFIG: userNpmrc,
  };
  if (process.platform === "win32") {
    for (const key of ["COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR"]) {
      if (process.env[key]) env[key] = process.env[key];
    }
    env.USERPROFILE = workspace;
  }
  return env;
}

function trustedNpmCliPath() {
  const nodePrefix = process.platform === "win32"
    ? path.dirname(process.execPath)
    : path.dirname(path.dirname(process.execPath));
  const npmRoot = process.platform === "win32"
    ? path.join(nodePrefix, "node_modules", "npm")
    : path.join(nodePrefix, "lib", "node_modules", "npm");
  const npmCli = path.join(npmRoot, "bin", "npm-cli.js");
  const packageJson = path.join(npmRoot, "package.json");
  const cliMetadata = fs.lstatSync(npmCli, { throwIfNoEntry: false });
  if (!cliMetadata?.isFile() || cliMetadata.isSymbolicLink()) {
    throw new Error(`The trusted npm ${NPM_CLI_VERSION} entrypoint is unavailable`);
  }
  const manifest = JSON.parse(
    readBoundedRegularFile(packageJson, 1024 * 1024, "trusted npm package manifest").toString("utf8"),
  );
  if (manifest?.version !== NPM_CLI_VERSION) {
    throw new Error(
      `The trusted npm entrypoint has version ${format(manifest?.version)}, expected ${NPM_CLI_VERSION}`,
    );
  }
  return npmCli;
}

function validateRegistryVersion({ packument, packageName, version, expectedTag, record }) {
  assertPlainObject(packument, `npm package metadata for ${packageName}`);
  const versionMetadata = packument.versions?.[version];
  assertPlainObject(versionMetadata, `npm version metadata for ${packageName}@${version}`);
  assertPlainObject(versionMetadata.dist, `npm distribution metadata for ${packageName}@${version}`);
  if (versionMetadata.name !== packageName || versionMetadata.version !== version) {
    throw new Error(`The npm version identity does not match for ${packageName}@${version}`);
  }
  if (versionMetadata.dist.shasum !== record.shasum) {
    throw new Error(`The published SHA-1 shasum does not match for ${packageName}@${version}`);
  }
  if (versionMetadata.dist.integrity !== record.integrity) {
    throw new Error(`The published SHA-512 integrity does not match for ${packageName}@${version}`);
  }
  if (packument["dist-tags"]?.[expectedTag] !== version) {
    throw new Error(`The npm ${expectedTag} dist-tag does not select ${packageName}@${version}`);
  }
  if (versionMetadata.dist.attestations?.provenance?.predicateType !== PROVENANCE_PREDICATE) {
    throw new Error(`The npm metadata has no SLSA provenance for ${packageName}@${version}`);
  }
}

function validateAttestations({
  document,
  packageName,
  version,
  expectedTag,
  expectedSha512,
  expectedSourceRunId,
  expectedSourceSha,
  expectedSourceRef,
}) {
  assertPlainObject(document, `npm attestations for ${packageName}@${version}`);
  if (!Array.isArray(document.attestations)) {
    throw new Error(`The npm attestation response is not valid for ${packageName}@${version}`);
  }

  const statements = new Map();
  for (const predicateType of [PUBLISH_PREDICATE, PROVENANCE_PREDICATE]) {
    const matches = document.attestations.filter(entry => entry?.predicateType === predicateType);
    if (matches.length !== 1) {
      throw new Error(
        `The npm attestation response must contain one ${predicateType} statement for ${packageName}@${version}`,
      );
    }
    statements.set(
      predicateType,
      decodeAttestationStatement(matches[0], packageName, version, expectedSha512),
    );
  }

  const publish = statements.get(PUBLISH_PREDICATE);
  if (
    publish.predicate?.name !== packageName ||
    publish.predicate?.version !== version ||
    publish.predicate?.registry !== REGISTRY_ORIGIN
  ) {
    throw new Error(`The npm publication attestation identity does not match ${packageName}@${version}`);
  }

  const provenance = statements.get(PROVENANCE_PREDICATE);
  const build = provenance.predicate?.buildDefinition;
  const workflow = build?.externalParameters?.workflow;
  if (
    workflow?.repository !== RELEASE_REPOSITORY ||
    workflow?.path !== RELEASE_WORKFLOW ||
    workflow?.ref !== expectedSourceRef
  ) {
    throw new Error(`The npm provenance workflow does not match ${packageName}@${version}`);
  }

  const github = build.internalParameters?.github;
  const eventMatches = expectedSourceRef === "refs/heads/main"
    ? expectedTag === "latest"
      ? github?.event_name === "workflow_dispatch"
      : github?.event_name === "schedule" || github?.event_name === "workflow_dispatch"
    : github?.event_name === "push" || github?.event_name === "workflow_dispatch";
  const dependencies = build.resolvedDependencies;
  const expectedDependencyUri = `git+${RELEASE_REPOSITORY}@${expectedSourceRef}`;
  const invocationId = provenance.predicate?.runDetails?.metadata?.invocationId;
  const invocationRun = expectedSourceRunId === "trusted" ? "([1-9]\\d*)" : `(${expectedSourceRunId})`;
  const invocationPattern = new RegExp(
    `^${escapeRegExp(RELEASE_REPOSITORY)}/actions/runs/${invocationRun}/attempts/([1-9]\\d*)$`,
  );
  const invocationMatch = typeof invocationId === "string" ? invocationId.match(invocationPattern) : null;
  if (
    build.buildType !== RELEASE_BUILD_TYPE ||
    !eventMatches ||
    github.repository_id !== RELEASE_REPOSITORY_ID ||
    github.repository_owner_id !== RELEASE_OWNER_ID ||
    !Array.isArray(dependencies) ||
    dependencies.length !== 1 ||
    dependencies[0]?.uri !== expectedDependencyUri ||
    dependencies[0]?.digest?.gitCommit !== expectedSourceSha ||
    provenance.predicate?.runDetails?.builder?.id !== RELEASE_BUILDER ||
    invocationMatch === null
  ) {
    throw new Error(`The npm provenance source does not match ${packageName}@${version}`);
  }
  return Object.freeze({ runId: invocationMatch[1], runAttempt: invocationMatch[2] });
}

function decodeAttestationStatement(attestation, packageName, version, expectedSha512) {
  assertPlainObject(attestation, `npm attestation for ${packageName}@${version}`);
  assertPlainObject(attestation.bundle, `Sigstore bundle for ${packageName}@${version}`);
  const envelope = attestation.bundle.dsseEnvelope;
  assertPlainObject(envelope, `DSSE envelope for ${packageName}@${version}`);
  if (envelope.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    throw new Error(`The npm attestation payload type is not valid for ${packageName}@${version}`);
  }

  const material = attestation.bundle.verificationMaterial;
  assertPlainObject(material, `verification material for ${packageName}@${version}`);
  if (!Array.isArray(material.tlogEntries) || material.tlogEntries.length === 0) {
    throw new Error(`The npm attestation has no transparency-log entry for ${packageName}@${version}`);
  }
  if (attestation.predicateType === PROVENANCE_PREDICATE) {
    if (typeof material.certificate?.rawBytes !== "string" || material.certificate.rawBytes === "") {
      throw new Error(`The npm provenance has no signing certificate for ${packageName}@${version}`);
    }
  } else if (typeof material.publicKey?.hint !== "string" || material.publicKey.hint === "") {
    throw new Error(`The npm publication attestation has no signing key for ${packageName}@${version}`);
  }

  const payload = decodeBase64Json(envelope.payload, `attestation payload for ${packageName}@${version}`);
  const expectedStatementType =
    attestation.predicateType === PUBLISH_PREDICATE
      ? IN_TOTO_PUBLISH_STATEMENT_TYPE
      : IN_TOTO_PROVENANCE_STATEMENT_TYPE;
  if (payload._type !== expectedStatementType || payload.predicateType !== attestation.predicateType) {
    throw new Error(`The npm attestation statement is not valid for ${packageName}@${version}`);
  }
  const expectedSubject = npmPurl(packageName, version);
  if (
    !Array.isArray(payload.subject) ||
    payload.subject.length !== 1 ||
    payload.subject[0]?.name !== expectedSubject ||
    payload.subject[0]?.digest?.sha512 !== expectedSha512
  ) {
    throw new Error(`The npm attestation subject does not match ${packageName}@${version}`);
  }
  return payload;
}

async function registryJson(fetchImpl, url, maximumBytes, label, extraHeaders = {}) {
  let response;
  try {
    response = await fetchImpl(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "lpm-release-publication-verifier",
        ...extraHeaders,
      },
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    throw new Error(`The ${label} request failed`, { cause: error });
  }
  if (!response?.ok) {
    throw new Error(`The ${label} request returned HTTP ${response?.status ?? "unknown"}`);
  }

  const contentLength = Number(response.headers?.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
    throw new Error(`The ${label} response is too large`);
  }
  if (!response.body?.getReader) {
    throw new Error(`The ${label} response has no body`);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        throw new Error(`The ${label} response is too large`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }

  try {
    return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
  } catch (error) {
    throw new Error(`The ${label} response is not valid JSON`, { cause: error });
  }
}

function integritySha512Hex(integrity, packageName) {
  if (typeof integrity !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity)) {
    throw new Error(`The SHA-512 integrity is not valid for ${packageName}`);
  }
  const encoded = integrity.slice("sha512-".length);
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== encoded) {
    throw new Error(`The SHA-512 integrity is not canonical for ${packageName}`);
  }
  return bytes.toString("hex");
}

function decodeBase64Json(value, label) {
  if (typeof value !== "string" || value.length > ATTESTATION_LIMIT * 2 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`The ${label} is not valid base64`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > ATTESTATION_LIMIT || bytes.toString("base64") !== value) {
    throw new Error(`The ${label} is not canonical base64`);
  }
  return parseJson(bytes.toString("utf8"), label);
}

function parseJson(value, label) {
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`The ${label} is not valid JSON`, { cause: error });
  }
}

function npmPurl(packageName, version) {
  const encodedName = packageName.startsWith("@") ? `%40${packageName.slice(1)}` : packageName;
  return `pkg:npm/${encodedName}@${version}`;
}

export function readManifest(file) {
  const bytes = readBoundedRegularFile(file, MANIFEST_LIMIT, "release manifest");
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`The release manifest is not valid JSON: ${file}`, { cause: error });
  }
}

function readBoundedRegularFile(file, limit, label) {
  const before = fs.lstatSync(file, { throwIfNoEntry: false });
  if (!before?.isFile() || before.isSymbolicLink()) {
    throw new Error(`The ${label} is missing or is not a regular file: ${file}`);
  }
  if (before.size > limit) {
    throw new Error(`The ${label} is too large: ${file}`);
  }

  let flags = fs.constants.O_RDONLY;
  if (typeof fs.constants.O_CLOEXEC === "number") flags |= fs.constants.O_CLOEXEC;
  if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
  if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
  let descriptor;
  try {
    descriptor = fs.openSync(file, flags);
  } catch (error) {
    throw new Error(`The ${label} changed or is unsafe: ${file}`, { cause: error });
  }

  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || !sameFileIdentity(before, opened)) {
      throw new Error(`The ${label} changed before it was opened: ${file}`);
    }
    const chunks = [];
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    for (;;) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > limit) {
        throw new Error(`The ${label} is too large: ${file}`);
      }
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    const after = fs.fstatSync(descriptor);
    const pathAfter = fs.lstatSync(file, { throwIfNoEntry: false });
    if (
      !pathAfter?.isFile() ||
      pathAfter.isSymbolicLink() ||
      !sameFileIdentity(opened, after) ||
      !sameFileIdentity(opened, pathAfter) ||
      after.size !== total
    ) {
      throw new Error(`The ${label} changed while it was read: ${file}`);
    }
    return Buffer.concat(chunks, total);
  } finally {
    fs.closeSync(descriptor);
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`The ${label} must be an object`);
  }
}

function assertLowerHex(value, length, label) {
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`The ${label} is not valid`);
  }
}

function format(value) {
  return JSON.stringify(value);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`The argument sequence is not valid at ${name ?? "<end>"}`);
    }
    const key = name.slice(2);
    if (!ARGUMENT_NAMES.includes(key) || options[key] !== undefined) {
      throw new Error(`The argument is not valid: ${name}`);
    }
    options[key] = value;
  }
  for (const required of REQUIRED_ARGUMENT_NAMES) {
    if (!options[required]) throw new Error(`The --${required} argument is required`);
  }
  return options;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = await verifyPublishedPackage({
      releaseManifest: readManifest(options.manifest),
      packageName: options.package,
      expectedTag: options.tag,
      expectedSourceRunId: options["source-run-id"],
      expectedSourceSha: options["source-sha"],
      expectedSourceRef: options["source-ref"],
      tarballPath: options.tarball,
    });
    console.log(`Verified existing npm publication ${result.packageName}@${result.version}`);
  } catch (error) {
    console.error(`verify-published-package: ${error.message}`);
    process.exit(1);
  }
}
