import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const CANDIDATE_SCHEMA = 1;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export function sealReleaseCandidate({
  githubReleaseDirectory,
  npmPackagesDirectory,
  outputDirectory,
  repository,
  sourceSha,
  sourceRunId,
  version,
}) {
  validateIdentity({ repository, sourceSha, sourceRunId, version });
  const output = path.resolve(outputDirectory);
  fs.rmSync(output, { force: true, recursive: true });
  fs.mkdirSync(output, { recursive: true, mode: 0o755 });

  copyPayload(githubReleaseDirectory, path.join(output, "github-release"));
  copyPayload(npmPackagesDirectory, path.join(output, "npm-release-packages"));
  const files = inventory(output);
  if (files.length === 0) throw new Error("release candidate payload is empty");

  const manifest = {
    schemaVersion: CANDIDATE_SCHEMA,
    repository,
    workflowPath: ".github/workflows/release.yml",
    sourceSha,
    sourceRunId: Number(sourceRunId),
    version,
    tag: `v${version}`,
    channel: "stable",
    files,
  };
  fs.writeFileSync(
    path.join(output, "release-candidate.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { mode: 0o644 },
  );
  return manifest;
}

export function verifyReleaseCandidate({
  candidateDirectory,
  repository,
  scope,
  sourceSha,
  sourceRunId,
  version,
}) {
  validateIdentity({ repository, sourceSha, sourceRunId, version });
  const root = path.resolve(candidateDirectory);
  const manifestPath = path.join(root, "release-candidate.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  assertEqual(manifest.schemaVersion, CANDIDATE_SCHEMA, "schema version");
  assertEqual(manifest.repository, repository, "repository");
  assertEqual(manifest.workflowPath, ".github/workflows/release.yml", "workflow path");
  assertEqual(manifest.sourceSha, sourceSha, "source SHA");
  assertEqual(manifest.sourceRunId, Number(sourceRunId), "source run ID");
  assertEqual(manifest.version, version, "version");
  assertEqual(manifest.tag, `v${version}`, "tag");
  assertEqual(manifest.channel, "stable", "channel");
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    throw new Error("candidate manifest has no files");
  }
  if (scope !== undefined && scope !== "github-release" && scope !== "npm-release-packages") {
    throw new Error("invalid candidate verification scope");
  }

  const actual = inventory(root, new Set(["release-candidate.json"]));
  const expected = scope === undefined
    ? manifest.files
    : manifest.files.filter(file => file?.path?.startsWith(`${scope}/`));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("candidate payload does not match its sealed file inventory");
  }
  requireFile(manifest.files, "github-release/SHA256SUMS.txt");
  requireFile(manifest.files, "github-release/SHA256SUMS.txt.sigstore");
  requireFile(manifest.files, "npm-release-packages/release-packages.json");
  return Object.freeze(manifest);
}

function copyPayload(sourceDirectory, destinationDirectory) {
  const source = path.resolve(sourceDirectory);
  const metadata = fs.statSync(source, { throwIfNoEntry: false });
  if (!metadata?.isDirectory()) throw new Error(`candidate source directory is missing: ${source}`);
  fs.cpSync(source, destinationDirectory, {
    recursive: true,
    dereference: false,
    errorOnExist: true,
    force: false,
  });
}

function inventory(root, ignored = new Set()) {
  const files = [];
  walk(root, "", ignored, files);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function walk(root, relative, ignored, files) {
  const directory = path.join(root, relative);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const child = relative ? `${relative}/${entry.name}` : entry.name;
    if (ignored.has(child)) continue;
    if (entry.isSymbolicLink()) throw new Error(`candidate payload contains a symbolic link: ${child}`);
    if (entry.isDirectory()) {
      walk(root, child, ignored, files);
      continue;
    }
    if (!entry.isFile()) throw new Error(`candidate payload contains an unsupported entry: ${child}`);
    const absolute = path.join(root, child);
    const content = fs.readFileSync(absolute);
    files.push({
      path: child,
      sha256: crypto.createHash("sha256").update(content).digest("hex"),
      size: content.byteLength,
    });
  }
}

function validateIdentity({ repository, sourceSha, sourceRunId, version }) {
  if (!REPOSITORY_PATTERN.test(repository ?? "")) throw new Error("invalid candidate repository");
  if (!SHA_PATTERN.test(sourceSha ?? "")) throw new Error("invalid candidate source SHA");
  if (!/^[1-9]\d*$/.test(String(sourceRunId)) || !Number.isSafeInteger(Number(sourceRunId))) {
    throw new Error("invalid candidate source run ID");
  }
  if (!VERSION_PATTERN.test(version ?? "")) throw new Error("invalid stable candidate version");
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`candidate ${label} mismatch`);
}

function requireFile(files, requiredPath) {
  if (!files.some(file => file.path === requiredPath)) {
    throw new Error(`candidate payload is missing ${requiredPath}`);
  }
}
