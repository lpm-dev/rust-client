#!/usr/bin/env node

import { fileURLToPath } from "node:url";

export const NIGHTLY_PACKAGES = Object.freeze([
  "@lpm-registry/cli",
  "@lpm-registry/cli-darwin-arm64",
  "@lpm-registry/cli-darwin-x64",
  "@lpm-registry/cli-linux-arm64",
  "@lpm-registry/cli-linux-x64",
  "@lpm-registry/cli-linux-x64-musl",
  "@lpm-registry/cli-win32-x64",
]);

const NIGHTLY_VERSION_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.0-nightly\.(\d{8})\.([1-9]\d*)\.([0-9a-f]{7}|g0\d{6})$/;
const COMMIT_SHA_PATTERN = /^[0-9a-f]{40}$/i;
const PUBLISHED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export function resolveNightlyReleaseState({
  currentSha,
  npmVersions,
  githubRelease,
  tagSha,
  relationship,
}) {
  const normalizedCurrentSha = validateCommitSha(currentSha, "current main");
  const normalizedTagSha = validateCommitSha(tagSha, "published nightly tag");
  const version = validateNpmVersions(npmVersions);
  validateNightlyVersion(version);

  const expectedTag = `v${version}`;
  if (githubRelease?.tagName !== expectedTag) {
    throw new Error(
      `npm nightly points to ${version}, but the GitHub release tag is ${githubRelease?.tagName ?? "<missing>"}`,
    );
  }
  if (githubRelease.prerelease !== true) {
    throw new Error(`${expectedTag} must be a GitHub prerelease`);
  }
  if (githubRelease.draft !== false) {
    throw new Error(`${expectedTag} must be published, not a draft`);
  }
  if (
    typeof githubRelease.publishedAt !== "string" ||
    !PUBLISHED_AT_PATTERN.test(githubRelease.publishedAt) ||
    Number.isNaN(Date.parse(githubRelease.publishedAt))
  ) {
    throw new Error(`${expectedTag} does not have a valid publication timestamp`);
  }

  if (normalizedTagSha === normalizedCurrentSha) {
    if (relationship !== "same") {
      throw new Error(
        `nightly state is contradictory: identical commits were classified as ${relationship}`,
      );
    }
    return {
      shouldRelease: false,
      reason: `${expectedTag} already targets current main commit ${normalizedCurrentSha.slice(0, 7)}`,
      version,
      tag: expectedTag,
      tagSha: normalizedTagSha,
      currentSha: normalizedCurrentSha,
    };
  }

  if (relationship === "ancestor") {
    return {
      shouldRelease: true,
      reason: `main advanced from ${normalizedTagSha.slice(0, 7)} to ${normalizedCurrentSha.slice(0, 7)}`,
      version,
      tag: expectedTag,
      tagSha: normalizedTagSha,
      currentSha: normalizedCurrentSha,
    };
  }
  if (relationship === "same") {
    throw new Error("nightly state is contradictory: different commits were classified as identical");
  }
  if (relationship === "diverged") {
    throw new Error(
      `${expectedTag} (${normalizedTagSha.slice(0, 7)}) is not an ancestor of current main (${normalizedCurrentSha.slice(0, 7)}); refusing to publish`,
    );
  }
  throw new Error(`unknown Git relationship: ${relationship}`);
}

function validateNpmVersions(npmVersions) {
  if (!npmVersions || typeof npmVersions !== "object" || Array.isArray(npmVersions)) {
    throw new Error("npm nightly versions must be supplied by package name");
  }

  const actualPackages = Object.keys(npmVersions).sort();
  const expectedPackages = [...NIGHTLY_PACKAGES].sort();
  if (
    actualPackages.length !== expectedPackages.length ||
    actualPackages.some((name, index) => name !== expectedPackages[index])
  ) {
    const missing = expectedPackages.filter((name) => !actualPackages.includes(name));
    const unexpected = actualPackages.filter((name) => !expectedPackages.includes(name));
    throw new Error(
      `npm nightly package set is inconsistent (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"})`,
    );
  }

  const versions = new Set(Object.values(npmVersions));
  if (versions.size !== 1) {
    throw new Error("npm nightly dist-tags do not all point to the same version");
  }
  const [version] = versions;
  if (typeof version !== "string") {
    throw new Error("npm nightly dist-tags must resolve to version strings");
  }
  return version;
}

function validateNightlyVersion(version) {
  const match = NIGHTLY_VERSION_PATTERN.exec(version);
  if (!match || !isUtcCalendarDate(match[3]) || /^0\d{6}$/.test(match[5])) {
    throw new Error(`npm nightly dist-tag has an invalid version: ${version}`);
  }
}

function validateCommitSha(value, label) {
  if (typeof value !== "string" || !COMMIT_SHA_PATTERN.test(value)) {
    throw new Error(`${label} commit must be a full 40-character Git SHA`);
  }
  return value.toLowerCase();
}

function isUtcCalendarDate(value) {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(4, 6));
  const day = Number(value.slice(6, 8));
  const parsed = new Date(Date.UTC(year, month - 1, day));
  return (
    parsed.getUTCFullYear() === year &&
    parsed.getUTCMonth() === month - 1 &&
    parsed.getUTCDate() === day
  );
}

function parseArguments(argv) {
  const options = { npmVersions: {} };
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument sequence at ${name ?? "<end>"}`);
    }
    if (name === "--npm-version") {
      const separator = value.indexOf("=");
      if (separator <= 0 || separator === value.length - 1) {
        throw new Error("--npm-version must be PACKAGE=VERSION");
      }
      const packageName = value.slice(0, separator);
      if (Object.hasOwn(options.npmVersions, packageName)) {
        throw new Error(`duplicate npm package: ${packageName}`);
      }
      options.npmVersions[packageName] = value.slice(separator + 1);
    } else {
      options[name.slice(2)] = value;
    }
  }

  for (const required of [
    "current-sha",
    "tag-sha",
    "github-tag",
    "github-prerelease",
    "github-draft",
    "github-published-at",
    "relationship",
  ]) {
    if (!options[required]) {
      throw new Error(`--${required} is required`);
    }
  }
  return options;
}

function parseBoolean(value, label) {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${label} must be true or false`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const state = resolveNightlyReleaseState({
      currentSha: options["current-sha"],
      tagSha: options["tag-sha"],
      relationship: options.relationship,
      npmVersions: options.npmVersions,
      githubRelease: {
        tagName: options["github-tag"],
        prerelease: parseBoolean(options["github-prerelease"], "--github-prerelease"),
        draft: parseBoolean(options["github-draft"], "--github-draft"),
        publishedAt: options["github-published-at"],
      },
    });
    console.log(JSON.stringify(state));
  } catch (error) {
    console.error(`nightly-release-state: ${error.message}`);
    process.exit(1);
  }
}
