#!/usr/bin/env node

import { fileURLToPath } from "node:url";

import { PLATFORM_PACKAGES } from "./release-artifacts.mjs";
import {
  PublishedVersionMismatchError,
  assertSupportedDistTag,
  readManifest,
  releasePackageRecord,
  verifyRegistryVersion,
} from "./verify-published-package.mjs";

const WRAPPER_PACKAGE = "@lpm-registry/cli";
// npm acknowledges a publish before it lists the version, and has taken over
// twelve minutes to list a large platform tarball.
export const PROPAGATION_TIMEOUT_MS = 30 * 60_000;
const INITIAL_RETRY_DELAY_MS = 5_000;
const MAX_RETRY_DELAY_MS = 30_000;
const ARGUMENT_NAMES = Object.freeze(["manifest", "scope", "tag"]);

export const PUBLICATION_SCOPES = Object.freeze({
  platforms: Object.freeze(PLATFORM_PACKAGES.map(({ packageName }) => packageName)),
  wrapper: Object.freeze([WRAPPER_PACKAGE]),
});

/**
 * Wait, within one shared registry-propagation window, until npm serves every
 * package in `scope` at the release version with the manifest's exact digests,
 * SLSA provenance, and `expectedTag` selecting it.
 *
 * Every package is checked concurrently, and a failure names each package that
 * never became verifiable together with its last error, so one run reports the
 * whole set of missing or mismatched publications. A package npm already lists
 * with a different identity or digest fails at once instead of being retried,
 * because npm never changes a published version.
 */
export async function verifyRegistryPublications({
  releaseManifest,
  scope,
  expectedTag,
  fetchImpl = fetch,
  timeoutMs = PROPAGATION_TIMEOUT_MS,
  now = Date.now,
  sleep = delay,
  log = message => console.error(message),
}) {
  if (!Object.hasOwn(PUBLICATION_SCOPES, scope)) {
    throw new Error(`The publication scope is not supported: ${JSON.stringify(scope)}`);
  }
  assertSupportedDistTag(expectedTag);
  assertOnlyKnownPackages(releaseManifest);
  const packageNames = PUBLICATION_SCOPES[scope];
  const records = packageNames.map(packageName => ({
    packageName,
    ...releasePackageRecord(releaseManifest, packageName),
  }));

  const deadline = now() + timeoutMs;
  const outcomes = await Promise.all(
    records.map(({ packageName, version, record }) =>
      verifyBeforeDeadline({
        deadline,
        log,
        now,
        sleep,
        verify: () =>
          verifyRegistryVersion({ packageName, version, expectedTag, record, fetchImpl }),
        label: `${packageName}@${version}`,
      }),
    ),
  );

  const failures = outcomes
    .map((error, index) => ({ error, packageName: packageNames[index] }))
    .filter(({ error }) => error !== null);
  if (failures.length > 0) {
    const details = failures
      .map(({ packageName, error }) => `  ${packageName}: ${describe(error)}`)
      .join("\n");
    throw new Error(
      `npm did not serve ${failures.length} of ${packageNames.length} package(s) in the ` +
        `${scope} scope within ${Math.round(timeoutMs / 1000)}s:\n${details}`,
    );
  }

  return Object.freeze({
    version: records[0].version,
    tag: expectedTag,
    packages: packageNames,
  });
}

async function verifyBeforeDeadline({ deadline, log, now, sleep, verify, label }) {
  let retryDelay = INITIAL_RETRY_DELAY_MS;
  for (let attempt = 1; ; attempt += 1) {
    try {
      await verify();
      return null;
    } catch (error) {
      if (error instanceof PublishedVersionMismatchError) return error;
      const remaining = deadline - now();
      if (remaining <= 0) return error;
      log(`${label} is not verifiable on npm yet (attempt ${attempt}): ${describe(error)}`);
      await sleep(Math.min(retryDelay, remaining));
      retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY_MS);
    }
  }
}

function assertOnlyKnownPackages(releaseManifest) {
  const known = new Set([...PUBLICATION_SCOPES.platforms, ...PUBLICATION_SCOPES.wrapper]);
  const unknown = (Array.isArray(releaseManifest?.packages) ? releaseManifest.packages : [])
    .map(record => record?.name)
    .filter(name => !known.has(name));
  if (unknown.length > 0) {
    throw new Error(
      `The release manifest contains packages no publication scope verifies: ${unknown
        .map(name => JSON.stringify(name))
        .join(", ")}`,
    );
  }
}

function describe(error) {
  return error?.cause?.message ? `${error.message} (${error.cause.message})` : error?.message;
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
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
  for (const required of ARGUMENT_NAMES) {
    if (!options[required]) throw new Error(`The --${required} argument is required`);
  }
  return options;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = await verifyRegistryPublications({
      releaseManifest: readManifest(options.manifest),
      scope: options.scope,
      expectedTag: options.tag,
    });
    console.log(
      `Verified npm serves ${result.packages.join(", ")} at ${result.version} ` +
        `under dist-tag ${result.tag}`,
    );
  } catch (error) {
    console.error(`verify-registry-publication: ${error.message}`);
    process.exit(1);
  }
}
