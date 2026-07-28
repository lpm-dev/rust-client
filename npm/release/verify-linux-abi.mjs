#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const GLIBC_SYMBOL_PATTERN = /\bGLIBC_(\d+(?:\.\d+)+)\b/g;
const VERSION_PATTERN = /^(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))+$/;

export function glibcVersionsFromReadelf(output) {
  const versions = new Set();
  for (const match of output.matchAll(GLIBC_SYMBOL_PATTERN)) {
    versions.add(match[1]);
  }
  return [...versions].sort(compareVersions);
}

export function verifyGlibcCeiling(output, ceiling) {
  parseVersion(ceiling);
  const versions = glibcVersionsFromReadelf(output);
  if (versions.length === 0) {
    throw new Error("binary does not declare any GLIBC symbol versions");
  }

  const maximum = versions.at(-1);
  if (compareVersions(maximum, ceiling) > 0) {
    throw new Error(
      `binary requires GLIBC_${maximum}, exceeding the supported ceiling GLIBC_${ceiling}`,
    );
  }
  return { maximum, ceiling };
}

function compareVersions(left, right) {
  const leftParts = parseVersion(left);
  const rightParts = parseVersion(right);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function parseVersion(version) {
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`invalid glibc version: ${version}`);
  }
  const parts = version.split(".").map(Number);
  if (parts.some(part => !Number.isSafeInteger(part))) {
    throw new Error(`invalid glibc version: ${version}`);
  }
  return parts;
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument sequence at ${name ?? "<end>"}`);
    }
    const key = name.slice(2);
    if (!["binary", "max-glibc"].includes(key)) {
      throw new Error(`unknown argument: ${name}`);
    }
    if (options[key] !== undefined) {
      throw new Error(`duplicate argument: ${name}`);
    }
    options[key] = value;
  }
  for (const required of ["binary", "max-glibc"]) {
    if (!options[required]) {
      throw new Error(`--${required} is required`);
    }
  }
  return options;
}

function readVersionInfo(binary) {
  const result = spawnSync("readelf", ["--version-info", "--wide", binary], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`failed to execute readelf: ${result.error.message}`, {
      cause: result.error,
    });
  }
  if (result.status !== 0) {
    throw new Error(
      `readelf failed for ${binary} with status ${result.status}: ${result.stderr.trim()}`,
    );
  }
  return result.stdout;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const verification = verifyGlibcCeiling(
      readVersionInfo(options.binary),
      options["max-glibc"],
    );
    console.log(
      `${options.binary} requires at most GLIBC_${verification.maximum} ` +
        `(supported ceiling GLIBC_${verification.ceiling})`,
    );
  } catch (error) {
    console.error(`verify-linux-abi: ${error.message}`);
    process.exit(1);
  }
}
