#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const STABLE_VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const DATE_PATTERN = /^\d{8}$/;
const RUN_NUMBER_PATTERN = /^[1-9]\d*$/;
const COMMIT_SHA_PATTERN = /^[0-9a-f]{7,40}$/i;

export function nightlyVersion({ stableVersion, date, runNumber, commitSha }) {
  const match = STABLE_VERSION_PATTERN.exec(stableVersion);
  if (!match) {
    throw new Error(`stable version must be X.Y.Z without a prerelease: ${stableVersion}`);
  }
  if (!DATE_PATTERN.test(date) || !isUtcCalendarDate(date)) {
    throw new Error(`nightly date must be a valid YYYYMMDD UTC date: ${date}`);
  }
  if (!RUN_NUMBER_PATTERN.test(String(runNumber))) {
    throw new Error(`run number must be a positive integer: ${runNumber}`);
  }
  if (!COMMIT_SHA_PATTERN.test(commitSha)) {
    throw new Error(`commit SHA must contain 7-40 hexadecimal characters: ${commitSha}`);
  }

  const major = Number(match[1]);
  const nextMinor = Number(match[2]) + 1;
  const shortSha = commitSha.slice(0, 7).toLowerCase();
  const semverSha = /^0\d+$/.test(shortSha) ? `g${shortSha}` : shortSha;
  return `${major}.${nextMinor}.0-nightly.${date}.${runNumber}.${semverSha}`;
}

export function workspaceStableVersion(repoRoot) {
  const cargoToml = fs.readFileSync(path.join(repoRoot, "Cargo.toml"), "utf8");
  const workspacePackage = cargoToml
    .split(/^\[workspace\.package\]\s*$/m)[1]
    ?.split(/^\[/m)[0];
  const version = workspacePackage?.match(/^\s*version\s*=\s*"([^"]+)"\s*$/m)?.[1];
  if (!version) {
    throw new Error("Cargo.toml [workspace.package] must declare version");
  }
  if (!STABLE_VERSION_PATTERN.test(version)) {
    throw new Error(`workspace version must be stable X.Y.Z: ${version}`);
  }
  return version;
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
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument sequence at ${name ?? "<end>"}`);
    }
    options[name.slice(2)] = value;
  }
  for (const required of ["repo", "date", "run-number", "sha"]) {
    if (!options[required]) {
      throw new Error(`--${required} is required`);
    }
  }
  return options;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    console.log(
      nightlyVersion({
        stableVersion: workspaceStableVersion(path.resolve(options.repo)),
        date: options.date,
        runNumber: options["run-number"],
        commitSha: options.sha,
      }),
    );
  } catch (error) {
    console.error(`nightly-version: ${error.message}`);
    process.exit(1);
  }
}
