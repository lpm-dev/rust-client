#!/usr/bin/env node

import { createRequire } from "node:module";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_REPO = "https://github.com/npm/node-semver";
const SOURCE_COMMIT = "8640bd68f1653e504b53e9be4030eccdfe4c307a";
const RAW_BASE = `https://raw.githubusercontent.com/npm/node-semver/${SOURCE_COMMIT}`;

const __dirname = dirname(fileURLToPath(import.meta.url));
const crateRoot = join(__dirname, "..");
const fixtureDir = join(crateRoot, "tests", "fixtures", "node-semver");
const tmpDir = join(fixtureDir, ".upstream-tmp");

async function fetchText(path) {
  const url = `${RAW_BASE}/${path}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to fetch ${url}: ${response.status} ${response.statusText}`);
  }
  return response.text();
}

async function writeFetched(path) {
  const content = await fetchText(path);
  const target = join(tmpDir, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content);
  return target;
}

function optionSummary(value) {
  if (value === undefined) {
    return null;
  }
  if (value === null) {
    return { loose: false, include_prerelease: false };
  }
  if (typeof value === "boolean") {
    return { loose: value, include_prerelease: false };
  }
  if (typeof value === "object" && value.constructor === Object) {
    return {
      loose: Boolean(value.loose),
      include_prerelease: Boolean(value.includePrerelease),
    };
  }
  return { unsupported: Object.prototype.toString.call(value) };
}

function defaultOptions(options) {
  const summary = optionSummary(options);
  if (!summary) {
    return true;
  }
  return !summary.unsupported && !summary.loose && !summary.include_prerelease;
}

function rangeCase(tuple, expected, sourceIndex) {
  const [range, version, options] = tuple;
  const details = {
    source_index: sourceIndex,
    range: typeof range === "string" ? range : String(range),
    version: typeof version === "string" ? version : String(version),
    expected,
    upstream_options: optionSummary(options),
  };

  if (typeof range !== "string") {
    return { skipped: { ...details, reason: "range is not a string" } };
  }
  if (typeof version !== "string") {
    return { skipped: { ...details, reason: "version is not a string" } };
  }
  if (!defaultOptions(options)) {
    return {
      skipped: {
        ...details,
        reason: "LPM VersionReq does not expose node-semver loose/includePrerelease options",
      },
    };
  }
  if (range.trim() === "" || range.trim() === "||") {
    return {
      skipped: {
        ...details,
        reason: "LPM rejects empty ranges while npm validRange treats them as wildcard",
      },
    };
  }
  return { case: details };
}

function comparisonCase(tuple, sourceIndex) {
  const [greater, less, options] = tuple;
  const details = {
    source_index: sourceIndex,
    greater: typeof greater === "string" ? greater : String(greater),
    less: typeof less === "string" ? less : String(less),
    upstream_options: optionSummary(options),
  };

  if (typeof greater !== "string" || typeof less !== "string") {
    return { skipped: { ...details, reason: "comparison operand is not a string" } };
  }
  if (!defaultOptions(options)) {
    return {
      skipped: {
        ...details,
        reason: "LPM Version does not expose node-semver loose options",
      },
    };
  }
  return { case: details };
}

function metadata(sourceFile) {
  return {
    source_repo: SOURCE_REPO,
    source_commit: SOURCE_COMMIT,
    source_file: sourceFile,
    generated_by: "crates/lpm-semver/scripts/vendor-node-semver-fixtures.mjs",
  };
}

async function main() {
  await rm(tmpDir, { recursive: true, force: true });
  await mkdir(fixtureDir, { recursive: true });

  const require = createRequire(import.meta.url);
  const sourceFiles = [
    "test/fixtures/range-include.js",
    "test/fixtures/range-exclude.js",
    "test/fixtures/comparisons.js",
    "internal/constants.js",
  ];
  for (const file of sourceFiles) {
    await writeFetched(file);
  }

  for (const [file, expected, output] of [
    ["test/fixtures/range-include.js", true, "range_include.json"],
    ["test/fixtures/range-exclude.js", false, "range_exclude.json"],
  ]) {
    const rows = require(join(tmpDir, file));
    const cases = [];
    const skipped = [];
    rows.forEach((tuple, index) => {
      const converted = rangeCase(tuple, expected, index);
      if (converted.case) {
        cases.push(converted.case);
      } else {
        skipped.push(converted.skipped);
      }
    });
    await writeFile(
      join(fixtureDir, output),
      `${JSON.stringify({ ...metadata(file), cases, skipped }, null, 2)}\n`,
    );
  }

  {
    const file = "test/fixtures/comparisons.js";
    const rows = require(join(tmpDir, file));
    const cases = [];
    const skipped = [];
    rows.forEach((tuple, index) => {
      const converted = comparisonCase(tuple, index);
      if (converted.case) {
        cases.push(converted.case);
      } else {
        skipped.push(converted.skipped);
      }
    });
    await writeFile(
      join(fixtureDir, "comparisons.json"),
      `${JSON.stringify({ ...metadata(file), cases, skipped }, null, 2)}\n`,
    );
  }

  await writeFile(join(fixtureDir, "LICENSE.node-semver"), await fetchText("LICENSE"));
  await rm(tmpDir, { recursive: true, force: true });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
