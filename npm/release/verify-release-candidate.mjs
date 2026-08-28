#!/usr/bin/env node

import { verifyReleaseCandidate } from "./release-candidate.mjs";

const options = parseArguments(process.argv.slice(2));
verifyReleaseCandidate({
  candidateDirectory: required(options, "candidate"),
  repository: required(options, "repository"),
  scope: options.scope,
  sourceSha: required(options, "source-sha"),
  sourceRunId: required(options, "source-run-id"),
  version: required(options, "version"),
});

function parseArguments(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) throw new Error("invalid arguments");
    parsed[name.slice(2)] = value;
  }
  return parsed;
}

function required(options, name) {
  if (!options[name]) throw new Error(`--${name} is required`);
  return options[name];
}
