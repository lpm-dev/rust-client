import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const workflow = (name) =>
  fs.readFileSync(path.join(repoRoot, ".github/workflows", name), "utf8").replaceAll("\r\n", "\n");
const job = (source, name, nextName) => {
  const start = source.indexOf(`\n  ${name}:\n`);
  const end = source.indexOf(`\n  ${nextName}:\n`, start + 1);
  assert.notEqual(start, -1, `missing ${name} job`);
  assert.notEqual(end, -1, `missing ${nextName} job`);
  return source.slice(start, end);
};

test("PR CI rejects release-profile warnings on every supported operating system", () => {
  const check = job(workflow("ci.yml"), "release-check", "lint");
  assert.doesNotMatch(check, /^ {4}if:|^ +continue-on-error:/m);
  assert.match(check, /os: \[ubuntu-latest, macos-15, windows-latest\]/);
  assert.match(check, /RUSTFLAGS: "-D warnings"/);
  assert.match(check, /cargo check --locked --release -p lpm-cli -p lpm-sandbox --bins/);
});

test("native release builds reject compiler warnings for the CLI and sandbox helper", () => {
  const source = workflow("release.yml");
  for (const [name, nextName] of [["build", "notarize-macos"], ["build-windows", "sign-windows"]]) {
    assert.match(job(source, name, nextName), /RUSTFLAGS: "-D warnings"/);
  }
});

test("portable Linux release containers inherit strict compiler warnings", () => {
  const build = job(workflow("release.yml"), "build", "notarize-macos");
  assert.match(build, /--env RUSTFLAGS \\/);
});
