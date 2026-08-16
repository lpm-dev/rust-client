import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("workspace packages, local tooling, and stable workflows declare Rust 1.94", () => {
  const toolchain = fs.readFileSync(path.join(repoRoot, "rust-toolchain.toml"), "utf8");
  assert.match(toolchain, /^channel = "1\.94\.0"$/m);

  for (const workflow of [
    "ci.yml",
    "release.yml",
    "windows-filesystem-gate.yml",
    "windows-signing-smoke.yml",
  ]) {
    const source = fs.readFileSync(path.join(repoRoot, ".github/workflows", workflow), "utf8");
    assert.match(source, /^\s+RUST_TOOLCHAIN: "1\.94\.0"$/m, `${workflow} has a different toolchain`);
  }

  const result = spawnSync(
    "cargo",
    ["metadata", "--locked", "--no-deps", "--format-version=1"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);

  const packages = JSON.parse(result.stdout).packages;
  assert.ok(packages.length > 0, "workspace metadata must contain packages");
  for (const pkg of packages) {
    assert.equal(pkg.rust_version, "1.94", `${pkg.name} does not declare Rust 1.94`);
  }
});
