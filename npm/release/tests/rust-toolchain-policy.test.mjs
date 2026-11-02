import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const workflowsDir = path.join(repoRoot, ".github/workflows");

function pinnedRelease() {
  const toolchain = fs.readFileSync(path.join(repoRoot, "rust-toolchain.toml"), "utf8");
  const channel = toolchain.match(/^channel = "(\d+\.\d+\.\d+)"$/m)?.[1];
  assert.ok(channel, "rust-toolchain.toml must pin an exact Rust release");
  return channel;
}

test("workspace packages, local tooling, and workflows use the Rust release rust-toolchain.toml pins", () => {
  const channel = pinnedRelease();

  for (const workflow of [
    "ci.yml",
    "release.yml",
    "windows-filesystem-gate.yml",
    "windows-signing-smoke.yml",
  ]) {
    const source = fs.readFileSync(path.join(workflowsDir, workflow), "utf8");
    assert.match(source, /^\s+RUST_TOOLCHAIN: "[^"]+"$/m, `${workflow} must declare RUST_TOOLCHAIN`);
  }

  for (const workflow of fs.readdirSync(workflowsDir).filter((name) => /\.ya?ml$/.test(name))) {
    const source = fs.readFileSync(path.join(workflowsDir, workflow), "utf8");
    const pins = [
      ...source.matchAll(/^\s+RUST_TOOLCHAIN: "([^"]*)"$/gm),
      ...source.matchAll(/^\s+toolchain: ['"]?([^'"\s$]+)['"]?$/gm),
      ...source.matchAll(/^\s+(?:key|restore-keys): .*-(\d+\.\d+\.\d+)-/gm),
    ].map((match) => match[1]);
    for (const pin of pins.filter((value) => value !== "nightly")) {
      assert.equal(pin, channel, `${workflow} pins Rust ${pin} instead of ${channel}`);
    }
  }

  const result = spawnSync(
    "cargo",
    ["metadata", "--locked", "--no-deps", "--format-version=1"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);

  const minor = channel.split(".").slice(0, 2).join(".");
  const packages = JSON.parse(result.stdout).packages;
  assert.ok(packages.length > 0, "workspace metadata must contain packages");
  for (const pkg of packages) {
    assert.equal(pkg.rust_version, minor, `${pkg.name} does not declare Rust ${minor}`);
  }
});

test("export scripts build with and record the release rust-toolchain.toml pins", () => {
  for (const script of ["export-env-engine.py", "export-env-validator.py", "export-skill-validator.py"]) {
    const source = fs.readFileSync(path.join(repoRoot, "scripts", script), "utf8");
    assert.match(source, /pinned_toolchain\(/, `${script} must read the toolchain from rust-toolchain.toml`);
    assert.doesNotMatch(source, /['"]\+\d+\.\d+\.\d+['"]/, `${script} must not override the toolchain with a fixed release`);
    assert.doesNotMatch(source, /toolchain['"]?\s*[:=]\s*['"]\d/, `${script} must not record a fixed Rust release`);
  }
});
