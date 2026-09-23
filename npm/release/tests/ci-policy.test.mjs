import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("live OSV contracts run separately on scheduled and manual CI", () => {
  const workflow = fs.readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const job = workflow.match(/^  osv-live:\n([\s\S]*?)(?=^  [a-z][\w-]*:)/m)?.[1];
  assert.ok(job, "missing separate live OSV job");
  assert.match(job, /if: github\.event_name == 'workflow_dispatch' \|\| github\.event_name == 'schedule'/);
  assert.match(job, /cargo build --locked -p lpm-cli --bin lpm-rs/);
  assert.match(job, /cargo nextest run --locked -p lpm-workflows --test osv_live --run-ignored only/);
  assert.doesNotMatch(job, /continue-on-error|LPM_OSV_URL/);
});

test("CI runs for pull requests targeting main and native stack branches", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const trigger = workflow.match(/^  pull_request:\n((?:    .*\n)*)/m)?.[1];

  assert.ok(trigger, "missing pull_request trigger");
  const branches = trigger.match(/^    branches: \[([^\]]+)\]$/m)?.[1]
    .split(",")
    .map((branch) => branch.trim().replace(/^["']|["']$/g, ""));
  assert.ok(branches, "missing pull_request base branch policy");
  for (const base of ["main", "codex/bun-converter-exit-race", "codex/organization-browser-env"]) {
    assert.ok(
      branches.some((pattern) => pattern === base || (pattern === "codex/**" && base.startsWith("codex/"))),
      `CI does not run for PRs targeting ${base}`,
    );
  }
  assert.match(workflow, /^  push:\n    branches: \[main\]$/m);
});

test("CI compiles experimental HTTP/3 with the required reqwest cfg", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = workflow.indexOf("\n  experimental-http3:\n");
  const end = workflow.indexOf("\n  test:\n", start + 1);

  assert.notEqual(start, -1, "missing experimental-http3 CI job");
  assert.notEqual(end, -1, "experimental-http3 job must run before the test job");

  const job = workflow.slice(start, end);
  assert.match(job, /^\s+RUSTFLAGS: "--cfg reqwest_unstable"$/m);
  assert.match(job, /cargo check --locked -p lpm-registry --all-features/);
  assert.match(job, /cargo check --locked -p lpm-cli --features experimental-http3/);
});
