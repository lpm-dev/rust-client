import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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

function readCiWorkflow() {
  return fs
    .readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8")
    .replaceAll("\r\n", "\n");
}

function ciJob(workflow, id) {
  return workflow.match(new RegExp(`^  ${id}:\\n([\\s\\S]*?)(?=^  [a-z][\\w-]*:$|(?![\\s\\S]))`, "m"))?.[1];
}

function ciStep(job, name) {
  return job.match(new RegExp(`^      - name: ${escapeRegExp(name)}\\n([\\s\\S]*?)(?=^      - |(?![\\s\\S]))`, "m"))?.[1];
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("the required macOS check fails unless every macOS job passes", {
  skip: process.platform === "win32" && "runs the gate script with bash and jq",
}, () => {
  const workflow = readCiWorkflow();
  const gate = ciJob(workflow, "macos-workspace");
  assert.ok(gate, "missing macos-workspace job");
  assert.match(gate, /^    name: macOS workspace checks$/m);
  assert.match(gate, /^    permissions: \{\}$/m, "the gate reads no repository content");
  assert.match(gate, /^    if: always\(\)$/m, "a gate skipped by a failed job counts as passing");
  const needs = gate.match(/^    needs: \[([^\]]+)\]$/m)?.[1].split(",").map((job) => job.trim());
  assert.deepEqual(needs, ["macos-workspace-tests", "macos-build-checks"]);
  for (const job of needs) {
    assert.match(ciJob(workflow, job) ?? "", /^    runs-on: macos-latest$/m, `${job} must run on macOS`);
  }

  const step = ciStep(gate, "Require every macOS job to pass");
  assert.ok(step, "missing macOS gate step");
  assert.match(step, /^          NEEDS: \$\{\{ toJSON\(needs\) \}\}$/m);
  const script = step
    .match(/^        run: \|\n((?:          .*\n|\n)+)/m)?.[1]
    .replace(/^ {10}/gm, "");
  assert.ok(script, "missing macOS gate script");

  const gateStatus = (results) => {
    const reported = Object.fromEntries(needs.map((job, index) => [job, { result: results[index], outputs: {} }]));
    return spawnSync("bash", ["-e", "-c", script], {
      env: { ...process.env, NEEDS: JSON.stringify(reported) },
      encoding: "utf8",
    }).status;
  };
  assert.equal(gateStatus(["success", "success"]), 0);
  for (const result of ["failure", "cancelled", "skipped"]) {
    assert.notEqual(gateStatus([result, "success"]), 0, `gate passed with ${needs[0]} ${result}`);
    assert.notEqual(gateStatus(["success", result]), 0, `gate passed with ${needs[1]} ${result}`);
  }
});

test("macOS workspace tests compile lpm-rs once, with the hermetic test feature", () => {
  const job = ciJob(readCiWorkflow(), "macos-workspace-tests");
  assert.ok(job, "missing macos-workspace-tests job");
  assert.match(job, /^    name: macOS workspace tests$/m);
  assert.match(job, /^    permissions:\n      contents: read\n/m);
  assert.doesNotMatch(job, /^    needs:/m);
  assert.doesNotMatch(job, /cargo (?:build|check|clippy)\b/);

  const selection = escapeRegExp("--locked --workspace --features lpm-cli/internal-test-sigstore-mock");
  assert.match(
    ciStep(job, "Build workspace tests") ?? "",
    new RegExp(`^        run: cargo nextest run ${selection} --no-run$`, "m"),
  );
  assert.match(
    ciStep(job, "Workspace tests") ?? "",
    new RegExp(`^        run: scripts/ci/with-hermetic-workflow-cli\\.sh --prebuilt cargo nextest run ${selection} `, "m"),
  );
});

test("macOS clippy, keychain and app bundle checks run beside the workspace tests", () => {
  const job = ciJob(readCiWorkflow(), "macos-build-checks");
  assert.ok(job, "missing macos-build-checks job");
  assert.match(job, /^    permissions:\n      contents: read\n/m);
  assert.doesNotMatch(job, /^    needs:/m);
  assert.match(job, /^          cargo check --locked -p lpm-keyring$/m);
  assert.match(job, /^          cargo check --locked -p lpm-auth$/m);
  assert.match(job, /^          cargo check --locked -p lpm-vault$/m);
  assert.match(job, /run: cargo test --locked -p lpm-keyring --test keyring3_compatibility -- --ignored$/m);
  assert.match(job, /run: cargo clippy --workspace --all-targets --locked -- -D warnings$/m);
  assert.match(
    ciStep(job, "Assemble and validate unsigned macOS app bundle") ?? "",
    /^          cargo build --locked -p lpm-cli --bin lpm-rs\n/m,
    "the bundle must hold a binary built with the shipped features",
  );
});

test("Lint builds, tests and type-checks the skills dashboard and compares its committed bundle", () => {
  const job = ciJob(readCiWorkflow(), "lint");
  assert.ok(job, "missing lint job");
  const step = ciStep(job, "Skills dashboard UI tests and committed bundle");
  assert.ok(step, "missing skills dashboard step");
  assert.ok(
    job.indexOf("      - name: Install Node 22\n") < job.indexOf("      - name: Skills dashboard UI tests and committed bundle\n"),
    "the dashboard step must run after Node is installed",
  );
  assert.match(step, /^        working-directory: crates\/lpm-cli\/dashboard-ui$/m);
  assert.match(step, /^          npm ci --no-audit --no-fund$/m);
  assert.match(step, /^          npm test$/m);
  assert.match(step, /^          npm run check:dist$/m);

  const { scripts } = JSON.parse(
    fs.readFileSync(path.join(repoRoot, "crates/lpm-cli/dashboard-ui/package.json"), "utf8"),
  );
  assert.equal(scripts.build, "tsc -b && vite build");
  assert.match(scripts["check:dist"], /^npm run build && /);
  assert.match(
    scripts["check:dist"],
    / && git add --intent-to-add -- \.\.\/src\/commands\/skills\/dashboard && git diff --exit-code -- \.\.\/src\/commands\/skills\/dashboard$/,
    "check:dist must also catch new, untracked build output",
  );
});
