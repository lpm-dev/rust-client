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

function readWorkflow(name) {
  return fs
    .readFileSync(path.join(repoRoot, ".github/workflows", name), "utf8")
    .replaceAll("\r\n", "\n");
}

function readCiWorkflow() {
  return readWorkflow("ci.yml");
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
  assert.match(
    gate,
    /^    if: \$\{\{ always\(\) && !github\.event\.pull_request\.draft \}\}$/m,
    "a gate skipped by a failed job counts as passing",
  );
  const needs = gate.match(/^    needs: \[([^\]]+)\]$/m)?.[1].split(",").map((job) => job.trim());
  assert.deepEqual(needs, ["macos-workspace-tests", "macos-build-checks"]);
  assert.match(macosWorkspaceTests(), /^    runs-on: macos-latest$/m, "macos-workspace-tests must run on macOS");
  assert.match(ciJob(workflow, "macos-build-checks") ?? "", /^    runs-on: macos-latest$/m, "macos-build-checks must run on macOS");

  const step = ciStep(gate, "Require every macOS job to pass");
  assert.ok(step, "missing macOS gate step");
  assert.match(step, /^          NEEDS: \$\{\{ toJSON\(needs\) \}\}$/m);
  assert.match(
    step,
    /^          DEFERRED: \$\{\{ github\.event_name == 'pull_request' && 'macos-workspace-tests' \|\| '' \}\}$/m,
    "only a pull request leaves the workspace tests to Full CI",
  );
  const script = step
    .match(/^        run: \|\n((?:          .*\n|\n)+)/m)?.[1]
    .replace(/^ {10}/gm, "");
  assert.ok(script, "missing macOS gate script");

  const gateStatus = (results, deferred = "") => {
    const reported = Object.fromEntries(needs.map((job, index) => [job, { result: results[index], outputs: {} }]));
    return spawnSync("bash", ["-e", "-c", script], {
      env: { ...process.env, NEEDS: JSON.stringify(reported), DEFERRED: deferred },
      encoding: "utf8",
    }).status;
  };
  assert.equal(gateStatus(["success", "success"]), 0);
  for (const result of ["failure", "cancelled", "skipped"]) {
    assert.notEqual(gateStatus([result, "success"]), 0, `gate passed with ${needs[0]} ${result}`);
    assert.notEqual(gateStatus(["success", result]), 0, `gate passed with ${needs[1]} ${result}`);
  }

  const onPullRequest = (results) => gateStatus(results, "macos-workspace-tests");
  assert.equal(onPullRequest(["skipped", "success"]), 0, "a pull request's gate must pass without the workspace tests");
  assert.equal(onPullRequest(["success", "success"]), 0);
  for (const result of ["failure", "cancelled"]) {
    assert.notEqual(onPullRequest([result, "success"]), 0, `a pull request's gate passed with ${needs[0]} ${result}`);
  }
  for (const result of ["failure", "cancelled", "skipped"]) {
    assert.notEqual(onPullRequest(["skipped", result]), 0, `a pull request's gate passed with ${needs[1]} ${result}`);
  }
});

function macosWorkspaceTests() {
  const job = ciJob(readWorkflow("macos-workspace-tests.yml"), "verify");
  assert.ok(job, "missing macOS workspace tests job");
  return job;
}

test("macOS workspace tests compile lpm-rs once, with the hermetic test feature", () => {
  const job = macosWorkspaceTests();
  assert.match(job, /^    name: macOS workspace tests$/m);
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

test("the CI workflow token can only read the repository", () => {
  const workflow = readCiWorkflow();
  assert.match(workflow, /^permissions:\n  contents: read\n/m);
  for (const grant of workflow.matchAll(/^ +permissions:(.*)$/gm)) {
    assert.equal(grant[1].trim(), "{}", `a job widens the workflow token: ${grant[0].trim()}`);
  }
});

const DRAFT_GATE = "${{ !github.event.pull_request.draft }}";
const DRAFT_GATE_AFTER_ANY_RESULT = "${{ always() && !github.event.pull_request.draft }}";

test("draft pull requests run no CI jobs, and marking one ready runs them all", () => {
  const pullRequestWorkflows = fs
    .readdirSync(path.join(repoRoot, ".github/workflows"))
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => [name, readWorkflow(name)])
    .filter(([, workflow]) => /^  pull_request:$|^on:.*\bpull_request\b/m.test(workflowTriggers(workflow)));
  assert.ok(pullRequestWorkflows.some(([name]) => name === "ci.yml"), "CI no longer runs on pull requests");

  for (const [name, workflow] of pullRequestWorkflows.filter(([name]) => name !== "full-ci.yml")) {
    // Branch protection counts a skipped check as passing, so a draft's skipped
    // checks must be replaced by a full run the moment the PR is marked ready.
    const trigger = workflow.match(/^  pull_request:\n((?:    .*\n)*)/m)?.[1] ?? "";
    assert.match(
      trigger,
      /^    types: \[opened, synchronize, reopened, ready_for_review\]$/m,
      `${name} must run again when a draft is marked ready`,
    );

    const jobs = workflowJobs(workflow);
    assert.ok(jobs.length > 0, `${name} has no jobs`);
    for (const [id, job] of jobs) {
      const condition = job.match(/^    if: (.*)$/m)?.[1];
      assert.ok(
        condition === DRAFT_GATE || condition === DRAFT_GATE_AFTER_ANY_RESULT || skipsPullRequests(condition),
        `${name} job ${id} must skip draft PRs and nothing else (if: ${DRAFT_GATE}), ` +
          `or not run on pull requests; found ${condition ?? "no condition"}`,
      );
    }
  }
});

function workflowTriggers(workflow) {
  const jobs = workflow.indexOf("\njobs:\n");
  return jobs === -1 ? workflow : workflow.slice(0, jobs);
}

function workflowJobs(workflow) {
  const jobs = workflow.indexOf("\njobs:\n");
  if (jobs === -1) return [];
  return [...workflow.slice(jobs).matchAll(/^  ([a-z][\w-]*):\n([\s\S]*?)(?=^  [a-z][\w-]*:$|(?![\s\S]))/gm)]
    .map(([, id, job]) => [id, job]);
}

function skipsPullRequests(condition) {
  if (condition === undefined) return false;
  if (condition === "github.event_name != 'pull_request'") return true;
  return condition
    .split(" || ")
    .every((clause) => /^github\.event_name == '(?:push|schedule|workflow_dispatch)'$/.test(clause));
}

const FULL_TIER = ["windows-filesystem", "windows-filesystem-arm64", "macos-workspace-tests"];
const FULL_CI_EVENTS = "(github.event.action != 'labeled' || github.event.label.name == 'full-ci')";

function reusableCall(job) {
  return job.match(/^    uses: .*\n(?:    with:\n(?:      .*\n)+)?/m)?.[0];
}

test("pull request CI leaves the Windows filesystem gates and macOS workspace tests to Full CI", () => {
  const ci = readCiWorkflow();
  const fullCi = readWorkflow("full-ci.yml");
  for (const id of FULL_TIER) {
    const inCi = ciJob(ci, id);
    const inFullCi = ciJob(fullCi, id);
    assert.ok(inCi, `ci.yml is missing ${id}, which pushes to main run`);
    assert.ok(inFullCi, `full-ci.yml is missing ${id}`);
    assert.match(inCi, /^    if: github\.event_name != 'pull_request'$/m, `${id} must not run in pull request CI`);
    assert.ok(reusableCall(inCi), `${id} must call a reusable workflow`);
    assert.equal(reusableCall(inFullCi), reusableCall(inCi), `${id} must be the same job in both workflows`);
  }
  assert.match(ciJob(ci, "windows-filesystem-arm64"), /^      runner: windows-11-arm$/m);
});

test("Full CI runs its tier where the plan says, and never for a draft or an unrelated label", () => {
  const workflow = readWorkflow("full-ci.yml");
  const trigger = workflow.match(/^  pull_request:\n((?:    .*\n)*)/m)?.[1] ?? "";
  assert.match(trigger, /^    branches: \[main, "codex\/\*\*"\]$/m);
  assert.match(
    trigger,
    /^    types: \[opened, synchronize, reopened, ready_for_review, labeled\]$/m,
    "Full CI must run again when a draft is marked ready, and when its label is added",
  );
  assert.match(workflow, /^  workflow_dispatch:$/m);
  assert.match(workflow, /^permissions:\n  contents: read\n/m);

  assert.ok(
    workflow.includes(
      "  group: full-ci-${{ github.event_name == 'pull_request' && " + FULL_CI_EVENTS +
        " && format('pr-{0}', github.event.pull_request.number) || github.run_id }}\n  cancel-in-progress: true\n",
    ),
    "an unrelated label must not cancel the pull request's run",
  );

  const jobs = Object.fromEntries(workflowJobs(workflow));
  assert.deepEqual(Object.keys(jobs), ["plan", ...FULL_TIER, "report"]);
  assert.ok(
    jobs.plan.includes(`    if: \${{ !github.event.pull_request.draft && ${FULL_CI_EVENTS} }}\n`),
    "the plan must skip drafts and labels other than full-ci",
  );
  assert.match(jobs.plan, /^      run: \$\{\{ steps\.plan\.outputs\.run \}\}$/m);
  assert.match(
    jobs.plan,
    /^          LABELED: \$\{\{ contains\(github\.event\.pull_request\.labels\.\*\.name, 'full-ci'\) && 'yes' \|\| '' \}\}$/m,
  );
  for (const id of FULL_TIER) {
    assert.match(jobs[id], /^    needs: plan$/m, `${id} must wait for the plan`);
    assert.match(jobs[id], /^    if: \$\{\{ needs\.plan\.outputs\.run == 'true' \}\}$/m, `${id} must follow the plan`);
  }

  assert.match(jobs.report, new RegExp(`^    needs: \\[plan, ${FULL_TIER.join(", ")}\\]$`, "m"));
  assert.match(
    jobs.report,
    /^    if: \$\{\{ !cancelled\(\) && needs\.plan\.outputs\.run == 'true' \}\}$/m,
    "the result must be reported when a tier job fails, and not when the run is replaced",
  );
  assert.match(jobs.report, /^    permissions:\n      contents: read\n      pull-requests: read\n      statuses: write\n/m);
  assert.match(jobs.report, /^          NEEDS: \$\{\{ toJSON\(needs\) \}\}$/m);
  for (const [id, job] of Object.entries(jobs)) {
    if (id !== "report") assert.doesNotMatch(job, /^    permissions:/m, `${id} must not widen the workflow token`);
  }
});
