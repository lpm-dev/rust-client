import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import os from "node:os";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function read(relative) {
  return fs.readFileSync(path.join(repoRoot, relative), "utf8").replaceAll("\r\n", "\n");
}

function jobSource(workflow, job, nextJob) {
  const start = workflow.indexOf(`\n  ${job}:\n`);
  const end = workflow.indexOf(`\n  ${nextJob}:\n`, start + 1);
  assert.notEqual(start, -1, `missing ${job} job`);
  assert.notEqual(end, -1, `missing ${nextJob} job after ${job}`);
  return workflow.slice(start, end);
}

function jobsOf(workflow) {
  const jobs = workflow.slice(workflow.indexOf("\njobs:\n"));
  const headers = [...jobs.matchAll(/^  ([A-Za-z0-9_-]+):\n/gm)];
  return headers.map((header, index) => [
    header[1],
    jobs.slice(header.index, headers[index + 1]?.index ?? jobs.length),
  ]);
}

function stepsOf(job) {
  const start = job.indexOf("\n    steps:\n");
  return start === -1 ? [] : job.slice(start).split("\n      - ").slice(1);
}

// Every step's `run:` script in a workflow, with the line its key is on. A
// block scalar runs until the first non-blank line indented no deeper than
// the key. A job output that happens to be named `run` is not a script.
function runScripts(workflow) {
  const lines = workflow.split("\n");
  const scripts = [];
  let stepsIndent = -1;
  for (let index = 0; index < lines.length; index++) {
    const lineIndent = lines[index].length - lines[index].trimStart().length;
    if (stepsIndent !== -1 && lines[index].trim() !== "" && lineIndent <= stepsIndent) {
      stepsIndent = -1;
    }
    const steps = /^(\s*)steps:\s*$/.exec(lines[index]);
    if (steps) {
      stepsIndent = steps[1].length;
      continue;
    }
    if (stepsIndent === -1) continue;
    const key = /^(\s*)(?:- )?run:(.*)$/.exec(lines[index]);
    if (!key) continue;
    const indent = key[1].length + (lines[index].trimStart().startsWith("- ") ? 2 : 0);
    const value = key[2].trim();
    if (!/^[|>][-+]?$/.test(value)) {
      scripts.push({ line: index + 1, script: value });
      continue;
    }
    const body = [];
    let next = index + 1;
    for (; next < lines.length; next++) {
      const line = lines[next];
      if (line.trim() !== "" && line.length - line.trimStart().length <= indent) break;
      body.push(line);
    }
    scripts.push({ line: index + 1, script: body.join("\n") });
    index = next - 1;
  }
  return scripts;
}

function workflowFiles() {
  const directory = path.join(repoRoot, ".github/workflows");
  return fs
    .readdirSync(directory)
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => `.github/workflows/${name}`);
}

test("nightly and candidate construction survives the unused verification branch being skipped", () => {
  const workflow = read(".github/workflows/release.yml");
  const constructionJobs = [
    ["build", "notarize-macos", ["release-metadata", "release-preflight", "verify-windows-filesystem"]],
    ["notarize-macos", "build-windows", ["build", "release-metadata"]],
    ["build-windows", "sign-windows", ["release-metadata", "release-preflight", "verify-windows-filesystem"]],
    ["sign-windows", "pack-npm-packages", ["build-windows", "release-metadata"]],
    ["pack-npm-packages", "smoke-npm-packages", ["build", "notarize-macos", "sign-windows", "release-metadata"]],
    ["smoke-npm-packages", "smoke-windows-recovery", ["pack-npm-packages", "release-metadata"]],
    ["release", "smoke-standalone-installer", ["build", "smoke-npm-packages", "release-metadata"]],
    ["smoke-standalone-installer", "seal-candidate", ["release", "release-metadata"]],
  ];

  for (const [job, nextJob, requiredJobs] of constructionJobs) {
    const source = jobSource(workflow, job, nextJob);
    assert.match(
      source,
      /if: >-\n\s+(?:always\(\)|!cancelled\(\)) &&/,
      `${job} must override the implicit skipped-ancestor status check`,
    );
    for (const requiredJob of requiredJobs) {
      assert.match(
        source,
        new RegExp(`needs\\.${requiredJob}\\.result == 'success'`),
        `${job} must fail closed unless ${requiredJob} succeeds`,
      );
    }
  }

  for (const job of ["build", "build-windows"]) {
    const source = jobSource(
      workflow,
      job,
      job === "build" ? "notarize-macos" : "sign-windows",
    );
    assert.match(source, /mode == 'full' && needs\.verify\.result == 'success'/);
    assert.match(
      source,
      /mode == 'candidate' && needs\.verify-candidate-source\.result == 'success'/,
    );
  }
});

test("stable releases build a candidate before promotion creates the tag", () => {
  const workflow = read(".github/workflows/release.yml");
  const downloader = read("scripts/ci/download-verified-artifact.sh");
  const promotionStart = workflow.indexOf("\n  prepare-promotion:\n");
  const promotionEnd = workflow.indexOf("\n  publish-release:\n", promotionStart + 1);
  assert.notEqual(promotionStart, -1);
  assert.notEqual(promotionEnd, -1);
  const promotion = workflow.slice(promotionStart, promotionEnd);

  assert.doesNotMatch(workflow, /^\s+tags:\s*$/m);
  assert.match(workflow, /^\s+- candidate$/m);
  assert.match(workflow, /^\s+- promote$/m);
  assert.match(workflow, /name: Seal stable release candidate/);
  assert.match(workflow, /name: stable-release-candidate-\$\{\{ needs\.release-metadata\.outputs\.version \}\}/);
  assert.match(workflow, /name: stable-release-candidate-[\s\S]*?retention-days: 7/);

  assert.match(promotion, /validate-release-candidate-source\.mjs/);
  assert.match(promotion, /verify-release-candidate\.mjs/);
  assert.match(promotion, /artifact_digest: \$\{\{ steps\.source\.outputs\.artifact_digest \}\}/);
  assert.match(
    promotion,
    /artifact_digest: sha256:\$\{\{ steps\.github-assets\.outputs\['artifact-digest'\] \}\}/,
  );
  assert.match(promotion, /scripts\/ci\/download-verified-artifact\.sh/);
  assert.match(downloader, /actual_digest="sha256:\$\(sha256sum/);
  assert.match(downloader, /actual_digest" != "\$expected_digest/);
  assert.match(promotion, /Create draft and upload exact assets/);
  assert.match(promotion, /Verify exact draft and publish stable release/);
  assert.match(promotion, /Create fresh promotion-time Sigstore proof/);
  assert.match(promotion, /files: promotion-github-release\/\*/);
  assert.match(promotion, /scripts\/ci\/verify-stable-release-signer\.sh/);
  assert.match(promotion, /releases\/latest/);
  assert.match(promotion, /--source-run-id trusted/);
  assert.match(promotion, /stable promotion recovery/i);
  assert.match(workflow, /Keep .*main.*until GitHub, npm, and Homebrew promotion all succeed/);
  assert.match(promotion, /one-day scoped-artifact retention window/);
  assert.doesNotMatch(promotion, /cargo (?:build|rustc)/);
  assert.ok(
    promotion.indexOf("Verify sealed candidate") < promotion.indexOf("Create draft and upload exact assets"),
    "promotion must verify the complete candidate before creating a tag",
  );
});

test("macOS release builds one current binary per target", () => {
  const workflow = read(".github/workflows/release.yml");
  const start = workflow.indexOf("\n  build:\n");
  const end = workflow.indexOf("\n  build-windows:\n", start + 1);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const build = workflow.slice(start, end);

  assert.doesNotMatch(build, /--target-dir target\/legacy-macos-keychain/);
  assert.match(build, /Preserve app-bundle macOS binary/);
  assert.match(build, /Sign app bundle \(macOS\)/);
  assert.doesNotMatch(build, /Sign raw binary|raw-notary/i);
  assert.doesNotMatch(build, /--features legacy-macos-keychain/);
});

test("candidate runs require the fast macOS release preflight", () => {
  const workflow = read(".github/workflows/release.yml");
  const preflight = read(".github/workflows/release-preflight.yml");

  assert.match(workflow, /uses: \.\/\.github\/workflows\/release-preflight\.yml/);
  assert.match(preflight, /APPLE_DEVELOPER_ID_P12_BASE64/);
  assert.match(preflight, /APPLE_CLI_PROVISIONING_PROFILE_BASE64/);
  assert.match(preflight, /test-macos-keychain-search-list\.sh/);
  assert.match(preflight, /notarytool history/);
  assert.match(preflight, /release-api-contract\.test\.mjs/);
});

test("macOS notarization retries submissions and resumes polling by submission ID", () => {
  const workflow = read(".github/workflows/release.yml");
  const helper = read("scripts/ci/notarize-with-retry.sh");

  assert.match(workflow, /scripts\/ci\/notarize-with-retry\.sh/);
  assert.match(helper, /notarytool submit/);
  assert.match(helper, /notarytool info/);
  assert.match(helper, /submission_id/);
  assert.match(helper, /MAX_SUBMIT_ATTEMPTS/);
  assert.match(workflow, /Persist notarization submission IDs before polling/);
  assert.match(workflow, /notarization-state-\$\{\{ matrix\.binary \}\}-\$\{\{ github\.run_attempt \}\}/);
  assert.ok(
    workflow.indexOf("LPM_NOTARY_MODE=submit") <
      workflow.indexOf("Persist notarization submission IDs before polling"),
  );
  assert.ok(
    workflow.indexOf("Persist notarization submission IDs before polling") <
      workflow.indexOf("LPM_NOTARY_MODE=poll"),
  );
  assert.doesNotMatch(workflow, /notarytool submit .*--wait/);
  const packStart = workflow.indexOf("\n  pack-npm-packages:\n");
  const packEnd = workflow.indexOf("\n  smoke-npm-packages:\n", packStart + 1);
  const pack = workflow.slice(packStart, packEnd);
  assert.match(pack, /needs:[\s\S]*?- notarize-macos/);
});

test("macOS signing and ticket checks outlast transient Apple service failures", () => {
  const workflow = read(".github/workflows/release.yml");
  const preflight = read(".github/workflows/release-preflight.yml");
  const ci = read(".github/workflows/ci.yml");

  assert.match(
    workflow,
    /scripts\/ci\/with-apple-service-retry\.sh" codesign \\\n\s+--force --timestamp --options runtime/,
  );
  assert.doesNotMatch(
    workflow,
    /^\s*(\/usr\/bin\/)?codesign [^\n]*--timestamp/m,
    "timestamped signatures must retry the timestamp authority",
  );
  assert.doesNotMatch(workflow, /xcrun stapler/, "stapler must retry the ticketing service");
  assert.deepEqual(
    [...workflow.matchAll(/with-apple-service-retry\.sh stapler (staple|validate) /g)].map(
      match => match[1],
    ),
    ["staple", "validate", "validate"],
  );
  assert.match(preflight, /bash scripts\/ci\/test-with-apple-service-retry\.sh/);
  assert.match(ci, /bash scripts\/ci\/test-with-apple-service-retry\.sh/);
});

test("Windows signing registers the PowerShell Gallery before the signing action installs from it", () => {
  const signingJobs = [];
  const workflows = fs
    .readdirSync(path.join(repoRoot, ".github/workflows"))
    .filter(name => /\.ya?ml$/.test(name))
    .sort();
  for (const file of workflows) {
    for (const [job, source] of jobsOf(read(`.github/workflows/${file}`))) {
      const steps = stepsOf(source);
      const signing = steps.findIndex(step => /\buses: azure\/artifact-signing-action@/.test(step));
      if (signing === -1) continue;
      signingJobs.push(`${file}:${job}`);

      const registration = steps.findIndex(step => /Register-PSRepository -Default/.test(step));
      assert.ok(
        registration !== -1 && registration < signing,
        `${file}:${job} must register PSGallery before the signing action installs its module`,
      );
      const step = steps[registration];
      assert.match(step, /\n        shell: pwsh\n/, `${file}:${job} must register PSGallery for pwsh`);
      assert.doesNotMatch(
        step,
        /^        (if|continue-on-error):/m,
        `${file}:${job} must always register PSGallery, and fail if it can't`,
      );
      assert.match(
        step,
        /if \(-not \(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue\)\) \{\n\s+Register-PSRepository -Default\n(?:\s+#.*\n)*\s+\$global:LASTEXITCODE = 0\n\s+\}\n\s+Get-PSRepository -Name PSGallery \|/,
        `${file}:${job} must register PSGallery only when it is missing, let the check after it decide the step's result, then confirm it is there`,
      );
    }
  }
  for (const job of ["release.yml:sign-windows", "windows-signing-smoke.yml:sign"]) {
    assert.ok(signingJobs.includes(job), `expected ${job} to use the signing action`);
  }
});

test("candidate smoke and sealing hard-enforce uploaded artifact digests", () => {
  const workflow = read(".github/workflows/release.yml");
  for (const [jobName, nextJob] of [
    ["smoke-npm-packages", "smoke-windows-recovery"],
    ["smoke-standalone-installer", "seal-candidate"],
    ["seal-candidate", "prepare-promotion"],
  ]) {
    const start = workflow.indexOf(`\n  ${jobName}:\n`);
    const next = workflow.indexOf(`\n  ${nextJob}:\n`, start + 4);
    assert.notEqual(start, -1, `missing ${jobName}`);
    assert.notEqual(next, -1, `missing ${nextJob}`);
    const job = workflow.slice(start, next);
    assert.match(job, /scripts\/ci\/download-verified-artifact\.sh/);
    assert.match(job, /ARTIFACT_DIGEST:/);
  }
});

test("macOS standalone smoke keeps its bounded server-start counter", () => {
  const workflow = read(".github/workflows/release.yml");
  const start = workflow.indexOf("python3 -m http.server 8765 --bind 127.0.0.1");
  const end = workflow.indexOf("# Exercise the real compatibility path", start + 1);
  const serverWait = workflow.slice(start, end);
  assert.match(serverWait, /for attempt in \{1\.\.30\}; do/);
  assert.match(serverWait, /if \[ "\$attempt" -eq 30 \]; then/);
});

test("promotion waits for the correlated Homebrew update", () => {
  const promotion = read(".github/workflows/release.yml");

  assert.match(promotion, /correlation_id/);
  assert.match(promotion, /Await correlated Homebrew workflow/);
  assert.match(promotion, /actions\/runs/);
  assert.match(promotion, /conclusion.*success/);
});

test("the Homebrew update reaches the tap only with a per-run app token scoped to it", () => {
  const workflow = read(".github/workflows/release.yml");
  const job = jobsOf(workflow).find(([name]) => name === "update-homebrew")?.[1];
  assert.ok(job, "missing update-homebrew job");

  assert.doesNotMatch(workflow, /HOMEBREW_TAP_TOKEN/, "no job may use the long-lived tap token");
  const mint = stepsOf(job).find((step) => step.startsWith("name: Create a token for the Homebrew tap"));
  assert.ok(mint, "update-homebrew must mint its own tap token");
  assert.match(mint, /uses: actions\/create-github-app-token@[0-9a-f]{40} #/);
  assert.match(mint, /client-id: \$\{\{ vars\.HOMEBREW_APP_CLIENT_ID \}\}/);
  assert.match(mint, /private-key: \$\{\{ secrets\.HOMEBREW_APP_PRIVATE_KEY \}\}/);
  assert.match(mint, /owner: lpm-dev\n\s+repositories: homebrew-lpm\n/);
  assert.match(mint, /permission-contents: write\n\s+permission-actions: read\n/);
  assert.doesNotMatch(mint, /permission-(?!contents|actions)/, "the token needs no other permission");

  const tapSteps = ["Dispatch correlated Homebrew update", "Await correlated Homebrew workflow"];
  for (const step of stepsOf(job)) {
    const token = step.match(/GH_TOKEN: (.+)/)?.[1];
    if (tapSteps.some((name) => step.startsWith(`name: ${name}`))) {
      assert.equal(token, "${{ steps.tap-token.outputs.token }}", step.split("\n")[0]);
    } else if (token !== undefined) {
      assert.equal(token, "${{ github.token }}", `${step.split("\n")[0]} must not hold the tap token`);
    }
  }
});

test("every SHA256SUMS.txt attestation passes the shipped self-update policy before anything else runs", () => {
  const workflow = read(".github/workflows/release.yml");
  const attestingJobs = jobsOf(workflow).filter(([, job]) =>
    job.includes("uses: actions/attest-build-provenance@"),
  );
  const gatedCommit = { release: "$GITHUB_SHA", "stage-promotion-release": "$SOURCE_SHA" };
  assert.deepEqual(
    attestingJobs.map(([name]) => name),
    Object.keys(gatedCommit),
  );

  for (const [name, job] of attestingJobs) {
    const steps = stepsOf(job);
    const attest = steps.findIndex(step => step.includes("uses: actions/attest-build-provenance@"));
    const gate = steps.findIndex(step => step.includes("scripts/ci/verify-release-signing-policy.sh"));
    assert.ok(gate > attest, `${name} must verify its fresh attestation with the shipped self-update policy`);
    for (const step of steps.slice(attest + 1, gate)) {
      assert.match(
        step,
        /env:\n\s+ATTESTATION_BUNDLE: \$\{\{ steps\.attest\.outputs\.bundle-path \}\}\n\s+run: cp "\$\{ATTESTATION_BUNDLE\}" \S+\/SHA256SUMS\.txt\.sigstore\n/,
        `${name} may only stage the bundle between attesting and verifying it`,
      );
    }

    const manifestDir = steps[attest].match(/subject-path: (\S+)\/SHA256SUMS\.txt\n/)?.[1];
    assert.ok(manifestDir, `${name} must attest a SHA256SUMS.txt`);
    const gateStep = steps[gate];
    assert.match(gateStep, /RELEASE_VERSION: \$\{\{ needs\.release-metadata\.outputs\.version \}\}/);
    const argumentPositions = [
      "scripts/ci/verify-release-signing-policy.sh",
      `${manifestDir}/lpm-linux-x64`,
      '"$RELEASE_VERSION"',
      `${manifestDir}/SHA256SUMS.txt`,
      `${manifestDir}/SHA256SUMS.txt.sigstore`,
      `"${gatedCommit[name]}"`,
    ].map(argument => [argument, gateStep.indexOf(`\n          ${argument}\n`)]);
    for (const [index, [argument, position]] of argumentPositions.entries()) {
      assert.ok(position >= 0, `${name} gate must pass ${argument}`);
      assert.ok(
        index === 0 || position > argumentPositions[index - 1][1],
        `${name} gate must pass ${argument} after ${argumentPositions[index - 1]?.[0]}`,
      );
    }
  }
});

test("a full-mode release is published only while its draft targets the commit the signing-policy gate bound", () => {
  const workflow = read(".github/workflows/release.yml");
  const release = jobSource(workflow, "release", "smoke-standalone-installer");
  assert.match(release, /^\s+target_commitish: \$\{\{ github\.sha \}\}$/m);

  const publish = jobSource(workflow, "publish-release", "publish-npm-platform");
  const targetCheck = publish.indexOf('if [ "$draft_target" != "$GITHUB_SHA" ]; then');
  assert.ok(targetCheck >= 0, "publish-release must compare the draft target with the gated commit");
  assert.match(
    publish,
    /draft_target=\$\(gh api "repos\/\$\{GITHUB_REPOSITORY\}\/releases\/\$\{release_id\}" --jq \.target_commitish\)/,
  );
  assert.ok(
    targetCheck < publish.indexOf("-F draft=false"),
    "the draft target must be checked before the draft is published",
  );
});

test("a promoted stable release passes the shipped self-update policy with its published metadata", () => {
  const workflow = read(".github/workflows/release.yml");
  const finalize = jobSource(workflow, "finalize-promotion-release", "publish-release");
  const steps = stepsOf(finalize);
  const published = steps.findIndex(step => step.startsWith("name: Verify published tag and exact release assets\n"));
  const gate = steps.findIndex(step => step.includes("scripts/ci/verify-release-signing-policy.sh"));
  assert.ok(published >= 0, "finalize-promotion-release must download the published release");
  assert.equal(gate, published + 1, "the published release must be verified right after it is downloaded");

  const gateStep = steps[gate];
  assert.doesNotMatch(gateStep, /^\s+if:/m, "an already-published release must be verified on every run");
  assert.match(gateStep, /set -euo pipefail\n/);
  assert.match(gateStep, /target_commit=\$\(jq -er '\.target_commitish' "\$RUNNER_TEMP\/published-release\.json"\)\n/);
  assert.match(gateStep, /published_at=\$\(jq -er '\.published_at' "\$RUNNER_TEMP\/published-release\.json"\)\n/);
  const argumentPositions = [
    "scripts/ci/verify-release-signing-policy.sh",
    "release-candidate/github-release/lpm-linux-x64",
    '"$RELEASE_VERSION"',
    '"$RUNNER_TEMP/published-release/SHA256SUMS.txt"',
    '"$RUNNER_TEMP/published-release/SHA256SUMS.txt.sigstore"',
    '"$target_commit"',
    '"$published_at"',
  ].map(argument => [argument, gateStep.indexOf(argument)]);
  for (const [index, [argument, position]] of argumentPositions.entries()) {
    assert.ok(position >= 0, `published-release gate must pass ${argument}`);
    assert.ok(
      index === 0 || position > argumentPositions[index - 1][1],
      `published-release gate must pass ${argument} after ${argumentPositions[index - 1]?.[0]}`,
    );
  }
});

test("workflow run scripts never expand template expressions", () => {
  // Expressions are substituted into the script text before the shell
  // parses it, so a dispatch input, an event field or an upstream output
  // could run as code. Scripts read every such value through `env:`.
  const expansions = [];
  for (const file of workflowFiles()) {
    for (const { line, script } of runScripts(read(file))) {
      for (const match of script.matchAll(/\$\{\{[^}]*\}\}/g)) {
        expansions.push(`${file}:${line} ${match[0]}`);
      }
    }
  }
  assert.deepEqual(expansions, []);
});

test("release metadata validates every dispatch input as a whole value before any job reads it", () => {
  const workflow = read(".github/workflows/release.yml");
  const metadata = jobSource(workflow, "release-metadata", "verify");

  assert.match(metadata, /INPUT_SOURCE_RUN_ID: \$\{\{ inputs\.source_run_id \}\}/);
  assert.match(metadata, /source_run_id: \$\{\{ steps\.metadata\.outputs\.source_run_id \}\}/);
  assert.match(metadata, /\[\[ "\$SOURCE_RUN_ID" =~ \^\[1-9\]\[0-9\]\{0,18\}\$ \]\]/);
  assert.match(metadata, /promote \| windows-smoke-only \| npm-publish-only \| wrapper-only\)/);
  assert.match(metadata, /candidate \| full\)/);
  assert.match(metadata, /echo "source_run_id=\$SOURCE_RUN_ID"/);

  // Each input is matched as one whole value, never line by line.
  assert.doesNotMatch(metadata, /printf '%s\\n' "\$(?:VERSION|NPM_NIGHTLY|SOURCE_RUN_ID)" \|\s*grep/);
  assert.match(metadata, /\[\[ "\$VERSION" =~ \$STABLE_VERSION_PATTERN \]\]/);
  assert.match(metadata, /\[\[ "\$VERSION" =~ \$NIGHTLY_VERSION_PATTERN \]\]/);
  assert.match(metadata, /\[\[ "\$NPM_NIGHTLY" =~ \$NIGHTLY_VERSION_PATTERN \]\]/);
  assert.match(metadata, /case "\$MODE" in\n\s+candidate \| promote \| full \| wrapper-only \| windows-smoke-only \| npm-publish-only\) ;;/);

  const outside = workflow.replace(metadata, "");
  assert.doesNotMatch(outside, /inputs\.source_run_id/, "later jobs must read the validated run ID");
});

test("release metadata accepts only whole, valid dispatch inputs when its script runs", {
  skip: process.platform === "win32" && "runs the release metadata script with bash",
}, () => {
  const workflow = read(".github/workflows/release.yml");
  const metadata = jobSource(workflow, "release-metadata", "verify");
  const scripts = runScripts(metadata).filter(({ script }) => script.includes("STABLE_VERSION_PATTERN="));
  assert.equal(scripts.length, 1, "missing the metadata script");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-release-metadata-"));
  const script = path.join(directory, "metadata.sh");
  fs.writeFileSync(script, scripts[0].script.replace(/^ {10}/gm, ""));
  const run = (mode, version, sourceRunId, channel = "stable") => {
    const output = path.join(directory, "output");
    fs.rmSync(output, { force: true });
    const result = spawnSync("bash", ["-e", script], {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        GITHUB_EVENT_NAME: "workflow_dispatch",
        GITHUB_REF: "refs/heads/main",
        GITHUB_OUTPUT: output,
        GITHUB_REPOSITORY: "lpm-dev/rust-client",
        INPUT_CHANNEL: channel,
        INPUT_MODE: mode,
        INPUT_VERSION: version,
        INPUT_SOURCE_RUN_ID: sourceRunId,
      },
    });
    const written = fs.existsSync(output) ? fs.readFileSync(output, "utf8") : "";
    return { status: result.status, written, stderr: result.stdout + result.stderr };
  };
  try {
    const promote = run("promote", "0.88.0", "123");
    assert.equal(promote.status, 0, promote.stderr);
    assert.match(promote.written, /^source_run_id=123$/m);
    assert.match(promote.written, /^tag=v0\.88\.0$/m);
    const recovery = run("npm-publish-only", "0.88.0", "456");
    assert.equal(recovery.status, 0, recovery.stderr);
    assert.match(recovery.written, /^source_run_id=456$/m);
    const nightly = "0.88.0-nightly.20261119.270.abcdef0";
    const nightlyRecovery = run("npm-publish-only", nightly, "789", "nightly");
    assert.equal(nightlyRecovery.status, 0, nightlyRecovery.stderr);
    assert.match(nightlyRecovery.written, /^npm_tag=nightly$/m);
    assert.match(nightlyRecovery.written, new RegExp(`^version=${nightly.replaceAll(".", "\\.")}$`, "m"));

    for (const [mode, version, sourceRunId, channel = "stable"] of [
      ["promote", "0.88.0", "12a3"],
      ["promote", "0.88.0\ntag=v9.9.9", "123"],
      ["promote", "0.88.0", ""],
      ["promote", "0.88.0", "0123"],
      ["promote", "0.88.0", "123\n456"],
      ["candidate", "0.88.0", "123"],
      ["unknown", "0.88.0", "123"],
      ["npm-publish-only", `${"0.88.0-nightly.20261119.270.abcdef0"}\ntag=v9.9.9`, "789", "nightly"],
      ["npm-publish-only", "0.88.0", "789", "nightly"],
      ["promote", "0.88.0-nightly.20261119.270.abcdef0", "789", "nightly"],
      ["promote", "0.88.0", "123", "beta"],
    ]) {
      const refused = run(mode, version, sourceRunId, channel);
      const label = JSON.stringify({ mode, version, sourceRunId, channel });
      assert.notEqual(refused.status, 0, `${label} must be refused`);
      assert.equal(refused.written, "", `${label} must write no outputs`);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("a published release must be immutable, checked after every publication path", () => {
  const workflow = read(".github/workflows/release.yml");
  const jobs = jobsOf(workflow);
  const entry = jobs.find(([name]) => name === "require-immutable-release");
  assert.ok(entry, "missing require-immutable-release job");
  const [, job] = entry;
  assert.equal(jobs.at(-1)[0], "require-immutable-release", "the check runs after Homebrew, last");
  for (const dependency of ["finalize-promotion-release", "publish-release", "release-metadata", "update-homebrew"]) {
    assert.match(job, new RegExp(`\\n      - ${dependency}\\n`), `must wait for ${dependency}`);
  }
  assert.match(job, /needs\.finalize-promotion-release\.result == 'success' \|\|\s+needs\.publish-release\.result == 'success'/);
  assert.match(job, /permissions:\n\s+contents: read\n/);
  assert.match(job, /RELEASE_TAG: \$\{\{ needs\.release-metadata\.outputs\.tag \}\}/);
  assert.match(job, /releases\/tags\/\$\{RELEASE_TAG\}/);
  assert.match(job, /\.immutable == true/);
  assert.match(job, /exit 1/);
});

test("the installer's security floor admits only releases that can update to main-signed releases", () => {
  const installer = read("install.sh");
  const floor = installer.match(/^MIN_VERSION="v(\d+)\.(\d+)\.(\d+)"$/m);
  assert.ok(floor, "install.sh must set MIN_VERSION to vX.Y.Z");
  const [major, minor, patch] = floor.slice(1).map(Number);
  // 0.85.0 is the first release that follows the releases signed from main
  // and binds a release to its signed source commit.
  assert.ok(
    major > 0 || minor > 85 || (minor === 85 && patch >= 0),
    `MIN_VERSION v${major}.${minor}.${patch} is below v0.85.0`,
  );
  const workspace = read("Cargo.toml").match(/^\[workspace\.package\]\nversion = "(\d+)\.(\d+)\.(\d+)"$/m);
  assert.ok(workspace, "missing workspace version");
  const [wMajor, wMinor, wPatch] = workspace.slice(1).map(Number);
  assert.ok(
    major < wMajor || (major === wMajor && (minor < wMinor || (minor === wMinor && patch <= wPatch))),
    "the floor can't be above the release being built, or every install of it is refused",
  );

  const harness = read("tests/install-sh/run.sh");
  assert.match(harness, new RegExp(`^FIXTURE_VERSION="v${major}\\.${minor}\\.${patch}"$`, "m"));
});

test("every stable release signature check holds the one exact signing identity", () => {
  const workflow = read(".github/workflows/release.yml");
  for (const file of [...workflowFiles(), "install.sh"]) {
    assert.doesNotMatch(read(file), /certificate-identity-regexp/, `${file} must match the exact identity`);
  }
  assert.doesNotMatch(workflow, /cosign verify-blob/, "release.yml checks signatures through the shared script");
  const calls = [...workflow.matchAll(/scripts\/ci\/verify-stable-release-signer\.sh(?: \\)?\n\s+(\S+)(?: \\)?\n\s+(\S+)(?: \\)?\n\s+(\S+)\n/g)];
  assert.equal(calls.length, 5, "four promotion checks and the Homebrew exporter");
  for (const [, manifest, bundle, commit] of calls) {
    assert.match(manifest, /SHA256SUMS\.txt"?$/);
    assert.equal(bundle, manifest.replace(/SHA256SUMS\.txt("?)$/, "SHA256SUMS.txt.sigstore$1"));
    assert.equal(commit, '"$SOURCE_SHA"');
  }
});

test("the stable signer script passes cosign the exact identity and refuses a malformed commit", () => {
  const script = path.join(repoRoot, "scripts/ci/verify-stable-release-signer.sh");
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-cosign-stub-"));
  const argsFile = path.join(bin, "args");
  fs.writeFileSync(path.join(bin, "cosign"), `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsFile}"\n`, { mode: 0o755 });
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
  const commit = "ef061b3e90d93f5822b870a844a5b37adc9059d4";
  try {
    const ok = spawnSync("bash", [script, "SHA256SUMS.txt", "SHA256SUMS.txt.sigstore", commit], { env, encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(fs.readFileSync(argsFile, "utf8").trimEnd().split("\n"), [
      "verify-blob",
      "--bundle", "SHA256SUMS.txt.sigstore",
      "--certificate-identity", "https://github.com/lpm-dev/rust-client/.github/workflows/release.yml@refs/heads/main",
      "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
      "--certificate-github-workflow-repository", "lpm-dev/rust-client",
      "--certificate-github-workflow-ref", "refs/heads/main",
      "--certificate-github-workflow-sha", commit,
      "--certificate-github-workflow-trigger", "workflow_dispatch",
      "SHA256SUMS.txt",
    ]);

    fs.rmSync(argsFile);
    for (const bad of ["ef061b3", `${commit}\nx`, commit.toUpperCase(), ""]) {
      const refused = spawnSync("bash", [script, "SHA256SUMS.txt", "SHA256SUMS.txt.sigstore", bad], { env, encoding: "utf8" });
      assert.equal(refused.status, 2, `must refuse ${JSON.stringify(bad)}`);
      assert.equal(fs.existsSync(argsFile), false, "cosign must not run for a malformed commit");
    }
  } finally {
    fs.rmSync(bin, { recursive: true, force: true });
  }
});

test("the Homebrew formula takes its checksums from the published release, verified against the promoted commit", () => {
  const workflow = read(".github/workflows/release.yml");
  const job = jobsOf(workflow).find(([name]) => name === "update-homebrew")?.[1];
  assert.ok(job, "missing update-homebrew job");

  assert.doesNotMatch(job, /mode == 'full'/, "stable releases are never built in full mode");
  assert.match(job, /needs\.release-metadata\.outputs\.mode == 'promote' &&/);
  assert.match(job, /SOURCE_SHA: \$\{\{ needs\.prepare-promotion\.outputs\.source_sha \}\}/);
  // A retry must work for as long as the release exists, so the job reads
  // no artifact with a short retention.
  assert.doesNotMatch(job, /download-verified-artifact|promotion-github-release|stage-promotion-release/);
  assert.match(job, /\[ "\$target_commit" != "\$SOURCE_SHA" \]/);
  assert.match(job, /--pattern SHA256SUMS\.txt --pattern SHA256SUMS\.txt\.sigstore --pattern lpm-linux-x64/);
  assert.match(job, /grep -E '\^\[0-9a-f\]\{64\}  lpm-linux-x64\$' SHA256SUMS\.txt \| sha256sum --check --strict/);
  assert.doesNotMatch(job, /releases\/download/, "the published release is read through the API, not by URL");

  const order = [
    "verify-stable-release-signer.sh",
    "sha256sum --check --strict",
    "verify-release-signing-policy.sh",
    "export_manifest_hash lpm-darwin-arm64.zip",
    "Create a token for the Homebrew tap",
  ];
  const positions = order.map((needle) => job.indexOf(needle));
  assert.ok(positions.every((position) => position !== -1), JSON.stringify(positions));
  assert.deepEqual([...positions].sort((a, b) => a - b), positions, "checks run before the checksums are exported and dispatched");
});
