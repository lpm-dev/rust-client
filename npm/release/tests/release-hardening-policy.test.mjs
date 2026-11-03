import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

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
  assert.match(promotion, /cosign verify-blob/);
  assert.match(promotion, /refs\/heads\/main\$/);
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
        /run: cp "\$\{\{ steps\.attest\.outputs\.bundle-path \}\}" \S+\/SHA256SUMS\.txt\.sigstore\n/,
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
