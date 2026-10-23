import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PROPAGATION_TIMEOUT_MS,
  PUBLICATION_SCOPES,
  verifyRegistryPublications,
} from "../verify-registry-publication.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const VERSION = "0.81.0";
const PREVIOUS_VERSION = "0.80.0";
const WRAPPER = "@lpm-registry/cli";
const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
const PLATFORMS = [
  "@lpm-registry/cli-darwin-arm64",
  "@lpm-registry/cli-darwin-x64",
  "@lpm-registry/cli-linux-arm64",
  "@lpm-registry/cli-linux-x64",
  "@lpm-registry/cli-linux-x64-musl",
  "@lpm-registry/cli-win32-x64",
];
const NPM_PUBLISH_JOBS = Object.freeze([
  "publish-promotion-platform",
  "publish-npm-platform",
  "publish-npm-wrapper",
]);
const NON_WAITING_STEP_MINUTES = 15;

test("the platform scope covers all six platform packages and nothing else", () => {
  assert.deepEqual([...PUBLICATION_SCOPES.platforms].sort(), PLATFORMS);
  assert.deepEqual(PUBLICATION_SCOPES.wrapper, [WRAPPER]);
});

test("registry publication passes when npm serves every platform package exactly", async () => {
  const registry = fakeRegistry(releaseManifest());

  const result = await verifyRegistryPublications({
    releaseManifest: registry.manifest,
    scope: "platforms",
    expectedTag: "latest",
    ...registry.options,
  });

  assert.deepEqual([...result.packages].sort(), PLATFORMS);
  assert.equal(result.version, VERSION);
  assert.deepEqual(
    registry.requests.map(url => decodeURIComponent(new URL(url).pathname.slice(1))).sort(),
    PLATFORMS,
  );
  assert.deepEqual(registry.sleeps, []);
});

test("registry publication waits for a package that is still propagating", async () => {
  const registry = fakeRegistry(releaseManifest(), {
    visibleAfterRequests: { "@lpm-registry/cli-win32-x64": 3 },
  });

  await verifyRegistryPublications({
    releaseManifest: registry.manifest,
    scope: "platforms",
    expectedTag: "nightly",
    ...registry.options,
  });

  assert.equal(registry.requestsFor("@lpm-registry/cli-win32-x64"), 3);
  assert.deepEqual(registry.sleeps, [5_000, 10_000]);
  assert.match(registry.logs[0], /cli-win32-x64@0\.81\.0 is not verifiable on npm yet \(attempt 1\)/);
});

test("registry publication outlasts the thirteen minutes npm has taken to list a published version", async () => {
  const listedAt = 13 * 60_000;
  const registry = fakeRegistry(releaseManifest(), {
    listedAfterMs: { "@lpm-registry/cli-win32-x64": listedAt },
  });

  await verifyRegistryPublications({
    releaseManifest: registry.manifest,
    scope: "platforms",
    expectedTag: "nightly",
    ...registry.options,
  });

  assert.ok(registry.clock() >= listedAt);
});

test("registry publication names the version npm has not listed yet", async () => {
  const registry = fakeRegistry(releaseManifest(), {
    listedAfterMs: { "@lpm-registry/cli-win32-x64": Infinity },
  });

  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: registry.manifest,
      scope: "platforms",
      expectedTag: "nightly",
      ...registry.options,
      timeoutMs: 60_000,
    }),
    /cli-win32-x64: The npm package metadata does not list @lpm-registry\/cli-win32-x64@0\.81\.0$/,
  );
});

test("registry publication names every platform package npm never serves", async () => {
  const registry = fakeRegistry(releaseManifest(), {
    missing: ["@lpm-registry/cli-darwin-x64", "@lpm-registry/cli-linux-x64-musl"],
  });

  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: registry.manifest,
      scope: "platforms",
      expectedTag: "latest",
      ...registry.options,
      timeoutMs: 60_000,
    }),
    error => {
      assert.match(error.message, /npm did not serve 2 of 6 package\(s\) in the platforms scope within 60s/);
      assert.match(error.message, /cli-darwin-x64: .*HTTP 404/);
      assert.match(error.message, /cli-linux-x64-musl: .*HTTP 404/);
      assert.doesNotMatch(error.message, /cli-linux-arm64:/);
      return true;
    },
  );
  assert.ok(registry.clock() >= 60_000, "missing packages are retried for the whole window");
});

test("registry publication fails without retrying when npm lists the version with other contents", async () => {
  const tampered = "@lpm-registry/cli-linux-arm64";
  const cases = [
    [
      metadata => {
        metadata.dist.integrity = integrity("tampered");
      },
      "The published SHA-512 integrity does not match",
    ],
    [
      metadata => {
        metadata.dist.shasum = "0".repeat(40);
      },
      "The published SHA-1 shasum does not match",
    ],
    [
      metadata => {
        metadata.name = "@lpm-registry/cli-linux-x64";
      },
      "The npm version identity does not match",
    ],
  ];

  for (const [tamper, message] of cases) {
    const registry = fakeRegistry(releaseManifest(), { tamperVersion: { [tampered]: tamper } });

    await assert.rejects(
      verifyRegistryPublications({
        releaseManifest: registry.manifest,
        scope: "platforms",
        expectedTag: "latest",
        ...registry.options,
      }),
      error => {
        assert.match(error.message, /npm did not serve 1 of 6 package\(s\)/);
        assert.ok(error.message.includes(`cli-linux-arm64: ${message}`), error.message);
        return true;
      },
    );
    assert.equal(registry.requestsFor(tampered), 1, message);
    assert.deepEqual(registry.sleeps, [], message);
  }
});

test("registry publication rejects a dist-tag that still selects the previous version", async () => {
  const registry = fakeRegistry(releaseManifest(), {
    distTagOverride: { [WRAPPER]: "0.80.0" },
  });

  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: registry.manifest,
      scope: "wrapper",
      expectedTag: "latest",
      ...registry.options,
      timeoutMs: 1_000,
    }),
    /@lpm-registry\/cli: The npm latest dist-tag does not select @lpm-registry\/cli@0\.81\.0/,
  );
  assert.ok(registry.sleeps.length > 0, "a dist-tag that has not moved yet is retried");
});

test("the wrapper scope checks only the wrapper package", async () => {
  const registry = fakeRegistry(releaseManifest());

  await verifyRegistryPublications({
    releaseManifest: registry.manifest,
    scope: "wrapper",
    expectedTag: "latest",
    ...registry.options,
  });

  assert.equal(registry.requests.length, 1);
  assert.equal(registry.requestsFor(WRAPPER), 1);
});

test("registry publication fails before any request when the manifest lacks a platform", async () => {
  const manifest = releaseManifest();
  manifest.packages = manifest.packages.filter(
    record => record.name !== "@lpm-registry/cli-darwin-arm64",
  );
  const registry = fakeRegistry(manifest);

  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: manifest,
      scope: "platforms",
      expectedTag: "latest",
      ...registry.options,
    }),
    /must contain one record for @lpm-registry\/cli-darwin-arm64/,
  );
  assert.equal(registry.requests.length, 0);
});

test("registry publication rejects manifests with packages no scope verifies", async () => {
  const manifest = releaseManifest();
  manifest.packages.push(packageRecord("@lpm-registry/cli-freebsd-x64"));
  const registry = fakeRegistry(manifest);

  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: manifest,
      scope: "platforms",
      expectedTag: "latest",
      ...registry.options,
    }),
    /contains packages no publication scope verifies: "@lpm-registry\/cli-freebsd-x64"/,
  );
  assert.equal(registry.requests.length, 0);
});

test("registry publication rejects unsupported scopes and dist-tags before any request", async () => {
  const registry = fakeRegistry(releaseManifest());

  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: registry.manifest,
      scope: "everything",
      expectedTag: "latest",
      ...registry.options,
    }),
    /publication scope is not supported/,
  );
  await assert.rejects(
    verifyRegistryPublications({
      releaseManifest: registry.manifest,
      scope: "platforms",
      expectedTag: "beta",
      ...registry.options,
    }),
    /dist-tag is not supported/,
  );
  assert.equal(registry.requests.length, 0);
});

test("the registry publication CLI requires a manifest, scope, and dist-tag", () => {
  const script = path.join(repoRoot, "npm/release/verify-registry-publication.mjs");
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-registry-publication-"));
  try {
    const manifest = path.join(workspace, "release-packages.json");
    fs.writeFileSync(manifest, JSON.stringify(releaseManifest()));
    const result = spawnSync(process.execPath, [script, "--manifest", manifest, "--tag", "latest"], {
      encoding: "utf8",
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /verify-registry-publication: The --scope argument is required/);
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("every npm publish job verifies on the registry each package it publishes", () => {
  const verification = scope =>
    new RegExp(
      `node npm/release/verify-registry-publication\\.mjs\\n\\s+--manifest [^\\n]+\\n\\s+--scope ${scope}\\n`,
    );
  const assertOrdered = (source, job, markers) => {
    let previous = -1;
    for (const marker of markers) {
      const index =
        typeof marker === "string"
          ? source.indexOf(marker, previous + 1)
          : source.slice(previous + 1).search(marker) + previous + 1;
      assert.ok(index > previous, `${job} is missing or misorders ${marker}`);
      previous = index;
    }
  };

  assertOrdered(workflowJob("publish-promotion-platform"), "publish-promotion-platform", [
    "publish_package @lpm-registry/cli-win32-x64",
    verification("platforms"),
    "- name: Publish exact wrapper tarball last",
    verification("wrapper"),
    "bash scripts/ci/verify-published-wrapper.sh",
  ]);
  assertOrdered(workflowJob("publish-npm-platform"), "publish-npm-platform", [
    "publish_pkg @lpm-registry/cli-win32-x64",
    verification("platforms"),
  ]);
  assertOrdered(workflowJob("publish-npm-wrapper"), "publish-npm-wrapper", [
    verification("platforms"),
    "- name: Publish exact verified wrapper tarball",
    verification("wrapper"),
    "bash scripts/ci/verify-published-wrapper.sh",
  ]);
});

test("every npm publish job outlasts the worst case of every registry wait it runs", () => {
  const verifierMinutes = PROPAGATION_TIMEOUT_MS / 60_000;
  const wrapperSmokeMinutes =
    Number(
      fs
        .readFileSync(path.join(repoRoot, "scripts/ci/verify-published-wrapper.sh"), "utf8")
        .match(/^propagation_timeout_seconds=(\d+)$/m)?.[1],
    ) / 60;
  assert.ok(wrapperSmokeMinutes > 0, "verify-published-wrapper.sh has no propagation window");

  for (const job of NPM_PUBLISH_JOBS) {
    const source = workflowJob(job);
    const count = pattern => source.match(pattern)?.length ?? 0;
    const verifications = count(/node npm\/release\/verify-registry-publication\.mjs\n/g);
    const wrapperSmokes = count(/bash scripts\/ci\/verify-published-wrapper\.sh /g);
    const requiredMinutes =
      verifications * verifierMinutes +
      wrapperSmokes * wrapperSmokeMinutes +
      NON_WAITING_STEP_MINUTES;
    const timeoutMinutes = Number(source.match(/^ {4}timeout-minutes:\s*(\d+)\s*$/m)?.[1]);

    assert.ok(
      timeoutMinutes >= requiredMinutes,
      `${job} allows ${timeoutMinutes} minutes, but ${verifications} registry verification(s) and ` +
        `${wrapperSmokes} wrapper smoke(s) can wait ${requiredMinutes} minutes before reporting`,
    );
  }
});

function workflowJob(job) {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = workflow.indexOf(`\n  ${job}:\n`);
  assert.notEqual(start, -1, `missing ${job} job`);
  const next = workflow.slice(start + 1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
  return next === -1 ? workflow.slice(start) : workflow.slice(start, start + 1 + next);
}

function releaseManifest() {
  return {
    schemaVersion: 1,
    version: VERSION,
    wrapperOnly: false,
    packages: [WRAPPER, ...PLATFORMS].map(name => packageRecord(name)),
  };
}

function packageRecord(name) {
  return {
    name,
    version: VERSION,
    tarball: `${name.replace("@", "").replace("/", "-")}-${VERSION}.tgz`,
    shasum: crypto.createHash("sha1").update(name).digest("hex"),
    sha256: crypto.createHash("sha256").update(name).digest("hex"),
    integrity: integrity(name),
  };
}

function integrity(seed) {
  return `sha512-${crypto.createHash("sha512").update(seed).digest("base64")}`;
}

function packumentResponse(packument) {
  return new Response(JSON.stringify(packument), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function fakeRegistry(
  manifest,
  {
    visibleAfterRequests = {},
    listedAfterMs = {},
    missing = [],
    tamperVersion = {},
    distTagOverride = {},
  } = {},
) {
  let clock = 0;
  const requests = [];
  const sleeps = [];
  const logs = [];
  const requestsFor = name =>
    requests.filter(url => decodeURIComponent(new URL(url).pathname.slice(1)) === name).length;
  const fetchImpl = async url => {
    requests.push(String(url));
    const name = decodeURIComponent(new URL(url).pathname.slice(1));
    const record = manifest.packages.find(candidate => candidate.name === name);
    if (
      !record ||
      missing.includes(name) ||
      requestsFor(name) < (visibleAfterRequests[name] ?? 1)
    ) {
      return new Response("not found", { status: 404 });
    }
    if (clock < (listedAfterMs[name] ?? 0)) {
      return packumentResponse({
        name,
        "dist-tags": { latest: PREVIOUS_VERSION, nightly: PREVIOUS_VERSION },
        versions: { [PREVIOUS_VERSION]: { name, version: PREVIOUS_VERSION } },
      });
    }
    const tag = distTagOverride[name] ?? VERSION;
    const versionMetadata = {
      name,
      version: VERSION,
      dist: {
        shasum: record.shasum,
        integrity: record.integrity,
        attestations: { provenance: { predicateType: PROVENANCE_PREDICATE } },
      },
    };
    tamperVersion[name]?.(versionMetadata);
    return packumentResponse({
      name,
      "dist-tags": { latest: tag, nightly: tag },
      versions: { [VERSION]: versionMetadata },
    });
  };
  return {
    manifest,
    requests,
    sleeps,
    logs,
    requestsFor,
    clock: () => clock,
    options: {
      fetchImpl,
      now: () => clock,
      sleep: async milliseconds => {
        sleeps.push(milliseconds);
        clock += milliseconds;
      },
      log: message => logs.push(message),
    },
  };
}
