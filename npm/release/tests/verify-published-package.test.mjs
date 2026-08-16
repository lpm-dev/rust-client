import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  verifyLocalTarball,
  verifyNpmSignatures,
  verifyPublishedPackage,
} from "../verify-published-package.mjs";

const PACKAGE = "@lpm-registry/cli";
const VERSION = "0.74.1";
const SOURCE_RUN_ID = "31438465271";
const SOURCE_SHA = "1e98fb8efbcc00f620678fc8091b512ed503768f";
const SHASUM = "a".repeat(40);
const SHA256 = "b".repeat(64);
const SHA512_BYTES = Buffer.alloc(64, 0x2a);
const SHA512_HEX = SHA512_BYTES.toString("hex");
const INTEGRITY = `sha512-${SHA512_BYTES.toString("base64")}`;
const PUBLISH_PREDICATE = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";
const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";

test("existing npm publication verification accepts exact stable metadata", async () => {
  const fixture = publicationFixture();

  const result = await verifyPublishedPackage({
    releaseManifest: fixture.manifest,
    packageName: PACKAGE,
    expectedTag: "latest",
    expectedSourceRunId: SOURCE_RUN_ID,
    expectedSourceSha: SOURCE_SHA,
    fetchImpl: fixture.fetch,
    verifySignaturesImpl: fixture.verifySignatures,
    verifyTarballImpl: fixture.verifyTarball,
  });

  assert.deepEqual(result, { packageName: PACKAGE, version: VERSION, tag: "latest" });
  assert.equal(fixture.requests.length, 1);
  assert.match(fixture.requests[0], /registry\.npmjs\.org\/%40lpm-registry%2Fcli$/);
  assert.equal(fixture.requestOptions[0].redirect, "error");
  assert.equal(fixture.requestOptions[0].headers.Accept, "application/json");
  assert.ok(fixture.requestOptions[0].signal instanceof AbortSignal);
});

test("existing npm publication verification accepts main-branch nightly provenance", async () => {
  const fixture = publicationFixture({ tag: "nightly", provenanceRef: "refs/heads/main" });

  await assert.doesNotReject(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "nightly",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
  );
});

test("existing npm publication verification rejects mismatched distribution digests", async t => {
  for (const [name, mutate, message] of [
    [
      "shasum",
      fixture => {
        fixture.packument.versions[VERSION].dist.shasum = "b".repeat(40);
      },
      /published SHA-1 shasum does not match/,
    ],
    [
      "integrity",
      fixture => {
        fixture.packument.versions[VERSION].dist.integrity =
          `sha512-${Buffer.alloc(64, 0x3b).toString("base64")}`;
      },
      /published SHA-512 integrity does not match/,
    ],
  ]) {
    await t.test(name, async () => {
      const fixture = publicationFixture();
      mutate(fixture);
      await assert.rejects(
        verifyPublishedPackage({
          releaseManifest: fixture.manifest,
          packageName: PACKAGE,
          expectedTag: "latest",
          expectedSourceRunId: SOURCE_RUN_ID,
          expectedSourceSha: SOURCE_SHA,
          fetchImpl: fixture.fetch,
          verifySignaturesImpl: fixture.verifySignatures,
          verifyTarballImpl: fixture.verifyTarball,
        }),
        message,
      );
    });
  }
});

test("existing npm publication verification rejects the wrong dist-tag", async () => {
  const fixture = publicationFixture();
  fixture.packument["dist-tags"].latest = "0.74.0";

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /latest dist-tag does not select/,
  );
});

test("existing npm publication verification rejects missing provenance metadata", async () => {
  const fixture = publicationFixture();
  delete fixture.packument.versions[VERSION].dist.attestations;

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /has no SLSA provenance/,
  );
});

test("existing npm publication verification rejects an attestation digest mismatch", async () => {
  const fixture = publicationFixture();
  const provenance = fixture.attestations.attestations.find(
    entry => entry.predicateType === PROVENANCE_PREDICATE,
  );
  const statement = decodeStatement(provenance);
  statement.subject[0].digest.sha512 = "0".repeat(128);
  provenance.bundle.dsseEnvelope.payload = encodeStatement(statement);

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /attestation subject does not match/,
  );
});

test("existing npm publication verification rejects foreign workflow provenance", async () => {
  const fixture = publicationFixture({ provenanceRepository: "https://github.com/other/repository" });

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /provenance workflow does not match/,
  );
});

test("existing npm publication verification rejects a different source commit", async () => {
  const fixture = publicationFixture();
  const provenance = fixture.attestations.attestations.find(
    entry => entry.predicateType === PROVENANCE_PREDICATE,
  );
  const statement = decodeStatement(provenance);
  statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = "f".repeat(40);
  provenance.bundle.dsseEnvelope.payload = encodeStatement(statement);

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /provenance source does not match/,
  );
});

test("existing npm publication verification rejects missing transparency evidence", async () => {
  const fixture = publicationFixture();
  fixture.attestations.attestations[0].bundle.verificationMaterial.tlogEntries = [];

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /has no transparency-log entry/,
  );
});

test("existing npm publication verification rejects statement version drift", async t => {
  for (const [name, predicateType, statementType] of [
    ["publication", PUBLISH_PREDICATE, "https://in-toto.io/Statement/v1"],
    ["provenance", PROVENANCE_PREDICATE, "https://in-toto.io/Statement/v0.1"],
  ]) {
    await t.test(name, async () => {
      const fixture = publicationFixture();
      const entry = fixture.attestations.attestations.find(
        candidate => candidate.predicateType === predicateType,
      );
      const statement = decodeStatement(entry);
      statement._type = statementType;
      entry.bundle.dsseEnvelope.payload = encodeStatement(statement);

      await assert.rejects(
        verifyPublishedPackage({
          releaseManifest: fixture.manifest,
          packageName: PACKAGE,
          expectedTag: "latest",
          expectedSourceRunId: SOURCE_RUN_ID,
          expectedSourceSha: SOURCE_SHA,
          fetchImpl: fixture.fetch,
          verifySignaturesImpl: fixture.verifySignatures,
          verifyTarballImpl: fixture.verifyTarball,
        }),
        /attestation statement is not valid/,
      );
    });
  }
});

test("existing npm publication verification rejects duplicate predicate attestations", async () => {
  const fixture = publicationFixture();
  fixture.attestations.attestations.push(structuredClone(fixture.attestations.attestations[0]));

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /must contain one .*publish\/v0\.1 statement/,
  );
});

test("existing npm publication verification rejects missing signing material", async t => {
  for (const [name, predicateType, field, message] of [
    ["publication", PUBLISH_PREDICATE, "publicKey", /publication attestation has no signing key/],
    ["provenance", PROVENANCE_PREDICATE, "certificate", /provenance has no signing certificate/],
  ]) {
    await t.test(name, async () => {
      const fixture = publicationFixture();
      const entry = fixture.attestations.attestations.find(
        candidate => candidate.predicateType === predicateType,
      );
      delete entry.bundle.verificationMaterial[field];

      await assert.rejects(
        verifyPublishedPackage({
          releaseManifest: fixture.manifest,
          packageName: PACKAGE,
          expectedTag: "latest",
          expectedSourceRunId: SOURCE_RUN_ID,
          expectedSourceSha: SOURCE_SHA,
          fetchImpl: fixture.fetch,
          verifySignaturesImpl: fixture.verifySignatures,
          verifyTarballImpl: fixture.verifyTarball,
        }),
        message,
      );
    });
  }
});

test("existing npm publication verification rejects a cryptographic verification failure", async () => {
  const fixture = publicationFixture();

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: async () => {
        throw new Error("npm signature verification failed");
      },
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /npm signature verification failed/,
  );
});

test("existing npm publication verification rejects a local tarball verification failure", async () => {
  const fixture = publicationFixture();

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      tarballPath: "/tmp/release-package.tgz",
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: () => {
        throw new Error("local tarball digest mismatch");
      },
    }),
    /local tarball digest mismatch/,
  );
});

test("existing npm publication verification rejects oversized registry responses", async () => {
  const fixture = publicationFixture();
  fixture.fetch = async () =>
    new Response("{}", {
      headers: { "content-length": String(8 * 1024 * 1024 + 1) },
    });

  await assert.rejects(
    verifyPublishedPackage({
      releaseManifest: fixture.manifest,
      packageName: PACKAGE,
      expectedTag: "latest",
      expectedSourceRunId: SOURCE_RUN_ID,
      expectedSourceSha: SOURCE_SHA,
      fetchImpl: fixture.fetch,
      verifySignaturesImpl: fixture.verifySignatures,
      verifyTarballImpl: fixture.verifyTarball,
    }),
    /response is too large/,
  );
});

test("npm cryptographic verification uses the pinned script-disabled audit flow", () => {
  const calls = [];
  const bundles = JSON.parse(
    JSON.stringify(publicationFixture().attestations.attestations),
  );
  const spawnImpl = (command, args, options) => {
    calls.push({ args, command, options });
    if (calls.length === 1) return { status: 0, stdout: "", stderr: "" };
    return {
      status: 0,
      stdout: JSON.stringify({
        invalid: [],
        missing: [],
        verified: [
          {
            name: PACKAGE,
            version: VERSION,
            registry: "https://registry.npmjs.org/",
            attestationBundles: bundles,
          },
        ],
      }),
      stderr: "",
    };
  };

  assert.deepEqual(verifyNpmSignatures({ packageName: PACKAGE, version: VERSION, spawnImpl }), {
    attestations: bundles,
  });
  assert.equal(calls.length, 2);
  assert.equal(calls[0].command, "npx");
  assert.deepEqual(calls[0].args.slice(0, 4), ["--yes", "npm@11.12.1", "install", "--prefix"]);
  assert.ok(calls[0].args.includes("--ignore-scripts"));
  assert.ok(calls[0].args.includes("--omit=optional"));
  assert.ok(calls[0].args.includes("--"));
  assert.deepEqual(calls[1].args.slice(0, 4), ["--yes", "npm@11.12.1", "audit", "signatures"]);
  assert.ok(calls[1].args.includes("--include-attestations"));
  assert.equal(Object.hasOwn(calls[0].options, "shell"), false);
  assert.match(calls[0].options.env.NPM_CONFIG_USERCONFIG, /lpm-npm-signatures-/);
});

test("npm cryptographic verification rejects a report for a different package", () => {
  let calls = 0;
  const spawnImpl = () => {
    calls += 1;
    if (calls === 1) return { status: 0, stdout: "", stderr: "" };
    return {
      status: 0,
      stdout: JSON.stringify({
        invalid: [],
        missing: [],
        verified: [
          {
            name: "other-package",
            version: VERSION,
            registry: "https://registry.npmjs.org/",
            attestationBundles: [],
          },
        ],
      }),
      stderr: "",
    };
  };

  assert.throws(
    () => verifyNpmSignatures({ packageName: PACKAGE, version: VERSION, spawnImpl }),
    /did not verify the expected package/,
  );
});

test("npm cryptographic verification rejects unexpected verified packages", () => {
  let calls = 0;
  const bundles = JSON.parse(
    JSON.stringify(publicationFixture().attestations.attestations),
  );
  const spawnImpl = () => {
    calls += 1;
    if (calls === 1) return { status: 0, stdout: "", stderr: "" };
    return {
      status: 0,
      stdout: JSON.stringify({
        invalid: [],
        missing: [],
        verified: [
          {
            name: PACKAGE,
            version: VERSION,
            registry: "https://registry.npmjs.org/",
            attestationBundles: bundles,
          },
          {
            name: "unexpected-package",
            version: "1.0.0",
            registry: "https://registry.npmjs.org/",
            attestationBundles: [],
          },
        ],
      }),
      stderr: "",
    };
  };

  assert.throws(
    () => verifyNpmSignatures({ packageName: PACKAGE, version: VERSION, spawnImpl }),
    /did not verify every signature/,
  );
});

test("local tarball verification accepts exact SHA-1 SHA-256 and SHA-512 digests", t => {
  const fixture = localTarballFixture(t);

  assert.deepEqual(
    verifyLocalTarball({
      tarballPath: fixture.file,
      record: fixture.record,
      packageName: PACKAGE,
    }),
    {
      shasum: fixture.record.shasum,
      sha256: fixture.record.sha256,
      integrity: fixture.record.integrity,
    },
  );
});

test("local tarball verification rejects bytes outside the release manifest", t => {
  const fixture = localTarballFixture(t);
  fixture.record.sha256 = "0".repeat(64);

  assert.throws(
    () =>
      verifyLocalTarball({
        tarballPath: fixture.file,
        record: fixture.record,
        packageName: PACKAGE,
      }),
    /local tarball digests do not match/,
  );
});

test("publication verifier CLI accepts every workflow argument", () => {
  const script = path.resolve("npm/release/verify-published-package.mjs");
  const result = spawnSync(
    process.execPath,
    [
      script,
      "--manifest",
      "/definitely/missing/release-packages.json",
      "--package",
      PACKAGE,
      "--tag",
      "latest",
      "--source-sha",
      SOURCE_SHA,
      "--source-run-id",
      SOURCE_RUN_ID,
      "--tarball",
      "/definitely/missing/package.tgz",
    ],
    { encoding: "utf8" },
  );

  assert.equal(result.status, 1);
  assert.match(result.stderr, /release manifest is missing or is not a regular file/);
  assert.doesNotMatch(result.stderr, /argument is not valid/);
});

function localTarballFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-local-tarball-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "package.tgz");
  const bytes = Buffer.from("exact local npm tarball bytes");
  fs.writeFileSync(file, bytes);
  return {
    file,
    record: {
      shasum: crypto.createHash("sha1").update(bytes).digest("hex"),
      sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
      integrity: `sha512-${crypto.createHash("sha512").update(bytes).digest("base64")}`,
    },
  };
}

function publicationFixture({
  tag = "latest",
  provenanceRef = `refs/tags/v${VERSION}`,
  provenanceRepository = "https://github.com/lpm-dev/rust-client",
} = {}) {
  const manifest = {
    schemaVersion: 1,
    version: VERSION,
    wrapperOnly: false,
    packages: [
      {
        name: PACKAGE,
        version: VERSION,
        shasum: SHASUM,
        sha256: SHA256,
        integrity: INTEGRITY,
      },
    ],
  };
  const packument = {
    name: PACKAGE,
    "dist-tags": { [tag]: VERSION },
    versions: {
      [VERSION]: {
        name: PACKAGE,
        version: VERSION,
        dist: {
          shasum: SHASUM,
          integrity: INTEGRITY,
          attestations: { provenance: { predicateType: PROVENANCE_PREDICATE } },
        },
      },
    },
  };
  const subject = [{ name: `pkg:npm/%40lpm-registry/cli@${VERSION}`, digest: { sha512: SHA512_HEX } }];
  const attestations = {
    attestations: [
      attestation(PUBLISH_PREDICATE, {
        _type: "https://in-toto.io/Statement/v0.1",
        subject,
        predicateType: PUBLISH_PREDICATE,
        predicate: { name: PACKAGE, version: VERSION, registry: "https://registry.npmjs.org" },
      }),
      attestation(PROVENANCE_PREDICATE, {
        _type: "https://in-toto.io/Statement/v1",
        subject,
        predicateType: PROVENANCE_PREDICATE,
        predicate: {
          buildDefinition: {
            buildType: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
            externalParameters: {
              workflow: {
                repository: provenanceRepository,
                path: ".github/workflows/release.yml",
                ref: provenanceRef,
              },
            },
            internalParameters: {
              github: {
                event_name: tag === "nightly" ? "schedule" : "push",
                repository_id: "1189082766",
                repository_owner_id: "261638357",
              },
            },
            resolvedDependencies: [
              {
                uri: `git+https://github.com/lpm-dev/rust-client@${provenanceRef}`,
                digest: { gitCommit: SOURCE_SHA },
              },
            ],
          },
          runDetails: {
            builder: { id: "https://github.com/actions/runner/github-hosted" },
            metadata: {
              invocationId: `https://github.com/lpm-dev/rust-client/actions/runs/${SOURCE_RUN_ID}/attempts/1`,
            },
          },
        },
      }),
    ],
  };
  const requests = [];
  const requestOptions = [];
  const fetch = async (url, options) => {
    requests.push(String(url));
    requestOptions.push(options);
    if (requests.length === 1) return jsonResponse(packument);
    return new Response("not found", { status: 404 });
  };
  const verifySignatures = async () => attestations;
  const verifyTarball = () => {};
  return {
    attestations,
    fetch,
    manifest,
    packument,
    requestOptions,
    requests,
    verifySignatures,
    verifyTarball,
  };
}

function attestation(predicateType, statement) {
  return {
    predicateType,
    bundle: {
      dsseEnvelope: {
        payloadType: "application/vnd.in-toto+json",
        payload: encodeStatement(statement),
      },
      verificationMaterial: {
        certificate: predicateType === PROVENANCE_PREDICATE ? { rawBytes: "certificate" } : undefined,
        publicKey: predicateType === PUBLISH_PREDICATE ? { hint: "SHA256:key" } : undefined,
        tlogEntries: [{}],
      },
    },
  };
}

function encodeStatement(statement) {
  return Buffer.from(JSON.stringify(statement)).toString("base64");
}

function decodeStatement(entry) {
  return JSON.parse(Buffer.from(entry.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
}

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });
}
