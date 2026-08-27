import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import { PLATFORM_PACKAGES, manifestForRelease } from "../release-artifacts.mjs";
import { prepareReleasePackages } from "../prepare-packages.mjs";
import { verifyReleasePackages } from "../verify-packages.mjs";

const VERSION = "0.69.0";
const WRAPPER_PACKAGE = "@lpm-registry/cli";
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("release package verification accepts the exact full package set", async t => {
  const { binaries, output } = createFullFixture(t);
  prepareValidFullPackageSet(binaries, output);

  const manifest = await verifyReleasePackages({
    packagesDir: output,
    expectedVersion: VERSION,
  });

  assert.equal(manifest.packages.length, PLATFORM_PACKAGES.length + 1);
});

test("release package verification accepts canonical Windows test archives", async t => {
  const { binaries, output } = createFullFixture(t);
  prepareValidFullPackageSet(binaries, output, "win32");

  await assert.doesNotReject(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
    }),
  );
});

test("release package verification rejects a changed tarball", async t => {
  const output = createWrapperFixture(t);
  const manifest = prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });
  fs.appendFileSync(path.join(output, manifest.packages[0].tarball), "changed");

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /SHA-256 digest does not match/,
  );
});

test("release package verification rejects incorrect declared tarball digests", async t => {
  for (const [field, value, message] of [
    ["sha256", "0".repeat(64), /SHA-256 digest does not match/],
    ["shasum", "0".repeat(40), /SHA-1 shasum does not match/],
    [
      "integrity",
      `sha512-${Buffer.alloc(64).toString("base64")}`,
      /SHA-512 integrity does not match/,
    ],
  ]) {
    await t.test(field, async subtest => {
      const output = createWrapperFixture(subtest);
      const manifest = prepareReleasePackages({
        repoRoot,
        outputDir: output,
        version: VERSION,
        wrapperOnly: true,
      });
      manifest.packages[0][field] = value;
      writeJson(path.join(output, "release-packages.json"), manifest);

      await assert.rejects(
        verifyReleasePackages({
          packagesDir: output,
          expectedVersion: VERSION,
          wrapperOnly: true,
        }),
        message,
      );
    });
  }
});

test("release package verification rejects duplicate package records", async t => {
  const output = createWrapperFixture(t);
  const manifest = prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });
  manifest.packages.push(structuredClone(manifest.packages[0]));
  writeJson(path.join(output, "release-packages.json"), manifest);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /contains the package more than once/,
  );
});

test("release package verification rejects missing package records", async t => {
  const output = createWrapperFixture(t);
  const manifest = prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });
  manifest.packages = [];
  writeJson(path.join(output, "release-packages.json"), manifest);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /release package inventory does not match/,
  );
});

test("release package verification rejects unexpected package records", async t => {
  const output = createWrapperFixture(t);
  const manifest = prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });
  const unexpected = structuredClone(manifest.packages[0]);
  unexpected.name = "@lpm-registry/unexpected";
  manifest.packages.push(unexpected);
  writeJson(path.join(output, "release-packages.json"), manifest);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /contains an unexpected package/,
  );
});

test("release package verification rejects unlisted directory entries", async t => {
  const output = createWrapperFixture(t);
  prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });
  fs.writeFileSync(path.join(output, "unlisted.txt"), "unexpected");

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /directory inventory does not match/,
  );
});

test("release package verification rejects missing directory entries", async t => {
  const output = createWrapperFixture(t);
  const manifest = prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });
  fs.rmSync(path.join(output, manifest.packages[0].tarball));

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /directory inventory does not match/,
  );
});

test("release package verification rejects parent traversal in a tar path", async t => {
  const output = createWrapperFixture(t);
  const packageManifest = wrapperManifest();
  writeSyntheticWrapperArtifact(
    output,
    [
      tarFile("package/package.json", JSON.stringify(packageManifest)),
      tarFile("package/../escape", "escape"),
    ],
    [
      packedFile("package.json", Buffer.byteLength(JSON.stringify(packageManifest))),
      packedFile("escape", 6),
    ],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /tar path is unsafe/,
  );
});

test("release package verification rejects absolute tar paths", async t => {
  const output = createWrapperFixture(t);
  const packageManifest = wrapperManifest();
  const packageJson = JSON.stringify(packageManifest);
  writeSyntheticWrapperArtifact(
    output,
    [tarFile("package/package.json", packageJson), tarFile("/absolute", "escape")],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /tar path is outside package\//,
  );
});

test("release package verification rejects duplicate tar paths", async t => {
  const output = createWrapperFixture(t);
  const packageJson = JSON.stringify(wrapperManifest());
  writeSyntheticWrapperArtifact(
    output,
    [tarFile("package/package.json", packageJson), tarFile("package/package.json", packageJson)],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /tar archive contains a duplicate path/,
  );
});

test("release package verification rejects link entries", async t => {
  const output = createWrapperFixture(t);
  const packageManifest = wrapperManifest();
  const packageJson = JSON.stringify(packageManifest);
  writeSyntheticWrapperArtifact(
    output,
    [
      tarFile("package/package.json", packageJson),
      { body: Buffer.alloc(0), mode: 0o777, name: "package/link", type: "2" },
    ],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /unsupported entry type/,
  );
});

test("release package verification rejects incorrect embedded metadata", async t => {
  const output = createWrapperFixture(t);
  const packageManifest = { ...wrapperManifest(), name: "untrusted-wrapper" };
  const packageJson = JSON.stringify(packageManifest);
  writeSyntheticWrapperArtifact(
    output,
    [tarFile("package/package.json", packageJson)],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /wrapper package must be @lpm-registry\/cli/,
  );
});

test("release package verification rejects embedded publish configuration", async t => {
  const output = createWrapperFixture(t);
  const packageManifest = {
    ...wrapperManifest(),
    publishConfig: { registry: "https://untrusted.example/" },
  };
  const { entries, files } = syntheticWrapperContents(packageManifest);
  writeSyntheticWrapperArtifact(output, entries, files);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /must not contain publishConfig/,
  );
});

test("release package verification rejects an incomplete wrapper archive", async t => {
  const output = createWrapperFixture(t);
  const packageJson = JSON.stringify(wrapperManifest());
  writeSyntheticWrapperArtifact(
    output,
    [tarFile("package/package.json", packageJson)],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /expected package file inventory.*does not match/,
  );
});

test("release package verification rejects unexpected wrapper files", async t => {
  const output = createWrapperFixture(t);
  const { entries, files } = syntheticWrapperContents(wrapperManifest());
  entries.push(tarFile("package/extra.txt", "unexpected"));
  files.push(packedFile("extra.txt", Buffer.byteLength("unexpected")));
  writeSyntheticWrapperArtifact(output, entries, files);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /expected package file inventory.*does not match/,
  );
});

test("release package verification rejects implicit node-gyp install behavior", async t => {
  const output = createWrapperFixture(t);
  const { entries, files } = syntheticWrapperContents(wrapperManifest());
  entries.push(tarFile("package/binding.gyp", "{}\n"));
  files.push(packedFile("binding.gyp", 3));
  writeSyntheticWrapperArtifact(output, entries, files);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /expected package file inventory.*does not match/,
  );
});

test("release package verification requires USTAR metadata before using a path prefix", async t => {
  const output = createWrapperFixture(t);
  const packageJson = JSON.stringify(wrapperManifest());
  writeSyntheticWrapperArtifact(
    output,
    [
      {
        body: Buffer.from(packageJson),
        mode: 0o644,
        name: "package.json",
        prefix: "package",
        type: "0",
        ustar: false,
      },
    ],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /USTAR format marker/,
  );
});

test("release package verification rejects incorrect file sizes and modes", async t => {
  for (const [name, packed, message] of [
    ["size", packedFile("package.json", 1), /archived size does not match/],
    ["mode", packedFile("package.json", 0, 0o600), /archived mode does not match/],
  ]) {
    await t.test(name, async subtest => {
      const output = createWrapperFixture(subtest);
      const packageJson = JSON.stringify(wrapperManifest());
      const file = {
        ...packed,
        size: name === "size" ? packed.size : Buffer.byteLength(packageJson),
      };
      writeSyntheticWrapperArtifact(output, [tarFile("package/package.json", packageJson)], [file]);

      await assert.rejects(
        verifyReleasePackages({
          packagesDir: output,
          expectedVersion: VERSION,
          wrapperOnly: true,
        }),
        message,
      );
    });
  }
});

test("release package verification rejects a self-declared unsafe file mode", async t => {
  const output = createWrapperFixture(t);
  const { entries, files } = syntheticWrapperContents(wrapperManifest());
  const entry = entries.find(candidate => candidate.name === "package/bin/lpm");
  const file = files.find(candidate => candidate.path === "bin/lpm");
  entry.mode = 0o644;
  file.mode = 0o644;
  writeSyntheticWrapperArtifact(output, entries, files);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /expected file mode does not match/,
  );
});

test("release package verification rejects an incorrect binary digest", async t => {
  const { binaries, output } = createFullFixture(t);
  const manifest = prepareValidFullPackageSet(binaries, output);
  const platform = PLATFORM_PACKAGES[0];
  const record = manifest.packages.find(entry => entry.name === platform.packageName);
  record.binaries[platform.binaries[0].destination].sha256 = "0".repeat(64);
  writeJson(path.join(output, "release-packages.json"), manifest);

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
    }),
    /binary SHA-256 does not match/,
  );
});

test("release package verification rejects an oversized embedded package manifest", async t => {
  const output = createWrapperFixture(t);
  const packageJson = JSON.stringify({
    ...wrapperManifest(),
    padding: "x".repeat(1024 * 1024),
  });
  writeSyntheticWrapperArtifact(
    output,
    [tarFile("package/package.json", packageJson)],
    [packedFile("package.json", Buffer.byteLength(packageJson))],
  );

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /embedded package\.json is too large/,
  );
});

test("release package verification rejects an oversized release manifest", async t => {
  const output = createWrapperFixture(t);
  fs.mkdirSync(output);
  fs.writeFileSync(path.join(output, "release-packages.json"), Buffer.alloc(1024 * 1024 + 1));

  await assert.rejects(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
    /release package manifest is too large/,
  );
});

test("release package verification reports archive read errors without waiting", async t => {
  const output = createWrapperFixture(t);
  prepareReleasePackages({
    repoRoot,
    outputDir: output,
    version: VERSION,
    wrapperOnly: true,
  });

  const createReadStream = fs.createReadStream;
  fs.createReadStream = () => {
    const input = new Readable({
      read() {
        this.destroy(new Error("fixture archive read failure"));
      },
    });
    input.on("error", () => {});
    return input;
  };
  t.after(() => {
    fs.createReadStream = createReadStream;
  });

  let timeout;
  try {
    await assert.rejects(
      Promise.race([
        verifyReleasePackages({
          packagesDir: output,
          expectedVersion: VERSION,
          wrapperOnly: true,
        }),
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error("archive verification waited")), 1000);
        }),
      ]),
      /fixture archive read failure/,
    );
  } finally {
    clearTimeout(timeout);
  }
});

test("release package verification streams the outer directory inventory", async t => {
  const output = createWrapperFixture(t);
  prepareValidWrapperPackageSet(output);

  const readdirSync = fs.readdirSync;
  fs.readdirSync = () => {
    throw new Error("eager directory enumeration");
  };
  t.after(() => {
    fs.readdirSync = readdirSync;
  });

  await assert.doesNotReject(
    verifyReleasePackages({
      packagesDir: output,
      expectedVersion: VERSION,
      wrapperOnly: true,
    }),
  );
});

function createFullFixture(t) {
  const binaries = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-verify-binaries-"));
  const output = createWrapperFixture(t);
  t.after(() => fs.rmSync(binaries, { recursive: true, force: true }));
  for (const platform of PLATFORM_PACKAGES) {
    if (platform.bundleSource) {
      for (const entry of platform.bundleFiles) {
        const artifact = path.join(
          binaries,
          platform.bundleSource,
          path.relative("LPM CLI.app", entry.path),
        );
        fs.mkdirSync(path.dirname(artifact), { recursive: true });
        fs.writeFileSync(artifact, `fixture:${entry.path}\n`);
        fs.chmodSync(artifact, entry.mode);
      }
      continue;
    }
    for (const mapping of platform.binaries) {
      const artifact = path.join(binaries, mapping.artifact);
      fs.mkdirSync(path.dirname(artifact), { recursive: true });
      if (!fs.existsSync(artifact)) fs.writeFileSync(artifact, `fixture:${mapping.artifact}\n`);
    }
  }
  return { binaries, output };
}

function prepareValidFullPackageSet(binaries, output, hostPlatform = process.platform) {
  if (hostPlatform !== "win32") {
    return prepareReleasePackages({
      repoRoot,
      binariesDir: binaries,
      outputDir: output,
      version: VERSION,
    });
  }

  fs.mkdirSync(output);
  const packages = PLATFORM_PACKAGES.map(platform => {
    const sourceManifest = JSON.parse(
      fs.readFileSync(path.join(repoRoot, platform.directory, "package.json"), "utf8"),
    );
    const packageManifest = manifestForRelease(sourceManifest, VERSION, platform);
    const platformContents = platform.bundleSource
      ? platform.bundleFiles.map(entry => [
          entry.path,
          fs.readFileSync(
            path.join(
              binaries,
              platform.bundleSource,
              path.relative("LPM CLI.app", entry.path),
            ),
          ),
          entry.mode,
        ])
      : platform.binaries.map(mapping => [
          mapping.destination,
          fs.readFileSync(path.join(binaries, mapping.artifact)),
          platform.os === "win32" ? 0o644 : 0o755,
        ]);
    const contents = [
      ["README.md", Buffer.from("platform readme\n"), 0o644],
      ["package.json", Buffer.from(JSON.stringify(packageManifest)), 0o644],
      ...platformContents,
    ];
    const entries = contents.map(([relative, body, mode]) =>
      tarFile(`package/${relative}`, body, mode),
    );
    const files = contents.map(([relative, body, mode]) => packedFile(relative, body.length, mode));
    const binaryHashes = Object.fromEntries(
      platform.binaries.map(mapping => {
        const body = contents.find(([relative]) => relative === mapping.destination)[1];
        return [
          mapping.destination,
          { artifact: mapping.artifact, sha256: digest(body, "sha256", "hex") },
        ];
      }),
    );
    return writeSyntheticPackageArtifact(
      output,
      platform.packageName,
      platform.key,
      entries,
      files,
      binaryHashes,
    );
  });
  const wrapper = syntheticWrapperContents(wrapperManifest());
  packages.push(
    writeSyntheticPackageArtifact(
      output,
      WRAPPER_PACKAGE,
      null,
      wrapper.entries,
      wrapper.files,
      {},
    ),
  );
  const manifest = { schemaVersion: 1, version: VERSION, wrapperOnly: false, packages };
  writeJson(path.join(output, "release-packages.json"), manifest);
  return manifest;
}

function prepareValidWrapperPackageSet(output) {
  if (process.platform !== "win32") {
    return prepareReleasePackages({
      repoRoot,
      outputDir: output,
      version: VERSION,
      wrapperOnly: true,
    });
  }
  const { entries, files } = syntheticWrapperContents(wrapperManifest());
  writeSyntheticWrapperArtifact(output, entries, files);
  return JSON.parse(fs.readFileSync(path.join(output, "release-packages.json"), "utf8"));
}

function createWrapperFixture(t) {
  const output = path.join(
    os.tmpdir(),
    `lpm-verify-packages-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
  );
  t.after(() => fs.rmSync(output, { recursive: true, force: true }));
  return output;
}

function wrapperManifest() {
  const source = JSON.parse(fs.readFileSync(path.join(repoRoot, "npm/cli/package.json"), "utf8"));
  return manifestForRelease(source, VERSION);
}

function writeSyntheticWrapperArtifact(output, entries, files) {
  fs.mkdirSync(output);
  const record = writeSyntheticPackageArtifact(
    output,
    WRAPPER_PACKAGE,
    null,
    entries,
    files,
    {},
  );
  writeJson(path.join(output, "release-packages.json"), {
    schemaVersion: 1,
    version: VERSION,
    wrapperOnly: true,
    packages: [record],
  });
}

function writeSyntheticPackageArtifact(output, packageName, platform, entries, files, binaries) {
  const tarball = `${packageName.replace(/^@/u, "").replace("/", "-")}-${VERSION}.tgz`;
  const archive = createTarGz(entries);
  fs.writeFileSync(path.join(output, tarball), archive);
  return {
    name: packageName,
    version: VERSION,
    platform,
    tarball,
    sha256: digest(archive, "sha256", "hex"),
    shasum: digest(archive, "sha1", "hex"),
    integrity: `sha512-${digest(archive, "sha512", "base64")}`,
    files,
    binaries,
  };
}

function createTarGz(entries) {
  const blocks = [];
  for (const entry of entries) {
    const header = Buffer.alloc(512);
    writeTarText(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, entry.mode);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, entry.body.length);
    writeTarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = entry.type.charCodeAt(0);
    if (entry.ustar !== false) {
      writeTarText(header, 257, 6, "ustar");
      writeTarText(header, 263, 2, "00");
    }
    if (entry.prefix) writeTarText(header, 345, 155, entry.prefix);
    let checksum = 0;
    for (const byte of header) checksum += byte;
    writeTarChecksum(header, checksum);
    blocks.push(header, entry.body);
    const padding = (512 - (entry.body.length % 512)) % 512;
    if (padding > 0) blocks.push(Buffer.alloc(padding));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

function tarFile(name, content, mode = 0o644) {
  return { body: Buffer.from(content), mode, name, type: "0" };
}

function packedFile(filePath, size, mode = 0o644) {
  return { path: filePath, size, mode };
}

function syntheticWrapperContents(packageManifest) {
  const contents = [
    ["README.md", "wrapper readme\n", 0o644],
    ["bin/lpm", "lpm shim\n", 0o755],
    ["bin/lpm.js", "legacy lpm shim\n", 0o755],
    ["bin/lpx", "lpx shim\n", 0o755],
    ["bin/lpx.js", "legacy lpx shim\n", 0o755],
    ["bin/native.js", "native loader\n", 0o644],
    ["package.json", JSON.stringify(packageManifest), 0o644],
    ["scripts/install-binary.js", "installer\n", 0o644],
  ];
  return {
    entries: contents.map(([relative, body, mode]) => tarFile(`package/${relative}`, body, mode)),
    files: contents.map(([relative, body, mode]) =>
      packedFile(relative, Buffer.byteLength(body), mode),
    ),
  };
}

function writeTarText(header, offset, length, value) {
  const bytes = Buffer.from(value);
  assert.ok(bytes.length <= length, `tar fixture field is too long: ${value}`);
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, "0");
  assert.equal(text.length, length - 1);
  header.write(text, offset, "ascii");
  header[offset + length - 1] = 0;
}

function writeTarChecksum(header, value) {
  const text = value.toString(8).padStart(6, "0");
  assert.equal(text.length, 6);
  header.write(text, 148, "ascii");
  header[154] = 0;
  header[155] = 0x20;
}

function digest(bytes, algorithm, encoding) {
  return crypto.createHash(algorithm).update(bytes).digest(encoding);
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}
