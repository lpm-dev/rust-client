#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";
import { createGunzip } from "node:zlib";
import { fileURLToPath } from "node:url";

import {
  PLATFORM_PACKAGES,
  manifestForRelease,
  parseReleaseVersion,
} from "./release-artifacts.mjs";

const WRAPPER_PACKAGE = "@lpm-registry/cli";
const RELEASE_MANIFEST = "release-packages.json";
const TAR_BLOCK_SIZE = 512;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_TARBALL_BYTES = 512 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 1024 * 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES = 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 10_000;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const USTAR_FORMAT_MARKER = Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72, 0, 0x30, 0x30]);
const WRAPPER_ARCHIVE_FILES = Object.freeze([
  Object.freeze({ path: "README.md", mode: 0o644 }),
  Object.freeze({ path: "bin/lpm", mode: 0o755 }),
  Object.freeze({ path: "bin/lpm.js", mode: 0o755 }),
  Object.freeze({ path: "bin/lpx", mode: 0o755 }),
  Object.freeze({ path: "bin/lpx.js", mode: 0o755 }),
  Object.freeze({ path: "bin/native.js", mode: 0o644 }),
  Object.freeze({ path: "package.json", mode: 0o644 }),
  Object.freeze({ path: "scripts/install-binary.js", mode: 0o644 }),
]);

export async function verifyReleasePackages({ packagesDir, expectedVersion, wrapperOnly = false }) {
  const version = parseReleaseVersion(expectedVersion);
  const root = path.resolve(packagesDir);
  assertDirectory(root, "release package directory");

  const manifestPath = path.join(root, RELEASE_MANIFEST);
  const releaseManifest = readJsonFile(
    manifestPath,
    MAX_MANIFEST_BYTES,
    "release package manifest",
  );
  validateReleaseManifest(releaseManifest, version, wrapperOnly);

  const expectedPackages = wrapperOnly
    ? new Map([[WRAPPER_PACKAGE, null]])
    : new Map([
        ...PLATFORM_PACKAGES.map(platform => [platform.packageName, platform]),
        [WRAPPER_PACKAGE, null],
      ]);
  const packageRecords = new Map();
  const expectedDirectoryFiles = new Set([RELEASE_MANIFEST]);

  for (const record of releaseManifest.packages) {
    assertPlainObject(record, "release package record");
    const platform = expectedPackages.get(record.name);
    if (!expectedPackages.has(record.name)) {
      throw new Error(
        `The release manifest contains an unexpected package: ${format(record.name)}`,
      );
    }
    if (packageRecords.has(record.name)) {
      throw new Error(`The release manifest contains the package more than once: ${record.name}`);
    }
    validatePackageRecord(record, version, platform);
    packageRecords.set(record.name, record);
    if (expectedDirectoryFiles.has(record.tarball)) {
      throw new Error(`The release manifest uses the tarball more than once: ${record.tarball}`);
    }
    expectedDirectoryFiles.add(record.tarball);
  }

  assertExactSet(
    [...packageRecords.keys()],
    [...expectedPackages.keys()],
    "release package inventory",
  );
  assertDirectoryInventory(root, expectedDirectoryFiles);

  for (const [name, platform] of expectedPackages) {
    const record = packageRecords.get(name);
    const tarballPath = path.join(root, record.tarball);
    const digests = hashRegularFile(tarballPath, MAX_TARBALL_BYTES, `tarball for ${name}`);
    if (record.sha256 !== digests.sha256) {
      throw new Error(`The SHA-256 digest does not match for ${record.tarball}`);
    }
    if (record.shasum !== digests.sha1) {
      throw new Error(`The SHA-1 shasum does not match for ${record.tarball}`);
    }
    if (record.integrity !== `sha512-${digests.sha512}`) {
      throw new Error(`The SHA-512 integrity does not match for ${record.tarball}`);
    }

    const archive = await inspectPackageArchive(tarballPath, platform);
    validateArchiveFiles(record, archive.files);
    validateEmbeddedManifest(archive.packageManifest, version, platform);
    validateExpectedArchiveFiles(record.name, archive.files, platform);
    validateBinaryDigests(record, archive.files, platform);
  }

  return releaseManifest;
}

function validateReleaseManifest(manifest, version, wrapperOnly) {
  assertPlainObject(manifest, "release package manifest");
  if (manifest.schemaVersion !== 1) {
    throw new Error(
      `The release package schema is not supported: ${format(manifest.schemaVersion)}`,
    );
  }
  if (manifest.version !== version) {
    throw new Error(
      `The release manifest version is ${format(manifest.version)}. Expected ${version}`,
    );
  }
  if (manifest.wrapperOnly !== wrapperOnly) {
    throw new Error(
      `The wrapper-only state does not match the release mode: ${format(manifest.wrapperOnly)}`,
    );
  }
  if (!Array.isArray(manifest.packages)) {
    throw new Error("The release manifest packages value must be an array");
  }
}

function validatePackageRecord(record, version, platform) {
  if (record.version !== version) {
    throw new Error(`The package version is not ${version}: ${format(record.version)}`);
  }
  const expectedPlatform = platform?.key ?? null;
  if (record.platform !== expectedPlatform) {
    throw new Error(
      `The platform value for ${record.name} is ${format(record.platform)}. Expected ${format(expectedPlatform)}`,
    );
  }

  const expectedTarball = tarballName(record.name, version);
  if (record.tarball !== expectedTarball) {
    throw new Error(`The tarball for ${record.name} must be ${expectedTarball}`);
  }
  assertLowerHex(record.sha256, 64, `SHA-256 digest for ${record.name}`);
  assertLowerHex(record.shasum, 40, `SHA-1 shasum for ${record.name}`);
  if (
    typeof record.integrity !== "string" ||
    !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(record.integrity)
  ) {
    throw new Error(`The SHA-512 integrity is not valid for ${record.name}`);
  }
  if (!Array.isArray(record.files)) {
    throw new Error(`The file inventory must be an array for ${record.name}`);
  }
  assertPlainObject(record.binaries, `binary digest inventory for ${record.name}`);
}

function validateArchiveFiles(record, archiveFiles) {
  const declaredFiles = new Map();
  for (const file of record.files) {
    assertPlainObject(file, `file record for ${record.name}`);
    const relative = safeRelativePath(file.path, `file path for ${record.name}`);
    if (declaredFiles.has(relative)) {
      throw new Error(
        `The file inventory contains a duplicate path for ${record.name}: ${relative}`,
      );
    }
    if (!Number.isSafeInteger(file.size) || file.size < 0) {
      throw new Error(`The file size is not valid for ${record.name}: ${relative}`);
    }
    if (!Number.isSafeInteger(file.mode) || file.mode < 0 || file.mode > 0o7777) {
      throw new Error(`The file mode is not valid for ${record.name}: ${relative}`);
    }
    declaredFiles.set(relative, { size: file.size, mode: file.mode });
  }

  assertExactSet(
    [...archiveFiles.keys()],
    [...declaredFiles.keys()],
    `file inventory for ${record.name}`,
  );
  for (const [relative, declared] of declaredFiles) {
    const archived = archiveFiles.get(relative);
    if (archived.size !== declared.size) {
      throw new Error(`The archived size does not match for ${record.name}: ${relative}`);
    }
    if (archived.mode !== declared.mode) {
      throw new Error(`The archived mode does not match for ${record.name}: ${relative}`);
    }
  }
}

function validateEmbeddedManifest(manifest, version, platform) {
  assertPlainObject(manifest, "embedded package.json");
  if (manifest.version !== version) {
    throw new Error(
      `The embedded package version is ${format(manifest.version)}. Expected ${version}`,
    );
  }
  if (manifest.publishConfig !== undefined) {
    throw new Error("The embedded package.json must not contain publishConfig");
  }

  if (platform) {
    manifestForRelease(manifest, version, platform);
    for (const field of [
      "bin",
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "scripts",
    ]) {
      if (manifest[field] !== undefined) {
        throw new Error(`The platform package must not contain ${field}: ${platform.packageName}`);
      }
    }
    return;
  }

  const expected = manifestForRelease(manifest, version).optionalDependencies;
  if (!sameStringMap(manifest.optionalDependencies, expected)) {
    throw new Error("The wrapper optional dependencies do not match the platform package set");
  }
}

function validateExpectedArchiveFiles(packageName, archiveFiles, platform) {
  const expectedFiles = platform
    ? [
        { path: "README.md", mode: 0o644 },
        { path: "package.json", mode: 0o644 },
        ...(platform.bundleSource
          ? platform.bundleFiles
          : platform.binaries.map(binary => ({
              path: binary.destination,
              mode: platform.os === "win32" ? 0o644 : 0o755,
            }))),
      ]
    : WRAPPER_ARCHIVE_FILES;

  assertExactSet(
    [...archiveFiles.keys()],
    expectedFiles.map(file => file.path),
    `expected package file inventory for ${packageName}`,
  );
  for (const expected of expectedFiles) {
    if (archiveFiles.get(expected.path).mode !== expected.mode) {
      throw new Error(`The expected file mode does not match for ${packageName}: ${expected.path}`);
    }
  }
}

function validateBinaryDigests(record, archiveFiles, platform) {
  if (!platform) {
    if (Object.keys(record.binaries).length !== 0) {
      throw new Error("The wrapper package must not contain binary digest records");
    }
    return;
  }

  const expectedBinaries = new Map(platform.binaries.map(binary => [binary.destination, binary]));
  assertExactSet(
    Object.keys(record.binaries),
    [...expectedBinaries.keys()],
    `binary digest inventory for ${record.name}`,
  );
  for (const [destination, expected] of expectedBinaries) {
    const digestRecord = record.binaries[destination];
    assertPlainObject(digestRecord, `binary digest for ${record.name}/${destination}`);
    if (digestRecord.artifact !== expected.artifact) {
      throw new Error(`The source artifact does not match for ${record.name}/${destination}`);
    }
    assertLowerHex(digestRecord.sha256, 64, `binary SHA-256 for ${record.name}/${destination}`);
    if (archiveFiles.get(destination)?.sha256 !== digestRecord.sha256) {
      throw new Error(`The binary SHA-256 does not match for ${record.name}/${destination}`);
    }
  }
}

async function inspectPackageArchive(tarballPath, platform) {
  const input = fs.createReadStream(tarballPath);
  const gunzip = createGunzip();
  input.once("error", error => gunzip.destroy(error));
  input.pipe(gunzip);

  const header = Buffer.alloc(TAR_BLOCK_SIZE);
  const files = new Map();
  const paths = new Set();
  const binaryPaths = new Set(platform?.binaries.map(binary => binary.destination) ?? []);
  let headerBytes = 0;
  let currentEntry = null;
  let paddingBytes = 0;
  let zeroBlocks = 0;
  let endOfArchive = false;
  let unpackedBytes = 0;
  let entryCount = 0;
  let packageJsonChunks = null;

  try {
    for await (const chunk of gunzip) {
      unpackedBytes += chunk.length;
      if (unpackedBytes > MAX_UNPACKED_BYTES) {
        throw new Error(`The unpacked archive is too large: ${path.basename(tarballPath)}`);
      }

      let offset = 0;
      while (offset < chunk.length) {
        if (endOfArchive) {
          assertZeroBytes(chunk.subarray(offset), "data after the tar end marker");
          break;
        }

        if (currentEntry) {
          const bytes = Math.min(currentEntry.remaining, chunk.length - offset);
          const slice = chunk.subarray(offset, offset + bytes);
          currentEntry.hash?.update(slice);
          if (currentEntry.capture) packageJsonChunks.push(Buffer.from(slice));
          currentEntry.remaining -= bytes;
          offset += bytes;
          if (currentEntry.remaining === 0) {
            if (currentEntry.file) {
              files.set(currentEntry.relative, {
                size: currentEntry.size,
                mode: currentEntry.mode,
                sha256: currentEntry.hash?.digest("hex"),
              });
            }
            currentEntry = null;
          }
          continue;
        }

        if (paddingBytes > 0) {
          const bytes = Math.min(paddingBytes, chunk.length - offset);
          assertZeroBytes(chunk.subarray(offset, offset + bytes), "non-zero tar padding");
          paddingBytes -= bytes;
          offset += bytes;
          continue;
        }

        const bytes = Math.min(TAR_BLOCK_SIZE - headerBytes, chunk.length - offset);
        chunk.copy(header, headerBytes, offset, offset + bytes);
        headerBytes += bytes;
        offset += bytes;
        if (headerBytes !== TAR_BLOCK_SIZE) continue;
        headerBytes = 0;

        if (isZeroBlock(header)) {
          zeroBlocks += 1;
          if (zeroBlocks === 2) endOfArchive = true;
          continue;
        }
        if (zeroBlocks !== 0) {
          throw new Error("The tar archive has an incomplete end marker");
        }

        entryCount += 1;
        if (entryCount > MAX_ARCHIVE_ENTRIES) {
          throw new Error(`The tar archive has too many entries: ${path.basename(tarballPath)}`);
        }
        const entry = parseTarHeader(header);
        const relative = packageRelativePath(entry.name, entry.type === "directory");
        if (paths.has(relative)) {
          throw new Error(`The tar archive contains a duplicate path: ${relative}`);
        }
        paths.add(relative);

        const file = entry.type === "file";
        if (file && files.has(relative)) {
          throw new Error(`The tar archive contains a duplicate file: ${relative}`);
        }
        const capture = file && relative === "package.json";
        if (capture) {
          if (entry.size > MAX_PACKAGE_JSON_BYTES) {
            throw new Error("The embedded package.json is too large");
          }
          packageJsonChunks = [];
        }
        currentEntry = {
          capture,
          file,
          hash: file && binaryPaths.has(relative) ? crypto.createHash("sha256") : null,
          mode: entry.mode,
          relative,
          remaining: entry.size,
          size: entry.size,
        };
        paddingBytes = (TAR_BLOCK_SIZE - (entry.size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
        if (entry.size === 0) {
          if (file) {
            files.set(relative, {
              size: 0,
              mode: entry.mode,
              sha256: currentEntry.hash?.digest("hex"),
            });
          }
          currentEntry = null;
        }
      }
    }
  } finally {
    input.destroy();
    gunzip.destroy();
  }

  if (!endOfArchive || currentEntry || paddingBytes !== 0 || headerBytes !== 0) {
    throw new Error(`The tar archive ended before it was complete: ${path.basename(tarballPath)}`);
  }
  if (!packageJsonChunks) {
    throw new Error("The tar archive does not contain package/package.json");
  }

  let packageManifest;
  try {
    packageManifest = JSON.parse(Buffer.concat(packageJsonChunks).toString("utf8"));
  } catch (error) {
    throw new Error("The embedded package.json is not valid JSON", {
      cause: error,
    });
  }
  return { files, packageManifest };
}

function parseTarHeader(header) {
  const expectedChecksum = parseTarOctal(header.subarray(148, 156), "tar checksum");
  let actualChecksum = 0;
  for (let index = 0; index < header.length; index += 1) {
    actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actualChecksum !== expectedChecksum) {
    throw new Error("The tar header checksum does not match");
  }
  if (!header.subarray(257, 265).equals(USTAR_FORMAT_MARKER)) {
    throw new Error("The tar header does not contain the required USTAR format marker");
  }

  const name = readTarText(header.subarray(0, 100), "tar path");
  const prefix = readTarText(header.subarray(345, 500), "tar path prefix");
  const fullName = prefix ? `${prefix}/${name}` : name;
  const typeByte = header[156];
  let type;
  if (typeByte === 0 || typeByte === 0x30) type = "file";
  else if (typeByte === 0x35) type = "directory";
  else throw new Error(`The tar archive contains an unsupported entry type: ${typeByte}`);

  return {
    mode: parseTarOctal(header.subarray(100, 108), "tar mode"),
    name: fullName,
    size: parseTarOctal(header.subarray(124, 136), "tar size"),
    type,
  };
}

function readTarText(field, label) {
  const zero = field.indexOf(0);
  const end = zero === -1 ? field.length : zero;
  if (zero !== -1) assertZeroBytes(field.subarray(zero), `${label} suffix`);
  try {
    return UTF8_DECODER.decode(field.subarray(0, end));
  } catch (error) {
    throw new Error(`The ${label} is not valid UTF-8`, { cause: error });
  }
}

function parseTarOctal(field, label) {
  if ((field[0] & 0x80) !== 0) {
    throw new Error(`The ${label} uses unsupported base-256 encoding`);
  }
  const value = field
    .toString("ascii")
    .replace(/[\0 ]+$/u, "")
    .trimStart();
  if (!/^[0-7]+$/.test(value)) {
    throw new Error(`The ${label} is not valid octal`);
  }
  const number = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(number)) {
    throw new Error(`The ${label} is too large`);
  }
  return number;
}

function packageRelativePath(value, directory) {
  if (typeof value !== "string" || !value.startsWith("package/")) {
    throw new Error(`The tar path is outside package/: ${format(value)}`);
  }
  let relative = value.slice("package/".length);
  if (directory && relative.endsWith("/")) relative = relative.slice(0, -1);
  return safeRelativePath(relative, "tar path");
}

function safeRelativePath(value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    value.includes("\\") ||
    /[\x00-\x1f\x7f]/u.test(value) ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value)
  ) {
    throw new Error(`The ${label} is unsafe: ${format(value)}`);
  }
  const segments = value.split("/");
  if (segments.some(segment => segment === "" || segment === "." || segment === "..")) {
    throw new Error(`The ${label} is unsafe: ${format(value)}`);
  }
  return value;
}

function tarballName(packageName, version) {
  if (typeof packageName !== "string") {
    throw new Error(`The package name is not valid: ${format(packageName)}`);
  }
  return `${packageName.replace(/^@/u, "").replace("/", "-")}-${version}.tgz`;
}

function hashRegularFile(file, maximumBytes, label) {
  const metadata = fs.lstatSync(file, { throwIfNoEntry: false });
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`The ${label} is missing or is not a regular file: ${file}`);
  }
  if (metadata.size > maximumBytes) {
    throw new Error(`The ${label} is too large: ${file}`);
  }

  const hashes = {
    sha1: crypto.createHash("sha1"),
    sha256: crypto.createHash("sha256"),
    sha512: crypto.createHash("sha512"),
  };
  const descriptor = fs.openSync(file, "r");
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    for (;;) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length);
      if (bytesRead === 0) break;
      const bytes = buffer.subarray(0, bytesRead);
      for (const hash of Object.values(hashes)) hash.update(bytes);
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return {
    sha1: hashes.sha1.digest("hex"),
    sha256: hashes.sha256.digest("hex"),
    sha512: hashes.sha512.digest("base64"),
  };
}

function readJsonFile(file, maximumBytes, label) {
  const metadata = fs.lstatSync(file, { throwIfNoEntry: false });
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`The ${label} is missing or is not a regular file: ${file}`);
  }
  if (metadata.size > maximumBytes) {
    throw new Error(`The ${label} is too large: ${file}`);
  }
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`The ${label} is not valid JSON: ${file}`, {
      cause: error,
    });
  }
}

function assertDirectory(directory, label) {
  const metadata = fs.lstatSync(directory, { throwIfNoEntry: false });
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`The ${label} is missing or is not a directory: ${directory}`);
  }
}

function assertDirectoryInventory(directory, expectedFiles) {
  const remaining = new Set(expectedFiles);
  const handle = fs.opendirSync(directory);
  try {
    for (;;) {
      const entry = handle.readSync();
      if (!entry) break;
      if (!entry.isFile() || entry.isSymbolicLink()) {
        throw new Error(`The release package directory contains a non-regular entry: ${entry.name}`);
      }
      if (!remaining.delete(entry.name)) {
        throw new Error(
          `The release package directory inventory does not match. Found unexpected ${entry.name}`,
        );
      }
    }
  } finally {
    handle.closeSync();
  }
  if (remaining.size !== 0) {
    throw new Error(
      `The release package directory inventory does not match. Missing ${[...remaining].sort().join(", ")}`,
    );
  }
}

function assertExactSet(actual, expected, label) {
  const actualSorted = [...actual].sort();
  const expectedSorted = [...expected].sort();
  if (JSON.stringify(actualSorted) !== JSON.stringify(expectedSorted)) {
    throw new Error(
      `The ${label} does not match. Expected ${expectedSorted.join(", ")}. Found ${actualSorted.join(", ")}`,
    );
  }
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`The ${label} must be an object`);
  }
}

function assertLowerHex(value, length, label) {
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`The ${label} is not valid`);
  }
}

function assertZeroBytes(bytes, label) {
  for (const byte of bytes) {
    if (byte !== 0) throw new Error(`The tar archive contains ${label}`);
  }
}

function isZeroBlock(block) {
  for (const byte of block) {
    if (byte !== 0) return false;
  }
  return true;
}

function sameStringMap(actual, expected) {
  if (actual === null || typeof actual !== "object" || Array.isArray(actual)) return false;
  const actualEntries = Object.entries(actual).sort(([left], [right]) => left.localeCompare(right));
  const expectedEntries = Object.entries(expected).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  return JSON.stringify(actualEntries) === JSON.stringify(expectedEntries);
}

function format(value) {
  return JSON.stringify(value);
}

function parseArguments(argv) {
  const options = { wrapperOnly: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--wrapper-only") {
      options.wrapperOnly = true;
      continue;
    }
    if (!argument.startsWith("--") || index + 1 >= argv.length) {
      throw new Error(`The argument is not valid: ${argument}`);
    }
    options[argument.slice(2)] = argv[index + 1];
    index += 1;
  }
  for (const required of ["packages", "version"]) {
    if (!options[required]) throw new Error(`The --${required} argument is required`);
  }
  return {
    packagesDir: options.packages,
    expectedVersion: options.version,
    wrapperOnly: options.wrapperOnly,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const manifest = await verifyReleasePackages(parseArguments(process.argv.slice(2)));
    console.log(
      `Verified ${manifest.packages.length} release package archive(s) for ${manifest.version}`,
    );
  } catch (error) {
    console.error(`verify-packages: ${error.message}`);
    process.exit(1);
  }
}
