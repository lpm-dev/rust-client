import fs from "node:fs";
import path from "node:path";

const WRAPPER_PACKAGE = "@lpm-registry/cli";
const WRAPPER_POSTINSTALL = "node scripts/install-binary.js";
const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export const PLATFORM_PACKAGES = Object.freeze([
  platformPackage("darwin-arm64", "darwin", "arm64", [
    binary("lpm-darwin-arm64", "lpm"),
    binary("lpm-darwin-arm64", "lpx"),
  ]),
  platformPackage("darwin-x64", "darwin", "x64", [
    binary("lpm-darwin-x64", "lpm"),
    binary("lpm-darwin-x64", "lpx"),
  ]),
  platformPackage("linux-arm64", "linux", "arm64", [
    binary("lpm-linux-arm64", "lpm"),
    binary("lpm-linux-arm64", "lpx"),
  ], "glibc"),
  platformPackage("linux-x64", "linux", "x64", [
    binary("lpm-linux-x64", "lpm"),
    binary("lpm-linux-x64", "lpx"),
  ], "glibc"),
  platformPackage("linux-x64-musl", "linux", "x64", [
    binary("lpm-linux-x64-musl", "lpm"),
    binary("lpm-linux-x64-musl", "lpx"),
  ], "musl"),
  platformPackage("win32-x64", "win32", "x64", [
    binary("lpm-win32-x64.exe", "lpm.exe"),
    binary("lpm-win32-x64.exe", "lpx.exe"),
    binary("lpm-sandbox-helper-win32-x64.exe", "lpm-sandbox-helper.exe"),
  ]),
]);

export function parseReleaseVersion(value) {
  if (typeof value !== "string" || !SEMVER_PATTERN.test(value)) {
    throw new Error(`release version must be valid npm semver, got ${JSON.stringify(value)}`);
  }
  return value;
}

export function manifestForRelease(source, version, platform = undefined) {
  parseReleaseVersion(version);
  const manifest = structuredClone(source);

  if (platform) {
    validatePlatformManifest(manifest, platform);
  } else {
    validateWrapperManifest(manifest);
    manifest.optionalDependencies = Object.fromEntries(
      PLATFORM_PACKAGES.map(entry => [entry.packageName, version]),
    );
  }

  manifest.version = version;
  return manifest;
}

export function expectedPackedFiles(packageDir, manifest) {
  const packageRoot = path.resolve(packageDir);
  const files = new Set(["package.json"]);

  for (const automatic of ["README", "README.md", "README.txt", "LICENSE", "LICENSE.md"]) {
    const candidate = path.join(packageRoot, automatic);
    if (fs.existsSync(candidate) && fs.lstatSync(candidate).isFile()) {
      files.add(automatic);
    }
  }

  for (const declared of manifest.files ?? []) {
    const relative = safePackagePath(declared);
    collectPackedPath(packageRoot, relative, files);
  }

  return [...files].sort();
}

export function runtimePlatformKey(platform, arch, libc = undefined) {
  if (platform === "linux" && libc === "musl") {
    return `${platform}-${arch}-musl`;
  }
  return `${platform}-${arch}`;
}

export function assertCliVersion(output, expectedVersion) {
  parseReleaseVersion(expectedVersion);
  const normalized = String(output ?? "").trim();
  if (!normalized) {
    throw new Error("lpm reported no version");
  }
  const reported = normalized.split(/\s+/).at(-1);
  if (reported !== expectedVersion) {
    throw new Error(`lpm reported ${JSON.stringify(normalized)}; expected ${expectedVersion}`);
  }
  return reported;
}

function platformPackage(key, os, cpu, binaries, libc = undefined) {
  return Object.freeze({
    key,
    packageName: `@lpm-registry/cli-${key}`,
    directory: `npm/cli-${key}`,
    os,
    cpu,
    libc,
    binaries: Object.freeze(binaries),
  });
}

function binary(artifact, destination) {
  return Object.freeze({ artifact, destination });
}

function validateWrapperManifest(manifest) {
  if (manifest.name !== WRAPPER_PACKAGE) {
    throw new Error(`wrapper package must be ${WRAPPER_PACKAGE}`);
  }
  if (manifest.dependencies) {
    throw new Error(`${WRAPPER_PACKAGE} wrapper must not publish runtime dependencies`);
  }
  if (manifest.devDependencies) {
    throw new Error(`${WRAPPER_PACKAGE} wrapper must not publish devDependencies`);
  }
  if (manifest.scripts?.preinstall || manifest.scripts?.install) {
    throw new Error(`${WRAPPER_PACKAGE} wrapper must not publish preinstall/install lifecycle scripts`);
  }
  if (manifest.scripts?.postinstall !== WRAPPER_POSTINSTALL) {
    throw new Error(`${WRAPPER_PACKAGE} wrapper must publish the native binary postinstall verifier`);
  }
  if (manifest.bin?.lpm !== "bin/lpm" || manifest.bin?.lpx !== "bin/lpx") {
    throw new Error(`${WRAPPER_PACKAGE} wrapper bin contract has drifted`);
  }
  if (!manifest.files?.includes("bin") || !manifest.files?.includes("scripts")) {
    throw new Error(`${WRAPPER_PACKAGE} wrapper must pack both bin and scripts`);
  }
}

function validatePlatformManifest(manifest, platform) {
  if (manifest.name !== platform.packageName) {
    throw new Error(`${platform.key} package name must be ${platform.packageName}`);
  }
  if (!sameSingleValue(manifest.os, platform.os)) {
    throw new Error(`${platform.packageName} operating-system contract has drifted`);
  }
  if (!sameSingleValue(manifest.cpu, platform.cpu)) {
    throw new Error(`${platform.packageName} CPU contract has drifted`);
  }
  if (platform.libc && !sameSingleValue(manifest.libc, platform.libc)) {
    throw new Error(`${platform.packageName} libc contract has drifted`);
  }
  if (!platform.libc && manifest.libc) {
    throw new Error(`${platform.packageName} must not declare a libc contract`);
  }

  const expectedFiles = platform.binaries.map(entry => entry.destination).sort();
  const declaredFiles = [...(manifest.files ?? [])].sort();
  if (JSON.stringify(declaredFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(
      `${platform.packageName} binary inventory has drifted: expected ${expectedFiles.join(", ")}`,
    );
  }
}

function sameSingleValue(values, expected) {
  return Array.isArray(values) && values.length === 1 && values[0] === expected;
}

function safePackagePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error(`unsafe package file path: ${JSON.stringify(value)}`);
  }
  if (value.includes("\\") || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    throw new Error(`unsafe package file path: ${JSON.stringify(value)}`);
  }

  const normalized = path.posix.normalize(value);
  if (normalized === "." || normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`unsafe package file path: ${JSON.stringify(value)}`);
  }
  return normalized;
}

function collectPackedPath(packageRoot, relative, files) {
  const absolute = path.resolve(packageRoot, ...relative.split("/"));
  const withinRoot = absolute.startsWith(`${packageRoot}${path.sep}`);
  if (!withinRoot) {
    throw new Error(`unsafe package file path: ${JSON.stringify(relative)}`);
  }

  const metadata = fs.lstatSync(absolute, { throwIfNoEntry: false });
  if (!metadata) {
    throw new Error(`declared package file does not exist: ${relative}`);
  }
  if (metadata.isSymbolicLink()) {
    throw new Error(`release packages must not contain symbolic links: ${relative}`);
  }
  if (metadata.isFile()) {
    files.add(relative);
    return;
  }
  if (!metadata.isDirectory()) {
    throw new Error(`unsupported package file type: ${relative}`);
  }

  for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
    collectPackedPath(packageRoot, path.posix.join(relative, entry.name), files);
  }
}
