#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PLATFORM_PACKAGES,
  expectedPackedFiles,
  manifestForRelease,
  parseReleaseVersion,
} from "./release-artifacts.mjs";
import { npmInvocation } from "./npm-invocation.mjs";

export function prepareReleasePackages({
  repoRoot,
  binariesDir,
  outputDir,
  version,
  wrapperOnly = false,
}) {
  const releaseVersion = parseReleaseVersion(version);
  const root = path.resolve(repoRoot);
  const binaries = binariesDir ? path.resolve(binariesDir) : undefined;
  const output = path.resolve(outputDir);
  ensureFreshOutputDirectory(output);

  if (!wrapperOnly && !binaries) {
    throw new Error("--binaries is required unless --wrapper-only is used");
  }

  const staging = path.join(output, ".staging");
  fs.mkdirSync(staging);
  const packages = [];

  try {
    if (!wrapperOnly) {
      for (const platform of PLATFORM_PACKAGES) {
        packages.push(
          preparePlatformPackage({ root, binaries, output, staging, releaseVersion, platform }),
        );
      }
    }
    packages.push(prepareWrapperPackage({ root, output, staging, releaseVersion }));

    const releaseManifest = {
      schemaVersion: 1,
      version: releaseVersion,
      wrapperOnly,
      packages,
    };
    fs.writeFileSync(
      path.join(output, "release-packages.json"),
      `${JSON.stringify(releaseManifest, null, 2)}\n`,
    );
    return releaseManifest;
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
}

function preparePlatformPackage({ root, binaries, output, staging, releaseVersion, platform }) {
  const sourceDir = path.join(root, platform.directory);
  const packageDir = path.join(staging, platform.key);
  copyPackageSource(sourceDir, packageDir);

  const sourceManifest = readJson(path.join(packageDir, "package.json"));
  const manifest = manifestForRelease(sourceManifest, releaseVersion, platform);
  writeJson(path.join(packageDir, "package.json"), manifest);

  const binaryHashes = {};
  for (const mapping of platform.binaries) {
    const source = path.join(binaries, mapping.artifact);
    const destination = path.join(packageDir, mapping.destination);
    assertRegularFile(source, `release binary ${mapping.artifact}`);
    fs.copyFileSync(source, destination);
    if (platform.os !== "win32") {
      fs.chmodSync(destination, 0o755);
    }

    const sourceSha256 = sha256File(source);
    const stagedSha256 = sha256File(destination);
    if (sourceSha256 !== stagedSha256) {
      throw new Error(`staged binary hash mismatch for ${platform.packageName}/${mapping.destination}`);
    }
    binaryHashes[mapping.destination] = {
      artifact: mapping.artifact,
      sha256: stagedSha256,
    };
  }

  return packPackage({ packageDir, output, manifest, platform: platform.key, binaryHashes });
}

function prepareWrapperPackage({ root, output, staging, releaseVersion }) {
  const packageDir = path.join(staging, "wrapper");
  copyPackageSource(path.join(root, "npm/cli"), packageDir);
  const sourceManifest = readJson(path.join(packageDir, "package.json"));
  const manifest = manifestForRelease(sourceManifest, releaseVersion);
  writeJson(path.join(packageDir, "package.json"), manifest);
  return packPackage({ packageDir, output, manifest, platform: null, binaryHashes: {} });
}

function packPackage({ packageDir, output, manifest, platform, binaryHashes }) {
  const expectedFiles = expectedPackedFiles(packageDir, manifest);
  const npm = npmInvocation();
  if (process.platform === "win32") {
    assertRegularFile(npm.argsPrefix[0], "npm CLI entry point");
  }
  const result = spawnSync(
    npm.command,
    [
      ...npm.argsPrefix,
      "pack",
      "--ignore-scripts",
      "--json",
      "--pack-destination",
      output,
    ],
    {
      cwd: packageDir,
      encoding: "utf8",
      env: {
        ...process.env,
        NO_COLOR: "1",
        NPM_CONFIG_AUDIT: "false",
        NPM_CONFIG_FUND: "false",
        NPM_CONFIG_PROGRESS: "false",
      },
    },
  );
  if (result.error) {
    throw new Error(`failed to run npm pack for ${manifest.name}: ${result.error.message}`, {
      cause: result.error,
    });
  }
  if (result.status !== 0) {
    throw new Error(
      `npm pack failed for ${manifest.name} with status ${result.status}:\n${result.stderr}`,
    );
  }

  let packResults;
  try {
    packResults = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`npm pack returned invalid JSON for ${manifest.name}: ${result.stdout}`, {
      cause: error,
    });
  }
  const resultEntries = Array.isArray(packResults)
    ? packResults
    : packResults && typeof packResults === "object"
      ? Object.values(packResults)
      : [];
  if (resultEntries.length !== 1) {
    throw new Error(
      `npm pack returned an unexpected result count for ${manifest.name}: ${result.stdout}`,
    );
  }

  const packResult = resultEntries[0];
  const actualFiles = (packResult.files ?? []).map(file => file.path).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(
      `packed files for ${manifest.name} drifted:\nexpected ${expectedFiles.join("\n")}\nactual ${actualFiles.join("\n")}`,
    );
  }

  const tarballPath = path.join(output, packResult.filename);
  assertRegularFile(tarballPath, `packed tarball for ${manifest.name}`);
  return {
    name: manifest.name,
    version: manifest.version,
    platform,
    tarball: packResult.filename,
    sha256: sha256File(tarballPath),
    shasum: packResult.shasum,
    integrity: packResult.integrity,
    files: packResult.files,
    binaries: binaryHashes,
  };
}

function copyPackageSource(source, destination) {
  assertDirectory(source, `package source ${source}`);
  fs.cpSync(source, destination, {
    recursive: true,
    dereference: false,
    filter(candidate) {
      return path.basename(candidate) !== "node_modules";
    },
  });
}

function ensureFreshOutputDirectory(output) {
  const metadata = fs.lstatSync(output, { throwIfNoEntry: false });
  if (metadata?.isSymbolicLink()) {
    throw new Error(`release package output must not be a symbolic link: ${output}`);
  }
  if (metadata && !metadata.isDirectory()) {
    throw new Error(`release package output is not a directory: ${output}`);
  }
  if (metadata && fs.readdirSync(output).length !== 0) {
    throw new Error(`release package output must be empty: ${output}`);
  }
  fs.mkdirSync(output, { recursive: true });
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function assertRegularFile(file, label) {
  const metadata = fs.statSync(file, { throwIfNoEntry: false });
  if (!metadata?.isFile()) {
    throw new Error(`${label} is missing or is not a regular file: ${file}`);
  }
}

function assertDirectory(directory, label) {
  const metadata = fs.statSync(directory, { throwIfNoEntry: false });
  if (!metadata?.isDirectory()) {
    throw new Error(`${label} is missing or is not a directory`);
  }
}

function sha256File(file) {
  const hash = crypto.createHash("sha256");
  const descriptor = fs.openSync(file, "r");
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    for (;;) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest("hex");
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--wrapper-only") {
      options.wrapperOnly = true;
      continue;
    }
    if (!argument.startsWith("--") || index + 1 >= argv.length) {
      throw new Error(`invalid argument: ${argument}`);
    }
    options[argument.slice(2)] = argv[index + 1];
    index += 1;
  }

  for (const required of ["repo", "output", "version"]) {
    if (!options[required]) throw new Error(`--${required} is required`);
  }
  return {
    repoRoot: options.repo,
    binariesDir: options.binaries,
    outputDir: options.output,
    version: options.version,
    wrapperOnly: options.wrapperOnly ?? false,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const manifest = prepareReleasePackages(parseArguments(process.argv.slice(2)));
    for (const pkg of manifest.packages) {
      console.log(`${pkg.name}@${pkg.version}: ${pkg.tarball} (${pkg.sha256})`);
    }
  } catch (error) {
    console.error(`prepare-packages: ${error.message}`);
    process.exit(1);
  }
}
