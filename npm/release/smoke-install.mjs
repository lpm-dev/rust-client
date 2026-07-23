#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PLATFORM_PACKAGES,
  assertCliVersion,
  parseReleaseVersion,
  runtimePlatformKey,
} from "./release-artifacts.mjs";
import { npmInvocation } from "./npm-invocation.mjs";

export function smokeInstall({ tarballsDir, expectedPlatform, expectedVersion, prefix }) {
  const releaseVersion = parseReleaseVersion(expectedVersion);
  const tarballRoot = path.resolve(tarballsDir);
  const manifest = readJson(path.join(tarballRoot, "release-packages.json"));
  if (manifest.schemaVersion !== 1 || manifest.version !== releaseVersion) {
    throw new Error(
      `release package manifest version mismatch: expected ${releaseVersion}, got ${manifest.version}`,
    );
  }

  const runtimeKey = runtimePlatformKey(process.platform, process.arch, detectLinuxLibc());
  if (runtimeKey !== expectedPlatform) {
    throw new Error(`smoke runner is ${runtimeKey}, expected ${expectedPlatform}`);
  }
  const platform = PLATFORM_PACKAGES.find(entry => entry.key === expectedPlatform);
  if (!platform) throw new Error(`unknown release platform: ${expectedPlatform}`);

  const wrapperRecord = findPackageRecord(manifest, "@lpm-registry/cli");
  const platformRecord = findPackageRecord(manifest, platform.packageName);
  const wrapperTarball = verifiedTarballPath(tarballRoot, wrapperRecord);
  const platformTarball = verifiedTarballPath(tarballRoot, platformRecord);
  const installPrefix = prefix
    ? path.resolve(prefix)
    : fs.mkdtempSync(path.join(os.tmpdir(), "lpm release smoke ü-"));
  fs.mkdirSync(installPrefix, { recursive: true });

  let succeeded = false;
  try {
    const npm = npmInvocation();
    if (process.platform === "win32") {
      assertRegularFile(npm.argsPrefix[0], "npm CLI entry point");
    }
    runChecked(
      npm.command,
      [
        ...npm.argsPrefix,
        "install",
        "--prefix",
        installPrefix,
        "--offline",
        "--ignore-scripts=false",
        "--no-audit",
        "--no-fund",
        "--no-package-lock",
        "--no-save",
        "--progress=false",
        wrapperTarball,
        platformTarball,
      ],
      {
        cwd: installPrefix,
        env: {
          ...process.env,
          NO_COLOR: "1",
          NPM_CONFIG_OFFLINE: "true",
          NPM_CONFIG_REGISTRY: "http://127.0.0.1:9/",
        },
      },
    );

    const nodeModules = path.join(installPrefix, "node_modules");
    const wrapperRoot = path.join(nodeModules, "@lpm-registry", "cli");
    const nativeRoot = path.join(nodeModules, "@lpm-registry", `cli-${expectedPlatform}`);
    assertDirectory(wrapperRoot, "installed wrapper package");
    assertDirectory(nativeRoot, "installed native platform package");

    for (const candidate of PLATFORM_PACKAGES) {
      if (candidate.key === expectedPlatform) continue;
      const incompatible = path.join(nodeModules, "@lpm-registry", `cli-${candidate.key}`);
      if (fs.existsSync(incompatible)) {
        throw new Error(`npm installed incompatible platform package ${candidate.packageName}`);
      }
    }

    verifyInstalledBinaries({ platform, platformRecord, nativeRoot, wrapperRoot });
    verifyPlatformSignatures({ platform, nativeRoot, wrapperRoot });
    verifyGeneratedCommands({ installPrefix, expectedVersion: releaseVersion });

    succeeded = true;
    console.log(`release npm smoke passed for ${expectedPlatform} in ${installPrefix}`);
    return { installPrefix, platform: expectedPlatform, version: releaseVersion };
  } finally {
    if (succeeded && !prefix) {
      fs.rmSync(installPrefix, { recursive: true, force: true });
    } else if (!succeeded) {
      console.error(`release npm smoke prefix retained for diagnosis: ${installPrefix}`);
    }
  }
}

function verifyInstalledBinaries({ platform, platformRecord, nativeRoot, wrapperRoot }) {
  for (const mapping of platform.binaries) {
    const record = platformRecord.binaries?.[mapping.destination];
    if (!record?.sha256) {
      throw new Error(`release manifest is missing the hash for ${mapping.destination}`);
    }
    const installed = path.join(nativeRoot, mapping.destination);
    assertRegularFile(installed, `installed ${platform.packageName}/${mapping.destination}`);
    assertFileHash(installed, record.sha256);

    if (mapping.destination.startsWith("lpm-sandbox-helper")) continue;
    const staged = path.join(wrapperRoot, "bin", mapping.destination);
    assertRegularFile(staged, `postinstall-staged ${mapping.destination}`);
    assertFileHash(staged, record.sha256);
  }
}

function verifyPlatformSignatures({ platform, nativeRoot, wrapperRoot }) {
  if (platform.os === "darwin") {
    for (const binary of [
      path.join(nativeRoot, "lpm"),
      path.join(nativeRoot, "lpx"),
      path.join(wrapperRoot, "bin", "lpm"),
      path.join(wrapperRoot, "bin", "lpx"),
    ]) {
      runChecked("codesign", ["--verify", "--strict", "--verbose=4", binary]);
    }
  }

  if (platform.os === "win32") {
    const signatureTargets = [
      path.join(nativeRoot, "lpm.exe"),
      path.join(nativeRoot, "lpx.exe"),
      path.join(nativeRoot, "lpm-sandbox-helper.exe"),
      path.join(wrapperRoot, "bin", "lpm.exe"),
      path.join(wrapperRoot, "bin", "lpx.exe"),
    ];
    runChecked(
      "pwsh.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$files = $env:LPM_SMOKE_SIGNATURE_TARGETS | ConvertFrom-Json; " +
          "foreach ($file in $files) { " +
          "$signature = Get-AuthenticodeSignature -FilePath $file; " +
          "if ($signature.Status -ne 'Valid') { throw \"Invalid Authenticode signature for $file`: $($signature.Status)\" }; " +
          "if ($null -eq $signature.TimeStamperCertificate) { throw \"Missing Authenticode timestamp for $file\" } " +
          "}",
      ],
      {
        env: {
          ...process.env,
          LPM_SMOKE_SIGNATURE_TARGETS: JSON.stringify(signatureTargets),
        },
      },
    );
  }
}

function verifyGeneratedCommands({ installPrefix, expectedVersion }) {
  const binDir = path.join(installPrefix, "node_modules", ".bin");
  if (process.platform === "win32") {
    const cmdLpm = path.join(binDir, "lpm.cmd");
    const cmdLpx = path.join(binDir, "lpx.cmd");
    const psLpm = path.join(binDir, "lpm.ps1");
    const bashLpm = path.join(binDir, "lpm");
    for (const command of [cmdLpm, cmdLpx, psLpm, bashLpm]) {
      assertRegularFile(command, "npm-generated Windows command shim");
    }

    const cmdVersion = runChecked("cmd.exe", ["/D", "/S", "/C", `\"${cmdLpm}\" --version`]);
    assertCliVersion(cmdVersion.stdout, expectedVersion);
    runChecked("cmd.exe", ["/D", "/S", "/C", `\"${cmdLpx}\" --help`]);

    const powerShellVersion = runChecked(
      "pwsh.exe",
      ["-NoProfile", "-NonInteractive", "-File", psLpm, "--version"],
    );
    assertCliVersion(powerShellVersion.stdout, expectedVersion);

    const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
    assertRegularFile(gitBash, "Git Bash executable");
    const bashVersion = runChecked(
      gitBash,
      ["-lc", 'binary=$(cygpath -u "$1"); "$binary" --version', "--", bashLpm],
    );
    assertCliVersion(bashVersion.stdout, expectedVersion);
    return;
  }

  const lpm = path.join(binDir, "lpm");
  const lpx = path.join(binDir, "lpx");
  const version = runChecked(lpm, ["--version"]);
  assertCliVersion(version.stdout, expectedVersion);
  runChecked(lpx, ["--help"]);
}

function verifiedTarballPath(root, record) {
  if (!record.tarball || path.basename(record.tarball) !== record.tarball) {
    throw new Error(`unsafe tarball path in release manifest: ${record.tarball}`);
  }
  const tarball = path.join(root, record.tarball);
  assertRegularFile(tarball, `release tarball ${record.tarball}`);
  assertFileHash(tarball, record.sha256);
  return tarball;
}

function findPackageRecord(manifest, name) {
  const matches = (manifest.packages ?? []).filter(pkg => pkg.name === name);
  if (matches.length !== 1) {
    throw new Error(`release manifest must contain exactly one ${name} package`);
  }
  return matches[0];
}

function detectLinuxLibc() {
  if (process.platform !== "linux") return undefined;
  return process.report?.getReport?.().header?.glibcVersionRuntime ? "glibc" : "musl";
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function assertDirectory(directory, label) {
  const metadata = fs.statSync(directory, { throwIfNoEntry: false });
  if (!metadata?.isDirectory()) throw new Error(`${label} is missing: ${directory}`);
}

function assertRegularFile(file, label) {
  const metadata = fs.statSync(file, { throwIfNoEntry: false });
  if (!metadata?.isFile()) throw new Error(`${label} is missing: ${file}`);
}

function assertFileHash(file, expected) {
  const actual = sha256File(file);
  if (actual !== expected) {
    throw new Error(`SHA-256 mismatch for ${file}: expected ${expected}, got ${actual}`);
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

function runChecked(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.error) {
    throw new Error(`failed to run ${command}: ${result.error.message}`, { cause: result.error });
  }
  if (result.status !== 0) {
    throw new Error(
      `${command} exited with status ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  return result;
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument: ${key}`);
    }
    options[key.slice(2)] = value;
  }
  for (const required of ["tarballs", "platform", "version"]) {
    if (!options[required]) throw new Error(`--${required} is required`);
  }
  return {
    tarballsDir: options.tarballs,
    expectedPlatform: options.platform,
    expectedVersion: options.version,
    prefix: options.prefix,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    smokeInstall(parseArguments(process.argv.slice(2)));
  } catch (error) {
    console.error(`smoke-install: ${error.message}`);
    process.exit(1);
  }
}
