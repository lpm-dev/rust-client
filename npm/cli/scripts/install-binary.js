import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  LpmWrapperError,
  PLATFORMS,
  detectLinuxLibc,
  platformKey,
  resolveNativeBinary,
} from "../bin/native.js";

const require = createRequire(import.meta.url);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const defaultWrapperRoot = path.resolve(scriptDir, "..");
const defaultValidateTimeoutMs = 30_000;
const commands = ["lpm", "lpx"];

export class SudoInstallError extends Error {
  constructor() {
    super(
      "LPM CLI does not support npm installation through sudo. Run the npm install command without sudo.",
    );
    this.name = "SudoInstallError";
  }
}

export function installNativeBinaries(options = {}) {
  const wrapperRoot = options.wrapperRoot ?? defaultWrapperRoot;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? os.arch();
  const libc = options.libc ?? detectLinuxLibc();
  const env = options.env ?? process.env;
  const requireFn = options.requireFn ?? require;
  const fsModule = options.fsModule ?? fs;
  const spawnSyncFn = options.spawnSyncFn ?? spawnSync;
  const logFn = options.logFn ?? console.log;
  const validateTimeoutMs =
    options.validateTimeoutMs ?? defaultValidateTimeoutMs;
  const geteuid =
    options.geteuid ??
    (typeof process.geteuid === "function" ? () => process.geteuid() : undefined);

  if (isSudoTransition({ geteuid, env })) {
    throw new SudoInstallError();
  }

  const key = platformKey(platform, arch, libc);
  const spec = PLATFORMS[key];
  if (!spec) {
    logFn(
      `[lpm] No pre-built native npm package for ${key}; the JS wrapper will report this at runtime.`,
    );
    return { status: "unsupported", platform: key, optimized: [] };
  }

  const expectedVersion = readWrapperVersion(wrapperRoot, fsModule);
  const lpmBinary = resolveNativeBinary({
    command: "lpm",
    platform,
    arch,
    libc,
    env,
    requireFn,
  });

  validateNativeBinary(lpmBinary.path, {
    expectedVersion,
    env,
    spawnSyncFn,
    validateTimeoutMs,
  });

  const optimized = [];
  for (const command of commands) {
    const native =
      command === "lpm"
        ? lpmBinary
        : resolveNativeBinary({
            command,
            platform,
            arch,
            libc,
            env,
            requireFn,
          });
    const target = optimizedTargetPath(wrapperRoot, platform, command);
    const action = stageOptimizedBinary({
      source: native.path,
      target,
      platform,
      fsModule,
    });
    optimized.push({
      command,
      source: native.path,
      target,
      action,
    });
  }

  logFn(`[lpm] Installed native binary from ${spec.pkg}`);
  return { status: "installed", platform: key, package: spec.pkg, optimized };
}

export function isSudoTransition({ geteuid, env = process.env } = {}) {
  if (typeof geteuid !== "function" || geteuid() !== 0) {
    return false;
  }

  const sudoUser = env.SUDO_USER;
  return (
    typeof sudoUser === "string" &&
    sudoUser.trim() !== "" &&
    sudoUser.trim() !== "root"
  );
}

export function validateNativeBinary(
  binaryPath,
  {
    expectedVersion = "",
    env = process.env,
    spawnSyncFn = spawnSync,
    validateTimeoutMs = defaultValidateTimeoutMs,
  } = {},
) {
  let result;
  try {
    result = spawnSyncFn(binaryPath, ["--version"], {
      stdio: ["ignore", "pipe", "pipe"],
      encoding: "utf8",
      env,
      timeout: validateTimeoutMs,
    });
  } catch (error) {
    throw new Error(
      `Native binary at ${binaryPath} could not be started: ${error.message}`,
      { cause: error },
    );
  }

  if (result.error) {
    const timeout =
      result.error.code === "ETIMEDOUT"
        ? ` within ${Math.ceil(validateTimeoutMs / 1000)}s`
        : "";
    throw new Error(
      `Native binary at ${binaryPath} did not report its version${timeout}: ${result.error.message}`,
      { cause: result.error },
    );
  }

  if (result.signal) {
    throw new Error(
      `Native binary at ${binaryPath} was interrupted by ${result.signal} while reporting its version.`,
    );
  }

  if (result.status !== 0) {
    const stderr = String(result.stderr ?? "").trim();
    throw new Error(
      `Native binary at ${binaryPath} exited with status ${result.status} while reporting its version.${stderr ? ` ${stderr}` : ""}`,
    );
  }

  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  if (expectedVersion && !output.includes(expectedVersion)) {
    throw new Error(
      `Native binary at ${binaryPath} reported version ${JSON.stringify(output || "<empty>")} instead of ${expectedVersion}.`,
    );
  }

  return output;
}

export function stageOptimizedBinary({ source, target, platform, fsModule = fs }) {
  fsModule.mkdirSync(path.dirname(target), { recursive: true });
  if (platform === "win32") {
    atomicCopy(source, target, fsModule);
    return "copy";
  }

  try {
    atomicLink(source, target, fsModule);
    return "link";
  } catch {
    atomicCopy(source, target, fsModule);
    return "copy";
  }
}

function optimizedTargetPath(wrapperRoot, platform, command) {
  const filename = platform === "win32" ? `${command}.exe` : command;
  return path.join(wrapperRoot, "bin", filename);
}

function readWrapperVersion(wrapperRoot, fsModule) {
  try {
    const manifest = JSON.parse(
      fsModule.readFileSync(path.join(wrapperRoot, "package.json"), "utf8"),
    );
    return typeof manifest.version === "string" ? manifest.version : "";
  } catch {
    return "";
  }
}

function atomicLink(source, target, fsModule) {
  replaceWithTemp(target, fsModule, temp => {
    fsModule.linkSync(source, temp);
    fsModule.chmodSync(temp, 0o755);
  });
}

function atomicCopy(source, target, fsModule) {
  replaceWithTemp(target, fsModule, temp => {
    fsModule.copyFileSync(source, temp);
    fsModule.chmodSync(temp, 0o755);
  });
}

function replaceWithTemp(target, fsModule, writeTemp) {
  const temp = `${target}.${process.pid}.${Date.now()}.tmp`;
  let replaced = false;

  try {
    unlinkIfExists(temp, fsModule);
    writeTemp(temp);
    fsModule.renameSync(temp, target);
    replaced = true;
  } finally {
    if (!replaced) {
      unlinkIfExists(temp, fsModule);
    }
  }
}

function unlinkIfExists(filePath, fsModule) {
  try {
    fsModule.unlinkSync(filePath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

function printInstallError(error) {
  if (error instanceof SudoInstallError) {
    console.error(`[lpm] ${error.message}`);
    return;
  }

  if (error instanceof LpmWrapperError) {
    console.error(`[lpm] ${error.message}`);
    for (const hint of error.hints) {
      console.error(`[lpm] ${hint}`);
    }
  } else {
    console.error(`[lpm] Failed to install native binary: ${error.message}`);
  }

  console.error(
    "[lpm] Reinstall with optional dependencies and install scripts enabled: npm install -g @lpm-registry/cli",
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    installNativeBinaries();
  } catch (error) {
    printInstallError(error);
    process.exit(1);
  }
}
