import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";

const require = createRequire(import.meta.url);

export const PLATFORMS = Object.freeze({
  "darwin-arm64": {
    pkg: "@lpm-registry/cli-darwin-arm64",
    lpm: "lpm",
    lpx: "lpx",
  },
  "darwin-x64": {
    pkg: "@lpm-registry/cli-darwin-x64",
    lpm: "lpm",
    lpx: "lpx",
  },
  "linux-arm64": {
    pkg: "@lpm-registry/cli-linux-arm64",
    lpm: "lpm",
    lpx: "lpx",
  },
  "linux-x64": {
    pkg: "@lpm-registry/cli-linux-x64",
    lpm: "lpm",
    lpx: "lpx",
  },
  "linux-x64-musl": {
    pkg: "@lpm-registry/cli-linux-x64-musl",
    lpm: "lpm",
    lpx: "lpx",
  },
  "win32-x64": {
    pkg: "@lpm-registry/cli-win32-x64",
    lpm: "lpm.exe",
    lpx: "lpx.exe",
  },
});

export function platformKey(
  platform = process.platform,
  arch = os.arch(),
  libc,
) {
  if (platform === "linux" && libc === "musl") {
    return `linux-${arch}-musl`;
  }
  return `${platform}-${arch}`;
}

export function detectLinuxLibc(
  report = process.platform === "linux" ? process.report?.getReport?.() : undefined,
) {
  if (!report) {
    return undefined;
  }
  return report.header?.glibcVersionRuntime ? "glibc" : "musl";
}

export function resolveNativeBinary(options = {}) {
  const command = options.command ?? "lpm";
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const arch = options.arch ?? os.arch();
  const libc = options.libc ?? detectLinuxLibc();
  const requireFn = options.requireFn ?? require;

  const override = env.LPM_BINARY_PATH;
  if (override) {
    return {
      path: override,
      source: "env",
      argsPrefix: command === "lpx" ? ["dlx"] : [],
    };
  }

  const key = platformKey(platform, arch, libc);
  const spec = PLATFORMS[key];
  if (!spec) {
    throw new LpmWrapperError(
      `Unsupported platform: ${key}`,
      [
        "LPM publishes native npm packages for macOS, Linux, and Windows on x64/arm64.",
        "Use another install method from https://github.com/lpm-dev/rust-client.",
      ],
    );
  }

  let packageJsonPath;
  try {
    packageJsonPath = requireFn.resolve(`${spec.pkg}/package.json`);
  } catch (error) {
    throw new LpmWrapperError(
      `Native package ${spec.pkg} is not installed.`,
      [
        "Reinstall with optional dependencies enabled:",
        "  npm install -g @lpm-registry/cli",
        "If you used --omit=optional, --no-optional, or a package-manager policy that blocks optional dependencies, remove that setting.",
      ],
      error,
    );
  }

  const binaryPath = path.join(path.dirname(packageJsonPath), spec[command]);
  if (!fs.existsSync(binaryPath)) {
    throw new LpmWrapperError(
      `Native package ${spec.pkg} is installed, but ${spec[command]} is missing.`,
      ["Reinstall LPM with `npm install -g @lpm-registry/cli`."],
    );
  }

  return {
    path: binaryPath,
    source: spec.pkg,
    argsPrefix: [],
  };
}

export function runNativeCommand(command) {
  let native;
  try {
    native = resolveNativeBinary({ command });
  } catch (error) {
    printWrapperError(error);
    process.exit(1);
  }

  const args = native.argsPrefix.concat(process.argv.slice(2));
  const result = spawnSync(native.path, args, {
    stdio: "inherit",
    env: process.env,
  });

  if (result.error) {
    console.error(`[lpm] Failed to run native binary at ${native.path}`);
    console.error(`[lpm] ${result.error.message}`);
    process.exit(1);
  }

  if (result.signal) {
    forwardSignalExit(result.signal);
  }

  process.exit(result.status ?? 1);
}

export class LpmWrapperError extends Error {
  constructor(message, hints = [], cause = undefined) {
    super(message, cause ? { cause } : undefined);
    this.name = "LpmWrapperError";
    this.hints = hints;
  }
}

function printWrapperError(error) {
  if (error instanceof LpmWrapperError) {
    console.error(`[lpm] ${error.message}`);
    for (const hint of error.hints) {
      console.error(`[lpm] ${hint}`);
    }
    return;
  }

  console.error(`[lpm] ${error?.message ?? error}`);
}

function forwardSignalExit(signal) {
  const signalNumber = os.constants.signals[signal];
  if (signalNumber) {
    process.kill(process.pid, signal);
    process.exit(128 + signalNumber);
  }
  process.exit(1);
}
