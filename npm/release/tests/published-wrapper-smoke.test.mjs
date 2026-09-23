import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const version = "0.79.0-nightly.20260921.194.2120105";

function verifyWithDelayedRegistry(readyAfter, mode = "propagation", tag = "nightly") {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "lpm-published-smoke-"));
  try {
    fs.mkdirSync(path.join(fixture, "attempts"));
    const result = spawnSync("bash", ["-c", `
      unset SECONDS
      SECONDS=0
      sleep() {
        echo "$1" >> "$FIXTURE/sleeps"
        SECONDS=$((SECONDS + $1))
      }
      timeout() {
        echo "$*" >> "$FIXTURE/commands"
        local duration=
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --signal=TERM|--kill-after=5s) shift ;;
            *s) duration=\${1%s}; shift; break ;;
            *) echo 'Missing timeout' >&2; return 1 ;;
          esac
        done
        if [ "$duration" -gt "$((900 - SECONDS))" ]; then
          echo 'Command exceeds remaining deadline' >&2
          return 1
        fi
        if [ "$MODE" = hang ]; then
          SECONDS=$((SECONDS + duration))
          echo 'npm timed out' >&2
          return 124
        fi
        "$@"
      }
      npm() {
        if [ "$1" = view ]; then
          if [ "$MODE" = tag-error ]; then echo 'npm view failed' >&2; return 1; fi
          if [ "$MODE" = stale-tag ] && [ "$SECONDS" -lt "$READY_AFTER" ]; then
            echo '0.78.0'
          else
            printf '%s\n' "$FIXTURE_VERSION"
          fi
          return
        fi
        if [ "$MODE" = stale-tag ]; then create_install "$@"; return; fi
        if [ "$SECONDS" -lt "$READY_AFTER" ]; then
          if [ "$SECONDS" -lt 160 ]; then
            echo 'npm error ETARGET: registry metadata has not propagated' >&2
          else
            echo 'Native package @lpm-registry/cli-linux-x64 is not installed' >&2
          fi
          return 1
        fi
        create_install "$@"
      }
      create_install() {
        local prefix=
        while [ "$#" -gt 0 ]; do
          if [ "$1" = --prefix ]; then prefix=$2; break; fi
          shift
        done
        mkdir -p "$prefix/bin"
        local installed_version="$FIXTURE_VERSION"
        if [ "$MODE" = wrong-version ]; then installed_version=0.78.0; fi
        printf '#!/bin/sh\necho "lpm %s"\n' "$installed_version" > "$prefix/bin/lpm"
        printf '#!/bin/sh\nexit 0\n' > "$prefix/bin/lpx"
        if [ "$MODE" = broken-lpx ]; then printf '#!/bin/sh\necho "lpx failed" >&2\nexit 1\n' > "$prefix/bin/lpx"; fi
        chmod +x "$prefix/bin/lpm" "$prefix/bin/lpx"
      }
      source "$HELPER" "$FIXTURE_VERSION" "$NPM_TAG"
    `], {
      cwd: fixture,
      env: {
        ...process.env,
        FIXTURE: fixture,
        TMPDIR: path.join(fixture, "attempts"),
        HELPER: path.join(repoRoot, "scripts/ci/verify-published-wrapper.sh"),
        FIXTURE_VERSION: version,
        NPM_TAG: tag,
        READY_AFTER: String(readyAfter),
        MODE: mode,
      },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.deepEqual(fs.readdirSync(path.join(fixture, "attempts")), [], "attempts must be cleaned up");
    return {
      ...result,
      commands: fs.readFileSync(path.join(fixture, "commands"), "utf8"),
      sleeps: fs.existsSync(path.join(fixture, "sleeps"))
        ? fs.readFileSync(path.join(fixture, "sleeps"), "utf8").trim().split("\n").map(Number)
        : [],
    };
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
}

test("published wrapper verification succeeds when registry propagation takes more than five minutes", {
  skip: process.platform === "win32",
}, () => {
  const result = verifyWithDelayedRegistry(360);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /ETARGET/);
  assert.match(result.stderr, /Native package .* is not installed/);
  assert.match(result.commands, /--include=optional --ignore-scripts=false/);
  assert.match(result.commands, /dist-tags.nightly/);
  assert.deepEqual(result.sleeps.slice(0, 4), [5, 10, 20, 30]);
  assert.ok(result.sleeps.every(value => value > 0 && value <= 30));
  const caches = [...result.commands.matchAll(/--cache (\S+)/g)].map(match => match[1]);
  assert.equal(new Set(caches.slice(0, -1)).size, caches.length - 1, "installs must use fresh caches");
});

test("published wrapper verification retries a stale stable dist-tag after installation succeeds", {
  skip: process.platform === "win32",
}, () => {
  const result = verifyWithDelayedRegistry(360, "stale-tag", "latest");
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /Expected dist-tags.latest=/);
  assert.match(result.commands, /dist-tags.latest/);
});

test("published wrapper verification returns immediately once installation and both launchers work", {
  skip: process.platform === "win32",
}, () => {
  const result = verifyWithDelayedRegistry(0);
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual(result.sleeps, []);
  assert.match(result.commands, /bin\/lpm --version/);
  assert.match(result.commands, /bin\/lpx --help/);
});

for (const [mode, readyAfter, diagnostic] of [
  ["propagation", 901, /Native package .* is not installed/],
  ["stale-tag", 901, /Expected dist-tags.nightly=/],
  ["wrong-version", 0, /Expected lpm .*received: lpm 0.78.0/],
  ["broken-lpx", 0, /lpx failed/],
  ["tag-error", 0, /npm view failed/],
  ["hang", 0, /npm timed out/],
]) {
  test(`published wrapper verification fails within its deadline and preserves ${mode} diagnostics`, {
    skip: process.platform === "win32",
  }, () => {
    const result = verifyWithDelayedRegistry(readyAfter, mode);
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /failed after 900s registry-propagation window/);
    assert.match(result.stderr, diagnostic);
    assert.doesNotMatch(result.stderr, /Command exceeds remaining deadline/);
    assert.equal(result.sleeps.reduce((total, value) => total + value, 0), mode === "hang" ? 0 : 900);
  });
}
