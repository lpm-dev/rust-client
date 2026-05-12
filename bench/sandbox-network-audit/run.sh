#!/usr/bin/env bash
# Phase 46.1 sandbox-network-denial audit — single-package runner.
#
# Installs ONE package via `lpm-rs install` under the Phase 46.1
# sandbox (script-policy = allow, so the triage gate is bypassed
# and every scripted package's postinstall is given a chance to
# run -- the audit then measures whether the sandbox denies its
# outbound network attempt).
#
# Emits a single-line JSON record on stdout per the schema in
# bench/sandbox-network-audit/README.md.
#
# Usage:
#   run.sh <package@version>
#
# Requires:
#   - lpm-rs on $PATH (built from the implementation branch)
#   - node on $PATH
#   - tar, jq, mktemp

set -u

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <package@version>" >&2
    exit 2
fi

PKG_SPEC="$1"
# Split `name@version` -> `$NAME` + `$VERSION` (latest if absent).
# Scoped packages have one `@` at position 0; split on the LAST `@`
# so `@scope/pkg@1.0.0` keeps the scope intact.
if [[ "$PKG_SPEC" == *"@"* && "$PKG_SPEC" != "@"* ]]; then
    NAME="${PKG_SPEC%@*}"
    VERSION="${PKG_SPEC##*@}"
elif [[ "$PKG_SPEC" == "@"*"@"* ]]; then
    # Scoped + versioned: `@scope/pkg@1.0.0`
    NAME="${PKG_SPEC%@*}"
    VERSION="${PKG_SPEC##*@}"
else
    NAME="$PKG_SPEC"
    VERSION="latest"
fi

# Per-package staging directory under .cache/. Cleanup at the end
# regardless of outcome. The stage holds the synthetic project +
# an ISOLATED LPM store + isolated HOME so the audit doesn't leak
# into (or read from) the developer's real `~/.lpm`.
#
# `SCRIPT_DIR` is resolved to an ABSOLUTE path so downstream
# stdout/stderr redirects survive the `cd "$STAGE_DIR"` step
# below — a relative `$0` (e.g. `bench/.../run.sh`) would
# otherwise put the stderr file at a path that vanishes after
# the cd, and the script would silently fail to capture output
# while the install pipeline reports exit_code=1 with no
# explanation.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="$SCRIPT_DIR/.cache"
mkdir -p "$CACHE_DIR"
STAGE_DIR="$(mktemp -d "$CACHE_DIR/${NAME//\//_}.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

# Isolated LPM root. The production CLI's `LpmRoot::from_env()`
# honors `LPM_HOME` (and falls back to `$HOME/.lpm`); the marker
# at `$LPM_HOME/store/v1/<name>@<version>/.lpm-built` is the
# single source of truth for "did the build pipeline mint a
# success marker for this package".
#
# Note: `LPM_STORE_DIR` + `LPM_CACHE_DIR` are workflow-test-only
# decorations (set by `tests/workflows/tests/support/mod.rs:159`)
# — the production CLI never reads them. An earlier version of
# this script exported them defensively; that was misleading
# because it suggested isolation the CLI doesn't honor. Only
# LPM_HOME + HOME actually move the store root for the
# production-binary path this audit exercises.
mkdir -p "$STAGE_DIR/lpm-home" "$STAGE_DIR/home"
export LPM_HOME="$STAGE_DIR/lpm-home"
export HOME="$STAGE_DIR/home"

# Minimal project manifest pulling in the single audit target.
cat > "$STAGE_DIR/package.json" <<EOF
{
    "name": "sandbox-network-audit-fixture",
    "version": "0.0.0",
    "dependencies": {
        "${NAME}": "${VERSION}"
    }
}
EOF

# Run lpm install with --policy=allow so the triage gate doesn't
# block the postinstall before the sandbox even gets a chance to
# enforce. Capture stdout + stderr separately for the classifier.
STDOUT_FILE="$STAGE_DIR/stdout.log"
STDERR_FILE="$STAGE_DIR/stderr.log"

# Per-package install timeout. Lifecycle scripts that hang waiting
# on a TCP timeout (the kernel-denied connect can take 30s+ to
# emit ECONNREFUSED on some kernels) shouldn't gum up the whole
# audit. 120s covers honest installs + denial timeouts; anything
# longer is a hang we want to record + move past.
#
# `timeout(1)` is GNU coreutils — present on every Linux distro,
# absent on macOS's stock install (where it's `gtimeout` if
# coreutils is brew-installed). The design-note audit target is
# Linux 6.7+, but the harness is also smoke-tested on macOS dev
# hosts; prefer `timeout`, fall back to `gtimeout`, fall through
# to no-timeout (with a warning emitted ONCE per script
# invocation) if neither is on PATH. The no-timeout path is
# obviously hazardous for the full curated-sample run, but lets
# the smoke-test path work on a stock macOS box.
TIMEOUT_SEC=120
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    echo "warning: neither timeout(1) nor gtimeout(1) found; running without a timeout. Install GNU coreutils (\`brew install coreutils\` on macOS) before the full curated-sample run." >&2
fi

# Phase 46.1 rework (2026-05-11): strict sandbox (the dimension this
# audit measures) is opt-in, not the default. The harness exports
# `LPM_STRICT_SANDBOX=1` so each spawned `lpm-rs install` exercises
# the strict path — `denied_in_sandbox` counts what the strict
# contract blocks. Without this, the install would run under
# `mode = "default"` and the audit would measure nothing
# sandbox-relevant.
export LPM_STRICT_SANDBOX=1

(
    cd "$STAGE_DIR" && \
    if [[ -n "$TIMEOUT_CMD" ]]; then
        "$TIMEOUT_CMD" "$TIMEOUT_SEC" lpm-rs install --policy=allow 2>"$STDERR_FILE" >"$STDOUT_FILE"
    else
        lpm-rs install --policy=allow 2>"$STDERR_FILE" >"$STDOUT_FILE"
    fi
)
EXIT_CODE=$?

# Detect the OS-level sandbox-denial signal in stdout/stderr.
#
# This regex matches the unambiguous kernel-emitted denial tokens
# that Phase 46.1's landlock V4 `ConnectTcp` / `BindTcp` deny
# surfaces to the lifecycle script: `connect(2)` / `bind(2)`
# returning `EACCES` / `EPERM` (landlock's denial), or the
# socket-layer fallout `EHOSTUNREACH` / `ENETUNREACH` /
# "operation not permitted" / "permission denied". These are
# load-bearing because Phase 46.1's contract is "outbound TCP
# denied"; a script that called `connect(2)` and saw one of
# these errors was deniedly the sandbox.
COMBINED="$(cat "$STDERR_FILE" "$STDOUT_FILE" 2>/dev/null || true)"
DENIAL_SIGNAL_SEEN="false"
if echo "$COMBINED" | grep -qE 'EACCES|EPERM|EHOSTUNREACH|ENETUNREACH|operation not permitted|permission denied'; then
    DENIAL_SIGNAL_SEEN="true"
fi

# DNS-resolution-failure tokens are emitted as a SEPARATE soft
# heuristic — `dns_failure_seen` in the JSON output, NOT folded
# into `denial_signal_seen`.
#
# Why this is a separate axis: Phase 46.1's shipped contract on
# Linux is "outbound TCP denied" (see `lpm-sandbox/src/lib.rs`
# module doc + Phase 46.1.1 follow-up doc). DNS-via-UDP is
# explicitly OUT of scope for 46.1; Phase 46.1.1 will close it
# via a seccomp-bpf layer. In practice, on some host configs
# (glibc resolver falling back to TCP for AAAA / truncated UDP /
# systemd-resolved over 127.0.0.53:53/TCP), DNS lookups DO fail
# under Phase 46.1 alone — but the failure isn't guaranteed by
# the contract and host-to-host variance is real (musl, network
# namespace setups, alternative resolvers all behave differently).
#
# Treating these as the same axis as `denial_signal_seen` would:
# (a) overstate the product contract by claiming Phase 46.1
# already seals external DNS — it doesn't, that's 46.1.1's job;
# (b) misbucket ordinary resolver failures (a flaky DNS server,
# an unreachable nscd, a real network outage) as sandbox denials.
# Keep them as a separate flag the PR write-up can re-classify
# package-by-package.
DNS_FAILURE_SEEN="false"
if echo "$COMBINED" | grep -qE 'EAI_AGAIN|EAI_NODATA|EAI_NONAME|EAI_FAIL|getaddrinfo'; then
    DNS_FAILURE_SEEN="true"
fi

# Resolve the version that ACTUALLY got installed. The harness
# input may be a bare name (no `@version`) which we earlier
# defaulted to the string "latest" — but the install pipeline
# resolves "latest" to a concrete semver and the marker path is
# keyed off the concrete semver, not the dist-tag. Pre-fix, this
# script's marker check would never find a successful install of
# a bare-name input. Read the resolved version off the freshly-
# materialized `node_modules/<pkg>/package.json` (which the
# install pipeline writes regardless of script outcome — symlink
# / hardlink, but the file is reachable).
INSTALLED_VERSION=""
INSTALLED_PKG_JSON="$STAGE_DIR/node_modules/${NAME}/package.json"
if [[ -r "$INSTALLED_PKG_JSON" ]]; then
    INSTALLED_VERSION="$(jq -r '.version // empty' "$INSTALLED_PKG_JSON" 2>/dev/null || echo "")"
fi
# Fall back to the input version string so the report stays
# truthful when node_modules wasn't materialized (e.g. metadata
# fetch failed before extraction). The marker check below will
# correctly fail for such cases anyway — the install never got
# far enough to write one.
RESOLVED_VERSION="${INSTALLED_VERSION:-$VERSION}"

# Check whether the build pipeline minted a `.lpm-built` marker
# for the target package. The marker is written into the package's
# own node_modules dir inside the content-addressed store link.
# The store layout differs between versions: v1 was
# `$LPM_HOME/store/v1/<safe-name>@<version>/.lpm-built`; v2
# (Phase 66 default) is
# `$LPM_HOME/store/v2/links/<safe-name>@<version>+<hash>/node_modules/<pkg>/.lpm-built`
# with a per-link hash suffix the harness can't predict. The
# project-level `node_modules/<pkg>` symlink the install pipeline
# creates points at the version-appropriate store path, so
# probing through it works on both v1 and v2 without the harness
# having to know which one is active.
MARKER="$STAGE_DIR/node_modules/${NAME}/.lpm-built"
LPM_BUILT_PRESENT="false"
if [[ -e "$MARKER" ]]; then
    LPM_BUILT_PRESENT="true"
fi

# Family classification heuristic. The pattern-list is intentionally
# loose; the audit's job is to BUCKET, not to grade individual
# packages exhaustively. Mis-classified packages get re-bucketed
# manually in the PR description as the implementer reviews the
# results.
FAMILY="other"
case "$NAME" in
    esbuild|@swc/core|@swc/*|@biomejs/biome|sharp|bcrypt|node-sass|sqlite3|canvas|grpc|@grpc/*|node-rdkafka|robotjs|usb|node-serialport)
        FAMILY="prebuild-downloader" ;;
    puppeteer|puppeteer-*|@puppeteer/*|playwright|playwright-*|@playwright/*|cypress|electron|electron-*)
        FAMILY="browser-fetcher" ;;
    prisma|@prisma/*|tree-sitter|tree-sitter-*|lightningcss|oxc-*|@oxc/*|biome|node-gyp)
        FAMILY="native-bundler" ;;
esac

# Stderr-signal-based reclassification: pre-classifier list is
# name-based and necessarily incomplete; let the stderr text
# upgrade an `other` to a named family when the script's behaviour
# is unambiguous.
if [[ "$FAMILY" == "other" ]]; then
    if echo "$COMBINED" | grep -qiE 'downloading prebuilt'; then
        FAMILY="prebuild-downloader"
    elif echo "$COMBINED" | grep -qiE 'downloading (chromium|firefox|webkit|browser)'; then
        FAMILY="browser-fetcher"
    elif echo "$COMBINED" | grep -qiE '(sentry\.io|segment\.io|posthog|opencollective|analytics\.)'; then
        FAMILY="telemetry"
    fi
fi

# Per-family default remediation. Manually overridable in the PR
# write-up.
case "$FAMILY" in
    prebuild-downloader)
        REMEDIATION="trustedDependencies, or package-own env opt-out (e.g. PUPPETEER_SKIP_DOWNLOAD=1)" ;;
    browser-fetcher)
        REMEDIATION="package-own env opt-out (PUPPETEER_SKIP_DOWNLOAD=1, PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1), or trustedDependencies" ;;
    native-bundler)
        REMEDIATION="trustedDependencies (postinstall builds against host toolchain)" ;;
    telemetry)
        REMEDIATION="if business-critical: trustedDependencies; otherwise let it fail silently — the install completes" ;;
    other)
        REMEDIATION="case-by-case; most are no-op postinstalls or non-network failures unrelated to this phase" ;;
esac

# Tail the stderr to a manageable size so the per-package JSON
# stays under a few KB.
STDERR_TAIL="$(tail -n 30 "$STDERR_FILE" 2>/dev/null | sed 's/"/\\"/g' | tr '\n' ' ')"

# Emit the per-package record. `jq -c` keeps the line compact so
# the whole-suite runner can collect them with one
# `cat results/raw/*.json`. `requested_version` is what the user
# typed in the input file; `resolved_version` is what the install
# pipeline actually materialized in node_modules — the two
# diverge for bare-name inputs (resolved is the concrete semver,
# requested is "latest") and the marker path is keyed off the
# resolved one.
jq -cn \
    --arg package "$PKG_SPEC" \
    --arg name "$NAME" \
    --arg requested_version "$VERSION" \
    --arg resolved_version "$RESOLVED_VERSION" \
    --argjson exit_code "$EXIT_CODE" \
    --argjson lpm_built_present "$LPM_BUILT_PRESENT" \
    --argjson denial_signal_seen "$DENIAL_SIGNAL_SEEN" \
    --argjson dns_failure_seen "$DNS_FAILURE_SEEN" \
    --arg stderr_tail "$STDERR_TAIL" \
    --arg family "$FAMILY" \
    --arg recommendation "$REMEDIATION" \
    '{
        package: $package,
        name: $name,
        requested_version: $requested_version,
        resolved_version: $resolved_version,
        exit_code: $exit_code,
        lpm_built_present: $lpm_built_present,
        denial_signal_seen: $denial_signal_seen,
        dns_failure_seen: $dns_failure_seen,
        stderr_tail: $stderr_tail,
        family: $family,
        recommendation: $recommendation
    }'
