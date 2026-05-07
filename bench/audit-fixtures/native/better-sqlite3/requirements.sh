#!/bin/bash
# Env-conditional fixture: better-sqlite3 falls back to compile-on-install
# (node-gyp) when no prebuilt binary matches the host. lpm's lifecycle-script
# runner doesn't currently expose npm's bundled node-gyp, so the compile
# fallback fails on machines where node-gyp isn't on PATH (e.g., users
# managing Node via `n` instead of nvm). Skip cleanly in that case.
#
# Documented as A3 in the active-roadmap.
if ! command -v node-gyp &>/dev/null; then
    echo "node-gyp not on PATH (better-sqlite3 falls back to compile-on-install)" >&2
    echo "  → install with: npm install -g node-gyp" >&2
    echo "  → tracking as roadmap A3 (lpm lifecycle runner doesn't expose npm-bundled node-gyp)" >&2
    exit 1
fi
exit 0
