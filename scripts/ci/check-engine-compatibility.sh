#!/usr/bin/env bash
# Prove that an older release's companion engine reads every local history
# state this release writes: build tests/compat-engine against that release's
# engine and run the history fixtures through it.
#
# Usage: scripts/ci/check-engine-compatibility.sh [tag]   (default v0.84.0)
set -euo pipefail

tag="${1:-v0.84.0}"
root="$(git rev-parse --show-toplevel)"
harness="$root/tests/compat-engine"
engine="$root/target/compat-engine"

cleanup() {
    git -C "$root" worktree remove --force "$engine" >/dev/null 2>&1 || rm -rf "$engine"
}
trap cleanup EXIT

cleanup
mkdir -p "$root/target"
git -C "$root" worktree add --quiet --detach "$engine" "$tag"
# The older release's lockfile pins the engine's dependencies as it shipped.
# Updating only this workspace adds the harness's own entry; --locked then
# refuses any other change to it.
cp "$engine/Cargo.lock" "$harness/Cargo.lock"
cargo update --quiet --workspace --manifest-path "$harness/Cargo.toml"
cargo run --quiet --locked --manifest-path "$harness/Cargo.toml" -- \
    "$root/crates/lpm-env-companion/tests/fixtures/history.json"
