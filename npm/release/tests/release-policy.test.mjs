import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("release verification reruns every release-critical CI policy gate", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = workflow.indexOf("\n  verify:\n");
  const end = workflow.indexOf("\n  verify-windows-filesystem:\n", start + 1);

  assert.notEqual(start, -1, "missing release verification job");
  assert.notEqual(end, -1, "missing job after release verification");

  const verify = workflow.slice(start, end);
  for (const required of [
    /components: clippy, rustfmt/,
    /cargo clippy --workspace --all-targets --locked -- -D warnings/,
    /cargo fmt --check/,
    /EmbarkStudios\/cargo-deny-action@[0-9a-f]{40}/,
    /command-arguments: --hide-inclusion-graph advisories bans licenses/,
    /grep -r 'fancy-regex' crates\/\*\/Cargo\.toml/,
    /sh tests\/install-sh\/run\.sh/,
    /bash bench\/test-audit-install-args\.sh/,
    /bash bench\/test-local-install\.sh/,
    /bash bench\/test-live-metadata-route\.sh/,
    /bash bench\/test-run-readme\.sh/,
    /node bench\/scripts\/run-install-readiness\.mjs --self-test/,
    /node bench\/scripts\/run-runtime-readiness\.mjs --self-test/,
    /npm --prefix npm\/cli test/,
    /npm --prefix npm\/cli run pack:check/,
  ]) {
    assert.match(verify, required);
  }
});
