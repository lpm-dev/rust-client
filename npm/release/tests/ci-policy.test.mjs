import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

test("CI compiles experimental HTTP/3 with the required reqwest cfg", () => {
  const workflow = fs
    .readFileSync(path.join(repoRoot, ".github/workflows/ci.yml"), "utf8")
    .replaceAll("\r\n", "\n");
  const start = workflow.indexOf("\n  experimental-http3:\n");
  const end = workflow.indexOf("\n  test:\n", start + 1);

  assert.notEqual(start, -1, "missing experimental-http3 CI job");
  assert.notEqual(end, -1, "experimental-http3 job must run before the test job");

  const job = workflow.slice(start, end);
  assert.match(job, /^\s+RUSTFLAGS: "--cfg reqwest_unstable"$/m);
  assert.match(job, /cargo check --locked -p lpm-registry --all-features/);
  assert.match(job, /cargo check --locked -p lpm-cli --features experimental-http3/);
});
