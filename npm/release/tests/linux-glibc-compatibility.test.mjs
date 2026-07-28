import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  glibcVersionsFromReadelf,
  verifyGlibcCeiling,
} from "../verify-linux-abi.mjs";

const READELF_VERSION_INFO = `
Version needs section '.gnu.version_r' contains 2 entries:
  0x0010: Version: 1  File: libgcc_s.so.1  Cnt: 1
  0x0020:   Name: GCC_3.0  Flags: none  Version: 12
  0x0030: Version: 1  File: libc.so.6  Cnt: 3
  0x0040:   Name: GLIBC_2.2.5  Flags: none  Version: 11
  0x0050:   Name: GLIBC_2.17  Flags: none  Version: 10
  0x0060:   Name: GLIBC_2.28  Flags: none  Version: 9
`;

test("GNU release ABI accepts symbols at or below the declared glibc floor", () => {
  assert.deepEqual(glibcVersionsFromReadelf(READELF_VERSION_INFO), [
    "2.2.5",
    "2.17",
    "2.28",
  ]);
  assert.deepEqual(verifyGlibcCeiling(READELF_VERSION_INFO, "2.28"), {
    maximum: "2.28",
    ceiling: "2.28",
  });
});

test("GNU release ABI rejects a symbol newer than the declared glibc floor", () => {
  assert.throws(
    () =>
      verifyGlibcCeiling(
        `${READELF_VERSION_INFO}\n  0x0070: Name: GLIBC_2.39 Flags: none Version: 8`,
        "2.28",
      ),
    /requires GLIBC_2\.39, exceeding the supported ceiling GLIBC_2\.28/,
  );
});

test("GNU release ABI rejects missing or malformed version evidence", () => {
  assert.throws(
    () => verifyGlibcCeiling("", "2.28"),
    /does not declare any GLIBC symbol versions/,
  );
  assert.throws(
    () => verifyGlibcCeiling(READELF_VERSION_INFO, "latest"),
    /invalid glibc version/,
  );
});

test("release workflow builds and executes both GNU architectures at glibc 2.28", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const workflow = fs.readFileSync(path.join(repoRoot, ".github/workflows/release.yml"), "utf8");
  const cliManifest = fs.readFileSync(path.join(repoRoot, "crates/lpm-cli/Cargo.toml"), "utf8");

  assert.match(cliManifest, /^portable-linux = \["keyring\/vendored"\]$/m);
  assert.match(workflow, /manylinux_2_28_x86_64@sha256:[0-9a-f]{64}/);
  assert.match(workflow, /manylinux_2_28_aarch64@sha256:[0-9a-f]{64}/);
  assert.equal(workflow.match(/portable_glibc: true/g)?.length, 2);
  assert.equal(workflow.match(/rockylinux\/rockylinux:8\.10-minimal@sha256:/g)?.length, 2);
  assert.equal(workflow.match(/debian:12\.11-slim@sha256:/g)?.length, 2);
  assert.match(workflow, /--features portable-linux/);
  assert.equal(workflow.match(/--max-glibc 2\.28/g)?.length, 1);
  assert.match(workflow, /Verify GNU Linux binary on glibc 2\.28/);
  assert.match(workflow, /Smoke standalone installer on Debian 12/);
  assert.match(workflow, /needs\.smoke-standalone-installer\.result == 'success'/);
});
