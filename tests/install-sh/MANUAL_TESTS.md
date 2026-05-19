# Manual install.sh test procedure

`run.sh` covers the syntax check and the SHA-tool-required gate. The
remaining flows below require a real-world release with a signed
`SHA256SUMS.txt` manifest + `SHA256SUMS.txt.sigstore` bundle in
`https://github.com/lpm-dev/rust-client/releases/...`, so they're
covered by manual smoke instead of automated CI.

Run these against the first signed release (e.g., `v0.42.0-rc.1`) and
again on each major release until a wiremock-backed bats harness lands
as a follow-up.

## 1. Happy path

```sh
sh install.sh
```

Expected:
- `Verified SHA-256: <hex>` line for the chosen platform.
- (If `cosign` on PATH) `Verified Sigstore signature on manifest` line.
- Binary lands in `~/.lpm/bin/lpm` with `+x`.

## 2. SHA mismatch (negative)

Stage a release where the binary differs from what's in
`SHA256SUMS.txt`. Easiest reproduction: clone a known-good release,
`sed -i.bak 's/<expected>/0000…0000/' SHA256SUMS.txt`, host the
hostile manifest at a separate URL, point `$URL` and the manifest URL
at the local server.

Expected:
- `ERROR: SHA-256 mismatch` with both hex digests printed.
- Exit 1.
- No file written to `~/.lpm/bin/`.

## 3. cosign verify rejects (negative, opportunistic)

With a `cosign` binary on PATH, stage a release where
`SHA256SUMS.txt.sigstore` is replaced with a bundle from a different
repo / workflow.

Expected:
- `ERROR: cosign refused the signature` message.
- Exit 1.
- No file written to `~/.lpm/bin/`.

## 4. cosign absent (degrade to SHA-only)

With `cosign` removed from PATH, run against a valid signed release.

Expected:
- `Verified SHA-256` line.
- NO `Verified Sigstore signature` line.
- Happy install otherwise.

## 5. LPM_INSTALL_INSECURE=1 (escape valve)

```sh
LPM_INSTALL_INSECURE=1 sh install.sh
```

Expected:
- `WARN: LPM_INSTALL_INSECURE=1 — skipping ALL integrity checks` line.
- No manifest fetch attempted.
- Happy install.

## 6. Manifest 404 (release that predates the signed-install gate)

Point `$REPO` at a release published before `SHA256SUMS.txt` started
shipping alongside the binaries.

Expected:
- `ERROR: release vX.Y.Z does not ship a signed checksums manifest`
- Help text naming the manual install URL.
- Exit 1.
