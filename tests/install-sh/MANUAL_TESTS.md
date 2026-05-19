# Manual install.sh test procedure

The automated harness in `run.sh` covers:

- shell syntax (`sh -n`)
- fail-closed when neither `sha256sum` nor `shasum` is on PATH
- loopback-gating on the `LPM_INSTALL_TEST_*` override env vars
- happy path: manifest + binary match, no `cosign` on PATH → install succeeds
- manifest 404 → fail-closed with the "predates the signed-install gate" message
- bundle 404 → degrade to SHA-only floor (no Sigstore claim emitted)
- SHA mismatch → fail-closed, no install
- platform missing from manifest → fail-closed
- `LPM_INSTALL_INSECURE=1` bypasses the missing-manifest gate

The two flows below still need a real cosign install + a real signed
release to capture against; they are not covered by `run.sh` and run as
manual smoke before each major release.

## 1. cosign verify rejects (negative, opportunistic)

With a real `cosign` binary on PATH, stage a release where
`SHA256SUMS.txt.sigstore` is replaced with a bundle from a different
repo / workflow. Easiest reproduction: point `LPM_INSTALL_TEST_DOWNLOAD_BASE`
at a local fixture directory whose `.sigstore` file is an actual
captured Sigstore bundle from `axios/axios` or another non-LPM repo.

Expected:
- `ERROR: cosign refused the signature` message.
- Exit 1.
- No file written to `~/.lpm/bin/`.

## 2. cosign verifies a real signed release (positive, opportunistic)

With a real `cosign` binary on PATH and the first signed release of
`lpm-dev/rust-client` published:

```sh
sh install.sh
```

Expected:
- `Verified SHA-256:` line.
- `Verified Sigstore signature on manifest (identity-pinned to release.yml)` line.
- Binary lands in `~/.lpm/bin/lpm` with `+x`.

The Rust-side `cargo test -p lpm-cli` suite covers the Sigstore
verification semantics from the producer side (DSSE, Rekor body,
SET, inclusion proof, identity pin, replay window) — so the value of
this manual step is "the end-to-end shell pipeline still wires up
correctly," not "Sigstore verification is correct."
