# zxcvbn 3.1.1, patched

This is `zxcvbn` 3.1.1 from crates.io (zxcvbn-rs commit
`e7943234a77209ee52cf054f8531bfe928e0a0b3`), MIT licensed (see `LICENSE`),
with one change: `factorial` saturates at `usize::MAX` instead of
overflowing. The workspace and the fuzz workspace use it through
`[patch.crates-io]` in their `Cargo.toml`.

## Why

`lpm-env-backup` rates a backup passphrase with zxcvbn. zxcvbn searches for
the sequence of matches that is easiest to guess, and it multiplies the cost
of a sequence of `n` matches by `n!`. `factorial` computed `n!` with
`(1..=n).product()` on `usize`, which overflows from `n = 21`.

zxcvbn adds a penalty that makes a sequence of 6 or more matches lose, but it
computes `n!` before it compares. It takes its candidates from a `HashMap`,
whose order comes from a random seed. With some seeds, a long sequence
survives at each position until it reaches 21 matches. A build with overflow
checks, such as a debug, test or fuzz build, then panics. The
`env_backup_passphrase` fuzz target found this in CI, and its input is in
`fuzz/corpus/env_backup_passphrase/long-match-sequence`.

A release build wraps instead of panicking. The penalty for a sequence that
long already saturates at `u64::MAX`, so the wrap does not change the rating
of a release build, and the patch does not change it either.

## What changed

`lpm-factorial-saturation.patch` is the whole change against the published
crate:

- `factorial` folds with `usize::saturating_mul`. From `n = 21` it returns
  `usize::MAX`, and its caller already multiplies with `saturating_mul`.
- `factorial_saturates_at_usize_max_instead_of_overflowing` compares
  `factorial(n)` with the exact value for every `n` from 0 to 40. It fails on
  the published crate.

The crate keeps its own `Cargo.lock`, so the Lint job of CI runs its tests with
`--locked`. The packaging files of the published crate (`.cargo-ok`,
`.cargo_vcs_info.json`) and the repository files of upstream (`.github`,
`.editorconfig`, `.gitignore`) are not copied.

## Upgrading zxcvbn

1. Copy the new zxcvbn release over this directory. Keep this file and the
   patch, and do not copy the files that the previous section names.
2. Run `patch -p1 < lpm-factorial-saturation.patch`, and resolve any rejects
   by hand.
3. Regenerate the patch from a clean copy of the release:
   `diff -ruN <clean copy> . -x LPM-PATCH.md -x lpm-factorial-saturation.patch -x .cargo-ok -x .cargo_vcs_info.json -x .github -x .editorconfig -x .gitignore`.
   Write the headers as `a/<path>` and `b/<path>`.
4. Change the version in `scripts/check-fancy-regex-dependents.py`.
5. Run `cargo test --locked --manifest-path vendor/zxcvbn/Cargo.toml` and
   `cargo test -p lpm-env-backup`.

If upstream `factorial` stops overflowing, use the release, and remove this
directory and both `[patch.crates-io]` entries.
