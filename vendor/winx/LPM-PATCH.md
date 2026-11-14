# winx 0.36.4, patched

This is `winx` 0.36.4 from crates.io (winx commit
`23d6e2793b27979f7a7abbdbf1b2aedc1d0c78f3`), licensed
`Apache-2.0 WITH LLVM-exception` (see `LICENSE`), with one change: a link's
absolute target to a network folder reads as an absolute path. The workspace
and the fuzz workspace use it through `[patch.crates-io]` in their
`Cargo.toml`. cap-primitives, patched in `vendor/cap-primitives`, is its only
user.

## Why

cap-std reads a link's target with winx's `read_link`. An absolute target is
stored as an NT path, such as `\??\C:\pkg` or `\??\UNC\server\share\pkg`, and
`read_link` stripped the first four characters. That turns the first into
`C:\pkg`, but the second into `UNC\server\share\pkg`, a relative path, so a
symbolic link to a network folder read as a path inside the directory that
holds the link.

## What changed

`lpm-read-link-unc.patch` is the whole change against the published crate:

- After `\??\`, `UNC\server\share\…` becomes `\\server\share\…` and
  `C:\…` stays `C:\…`, where that is shorter than 260 characters and Win32
  reads it back unchanged (`GetFullPathNameW`, compared as strings), as
  std's `read_link` asks. Any other path gets the extended prefix `\\?\`,
  so each stays absolute and names what the link names: one Win32 would
  change, such as a name ending in a dot or a space, or holding `.` or a
  doubled separator; a long one; and one whose server reads as `?` or `.`.
  Relative targets are unchanged.
- `read_link_tests` cover these forms. They are Windows-only, as the
  crate is, and CI's Windows filesystem gate runs them with
  `cargo test --locked --manifest-path vendor/winx/Cargo.toml --lib read_link_tests`.
  The published crate has no lockfile; `Cargo.lock` here is for that run.

`lpm-common`'s `a_link_to_a_network_folder_reads_as_that_folder` reads such a
link through cap-std and fails on the published crate.

The packaging files of the published crate (`.cargo-ok`,
`.cargo_vcs_info.json`) are not copied, nor is its `.gitignore`, which would
leave out `Cargo.lock`.

## Upgrading winx

1. Copy the new winx release over this directory. Keep this file, the patch
   and `Cargo.lock`, and do not copy the packaging files or `.gitignore`.
2. Run `patch -p1 < lpm-read-link-unc.patch`, and resolve any rejects by
   hand.
3. Regenerate the patch from a clean copy of the release:
   `diff -ruN <clean copy> . -x LPM-PATCH.md -x lpm-read-link-unc.patch -x Cargo.lock -x .gitignore -x .cargo-ok -x .cargo_vcs_info.json`.
   Write the headers as `a/<path>` and `b/<path>`.
4. Run `cargo update --manifest-path vendor/winx/Cargo.toml`, then on
   Windows the tests above and `cargo test -p lpm-common`.

If upstream keeps network targets absolute, use the release, and remove this
directory and both `[patch.crates-io]` entries.
