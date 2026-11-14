# cap-primitives 4.0.3, patched

This is `cap-primitives` 4.0.3 from crates.io (cap-std commit
`b7acf8e8807fe3fab991884d2208b7e03d35a409`, `cap-primitives`), licensed
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` (see the `LICENSE-*`
files), with one change: on Windows, a directory reached through a network
path keeps that path absolute. The workspace and the fuzz workspace use it
through `[patch.crates-io]` in their `Cargo.toml`.

## Why

On Windows, cap-std creates, removes, renames and links an entry by path: it
asks for the path of the directory handle with `GetFinalPathNameByHandleW`
and joins the entry's name to it. That call returns an extended path, such
as `\\?\C:\project` or `\\?\UNC\server\share\project`. `get_path` stripped
the first four characters, which turns the first into `C:\project` but the
second into `UNC\server\share\project`, a relative path. Windows then
resolved it against the process's current directory.

So every entry LPM creates in a project on a network folder (a share, a
mapped network drive, a Parallels shared folder or a WSL path) failed with
"The system cannot find the path specified", or, where that relative path
happened to exist below the current directory, was created there instead.

## What changed

`lpm-unc-final-path.patch` is the whole change against the published crate:

- `\\?\UNC\server\share\…` becomes `\\server\share\…`, and `\\?\C:\…`
  becomes `C:\…` as before.
- A path with any other extended prefix stays extended, and so absolute.
- `fs/manually/open.rs` loses an import it never uses. A crate patched in
  through a path is linted as LPM's own code, so the warning would show in
  every build.
- `get_path`'s tests cover the three forms. They are Windows-only, as the
  module is, and CI's Windows filesystem gate runs them with
  `cargo test --locked --manifest-path vendor/cap-primitives/Cargo.toml --lib get_path`.
  Elsewhere the crate's tests don't build: one needs a crate from
  upstream's workspace that the published crate leaves out.

One related flaw is left as it is. `read_link` takes a link's target from
winx, which strips `\??\` from an absolute target, so a symbolic link to
`\\server\share\pkg` reads as the relative `UNC\server\share\pkg`. Fixing
it here would mean reading the reparse point without winx. LPM never makes
a link to a network folder: a junction can't point at one, and a project
whose links would need one can't be installed. A link someone else made to
a network folder reads instead as a path inside the project, where nothing
is found.

`lpm-common`'s `a_network_path_to_a_project_creates_its_state_inside_it`
creates a project's `.lpm` through `\\localhost\<drive>$` and fails on the
published crate.

The packaging files of the published crate (`.cargo-ok`,
`.cargo_vcs_info.json`) are not copied.

## Upgrading cap-std

1. Copy the new `cap-primitives` release over this directory. Keep this file
   and the patch, and do not copy the packaging files.
2. Run `patch -p1 < lpm-unc-final-path.patch`, and resolve any rejects by
   hand.
3. Regenerate the patch from a clean copy of the release:
   `diff -ruN <clean copy> . -x LPM-PATCH.md -x lpm-unc-final-path.patch -x .cargo-ok -x .cargo_vcs_info.json`.
   Write the headers as `a/<path>` and `b/<path>`.
4. Bump `cap-std` and `cap-fs-ext` to the same release, and on Windows run
   the tests above and `cargo test -p lpm-common`.

If upstream keeps network paths absolute, use the release, and remove this
directory and both `[patch.crates-io]` entries.
