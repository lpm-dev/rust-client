# oxc_parser 0.157.0, patched

This is `oxc_parser` 0.157.0 from crates.io (oxc commit
`f799f174b5db10f1fa9e136594e53de82d4f4f83`, `crates/oxc_parser`), MIT
licensed (see `LICENSE`), with one change: the parser can stop at a stack
floor instead of overflowing its thread's stack. The workspace uses it
through `[patch.crates-io]` in the root `Cargo.toml`.

## Why

oxc's parser is recursive descent and has no depth limit. Source nested
deeply enough, such as 20,000 `[` in a row, overflows the stack, and Rust
aborts the whole process on a stack overflow. `lpm-security` parses the
code of every package it analyzes, including packages written to attack it,
so a crafted package could abort `lpm audit`, an install's analysis, or a
registry's release scan.

## What changed

`lpm-stack-floor.patch` is the whole change against the published crate:

- `ParseOptions::stack_floor`: the lowest stack address the parser may use.
  The default, `0`, never stops, so every other user of the parser behaves
  exactly as upstream.
- Before reading each token, the parser compares the stack pointer with the
  floor. Every level of nesting reads at least one token, so the parser can't
  go deeper than the frames between two tokens past it. Below the floor it
  records a fatal error, which moves the lexer to the end of the source, so
  every caller unwinds without reading more.
- `ParserReturn::stack_exhausted` reports it. It stays set even when a
  speculative parse rewinds the fatal error away, because the speculation's
  outcome, and so the AST, may then differ from a parse with more stack.

`lpm-security`'s `behavioral/syntax.rs` sets the floor from the stack its
thread has left, retries a source that runs out on a 64 MiB stack, and
reads one that runs out of that too without parsing it.

## Upgrading oxc

1. Copy the new `oxc_parser` release over this directory, keeping
   `LICENSE`, this file and the patch.
2. `patch -p1 < lpm-stack-floor.patch`, and resolve any rejects by hand.
3. Regenerate the patch from a pristine copy of the release:
   `diff -ruN <pristine> . -x LICENSE -x LPM-PATCH.md -x lpm-stack-floor.patch`.
4. Bump the other `oxc_*` dependencies of `lpm-security` to the same release
   and run `cargo test -p lpm-security`, whose deep-nesting tests cover the
   parser, the AST visitors and semantic analysis.

If oxc gains a depth or stack limit of its own, switch to it and drop this
directory and the `[patch.crates-io]` entry.
