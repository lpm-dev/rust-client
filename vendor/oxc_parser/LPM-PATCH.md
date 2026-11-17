# oxc_parser 0.158.0, patched

This is `oxc_parser` 0.158.0 from crates.io (oxc commit
`74e5e665ab8227c3d43abf3ce0e4383830e80c12`, `crates/oxc_parser`), MIT
licensed (see `LICENSE`), with two changes: the parser can stop at a stack
floor instead of overflowing its thread's stack, and at a budget for the
work it spends on speculative parses. The workspace uses it through
`[patch.crates-io]` in the root `Cargo.toml`.

## Why

oxc's parser is recursive descent and has no depth limit. Source nested
deeply enough, such as 20,000 `[` in a row, overflows the stack, and Rust
aborts the whole process on a stack overflow. `lpm-security` parses the
code of every package it analyzes, including packages written to attack it,
so a crafted package could abort `lpm audit`, an install's analysis, or a
registry's release scan.

The parser also speculates. A parenthesized list that may be arrow
parameters, or a `<` that may open type arguments, is parsed one way and,
when that fails, rewound and parsed again the other way, with everything
nested in it. The checkpoint for a parenthesized list also copies every
diagnostic the lexer has recorded. Nested speculation, or speculation after
many lexer diagnostics, can make a parse take time quadratic in the
source's length.

## What changed

`lpm-stack-floor.patch` is the whole change against the published crate:

- `ParseOptions::stack_floor`: the lowest stack address the parser may use.
  The default, `0`, never stops, so every other user of the parser behaves
  exactly as upstream.
- Before reading each token, the parser compares the stack pointer with the
  floor. Every level of nesting in the source reads at least one token, so
  the parser can't go deeper than the frames between two tokens past it.
  Below the floor it records a fatal error, which moves the lexer to the end
  of the source, so every caller unwinds without reading more.
- Two recursions run over nodes already parsed and read no token, so they
  check the floor once per level themselves:
  - the cover grammar, which turns an expression into a destructuring
    assignment target (`AssignmentTarget::cover` in `js/grammar.rs`), stops
    with the same fatal error;
  - turning parenthesized arrow parameters back into an expression when no
    `=>` follows (`cover_binding_as_expression` in `js/arrow.rs`, new in
    0.158) gives up instead, and the parser reads the source again as an
    expression, which checks the floor per token.
  Either can go deeper than the parse that built its nodes, because its
  frames per level can be larger. In 0.158, parsing `x=([[…a…]]);` to just
  above the floor and converting it overflowed a 2 MiB stack.
- Once the floor is reached, every later token read records the fatal error
  again. A speculative parse, such as an arrow function's parameters, rewinds
  the fatal error away, and the parser then reads the other interpretation.
  If only reads below the floor stopped, each nested speculation would read
  back down to the floor: a source of arrow functions nested in parameter
  defaults took seconds and gigabytes of arena memory to give up on.
- `ParserReturn::stack_exhausted` reports it. It stays set even when a
  speculative parse rewinds the fatal error away, because the speculation's
  outcome, and so the AST, may then differ from a parse with more stack.
  Callers discard a parse that reports it.
- `ParseOptions::speculation_budget`: how much work the parser may spend
  on speculative parses. The lexer counts the bytes it moves back over in
  every rewind, the parser's and its own lookaheads', and the bytes it
  skips without reading when a fatal error moves it to the end of the
  source. Their difference is what it has read beyond its position, so in
  all it has read at most its position plus that. Each checkpoint that can
  restore the lexer's diagnostics also spends 16 per diagnostic it copies.
  The counts change only in rewinds, skips and those checkpoints, so a
  parse pays nothing for them per token. A parse already stopped at the
  floor is unwinding and isn't checked against the budget, so it can still
  be retried on a larger stack. Going past the budget stops the parse the
  same way the floor does, sticky across later rewinds, and
  `ParserReturn::speculation_budget_exhausted` reports it. The default,
  `0`, never stops.

`lpm-security`'s `behavioral/syntax.rs` sets the floor from the stack its
thread has left, retries a source that runs out on a 64 MiB stack, and
reads one that runs out of that too without parsing it. It gives each
parse a speculation budget of twice the source's length, and at least
64 KiB, and reads a source that exceeds it without parsing it. Across the
370,000 JavaScript and TypeScript files of a local package store, the most
any file read beyond its position was 0.93 bytes per byte, no file copied a
diagnostic, and no file used more than 30% of its budget.

## Upgrading oxc

1. Copy the new `oxc_parser` release over this directory, without its
   `.cargo_vcs_info.json` and `Cargo.lock`, keeping `LICENSE`, this file
   and the patch.
2. `patch -p1 < lpm-stack-floor.patch`, and resolve any rejects by hand.
3. Regenerate the patch from a pristine copy of the release:
   `diff -ruN <pristine> . -x LICENSE -x LPM-PATCH.md -x lpm-stack-floor.patch
   -x .cargo_vcs_info.json -x Cargo.lock`, with `a/` and `b/` file headers.
4. Look for new recursion that reads no token, such as conversions between
   AST shapes after a parse, and give it a floor check like the ones above.
   `lpm-security`'s
   `patterns_parsed_to_just_above_the_floor_turn_into_expressions_without_overflowing`
   test parses each shape it lists to the deepest nesting that fits. If the
   release changes how the parser speculates or takes checkpoints, measure
   again how much speculative work real code takes, against
   `PARSE_SPECULATION_PER_BYTE` in `lpm-security`'s `behavioral/syntax.rs`.
5. Bump every `oxc_*` dependency in the workspace to the same release:
   `lpm-cli`, `lpm-runner` and `lpm-security` pin them exactly, the crates
   share AST types, and the patch replaces `oxc_parser` for all of them.
   Then run `cargo test -p lpm-security`, whose deep-nesting tests cover the
   parser, the AST visitors and semantic analysis.

If oxc gains a depth or stack limit of its own, switch to it and drop this
directory and the `[patch.crates-io]` entry.
