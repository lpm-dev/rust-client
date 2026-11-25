# oxc_parser 0.160.0, patched

This is `oxc_parser` 0.160.0 from crates.io (oxc commit
`87e38f3270b00341695e02e8aaf681e9e985e4a3`, `crates/oxc_parser`), MIT
licensed (see `LICENSE`), with three changes: the parser can stop at a
stack floor instead of overflowing its thread's stack, it can stop at a
budget for the work it spends on speculative parses, and nested
parentheses and member chains take it linear time and constant stack. The workspace uses it through `[patch.crates-io]` in the root
`Cargo.toml`.

## Why

oxc's parser is recursive descent and has no depth limit. Source nested
deeply enough, such as 20,000 `[` in a row, overflows the stack, and Rust
aborts the whole process on a stack overflow. `lpm-security` parses the
code of every package it analyzes, including packages written to attack it,
so a crafted package could abort `lpm audit`, an install's analysis, or a
registry's release scan.

The parser also speculates. In TypeScript, a `<` that may open a generic
arrow function or type arguments is parsed one way and, when that fails,
rewound and parsed again the other way, with everything nested in it. The
arguments of an `async(…)` that mention `await` are parsed again as
parameters when `=>` follows. Nested speculation can make a parse take time
quadratic in the source's length: `x=<T>(a=<T>(a=…0)));` and
`x=async(a=async(a=…await 0)=>0)=>0;` read each level again for every level
around it.

Upstream 0.160 also walks every parenthesis inside a closing one to find
where the expression innermost in them starts, so `((((…a…))))` took
quadratic time without speculating: 80,000 levels, which fit on a 64 MiB
stack, took four seconds.

## What changed

`lpm-stack-floor.patch` is the whole change against the published crate:

- `ParseOptions::stack_floor`: the lowest stack address the parser may use.
  The default, `0`, never stops, so every other user of the parser behaves
  exactly as upstream.
- Before moving to each token, the parser compares the stack pointer with
  the floor: in `advance`, the JSX variants, and `advance_to`, which moves
  to a token the lexer has already read. Every level of nesting in the
  source reads at least one token, so the parser can't go deeper than the
  frames between two tokens past it. Below the floor it records a fatal
  error, which moves the lexer to the end of the source, so every caller
  unwinds without reading more.
- Recursions that run over nodes already parsed and read no token check
  the floor once per level themselves, because their frames per level can
  be larger than those of the parse that built the nodes:
  - the cover grammar that turns an expression into a destructuring
    assignment target (`AssignmentTarget::cover` in `js/grammar.rs`, and
    `SimpleAssignmentTarget::cover`, which nested parentheses recurse
    through on their own);
  - the conversions that turn the elements of a parenthesized list into
    arrow parameters once `=>` follows it
    (`cover_expression_to_binding_pattern` and
    `cover_assignment_target_to_binding_pattern`), which stop with the
    same fatal error;
  - the checks that decide whether those elements can be parameters
    (`check_cover_binding` and `check_cover_binding_target`). They borrow
    the parser, so they record the stop in a `Cell` and fail; the parse
    then stops at the next token it reads, and reports the stop even if it
    reads none.
- Once the floor is reached, every later token read records the fatal error
  again. A speculative parse rewinds the fatal error away, and the parser
  then reads the other interpretation. If only reads below the floor
  stopped, each nested speculation would read back down to the floor.
- `ParserReturn::stack_exhausted` reports it. It stays set even when a
  speculative parse rewinds the fatal error away, because the speculation's
  outcome, and so the AST, may then differ from a parse with more stack.
  Callers discard a parse that reports it.
- `ParseOptions::speculation_budget`: how much work the parser may spend
  on speculative parses. The lexer counts the bytes it moves back over in
  every rewind, the parser's and its own lookaheads', and the bytes it
  skips without reading when a fatal error moves it to the end of the
  source. Their difference is what it has read beyond its position, so in
  all it has read at most its position plus that. The counts change only in
  rewinds and skips, and the lexer compares them with the budget at every
  rewind, its own lookaheads' included, so a parse pays nothing for them
  per token. Going past the budget stops the parse at the next token it
  reads, the same way the floor does, sticky across later rewinds, and
  `ParserReturn::speculation_budget_exhausted` reports it. A parse that
  reached the floor reports only that, so it can still be retried on a
  larger stack. The default, `0`, never stops.
- Two recursions over a member chain, which the parser reads in a loop
  and so without using stack per member, are loops instead:
  `set_pure_on_call_or_new_expr`, for `/*#__PURE__*/a.b.c…`, and
  `jsx_member_expression_eq`, which compares `<a.b.c…>` with its closing
  tag. Each recursed once per member, and a debug build overflowed its
  stack on 200,000 members; a release build relied on the optimizer
  turning the tail calls into loops.
- `ParserState::last_parenthesized` keeps the start of the
  `ParenthesizedExpression` built last and of the expression innermost in
  its parentheses. Each place that builds one records it, and closing a
  chain of parentheses reads the innermost start from there instead of
  walking the chain. A rewind leaves no stale entry: only a parse of the
  same offset can build another `ParenthesizedExpression` starting there,
  and it records its own.

`lpm-security`'s `behavioral/syntax.rs` sets the floor from the stack its
thread has left, retries a source that runs out on a 64 MiB stack, and
reads one that runs out of that too without parsing it. It gives each
parse a speculation budget of twice the source's length, and at least
64 KiB, and reads a source that exceeds it without parsing it. Across the
370,776 JavaScript and TypeScript files of a local package store, the most
any file read beyond its position was 0.75 bytes per byte, and no file used
more than 30% of its budget.

## Upgrading oxc

1. Copy the new `oxc_parser` release over this directory, without its
   `.cargo_vcs_info.json` and `Cargo.lock`, keeping `LICENSE`, this file
   and the patch.
2. `patch -p1 < lpm-stack-floor.patch`, and resolve any rejects by hand.
3. Regenerate the patch from a pristine copy of the release:
   `diff -ruN <pristine> . -x LICENSE -x LPM-PATCH.md -x lpm-stack-floor.patch
   -x .cargo_vcs_info.json -x Cargo.lock`, with `a/` and `b/` file headers.
4. Look for every place the parser moves to a new token, and for new
   recursion that reads no token, such as conversions between AST shapes
   after a parse, and give them floor checks like the ones above.
   Look for walks over nodes already built, like the one through nested
   parentheses, that run once per level of nesting. `lpm-security`'s
   `parenthesized_lists_parsed_just_above_the_floor_become_parameters_or_expressions_without_overflowing`
   test parses each shape it lists to the deepest nesting that fits. If the
   release changes how the parser speculates or takes checkpoints, measure
   again how much speculative work real code takes, against
   `PARSE_SPECULATION_PER_BYTE` in `lpm-security`'s `behavioral/syntax.rs`,
   and check that the sources its budget tests nest still speculate.
5. Bump every `oxc_*` dependency in the workspace to the same release:
   `lpm-cli`, `lpm-runner` and `lpm-security` pin them exactly, the crates
   share AST types, and the patch replaces `oxc_parser` for all of them.
   Dependabot proposes them together, in its `oxc` group. Then run
   `cargo test -p lpm-security`, whose deep-nesting tests cover the parser,
   the AST visitors and semantic analysis, and whose rule tests catch AST
   changes that still compile, such as a new variant for keys the rules
   match.

If oxc gains a depth or stack limit of its own, switch to it and drop this
directory and the `[patch.crates-io]` entry.
