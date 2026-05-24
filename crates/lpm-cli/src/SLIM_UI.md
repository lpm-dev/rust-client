# Slim UI conventions

The contract every non-interactive `lpm` command should follow. The
worked reference implementation is the install pipeline:
[`install_ui.rs`](./install_ui.rs) + the call sites in
[`commands/install.rs`](./commands/install.rs).

Read this before rewriting human output for any command.

## When to use slim UI vs cliclack

| Command shape                                                                                                          | Use                                 |
| ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Non-interactive: prints progress / status, never prompts (`install`, `audit`, `outdated`, `doctor list`, `publish`)    | **Slim UI** (this doc)              |
| Interactive: confirms an action, multi-selects, masked input (`login`, `approve-scripts`, `init`, `add` source picker) | **cliclack** via `crate::output::*` |

A command that does both (interactive intro + long progress phase)
should mix: cliclack for the prompt, slim UI for the progress.

## Stream contract

Every line written by the slim UI goes to **stderr** (`eprintln!`).
**Rationale:** stdout is reserved for `--json` envelopes and for output
piped to another tool (e.g. `lpm outdated | jq`). Mixing progress
chatter into stdout breaks both.

## Glyph + color palette

These are project-wide. Don't introduce new glyphs or color choices in
a single command — bring it up for design alignment first so the whole
CLI stays coherent.

| Glyph | Color  | Meaning                                                 | Helper               |
| ----- | ------ | ------------------------------------------------------- | -------------------- |
| `›`   | blue   | Phase / progress line (persistent, stays on screen)     | `install_ui::phase`  |
| `✓`   | green  | Success terminus or per-item verified                   | `install_ui::done`   |
| `✗`   | red    | Failure terminus                                        | `install_ui::failed` |
| `!`   | yellow | Advisory / warning (informational, never fails the cmd) | `install_ui::warn`   |
| `+`   | plain  | Diff entry (added / changed)                            | `install_ui::plus`   |
| `-`   | plain  | Diff entry (removed)                                    | `install_ui::minus`  |

Within message bodies:

| Element                                | Style                         |
| -------------------------------------- | ----------------------------- |
| Project / package name                 | **bold** (`install_ui::bold`) |
| Resolved duration in a terminus line   | green (`install_ui::green`)   |
| Vulnerability / failure count when > 0 | red (`install_ui::red`)       |
| Hints, suffix metadata, parentheticals | dimmed (`install_ui::dim`)    |
| Plain text                             | unstyled                      |

## Reusable helpers in `install_ui`

These transfer directly to other commands — use them, don't
reimplement:

- `phase(msg)` / `done(msg)` / `failed(msg)` / `warn(msg)` — the five
  line shapes.
- `plus(name, version, hint)` / `minus(name, version, hint)` — the diff entry shapes.
- `bold` / `dim` / `green` / `red` — color helpers that honor
  `NO_COLOR` / `--color` via `lpm_common::color`.
- `format_duration(Duration)` — sub-second → `"Xms"`, else `"X.XXs"`.
- `packages_word(count)` — pluralization for "package(s)".

Install-specific helpers (`format_audit_advisory`,
`short_registry_host`) live in `install_ui` for now but will move into
the install module once a second command graduates the slim-UI
treatment and the install pipeline isn't the only consumer.

## How to add a new command's UI

1. Add a sibling module `commands/<command>_ui.rs` (or inline a small
   section inside the command file if it only needs the five core
   line shapes).
2. **Don't** reimplement the glyphs / colors. Either:

- Call `install_ui::phase` / `done` / `failed` / `warn` / `plus` / `minus`
  directly, or
- Re-export them from your `<command>_ui` module with
  command-specific helpers layered on top.

3. Keep every existing `if !json_output { ... }` gate in place. The
   slim UI is the **interior** of those gates; never the gate itself.
4. After: rebuild `lpm-rs` and smoke-test the human output in a temp
   project. Confirm `--json` output is byte-identical to before.

## JSON mode contract

The slim UI never inspects `--json`. The caller is responsible for
`if json_output { /* envelope */ } else { /* slim UI */ }`. When a
command needs to attach a slim-UI signal to its JSON envelope (e.g.
install's `audit_summary` field), compute the data once and feed both
surfaces from it — never re-derive in two places.

## Common pitfalls — what NOT to do

- **Don't leave cliclack-style narrate-every-step chatter.** If the
  diff / done / advisory at the end already conveys the state, the
  per-step "Adding X to Y", "Resolved in Nms", "Linked in Nms" lines
  are noise. The slim-UI rewrite of install dropped 8 of those.
- **Don't use spinners (`cliclack::spinner()`).** A persistent
  `phase()` line carries the same intent and survives piping.
- **Don't print to stdout** — that stream is for `--json` and pipes.
- **Don't add per-item progress lines** ("Downloaded ms@2.1.3",
  "Linked react@18", "...") for items in a large set. Aggregate at
  the end with one terminus line. If the operation is genuinely slow
  (10s+) and silence is worse than chatter, surface a phase line for
  the bucket ("Installing 247 packages"), not per item.
- **Don't introduce a new color or glyph** without bringing it up for
  design alignment. Drifting palettes are how every CLI's UX
  eventually rots.

## Reference implementation

Read the install pipeline as the worked example:

- [`install_ui.rs`](./install_ui.rs) — the module + module-doc that
  spells out the design contract again at the source.
- [`commands/install.rs`](./commands/install.rs) — search for
  `install_ui::` to see every call site in context.

The progression of the install command's output across the rewrite —
which lines were dropped, which were renamed, which got color — is
the most informative thing to skim before writing a new command's UI.
