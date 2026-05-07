# source-kind/link-protocol — link: source compat fixture

**Tests:** lpm's `link:./path` source-kind under both linker modes.

`link:` differs from `file:` in that it creates a **symlink** to the
source rather than copying bytes. Edits to the source are immediately
visible through the linked package — this is the canonical use case
for monorepo development without workspaces.

**Smoke test:** load the package + exercise its state machine.

**Behavioral note (not a hoisting concern, mode-agnostic):** lpm
currently materializes `link:` deps via byte-copy, the same as
`file:`. The live-edit semantic that distinguishes `link:` from
`file:` in npm/yarn isn't currently exercised. Both linker modes
behave identically here, so it's NOT a hoisting regression. Logged
as a separate behavioral gap to investigate post-default-flip.
