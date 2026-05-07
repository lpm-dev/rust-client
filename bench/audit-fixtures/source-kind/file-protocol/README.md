# source-kind/file-protocol — file: source compat fixture

**Tests:** lpm's `file:./path` source-kind handling under both linker
modes.

`file:` deps are extracted from the user's local filesystem rather
than a registry. lpm's pipeline has a separate pre-extract phase for
file/link/workspace sources ([install.rs:625](../../../crates/lpm-cli/src/commands/install.rs#L625)).
Tests that the resulting `node_modules/local-greeter/` correctly maps
to the on-disk source, plus a registry dep (`lodash`) for coexistence.
