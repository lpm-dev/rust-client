# source-kind/file-protocol — file: source compat fixture

**Tests:** lpm's `file:./path` source-kind handling under both linker
modes.

`file:` deps are extracted from the user's local filesystem rather
than a registry. lpm's pipeline handles file/link/workspace sources
before registry tarball extraction. Tests that the resulting
`node_modules/local-greeter/` correctly maps to the on-disk source,
plus a registry dep (`lodash`) for coexistence.
