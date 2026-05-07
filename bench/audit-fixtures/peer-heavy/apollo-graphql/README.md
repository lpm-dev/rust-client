# apollo-graphql — peer-heavy compat fixture (GraphQL ecosystem)

**Tests:** Apollo Client's tight `graphql` peer-dep coupling under
both linker modes.

**Risk:** `@apollo/client` parses queries through `graphql` (its peer)
and returns AST nodes. If hoisting nests a different `graphql` version
under apollo than what the user has at top level, the AST nodes are
incompatible across the module boundary — `Kind.OPERATION_DEFINITION`
is a different value, `print(parsed)` rejects the document, etc.

**Smoke test:** uses `gql` (Apollo's tag) to parse, then `graphql.print`
to round-trip, and asserts the AST `kind` matches the user-side
`Kind` enum. Confirms Apollo and our graphql resolve to the same
module instance.
