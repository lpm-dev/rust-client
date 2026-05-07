# prisma-codegen — native compat fixture (postinstall codegen)

**Tests:** Prisma's `prisma generate` postinstall under both linker
modes. Specifically targets the **sibling-write** pattern: Prisma
writes generated code into `node_modules/.prisma/client/`, a separate
top-level entry adjacent to `@prisma/client`. The runtime then
requires `@prisma/client` which internally re-requires `.prisma/client`.

**Risk shape:** under hoisted, both `@prisma/client` and `.prisma/client`
end up at the project root — works. Under isolated, `@prisma/client`
sits in its wrapper, `.prisma/client` is generated where the script
runs. If the script's CWD differs between modes or the runtime
resolution logic walks the wrong tree, the generated client isn't
found.

**Smoke test:** run `prisma generate` explicitly + load
`@prisma/client` + verify the User model methods are wired.
