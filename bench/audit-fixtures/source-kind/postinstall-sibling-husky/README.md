# postinstall-sibling-husky — sibling-write postinstall fixture

**Tests:** husky package load + bin link under both linker modes.

husky is the canonical example of a postinstall that writes OUTSIDE
its own directory — when invoked via `prepare` in a git repo, it
creates `.husky/` at the project root. The audit doesn't simulate
the git-init context (no repo here), but it does exercise the package
load path + bin link path which are common to all installs.

The sibling-write surface is covered in real-world adoption rather
than this fixture; what we verify here is that lpm's hoisted layout
doesn't break husky's loadability.
