# VitePress Docs Benchmark Fixture

This fixture captures the install graph from the VitePress 1.5.0 repository
without vendoring the full source tree. It keeps the root package manifest,
workspace manifests, pnpm settings, and the patch referenced by the manifest so
`bench/scripts/run-install-readiness.mjs --fixtures vitepress-workspace` can
reproduce the real install workload from tracked files. The root bin placeholder
keeps the declared `vitepress` executable structurally valid without vendoring
the runtime build output. The tracked `fixture.npmrc`
template is copied to `.npmrc` when the harness materializes a temp project,
because `.npmrc` is intentionally ignored at the repository root.

The fixture is used for README-facing install benchmarks because it is a
recognizable real-world project with enough dependencies for resolver, fetch,
link, and firewall monitor costs to be visible.
