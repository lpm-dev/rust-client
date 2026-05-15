# LPM — The Package Manager for Modern Software

Fast, secure, all-in-one. Written in Rust.

```bash
npm install -g @lpm-registry/cli
```

<details>
<summary>Other install methods</summary>

```bash
brew tap lpm-dev/lpm && brew install lpm        # Homebrew
curl -fsSL https://lpm.dev/install.sh | sh       # Standalone
cargo install --git https://github.com/lpm-dev/rust-client lpm-cli  # Source
```

</details>

## Commands

```bash
# Package management
lpm install                    # Install deps (aliases: i)
lpm add <package>              # Source delivery (any registry: lpm.dev, npm, .npmrc-private)
lpm remove <package>           # Remove added package (aliases: rm)
lpm uninstall <packages>       # Remove from deps (aliases: un, unlink)
lpm publish                    # Publish to lpm.dev (aliases: p)
lpm upgrade                    # Upgrade deps to latest
lpm outdated                   # Check for newer versions
lpm audit                      # Security + quality audit (OSV.dev)
lpm search <query>             # Search packages
lpm info <package>             # Package details
lpm quality <package>          # Quality report
lpm query <selector>           # CSS-like selector queries on installed packages
lpm rebuild                    # Run lifecycle scripts (phase 2 of install)
lpm approve-scripts            # Approve packages blocked by default-deny script policy
lpm trust                      # Manage `trustedDependencies` in package.json
lpm patch <package>            # Generate a local patch, `patch-package` style
lpm patch-commit               # Finalize a patch staging directory
lpm migrate                    # Migrate from npm/yarn/pnpm/bun

# Scripts & execution
lpm run <scripts...>           # Run scripts (parallel: -p, cached, watch)
lpm dev                        # Zero-config dev server + HTTPS + tunnel
lpm exec <file>                # Run JS/TS files directly
lpm dlx <package>              # Run without installing
lpm test                       # Auto-detect test runner
lpm bench                      # Auto-detect benchmark runner

# Built-in tools (lazy-downloaded)
lpm lint                       # Oxlint
lpm fmt                        # Biome
lpm check                      # TypeScript (tsc --noEmit)
lpm plugin list                # Show installed tools
lpm plugin update              # Update tools

# Runtime & environment
lpm use node@22                # Install + pin Node.js version
lpm env <subcommand>           # Project env vars / secrets (set, get, push, pull, …)
lpm vault                      # Secrets manager (Keychain-backed)
lpm global                     # Manage globally-installed CLIs (~/.lpm/global/)

# Dev infrastructure
lpm tunnel <port>              # Expose localhost to the internet
lpm tunnel claim <domain>      # Claim a stable domain
lpm tunnel inspect             # View captured webhooks
lpm tunnel replay <n>          # Replay a webhook
lpm cert status                # Local HTTPS certificate info
lpm cert trust                 # Install CA to trust store
lpm graph                      # Dependency graph (--format tree|dot|mermaid|json|stats|html)
lpm ports                      # Dev service port management

# Workspaces & deployment
lpm filter <expr>              # Preview the workspace set a `--filter` expression selects
lpm deploy <member>            # Materialize a member's production closure for `COPY --from=pruned`

# Project health
lpm doctor                     # Health check (--fix to auto-repair)
lpm health                     # Check registry health
lpm store verify               # Verify package store integrity
lpm store gc                   # Clean unused packages
lpm cache                      # Manage ephemeral caches (metadata, tasks, dlx)
lpm self-update                # Update LPM to the latest version

# Debug & inspection
lpm download <package>         # Download and extract a tarball (no install side-effects)
lpm resolve <packages...>      # Print the resolved dependency tree without installing

# Auth & config
lpm login                      # Authenticate (aliases: l)
lpm logout                     # Clear token (aliases: lo)
lpm whoami                     # Current user
lpm token-rotate               # Rotate your auth token
lpm setup                      # Generate .npmrc for CI/CD
lpm setup-npmrc                # Read-only `.npmrc` token for local development
lpm ci                         # CI/CD helpers (env, OIDC, workflow YAML)
lpm init                       # Create a new package
lpm config                     # CLI configuration
lpm pool                       # Pool revenue stats
lpm skills                     # AI agent skills (install, list, …)
lpm swift-registry             # Configure SPM integration (SE-0292)
lpm mcp setup                  # Configure MCP server for AI editors
```

## How `lpm dev` Works

One command. Zero config. Everything auto-detected.

```bash
$ lpm dev

  ● Node     22.12.0 (from .nvmrc)
  ● Deps     up to date (2ms)
  ● Env      .env loaded
  ● HTTPS    certificate valid
  ● Tunnel   https://acme-api.lpm.llc

  [db]  ✔ ready (0.8s)
  [web] ✔ ready (1.2s)
  [api] ✔ ready (3.4s)

  ⌘ Opening https://localhost:3000
```

Auto-installs deps if stale. Copies `.env.example` if no `.env`. Starts multi-service orchestrator from `lpm.json`. Opens browser after readiness checks. Tunnel domain from config. HTTPS with local CA.

Plus: dev tunnels, HTTPS certs, secrets vault, task caching, AI agent skills, Swift packages, dependency graph visualization — built in, not bolted on.

## Benchmarks

|                                |     npm |    pnpm |     bun |         **lpm** |
| ------------------------------ | ------: | ------: | ------: | --------------: |
| Cold install, equal footing ¹  | 6,784ms | 1,532ms |   905ms |       **880ms** |
| Cold install, full wipe loop ² | 7,077ms | 2,445ms | 1,151ms |     **2,193ms** |
| Warm install ³                 |   648ms |   665ms |   263ms |        **23ms** |
| Up-to-date install ³           |   348ms |   152ms |     8ms |         **6ms** |
| Script overhead ⁴              |    67ms |   107ms |     6ms |         **9ms** |
| `lpm lint` vs `npx oxlint` ⁴   |   250ms |       — |       — | **78ms** (3.2×) |
| `lpm fmt` vs `npx biome` ⁴     |   264ms |       — |       — |  **13ms** (20×) |

> **¹ Equal-footing cold install — `bench/fixture-large`** — 21 direct deps, 266 transitive packages. Apple M5, macOS 25.4. `RUNS=20` median, 2026-05-01. Tool-specific cache + lockfile wipes happen OUTSIDE the timed region so the comparison measures install work only, not asymmetric `rm -rf` cost across tools (LPM wipes two paths, bun wipes one, npm/pnpm wipe their own equivalents). **lpm and bun are measured in a 2-arm round-robin (alternating order per outer iter)** so both arms see the same warm/cold network mix across the run — without that, the arm that runs second per iter gets a ~200-300ms CDN-warmth advantage that biases the comparison. npm and pnpm run sequentially (their multi-second installs make any 200ms warmth bias negligible). lpm/bun ratio = **0.97×** (lpm wins by ~25 ms median). Reproduce: `./bench/scripts/run-readme.sh 20`.
>
> **² Full wipe loop** — same fixture as ¹, but cache wipes are INSIDE the timer. Representative of a CI cold-clone loop where setup and install are billed together. LPM's wipe covers two paths (`~/.lpm/cache` + `~/.lpm/store`) plus the project-local `${WORK}/.lpm/wrappers/` tree; bun's covers one; npm/pnpm wipe their own. This column includes the asymmetric `rm -rf` term — the wrappers tree alone is ~270 ms of the lpm full-wipe number, which is why lpm wins on row ¹ but loses on row ². The equal-footing row (¹) is the install-work-only comparison.
>
> **³ Warm / Up-to-date — `bench/project`** — 17 direct deps / 51 packages. **Warm install**: lockfile + global cache present, `node_modules` wiped before each timed iteration. Wrappers live at `<project>/.lpm/wrappers/` instead of `node_modules/.lpm/`, so `rm -rf node_modules` between iters no longer destroys the wrapper tree — warm install becomes a symlink rebuild from already-materialized wrappers, not a full clonefile pass. **Up-to-date install**: lockfile + cache + `node_modules` all present; the PM detects "nothing to do" and exits — the mtime fast-path (`lpm install` without `--allow-new`) takes the top-of-`main` shortcut. Same hardware and date as ¹.
>
> **⁴ Tool-overhead benches — `bench/project`**. Script overhead, lint, and fmt measure runner / built-in-tool execution time, not install pipeline cost — the dependency tree size is irrelevant. Same hardware and date as ¹. `lpm lint` / `lpm fmt` use lazy-downloaded binaries (oxlint, biome) — no `npx` resolution overhead per invocation.
>
> **Script-policy footing.** `lpm install` runs in `script-policy=deny` by default — lifecycle scripts (`preinstall` / `postinstall` / etc.) do **not** execute during install (two-phase model; scripts run via `lpm rebuild` or `lpm install --auto-build`). `npm` / `pnpm` / `bun` run scripts during install by default. To measure like-for-like cold install on a fixture with install scripts, compare `lpm install` ↔ `bun install --ignore-scripts` (both skip) OR `lpm install --yolo --auto-build` ↔ `bun install` (both run). On `bench/fixture-large` the measured intra-tool deny→allow delta is ~50-67 ms median in either direction (n=10).
>
> **Sample-size note.** Earlier passes used `RUNS=11` (n=11). lpm's install pipeline is heavily I/O-syscall-bound (~88 % of samples blocked in `libsystem_kernel.dylib` per the post-install profile), so any concurrent macOS background activity — Spotlight, Time Machine, mds_stores indexing the freshly-extracted store — produces a bimodal per-iter distribution that drags the n=11 median into a "slow cluster." `RUNS=20` is large enough for the median to land reliably in the steady-state cluster; the row ¹ number reproduces within ~16 ms across runs at n=20. Use n=20 if you reproduce locally and care about ±50 ms accuracy.
>
> **Reproduce locally.** `cargo build --release -p lpm-cli`, then `./bench/scripts/run-readme.sh 20` for rows ¹ and ². For warm / up-to-date / script-overhead / lint / fmt, use `./bench/run.sh warm-install` etc.

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
