# LPM — The Package Manager for Modern Software

Fast, secure, all-in-one. Written in Rust.

```bash
npm install -g @lpm-registry/cli
```

The npm package is a dependency-free launcher for the native Rust binary. npm
installs the matching platform package automatically through
`optionalDependencies`; `lpm self-update` keeps using the same npm channel.

<details>
<summary>Other install methods</summary>

```bash
brew tap lpm-dev/lpm && brew install lpm         # Homebrew
curl -fsSL https://cli.lpm.dev/install | sh       # Standalone
cargo install --git https://github.com/lpm-dev/rust-client lpm-cli   # Source
```

Standalone installs and self-updates verify release download integrity before
swapping the binary.

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
lpm rebuild                    # Run dependency lifecycle scripts (phase 2 of install)
lpm approve-scripts            # Approve packages blocked by default-deny script policy
lpm trust                      # Manage `trustedDependencies` in package.json
lpm patch <package>            # Generate a local patch, `patch-package` style
lpm patch-commit               # Finalize a patch staging directory
lpm migrate                    # Migrate from npm/yarn/pnpm/bun

# Scripts & execution
lpm run <scripts...>           # Run scripts (parallel: -p, cached, watch)
lpm dev                        # Zero-config dev server + HTTPS + tunnel
lpm <file>                     # Run JS/TS files directly
lpm exec <bin>                 # Run project-local binaries from node_modules/.bin
lpm <bin>                      # Shorthand local bin when no built-in/file/script matches
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
lpm deploy <output> --filter <member>  # Materialize a member's deploy closure for `COPY --from=pruned`

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
lpm setup ci npmrc             # Generate .npmrc for CI/CD
lpm setup ci github-actions    # Print a GitHub Actions OIDC snippet
lpm setup local                # Read-only `.npmrc` token for local development
lpm ci                         # Frozen lockfile install for CI
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

|                                 |     npm |    pnpm |     bun |         **lpm** |
| ------------------------------- | ------: | ------: | ------: | --------------: |
| Cold install, equal footing ¹   | 6,735ms | 1,124ms |   823ms |       **957ms** |
| Cold install, reset-each-iter ² | 7,146ms | 1,927ms | 1,207ms |       **945ms** |
| Warm install ³                  |   648ms |   665ms |   263ms |        **23ms** |
| Up-to-date install ³            |   348ms |   152ms |     8ms |         **6ms** |
| Script overhead ⁴               |    67ms |   107ms |     6ms |         **9ms** |
| `lpm lint` vs `npx oxlint` ⁴    |   250ms |       — |       — | **78ms** (3.2×) |
| `lpm fmt` vs `npx biome` ⁴      |   264ms |       — |       — |  **13ms** (20×) |

> **¹ Equal-footing cold install — `bench/fixture-large`** — Fresh cache and lockfile resets happen outside the timer, so this row measures install work instead of cleanup work. `lpm` and `bun` alternate per iteration to cancel out CDN warmth bias; `npm` and `pnpm` run sequentially because their install times are much larger.
>
> **² Reset-each-iter cold install** — Same fixture as ¹, but every iteration starts cold again. `npm`, `pnpm`, and `bun` wipe inside the timer. `lpm` rotates the previous cache, store, and project state before the timer so the result reflects a cold install without charging recursive deletion.
>
> **³ Warm / Up-to-date — `bench/project`** — Warm install means the cache and lockfile already exist and only `node_modules` gets rebuilt. Up-to-date install means nothing changed, so the package manager just checks state and exits.
>
> **⁴ Script overhead / lint / fmt — `bench/project`** — Script overhead is the cost of invoking the package runner itself. The lint and format rows compare `lpm`'s built-ins against `npx oxlint` and `npx biome`.
>
> **Script-policy footing.** `lpm install` runs the root project's install lifecycle (`pnpm:devPreinstall`, then `preinstall`/`install`/`postinstall`/`preprepare`/`prepare`/`postprepare`) on bare installs. Dependency lifecycle scripts stay blocked by default and run only through the trust-gated rebuild/auto-build path. For like-for-like comparisons on script-heavy fixtures, compare dependency skip-vs-skip (`bun install --ignore-scripts`) or dependency run-vs-run (`lpm install --yolo --auto-build`).
>
> **Bench setup.** Rows ¹-² use a `RUNS=20` cold-install sweep. Rows ³-⁴ come from the `bench/project` sweep.

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
