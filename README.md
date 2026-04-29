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
lpm vault                      # Secrets manager (Keychain-backed)

# Dev infrastructure
lpm tunnel <port>              # Expose localhost to the internet
lpm tunnel claim <domain>      # Claim a stable domain
lpm tunnel inspect             # View captured webhooks
lpm tunnel replay <n>          # Replay a webhook
lpm cert status                # Local HTTPS certificate info
lpm cert trust                 # Install CA to trust store
lpm graph                      # Dependency tree (--dot, --mermaid, --html)
lpm ports                      # Dev service port management

# Project health
lpm doctor                     # 11-check health report (--fix to auto-repair)
lpm store verify               # Verify package store integrity
lpm store gc                   # Clean unused packages

# Auth & config
lpm login                      # Authenticate (aliases: l)
lpm logout                     # Clear token (aliases: lo)
lpm whoami                     # Current user
lpm setup                      # Generate .npmrc for CI/CD
lpm init                       # Create a new package
lpm config                     # CLI configuration
lpm skills install             # Install AI agent skills
lpm swift-registry             # Configure SPM integration
lpm mcp setup                  # Configure MCP server for AI editors
```

## How `lpm add` Works

`lpm add <pkg>` is a **source delivery** command — distinct from `lpm install`. It downloads a tarball, copies the source files into your project (NOT `node_modules`), rewrites imports, and (if the package opts in) drives an interactive config + dependency install.

It works for any package on any registry the rust client can reach:

- `lpm add @lpm.dev/owner.name` — lpm.dev-hosted (the only form that resolves to lpm.dev).
- `lpm add @lpm-registry/ex-source` — public npm scoped.
- `lpm add react` / `lpm add lodash.merge` — bare npm names. Dotted bare names (`lodash.merge`, `lodash.debounce`) are real npm packages, not lpm.dev shorthand.
- `lpm add @private/internal-pkg` — private/corp registry declared in `.npmrc` (`@private:registry=...` + `_authToken=...`).

Two paths inside the command, decided after extraction:

- **Rich path** (`lpm.config.json` present at the tarball root) — schema prompts, conditional file filtering, conditional dependency installation, importAlias-aware rewrite.
- **Simple path** (`lpm.config.json` absent) — "download manager": prompt for target dir (or pass `--path`), copy source files verbatim, rewrite imports, NO automatic dep install. The user-facing summary lists external/bare imports the user needs to add to their `package.json`.

`--yes` / `--json` / non-TTY without `--path` errors explicitly: there's no human in the loop to confirm where 3rd-party source landed, so refusing is safer than heuristic-defaulting `components/`. Pass `--path <dir>` to opt in.

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

## Benchmarks

|                                  |     npm |    pnpm |     bun |     **lpm**      |
| -------------------------------- | ------: | ------: | ------: | ---------------: |
| Cold install, equal footing ¹    | 7,236ms | 1,442ms |   524ms |        **891ms** |
| Cold install, full wipe loop ²   | 8,022ms | 2,518ms | 1,350ms |      **1,833ms** |
| Warm install ¹                   | 1,324ms | 1,099ms |   478ms |        **732ms** |
| Up-to-date install ¹             |   522ms |   175ms |    11ms |          **5ms** |
| Script overhead ³                |    66ms |   103ms |     6ms |         **10ms** |
| `lpm lint` vs `npx oxlint` ³     |   257ms |       — |       — |  **77ms** (3.3×) |
| `lpm fmt` vs `npx biome` ³       |   271ms |       — |       — |   **14ms** (19×) |

> **¹ Install benches — `bench/fixture-large`** — 21 direct deps, 266 transitive packages, the fixture every Phase 49+ ship gate has anchored on. Apple M4 Pro, macOS 15.4. `RUNS=11` median, 2026-04-29 (post-Phase-60.1 default-flip — `lpm install` now reaches greedy-fusion without env vars).
>
> &nbsp;&nbsp;&nbsp;&nbsp;**Equal footing**: tool-specific cache wipes happen OUTSIDE the timed region so the comparison measures install work only, not asymmetric `rm -rf` cost across tools (LPM wipes two paths, bun wipes one, npm/pnpm wipe their own equivalents). This is the apples-to-apples row.
>
> &nbsp;&nbsp;&nbsp;&nbsp;**Warm install**: lockfile + global cache present, `node_modules` wiped before each timed iteration. Lockfile is reused; tarballs come from the warm content store / cache; only the link step is fresh.
>
> &nbsp;&nbsp;&nbsp;&nbsp;**Up-to-date install**: lockfile + cache + `node_modules` all present. The PM detects "nothing to do" and exits. Phase 45's mtime fast-path (`lpm install` without `--allow-new`) takes the top-of-`main` shortcut — no full pipeline, no resolution.
>
> **² Full wipe loop** — same fixture as ¹, but cache wipes are INSIDE the timer. Representative of a CI cold-clone loop where setup and install are billed together. LPM's wipe covers two paths (`~/.lpm/cache` + `~/.lpm/store`), bun's covers one, npm/pnpm wipe their own; this column includes the asymmetric `rm -rf` term. The equal-footing row (¹) is the install-work-only comparison.
>
> **³ Tool-overhead benches — `bench/project`** — 17 direct deps / 51 packages. Script overhead, lint, and fmt measure runner / built-in-tool execution time, not install pipeline cost — the dependency tree size is irrelevant. Same hardware and date as ¹. `lpm lint` / `lpm fmt` use lazy-downloaded binaries (oxlint, biome) — no `npx` resolution overhead per invocation.
>
> **Script-policy footing.** `lpm install` runs in `script-policy=deny` by default — lifecycle scripts (`preinstall` / `postinstall` / etc.) do **not** execute during install (Phase 46 two-phase model; scripts run via `lpm rebuild` or `lpm install --auto-build`). `npm` / `pnpm` / `bun` run scripts during install by default. To measure like-for-like cold install on a fixture with install scripts, compare `lpm install` ↔ `bun install --ignore-scripts` (both skip) OR `lpm install --yolo --auto-build` ↔ `bun install` (both run). On `bench/fixture-large` the measured intra-tool deny→allow delta is ~50-67 ms median in either direction (Phase 57 measurement-sprint, n=10) — well below this row's bun-vs-lpm gap.
>
> **Reproduce locally.** `cargo build --release -p lpm-cli`, then `BENCH_PROJECT_DIR=$PWD/bench/fixture-large RUNS=11 ./bench/run.sh cold-install-clean` (or `cold-install` / `warm-install` / `up-to-date`). Drop `BENCH_PROJECT_DIR` for the script/lint/fmt rows.

Plus: dev tunnels, HTTPS certs, secrets vault, task caching, AI agent skills, Swift packages, dependency graph visualization — built in, not bolted on.

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
