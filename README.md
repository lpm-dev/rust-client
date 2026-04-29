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

|                                | npm     | pnpm    | bun     | **lpm**          |
| ------------------------------ | ------- | ------- | ------- | ---------------- |
| Cold install, equal footing ¹  | 1,913ms | 1,247ms | 448ms   | **573ms**        |
| Cold install, full wipe loop ² | 2,748ms | 2,902ms | 1,068ms | **1,248ms**      |
| Warm install                   | 1,237ms | 1,026ms | 348ms   | **398ms**        |
| Up-to-date install             | 456ms   | 272ms   | 36ms    | **15ms**         |
| Script overhead                | 110ms   | 181ms   | 10ms    | **17ms**         |
| `lpm lint` vs `npx oxlint`     | 358ms   | —       | —       | **200ms** (1.8x) |
| `lpm fmt` vs `npx biome`       | 402ms   | —       | —       | **19ms** (21x)   |

> **¹ Equal-footing cold install** — 17 direct deps, 51 packages. Tool-specific cache wipes happen OUTSIDE the timed region so the comparison measures install work only, not asymmetric `rm -rf` cost across tools. Apple M4 Pro, macOS 15.4. `RUNS=11` median. 2026-04-19, post-Phase-45 (lazy keychain resolution, mtime fast-path for up-to-date, corrected bench methodology).
>
> **Script-policy footing:** `lpm install` runs in `script-policy=deny` by default — lifecycle scripts (`preinstall`/`postinstall`/etc.) do **not** execute during install (Phase 46 two-phase model; scripts run via `lpm rebuild` or `lpm install --auto-build`). `npm`/`pnpm`/`bun` run scripts during install by default. To measure like-for-like cold install on a fixture with install scripts, compare `lpm install` ↔ `bun install --ignore-scripts` (both skip) OR `lpm install --yolo --auto-build` ↔ `bun install` (both run). On `bench/fixture-large` (266 packages), the measured intra-tool deny→allow delta is ~50-67 ms median in either direction (Phase 57 measurement-sprint, n=10). The 51-package `bench/project` fixture above has minimal install-script load, so the asymmetry contributes <20 ms to this row.
>
> **² Full wipe loop** — same fixture, but cache wipes are INSIDE the timer (original methodology). Representative of a CI cold-clone loop where setup and install are billed together. LPM's wipe covers two paths (`~/.lpm/cache` + `~/.lpm/store`), bun's covers one, so this column includes an asymmetric `rm -rf` term. Same session and hardware as ¹.
>
> **Warm / up-to-date / script / lint / fmt**: Apple M4 Pro, 2026-04-19, median of 11. Phase 45 deferred the macOS Keychain IPC (~50ms) from startup to the first auth-required HTTP request, which shows up across every short command — up-to-date, script-overhead, lint, and fmt all dropped by 30-50ms. `lint`/`fmt` use lazy-downloaded binaries — no `npx` resolution overhead.

Plus: dev tunnels, HTTPS certs, secrets vault, task caching, AI agent skills, Swift packages, dependency graph visualization — built in, not bolted on.

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
