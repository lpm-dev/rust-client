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
lpm add <package>              # Source delivery (shadcn-style)
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
| Cold install, equal footing ¹  | 1,955ms | 1,334ms | 402ms   | **596ms**        |
| Cold install, full wipe loop ² | 2,620ms | 3,295ms | 1,431ms | **1,288ms**      |
| Warm install                   | 1,108ms | 1,026ms | 320ms   | **405ms**        |
| Up-to-date install             | 426ms   | 239ms   | 11ms    | **50ms**         |
| Script overhead                | 114ms   | 173ms   | 9ms     | **51ms**         |
| `lpm lint` vs `npx oxlint`     | 378ms   | —       | —       | **211ms** (1.8x) |
| `lpm fmt` vs `npx biome`       | 402ms   | —       | —       | **60ms** (6.7x)  |

> **¹ Equal-footing cold install** — 17 direct deps, 51 packages. Tool-specific cache wipes happen OUTSIDE the timed region so the comparison measures install work only, not asymmetric `rm -rf` cost across tools. Apple M4 Pro, macOS 15.4. `RUNS=11` median. 2026-04-19, post-Phase-43 (tarball URLs in lockfile + end-to-end `--insecure`).
>
> **² Full wipe loop** — same fixture, but cache wipes are INSIDE the timer (original methodology). Representative of a CI cold-clone loop where setup and install are billed together. LPM's wipe covers two paths (`~/.lpm/cache` + `~/.lpm/store`), bun's covers one, so this column includes an asymmetric `rm -rf` term. Same session and hardware as ¹.
>
> **Warm / up-to-date / script / lint / fmt**: Apple M4 Pro, 2026-04-19, median of 11. `lint`/`fmt` use lazy-downloaded binaries — no `npx` resolution overhead.
>
> **Phase 43 note** — Phase 43 stores tarball URLs in `lpm.lockb` so warm installs against an empty store (fresh CI shape: lockfile present, `node_modules` + store cold) skip the per-package metadata round-trip. On a 409-package decision-gate fixture the `fetch_breakdown.url_lookup.sum_ms` sub-timer drops from ~20 seconds to **0**, delivering a **−18% fetch_ms** improvement and **−12% total_ms** (5-run A/B median). The shape isn't in the cross-tool comparison above — npm/pnpm/bun don't have an equivalent "lockfile but empty store" scaffold — but it's the primary scenario Phase 43 targets.

Plus: dev tunnels, HTTPS certs, secrets vault, task caching, AI agent skills, Swift packages, dependency graph visualization — built in, not bolted on.

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
