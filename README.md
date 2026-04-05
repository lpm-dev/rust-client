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

## Benchmarks

|                            | npm       | pnpm      | bun       | **lpm**         |
| -------------------------- | --------- | --------- | --------- | --------------- |
| Cold install (51 pkgs)     | 2,461ms   | 2,256ms   | 1,312ms   | **2,416ms**     |
| Warm install               | 994ms     | 961ms     | 294ms     | **382ms**       |
| Up-to-date install         | 433ms     | 260ms     | 12ms      | **31ms**        |
| Script overhead            | 109ms     | 176ms     | 12ms      | **36ms**        |
| `lpm lint` vs `npx oxlint` | 469ms     | —         | —         | **186ms** (2.5x)|
| `lpm fmt` vs `npx biome`   | 411ms     | —         | —         | **52ms** (7.9x) |

> 17 direct dependencies, 51 resolved packages. Benchmarked on Apple M4 Pro, macOS 15.4, 2026-04-05. Cold = no cache/lockfile. Warm = lockfile + cache. Median of 3 runs. `lint`/`fmt` use lazy-downloaded binaries — no `npx` resolution overhead.

Plus: dev tunnels, HTTPS certs, secrets vault, task caching, AI agent skills, Swift packages, dependency graph visualization — built in, not bolted on.

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

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
