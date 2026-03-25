# LPM — Package Manager & Developer Toolchain

The fast, intelligent package manager for [LPM](https://lpm.dev). Written in Rust.

## Install

```bash
# npm (recommended)
npm install -g @lpm-registry/cli

# Homebrew
brew tap lpm-dev/lpm
brew install lpm

# curl (standalone, no Node required)
curl -fsSL https://raw.githubusercontent.com/lpm-dev/rust-client/main/install.sh | sh

# Cargo (build from source)
cargo install --git https://github.com/lpm-dev/rust-client lpm-cli
```

## Performance

Benchmarked on `express@^4.21.0` (74 packages, median of 5 runs):

| Scenario | npm | pnpm | yarn | bun | lpm |
|----------|-----|------|------|-----|-----|
| Cold install | 4,891ms | 4,205ms | 3,180ms | 357ms | **2,259ms** |
| Warm install | 2,006ms | 783ms | 1,277ms | 47ms | **85ms** |
| Hot install | 1,910ms | 748ms | 1,261ms | 26ms | **80ms** |

Script runner overhead (no-op script):

| npm | pnpm | yarn | deno | lpm | bun |
|-----|------|------|------|-----|-----|
| 99ms | 189ms | 115ms | 10ms | **26ms** | 5ms |

Tool commands vs npx:

| Command | lpm | npx | Speedup |
|---------|-----|-----|---------|
| `lpm lint` | 30ms | 329ms | **10.8x** |
| `lpm fmt` | 33ms | 338ms | **10.2x** |
| `lpm dlx cowsay` | 79ms | 352ms | **4.5x** |

## Features

**Package Manager**
- PubGrub resolver with multi-version support
- pnpm-style strict `node_modules` with symlinked dependencies
- Binary metadata cache — 166x faster warm resolution
- clonefile on macOS — zero-cost copy-on-write
- Offline mode — install from lockfile + global store, no network
- Phantom dependency detection
- AI-aware security — warnings for dangerous behaviors (eval, child_process, shell)
- Swift Package Registry — native SPM integration via SE-0292
- Source delivery — shadcn-style `lpm add`

**Script Runner**
- PATH injection for `node_modules/.bin`
- Pre/post script hooks (npm convention)
- Script shortcuts — `lpm dev` runs `scripts.dev`
- `.env` loading — auto-loads `.env`, `.env.local`, `--env=staging`
- `lpm.json` env mapping — `{"env": {"dev": ".env.development"}}`
- `lpm exec` — run JS/TS files directly
- `lpm dlx` — run packages without installing

**Runtime Management**
- `lpm use node@22` — install and activate Node.js versions
- Auto-switch per project via `lpm.json`, `engines`, `.nvmrc`
- Zero shell setup — works through PATH injection in `lpm run`

**Task Runner**
- Local task caching — hash inputs, restore outputs on cache hit (25ms)
- `lpm.json` task config with `dependsOn`, `cache`, `outputs`, `inputs`
- Workspace-aware — `--all`, `--filter`, `--affected` (git-based)
- `--watch` mode with file system watching and debounce

**Built-in Tools** (lazy-downloaded on first use, 6.2MB core binary stays lean)
- `lpm lint` — Oxlint (50-100x faster than ESLint)
- `lpm fmt` — Biome (20x faster than Prettier)
- `lpm check` — TypeScript type checking (tsc --noEmit)
- `lpm test` — auto-detects vitest/jest/mocha
- `lpm bench` — auto-detects vitest bench
- `lpm plugin list/update` — manage tool versions

**Project Health**
- `lpm doctor` — 11 checks: registry, auth, store, deps, runtime, lint, format, TypeScript, plugins, workspace

## Commands

```bash
# Package management
lpm install              # Install dependencies
lpm add <package>        # Add a package
lpm publish              # Publish to lpm.dev
lpm audit                # Security audit
lpm search <query>       # Search packages
lpm info <package>       # Package details
lpm outdated             # Check for newer versions

# Scripts & execution
lpm run <script>         # Run a script (with .env, hooks, PATH injection)
lpm dev                  # Shortcut for scripts.dev
lpm exec <file>          # Run a JS/TS file directly
lpm dlx <package>        # Run without installing

# Runtime management
lpm use node@22          # Install + activate Node.js version
lpm use --list           # List installed versions
lpm use --pin node@22    # Pin version in lpm.json

# Built-in tools
lpm lint                 # Lint with Oxlint
lpm fmt                  # Format with Biome
lpm check                # Type-check with tsc
lpm test                 # Run tests
lpm plugin list          # Show installed tool plugins
lpm plugin update        # Update plugins to latest

# Project health
lpm doctor               # Full health check
lpm login / logout       # Authentication
lpm whoami               # Current user
lpm swift-registry       # Configure SPM to use LPM
```

## Architecture

```
crates/
  lpm-cli/          CLI entry point (clap)
  lpm-common/       Shared types, errors, constants
  lpm-semver/       npm-compatible semver parsing
  lpm-registry/     Registry HTTP client + caching
  lpm-resolver/     PubGrub-based dependency resolution
  lpm-store/        Content-addressable package store
  lpm-linker/       node_modules layout (symlink/hoist)
  lpm-lockfile/     TOML + binary lockfile (mmap)
  lpm-extractor/    Tarball download, verify, extract
  lpm-workspace/    Monorepo/workspace discovery
  lpm-security/     Audit, lifecycle script blocking
  lpm-runner/       Script execution, .env, hooks, PATH
  lpm-runtime/      Node.js version management
  lpm-task/         Task graph, caching, watch mode
  lpm-plugin/       Lazy-download tool plugin system
```

## License

MIT
