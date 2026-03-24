# LPM — Package Manager

The fast, intelligent package manager for [LPM](https://lpm.dev). Written in Rust.

## Install

```bash
# npm (recommended)
npm install -g @lpm-registry/cli

# Homebrew
brew install lpm

# curl
curl -fsSL https://lpm.dev/install.sh | sh

# Cargo (build from source)
cargo install lpm
```

## Performance

Benchmarked on `express@^4.21.0` (74 packages):

| Scenario | npm | pnpm | lpm |
|----------|-----|------|-----|
| Warm install | 516ms | 377ms | **84ms** |
| Hot install | 559ms | 260ms | **46ms** |
| Offline | — | — | **92ms** |

6x faster than npm, 4.5x faster than pnpm for everyday installs.

## Features

- **PubGrub resolver** — correct dependency resolution with multi-version support
- **pnpm-style isolation** — strict `node_modules` with symlinked dependencies
- **Binary metadata cache** — 166x faster warm resolution
- **clonefile on macOS** — zero-cost copy-on-write file operations
- **Offline mode** — install from lockfile + global store, no network
- **Phantom dependency detection** — catch undeclared transitive imports
- **AI-aware security** — post-install warnings for dangerous behaviors (eval, child_process, shell)
- **Swift Package Registry** — native SPM integration via SE-0292, with CMS package signing
- **Source delivery** — shadcn-style `lpm add` for components and templates

## Commands

```bash
lpm install              # Install dependencies
lpm add <package>        # Add a package (Swift: edits Package.swift, JS: source delivery)
lpm publish              # Publish to lpm.dev
lpm audit                # Check for security issues
lpm search <query>       # Search packages
lpm info <package>       # Package details
lpm login / logout       # Authentication
lpm swift-registry       # Configure SPM to use LPM
lpm whoami               # Current user info
lpm quality <package>    # Quality score report
lpm pool stats           # Pool revenue breakdown
lpm doctor               # Health check
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
  lpm-lockfile/     TOML lockfile read/write
  lpm-extractor/    Tarball download, verify, extract
  lpm-workspace/    Monorepo/workspace discovery
  lpm-security/     Audit, lifecycle script blocking
```

## License

MIT
