<p align="center">
  <a href="https://cli.lpm.dev">
    <img src="assets/lpm-icon.svg" alt="LPM logo" height="150">
  </a>
</p>

<h1 align="center">LPM</h1>

<div align="center">
  <a href="https://cli.lpm.dev"><img src="assets/lpm-icon.svg" alt="" height="18"> CLI Documentation</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://lpm.dev"><img src="assets/lpm-registry-icon.svg" alt="" height="18"> LPM.dev Registry</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://firewall.lpm.dev"><img src="assets/lpm-firewall-icon.svg" alt="" height="18"> LPM Firewall</a>
</div>

## What is LPM?

LPM is a fast, secure package manager and developer platform for modern JavaScript and TypeScript projects. It ships as a single Rust binary called `lpm`, works with the npm ecosystem, and adds secure-by-default installs, built-in developer tooling, hosted registry features, and an npm package firewall.

```bash
lpm install
lpm add lpm-source-package
lpm run dev
```

LPM has three connected parts:

- **LPM CLI** - an npm-compatible package manager and dev toolkit written in Rust. It installs from npm, lpm.dev, JSR, and private registries; blocks dependency lifecycle scripts by default; and includes a task runner, dev server, test/bench runner, linter, formatter, Node version pinning, local HTTPS, tunnels, secrets, and project health checks.
- **LPM.dev Registry** - the hosted registry and platform behind the `@lpm.dev/*` scope. Use it for private packages, Pool distribution, Marketplace sales, Swift packages, package quality analysis, generated metadata, access control, and Pro/team platform features.
- **LPM Firewall** - a hosted verdict service for public npm package versions. It can run in monitor mode or enforcement mode before LPM materializes package bytes, helping teams catch malicious packages, critical vulnerabilities, suspicious lifecycle behavior, and policy violations during install.

## Install

LPM supports macOS, Linux glibc, Linux x64 musl (including Alpine), and Windows x64 through npm. Homebrew and the standalone installer support macOS and Linux; the standalone installer selects the matching glibc or musl binary automatically on Linux x64.

```bash
# npm
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli

# Homebrew
brew tap lpm-dev/lpm && brew install lpm

# Standalone
curl -fsSL https://cli.lpm.dev/install | sh
```

The npm package is a dependency-free launcher for the native Rust binary. npm installs the matching platform package through `optionalDependencies`; the approved `postinstall` verifier checks the native binary and wires the global command where the platform allows it.

If your npm version or policy does not require explicit script approval, this also works:

```bash
npm install -g @lpm-registry/cli
```

Update LPM with:

```bash
lpm self-update
```

## Quick Links

- Get Started
  - [Introduction](https://cli.lpm.dev/docs)
  - [Installation](https://cli.lpm.dev/docs/installation)
  - [Your first install](https://cli.lpm.dev/docs/first-install)
  - [Registries](https://cli.lpm.dev/docs/registries)
  - [Project setup](https://cli.lpm.dev/docs/project-setup)
  - [Migrating](https://cli.lpm.dev/docs/migrating)
  - [Comparison](https://cli.lpm.dev/docs/comparison)

- Packages
  - [`lpm install`](https://cli.lpm.dev/docs/packages/install)
  - [`lpm add`](https://cli.lpm.dev/docs/packages/add)
  - [`lpm publish`](https://cli.lpm.dev/docs/packages/publish)
  - [`lpm audit`](https://cli.lpm.dev/docs/packages/audit)
  - [`lpm trust`](https://cli.lpm.dev/docs/packages/trust)
  - [`lpm approve-scripts`](https://cli.lpm.dev/docs/packages/approve-scripts)
  - [Workspaces](https://cli.lpm.dev/docs/packages/workspaces)
  - [Lockfile](https://cli.lpm.dev/docs/packages/lockfile)
  - [Content-addressable store](https://cli.lpm.dev/docs/packages/content-addressable-store)
  - [npm compatibility](https://cli.lpm.dev/docs/packages/npm-compatibility)

- Dev
  - [`lpm dev`](https://cli.lpm.dev/docs/dev/dev)
  - [`lpm run`](https://cli.lpm.dev/docs/dev/run)
  - [`lpm exec`](https://cli.lpm.dev/docs/dev/exec)
  - [`lpm dlx`](https://cli.lpm.dev/docs/dev/dlx)
  - [`lpm test`](https://cli.lpm.dev/docs/dev/test)
  - [`lpm bench`](https://cli.lpm.dev/docs/dev/bench)
  - [`lpm lint`](https://cli.lpm.dev/docs/dev/lint)
  - [`lpm fmt`](https://cli.lpm.dev/docs/dev/fmt)
  - [Node version pinning](https://cli.lpm.dev/docs/dev/node-version-pinning)
  - [Environment variables](https://cli.lpm.dev/docs/dev/env)

- Infra
  - [`lpm tunnel`](https://cli.lpm.dev/docs/infra/tunnel)
  - [`lpm cert`](https://cli.lpm.dev/docs/infra/cert)
  - [`lpm config`](https://cli.lpm.dev/docs/infra/config)
  - [`lpm doctor`](https://cli.lpm.dev/docs/infra/doctor)
  - [`lpm store`](https://cli.lpm.dev/docs/infra/store)
  - [`lpm self-update`](https://cli.lpm.dev/docs/infra/self-update)
  - [Secrets vault](https://cli.lpm.dev/docs/infra/secrets-vault)
  - [Port management](https://cli.lpm.dev/docs/infra/port-management)
  - [Dependency graph](https://cli.lpm.dev/docs/infra/dependency-graph)

- Guides
  - [Publishing a package](https://cli.lpm.dev/docs/guides/publishing-a-package)
  - [Firewall for npm](https://cli.lpm.dev/docs/guides/firewall)
  - [Zero-config dev server](https://cli.lpm.dev/docs/guides/zero-config-dev-server)
  - [Monorepo setup](https://cli.lpm.dev/docs/guides/monorepo-setup)
  - [Managing secrets](https://cli.lpm.dev/docs/guides/managing-secrets)
  - [CI/CD setup](https://cli.lpm.dev/docs/guides/ci-cd-setup)
  - [Docker deploys](https://cli.lpm.dev/docs/guides/docker-deploys)
  - [Migrating from npm](https://cli.lpm.dev/docs/guides/migrating-from-npm)
  - [Migrating from pnpm](https://cli.lpm.dev/docs/guides/migrating-from-pnpm)
  - [Migrating from yarn](https://cli.lpm.dev/docs/guides/migrating-from-yarn)
  - [Migrating from Bun](https://cli.lpm.dev/docs/guides/migrating-from-bun)

- Reference
  - [`package.json` fields](https://cli.lpm.dev/docs/reference/package-json-lpm)
  - [`lpm.json`](https://cli.lpm.dev/docs/reference/lpm-json)
  - [`lpm.toml`](https://cli.lpm.dev/docs/reference/lpm-toml)
  - [Configuration](https://cli.lpm.dev/docs/reference/config-toml)
  - [Environment variables](https://cli.lpm.dev/docs/reference/env-vars)
  - [Schemas](https://cli.lpm.dev/docs/reference/schemas)
  - [Lockfile format](https://cli.lpm.dev/docs/reference/lockfile-format)
  - [MCP servers](https://cli.lpm.dev/docs/reference/mcp-servers)
  - [AI agent skills](https://cli.lpm.dev/docs/reference/ai-agent-skills)
  - [Exit codes](https://cli.lpm.dev/docs/reference/exit-codes)

## Benchmarks

Install benchmarks use the tracked VitePress docs fixture, a real-world workspace graph with 535 packages.

| Benchmark                       |       npm |    pnpm |     bun |  **lpm** | **lpm + Firewall monitor** |
| ------------------------------- | --------: | ------: | ------: | -------: | -------------------------: |
| Cold install, equal footing ¹   | 17,354ms | 6,125ms | 2,455ms | 2,945ms |                    3,043ms |
| Warm install ¹                  |  3,819ms | 3,301ms |   451ms | **387ms** |                   **324ms** |
| Up-to-date install ¹            |    282ms |   522ms |    77ms |  **14ms** |                    **14ms** |

Dev command benchmarks measure already-installed local scripts, local bins, and built-in tools.

| Benchmark                         | npm / npx / tsx |    pnpm | bun / bunx |  **lpm** |
| --------------------------------- | --------------: | ------: | ---------: | -------: |
| Package script: no-op ²           |            74ms |   161ms |       15ms | **10ms** |
| Package script: empty Node ²      |           101ms |   185ms |       33ms | **27ms** |
| Local bin: `esbuild --version` ²  |           144ms |   174ms |       27ms | **21ms** |
| Run TSX app, warm cache ³         |           112ms |       — |       19ms | **41ms** |
| `lpm lint` vs `npx oxlint` ⁴      |           273ms |       — |          — |  **3ms** |
| `lpm fmt` vs `npx biome` ⁴        |           340ms |       — |          — |  **3ms** |

<details>
<summary>Benchmark methodology</summary>

> **¹ Install benchmarks** — Generated by [`run-install-readiness.mjs`](bench/scripts/run-install-readiness.mjs) with `--samples 10 --fixtures vitepress --managers lpm,bun,pnpm,npm --modes cold,warm,up-to-date --lpm-firewall-modes off,report`. Each run uses an isolated temporary project, `HOME`, package-manager cache, and `LPM_HOME`; samples are round-robin interleaved to reduce live-network bias. Dependency lifecycle scripts are disabled for all package managers. Raw artifact: [`readme-install-vitepress-20260710T140139.md`](bench/perf-results/readme-install-vitepress-20260710T140139.md).
>
> **Firewall monitor mode** — The Firewall monitor column runs the same LPM install with `LPM_NPM_FIREWALL=report`. In the cold install row, LPM checked 535 package versions before materializing package bytes.
>
> **² Script and local-bin benchmarks** — Generated by [`run-bin-benchmark.mjs`](bench/scripts/run-bin-benchmark.mjs) with 10 measured iterations after 2 warmups. Dependency installation is setup-only and not timed; rows execute package scripts or already-installed local `node_modules/.bin` entries. Tool versions: `lpm 0.67.0`, `npm 10.9.4`, `npx 10.9.4`, `pnpm 11.3.0`, `bun 1.3.14`, `bunx 1.3.14`. Raw artifact: [`readme-run-bin-20260710T214708Z.md`](bench/perf-results/readme-run-bin-20260710T214708Z.md).
>
> **³ TSX benchmark** — Generated by [`exec-runtime-benchmark.mjs`](bench/scripts/exec-runtime-benchmark.mjs) against a generated 10-module TSX ESM app with 10 measured iterations after 2 warmups. The `npm / npx / tsx` column is `tsx`; the `bun / bunx` column is `bun`. Raw artifact: [`readme-exec-runtime-20260710T141510.md`](bench/perf-results/readme-exec-runtime-20260710T141510.md).
>
> **⁴ Built-in tool benchmarks** — Generated with `RUNS=10 LPM_BIN=target/release/lpm-rs BENCH_WORK_DIR=/tmp/lpm-readme-builtin-tools-work-20260711T205110Z ./bench/run.sh builtin-tools` on `bench/project`. The `npm / npx / tsx` column is `npx oxlint` or `npx @biomejs/biome`. Raw artifact: [`readme-builtin-tools-20260711T205110Z.md`](bench/perf-results/readme-builtin-tools-20260711T205110Z.md).
</details>

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
