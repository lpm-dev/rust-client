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
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://vault.lpm.dev"><img src="assets/lpm-vault.svg" alt="" height="18"> LPM Vault</a>
</div>

## What is LPM?

LPM is a fast, secure package manager and developer platform for modern JavaScript and TypeScript projects. It ships as a single Rust binary called `lpm`, works with the npm ecosystem, and adds secure-by-default installs, built-in developer tooling, hosted registry features, and an npm package firewall.

```bash
lpm install
lpm add lpm-source-package
lpm run dev
```

LPM has four connected parts:

- **LPM CLI** - an npm-compatible package manager and dev toolkit written in Rust. It installs from npm, lpm.dev, JSR, and private registries; blocks dependency lifecycle scripts by default; and includes a task runner, dev server, test/bench runner, linter, formatter, Node version pinning, local HTTPS, tunnels, secrets, and project health checks.
- **LPM.dev Registry** - the hosted registry and platform behind the `@lpm.dev/*` scope. Use it for private packages, Pool distribution, Marketplace sales, Swift packages, package quality analysis, generated metadata, access control, and Pro/team platform features.
- **LPM Firewall** - a hosted verdict service for public npm package versions. Enforcement mode checks versions before LPM materializes package bytes; monitor mode reports verdicts without holding the install. Both help teams catch malicious packages, critical vulnerabilities, suspicious lifecycle behavior, and policy violations during install.
- **LPM Vault** - a native macOS app for project environment variables and secrets. It stores secrets in the macOS Keychain, supports multiple environments, and syncs encrypted data through LPM.dev. The app shares local env data with the LPM CLI, so edits are available to `lpm env` and `lpm run`.

## CLI env approval on macOS

In LPM Vault, select a project. Use **CLI approval** beside **All variables**:

- **Off:** `lpm run` injects the linked project's env values automatically.
- **On:** Keychain requires Touch ID or your Mac login password before it releases the project's env values. If authentication fails or you cancel it, LPM stops before it runs lifecycle hooks or the main script.

The setting applies to every environment in that project on this Mac. Existing `lpm.json` project links still work. The app requires authentication to change the setting. The app's **Lock** button remains separate and does not change CLI approval.

Approval also protects other CLI commands that read the project's secrets. It controls secret retrieval. Processes that already received values retain them until they exit.

## Install

LPM supports macOS, Linux glibc 2.28 or newer, Linux x64 musl (including Alpine), and Windows x64 through npm. Homebrew and the standalone installer support macOS and Linux; the standalone installer selects the matching glibc or musl binary automatically on Linux x64.

```bash
# npm
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli

# Homebrew
brew tap lpm-dev/lpm && brew install lpm

# Standalone
curl -fsSL https://cli.lpm.dev/install | sh
```

Run the installer and all LPM CLI user commands without `sudo`. LPM CLI elevates only the specific operating-system operation that requires administrator access.

The npm package installs the matching platform package through `optionalDependencies`. The approved `postinstall` script verifies the native program and connects the global commands to it.

If your npm version or policy does not require explicit script approval, this also works:

```bash
npm install -g @lpm-registry/cli
```

Update LPM with:

```bash
lpm self-update                    # follow the installed stable/nightly channel
lpm self-update --channel nightly  # switch to nightly
lpm self-update --channel stable   # switch back to stable
```

Nightly snapshots are available through npm and the standalone installer:

```bash
npm install -g @lpm-registry/cli@nightly
curl -fsSL https://cli.lpm.dev/install | LPM_INSTALL_CHANNEL=nightly sh
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
  - [`lpm audit`](https://cli.lpm.dev/docs/packages/audit) — [source capabilities and JSON output](bench/source-analysis/README.md#audit-output)
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

Install benchmarks use the tracked [T3-stack Next.js fixture](bench/audit-fixtures/t3-install).
See [full benchmarks and methodology](https://cli.lpm.dev/docs/benchmarks).

Measured September 28, 2026, on an Apple M5 Pro with 48 GiB RAM and macOS arm64.
Each cell shows the median of 10 successful runs. Lower is better.

### Median install time (ms)

| Benchmark | npm | pnpm | bun | LPM | LPM Firewall enabled¹ |
| --- | ---: | ---: | ---: | ---: | ---: |
| First install | 13,787.5 | 4,174 | 1,825 | 1,594.5 | 2,171 |
| Fresh / warm | 3,318.5 | 355 | 191.5 | 66 | 321.5 |
| CI cold | 2,655.5 | 3,455.5 | 1,538 | 1,374.5 | 1,797 |
| CI warm | 2,293 | 329.5 | 186.5 | 102 | 387.5 |
| Installed / cache gone | 667.5 | 10 | 19 | 12 | 12 |
| Up to date | 440.5 | 10 | 19 | 12 | 12 |

### Median peak RSS (MiB)

| Benchmark | npm | pnpm | bun | LPM | LPM Firewall enabled¹ |
| --- | ---: | ---: | ---: | ---: | ---: |
| First install | 863.2 | 624.4 | 393.5 | 355.6 | 383.7 |
| Fresh / warm | 1,448.7 | 123.5 | 49.6 | 90.4 | 96.0 |
| CI cold | 395.3 | 481.9 | 129.7 | 239.0 | 258.3 |
| CI warm | 865.9 | 60.8 | 7.2 | 61.6 | 59.0 |
| Installed / cache gone | 158.7 | 18.5 | 7.9 | 25.3 | 25.5 |
| Up to date | 149.2 | 18.5 | 7.9 | 25.5 | 25.5 |

¹ Firewall enabled means **monitor mode**, measured in a separate run with the same LPM binary and fixture.
The difference between columns is not a controlled measurement of firewall overhead.

### Dev commands — median time (ms)

These benchmarks measure already-installed scripts, local binaries, and tools, with two warmups before the 10 measured runs.
Dependency installation is outside the measured interval.

| Benchmark | npm | pnpm | bun | LPM |
| --- | ---: | ---: | ---: | ---: |
| Package script: `echo hi` | 67.5 | 13.6 | 5.5 | 10.7 |
| Node startup + tiny script | 88.0 | 34.0 | 26.4 | 30.2 |
| Local bin: `esbuild --version` | 133.5 | 22.2 | 8.2 | 11.9 |
| Run TSX app, warm cache | 200.4 | 87.8 | 6.2 | 47.4 |
| Lint 20 JS files (Oxlint) | 162.4 | 50.7 | 37.0 | 16.6 |
| Format check, 20 JS files (Biome) | 158.7 | 46.6 | 33.7 | 15.5 |

<details>
<summary>Benchmark methodology</summary>

**Versions:** LPM 0.78.0, npm 12.1.0, pnpm 12.6.0, Bun 1.4.2, and Node 24.19.0.
LPM used a release build from commit `5cc8869c5a4c03b04788a80c5dc648098df295e3`.

**Install setup:** [`run-t3-install-six-states.mjs`](bench/scripts/run-t3-install-six-states.mjs) uses the T3 manifest from [Bun's install benchmark](https://github.com/oven-sh/bun/tree/9dd73746c7b51b6450bb675ce2abcf86a0ae076f/bench/install).
Each run uses an isolated project, home directory, and dependency cache.
Preparation is outside the measured interval. Manager and state order rotate between rounds.

Lifecycle scripts are disabled. Other security and release-age settings retain product defaults, except the explicit firewall monitor run.
LPM's default release age is zero and its firewall is off. npm retains its default audit behavior.

LPM uses V2 and `--json --no-security-summary --no-skills --no-editor-setup`.
This is not a comparison with identical security settings or dependency graphs.

**Six states:** First install and Fresh / warm have no lockfile or installed tree, with cold and warm dependency caches respectively.
CI cold and CI warm retain a lockfile but have no installed tree.
Installed / cache gone and Up to date retain both, with cold and warm dependency caches respectively.
The CI labels describe the initial state, not a dedicated `ci` command.
Each manager runs its normal install command.

Cold refers to local dependency caches, not operating-system or CDN caches.
LPM retains its backing content store in Installed / cache gone because installed symlinks depend on it.

**Firewall conditions:** All 40 install/reinstall samples completed verdict requests, but the server used individual lookups because its flagged-package index was stale.
The 20 no-op samples reused validated preparation state and did not request new verdicts.
Network and server conditions can differ between the firewall-off and monitor runs.

**Memory:** Peak RSS comes from `/usr/bin/time -l`. It is not the simultaneous memory total of a process tree.
Each table cell is the median of 10 per-run peaks.

**Dev commands:** [`run-dev-command-suite.mjs`](bench/scripts/run-dev-command-suite.mjs) runs commands sequentially and rotates manager order.
Script rows use `run`. Local binaries use `npm exec --no --`, `pnpm exec`, `bun run`, or `lpm exec`.

The TSX fixture imports 10 modules and uses a small local JSX runtime.
LPM and Bun use their built-in TSX entry commands. npm and pnpm launch local `tsx` through `exec`.
The npm TSX result therefore includes npm startup, unlike the previous direct-`tsx` result.

Tool versions are esbuild 0.28.2, tsx 4.23.15, Oxlint 1.79.0, and Biome 2.5.9.
LPM uses managed Oxlint and Biome. The other columns launch those versions as local tools.
Lint checks 20 lint-clean JavaScript files. Format checks use preformatted files and never write changes.
Correctness checks reject unexpected output, failed commands, and source changes.

[Reproduction instructions](bench/scripts/README.md) cover both suites.
More results and measurement details: [full benchmark page](https://cli.lpm.dev/docs/benchmarks).

</details>

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing expectations, and the pull request workflow.

Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md). Do not open a public issue for a security report.

## License

Dual-licensed under MIT OR Apache-2.0.

See `LICENSE-MIT` and `LICENSE-APACHE`.
