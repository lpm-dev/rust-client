# LPM CLI

Fast, secure, all-in-one package manager written in Rust.

```bash
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli
```

This package is the npm gateway for the native LPM CLI. It installs the
matching platform package, such as
`@lpm-registry/cli-darwin-arm64`, `@lpm-registry/cli-linux-x64`, or
`@lpm-registry/cli-linux-x64-musl`. The `postinstall` script validates the native
program and connects `lpm` and `lpx` directly to it.

On macOS, the platform package contains a signed `LPM CLI.app`. The direct
commands run `LPM CLI.app/Contents/MacOS/lpm-rs`. They do not start Node or a
shell. LPM CLI runs when LPM Vault is not installed or not open.

The package keeps a small JavaScript launcher for installs that disable
scripts. This launcher only finds and starts the native program. It does not
implement package-manager behavior.

## Installer behavior

These tools install the Rust client. They are not `lpm self-update` modes.

| Installer | Default command behavior | Install script option |
| --- | --- | --- |
| npm 11 | Direct native command | No extra option |
| npm 12 | JavaScript launcher | Use `--allow-scripts=@lpm-registry/cli` |
| Yarn | Direct native command | No extra option |
| Bun | JavaScript launcher | Use `--trust` |
| pnpm | JavaScript launcher | Use `--allow-build=@lpm-registry/cli` to validate the native program |
| Volta | Volta shim, then the native command | No extra option |

The JavaScript launcher only starts the Rust program. All LPM functions remain
available. The launcher adds one process start before the Rust program starts.

Use these commands for the native optimization on npm, Bun, or pnpm:

```bash
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli
bun add -g @lpm-registry/cli --trust
pnpm add -g @lpm-registry/cli --allow-build=@lpm-registry/cli
```

On macOS, pnpm keeps its launcher after it validates the signed app. This
preserves the links that pnpm manages.

Source for this npm package lives in `lpm-dev/rust-client/npm/cli`.

## Updating

```bash
lpm self-update
```

`lpm self-update` detects npm, pnpm, Bun, Yarn, and Volta installations. It
runs the update command for the detected installer.

For an npm installation, self-update runs:

```bash
npm install -g @lpm-registry/cli@<version>
```

On macOS, this install keeps the complete signed app bundle. If npm permits the
installer script, the script restores the direct command links.

If the detected installer blocks scripts, the update still completes. The
JavaScript launcher remains active until you use the applicable trust option.

## Troubleshooting

If your package manager was configured to omit optional dependencies, reinstall
with optional dependencies enabled:

```bash
npm install -g @lpm-registry/cli
```

If your npm policy blocks install scripts, LPM uses the JavaScript fallback.
Allow the installer script to validate the native program and create direct
commands:

```bash
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli
```

Do not run this install with `sudo`. Configure a user-writable npm global
prefix, or use the Homebrew or standalone installer. Run all LPM CLI user
commands without `sudo`.

Other install methods are documented at
[github.com/lpm-dev/rust-client](https://github.com/lpm-dev/rust-client).
