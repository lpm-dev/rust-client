# LPM CLI

Fast, secure, all-in-one package manager written in Rust.

```bash
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli
```

This package is the npm gateway for the native LPM CLI. It installs a small
JavaScript launcher plus the matching platform package, such as
`@lpm-registry/cli-darwin-arm64`, `@lpm-registry/cli-linux-x64`, or
`@lpm-registry/cli-linux-x64-musl`. A tiny
`postinstall` verifier checks the native binary and wires the global command to
it where the platform allows that.

The JavaScript launcher does not implement package-manager behavior. All CLI
commands run in the native Rust binary.

Source for this npm package lives in `lpm-dev/rust-client/npm/cli`.

## Updating

```bash
lpm self-update
```

When LPM was installed through npm, self-update runs:

```bash
npm install -g @lpm-registry/cli@<version>
```

## Troubleshooting

If your package manager was configured to omit optional dependencies, reinstall
with optional dependencies enabled:

```bash
npm install -g @lpm-registry/cli
```

If your npm policy blocks install scripts, allow LPM's installer script so npm
can validate the native binary during installation:

```bash
npm install -g @lpm-registry/cli --allow-scripts=@lpm-registry/cli
```

Other install methods are documented at
[github.com/lpm-dev/rust-client](https://github.com/lpm-dev/rust-client).
