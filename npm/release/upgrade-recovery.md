
### Standalone and Cargo upgrades from 0.75.0 to 0.84.0

`lpm self-update` in 0.75.0 to 0.84.0 expects each stable release to be signed from its version tag. Newer releases are signed from the `main` branch, so standalone and Cargo installations of those versions refuse them with `certificate identity must be ... at refs/tags/v...`. The release is not tampered.

For a standalone installation, rerun the installer once:

```sh
curl -fsSL https://cli.lpm.dev/install | sh
```

For a Cargo installation, install this release once, replacing `<version>` with its version:

```sh
cargo install --git https://github.com/lpm-dev/rust-client --tag v<version> lpm-cli --force --locked
```

Later versions accept both signing identities, so `lpm self-update` works again after this one reinstall. npm, Homebrew, and nightly installations are not affected.

### macOS standalone upgrades without Xcode from 0.76.0 to 0.88.0

`lpm self-update` in 0.76.0 to 0.88.0, and in nightly releases built before this fix, checks the release's notarization ticket with `stapler`, which macOS runs only when Xcode is installed. On a Mac without Xcode, including one with only the Command Line Tools, it stops with `tool 'stapler' requires Xcode` or another `xcrun` or `xcode-select` error. The release is not tampered. Rerun the installer once:

```sh
curl -fsSL https://cli.lpm.dev/install | sh
```

The installer checks the ticket with tools every Mac ships with, and so does `lpm self-update` from this release on. The reinstall installs this release or a later one, so later updates work through `lpm self-update` again.

### macOS standalone upgrades from 0.76.5

The standalone updater in 0.76.5 rejects newer signed app bundles with an icon. If it reports an unexpected `Contents/Resources/` entry, rerun the installer once:

```sh
curl -fsSL https://cli.lpm.dev/install | sh
```

For the latest nightly release:

```sh
curl -fsSL https://cli.lpm.dev/install | LPM_INSTALL_CHANNEL=nightly sh
```

The installer preserves saved credentials and configuration. It checks the release checksum and macOS signing and notarization. If `cosign` is installed, it also verifies the checksum manifest's Sigstore identity. Do not disable verification or delete your credentials. npm and Homebrew installations should continue using their package manager.
