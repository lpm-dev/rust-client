
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
