
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
