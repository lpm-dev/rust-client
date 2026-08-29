# Signed macOS builds and distribution

## Shared Keychain contract

LPM Vault records use the Data Protection Keychain access group
`823S8YKMRW.dev.lpm.vault.shared`. Only binaries signed by the matching Apple
team and carrying that entitlement can read the records. The CLI creates and
normalizes shared records as `WhenUnlockedThisDeviceOnly`, matching Vault's
non-migratable storage contract.

The macOS CLI release uses a hidden `LPM CLI.app` bundle. The bundle identifier
is `dev.lpm.cli`. The app contains the provisioning profile that authorizes the
shared access group.

This design does not sandbox the CLI. LPM can still read project directories,
start developer tools, and run without LPM Vault. The bundle gives the CLI a
stable Apple code identity for Keychain access.

## Development builds

An unsigned or ad-hoc `cargo run` build cannot access the production vault.
The shared access group is a restricted entitlement, so the CLI is wrapped in
an app-like bundle with a Developer ID provisioning profile. Set the profile
path, then build and sign the local CLI:

```bash
export LPM_CLI_PROVISIONING_PROFILE=/path/to/dev.lpm.cli.provisionprofile
./scripts/build-signed-macos.sh
./target/debug/LPM\ CLI.app/Contents/MacOS/lpm-rs env list
```

To build an optimized binary or execute it immediately:

```bash
./scripts/build-signed-macos.sh --release
./scripts/build-signed-macos.sh -- env list
```

To exercise an installed cross-compilation target locally, pass its Rust
target triple. For example, Apple Silicon can build an Intel bundle for a
Rosetta proof without changing the release workflow:

```bash
./scripts/build-signed-macos.sh --release --target x86_64-apple-darwin
```

Release builds use Apple's trusted timestamp service so the resulting bundle
can be notarized. Debug builds use a deterministic local signature without a
network timestamp.

The helper defaults to the same Developer ID identity used by the release
workflow. The profile must authorize application identifier
`823S8YKMRW.dev.lpm.cli` and the Team-scoped Keychain wildcard
`823S8YKMRW.*`. The signed app entitlement remains restricted to
`823S8YKMRW.dev.lpm.vault.shared`. Set `LPM_SIGNING_IDENTITY` only when another
identity from Apple team `823S8YKMRW` is configured with that profile.

Contributors without that signing identity can use the debug-only file backend
with `LPM_FORCE_FILE_VAULT=1`. It is isolated from the production Keychain.

## Release layout

The release workflow creates this bundle:

```text
LPM CLI.app/
  Contents/
    Info.plist
    CodeResources
    embedded.provisionprofile
    MacOS/lpm-rs
    Resources/LPMCLI.icns
    _CodeSignature/CodeResources
```

The npm, Homebrew, and standalone installers preserve the complete bundle.
They connect `lpm` and `lpx` directly to `Contents/MacOS/lpm-rs`. Normal CLI
commands do not start Node or a shell.

The bundle is a packaging and identity boundary. It is not a dependency on LPM
Vault. Users can remove Vault and continue to use every independent CLI
feature.

Every stable macOS release retains a signed raw compatibility executable while
the 0.75.0 standalone updater remains supported. That updater can install the
raw asset from the latest release. The next normal command installs the signed
app bundle at the same version. The bridge then restarts the original command
from the app bundle. This migration does not require a second
`lpm self-update` command. The raw bridge can be retired only when the 0.75.0
baseline is no longer supported.

The release stays as a GitHub draft until the exact staged artifacts pass the
standalone installer smoke tests. The workflow publishes it, and marks a
stable release as latest, only after those gates succeed.

## Release verification

Before a public release, verify these requirements for both macOS
architectures:

1. Build the bundle with the `dev.lpm.cli` provisioning profile.
2. Verify the Developer ID signature and Team ID.
3. Verify the bundle identifier and shared access group.
4. Verify the embedded profile permissions.
5. Notarize the bundle and staple its ticket.
6. Install the exact npm tarball and standalone ZIP.
7. Install the Homebrew formula with the same ZIP.
8. Run `lpm` and `lpx` through their final direct links.
9. Verify Vault-write to CLI-read and CLI-write to Vault-read access.
10. Verify upgrades, self-update, reinstall, and removal.

Do not publish a bundle that fails one of these requirements.
