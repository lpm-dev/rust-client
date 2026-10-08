# Relay key rotation

LPM CLI verifies the relay certificate chain and hostname before it accepts a key.
For the canonical relay, a signed key list authorizes every connection attempt, including reconnects and connections with a matching saved pin.
Other relay hosts retain per-host trust on first use.

The CLI fetches the list and its signature before each canonical connection attempt.
It verifies the Sigstore signature, transparency evidence, manifest digest, signing workflow, main branch, host, and validity window.
The approved keys come from `security/relay-pins.json`.
The signing identity is `lpm-dev/rust-client/.github/workflows/relay-trust.yml@refs/heads/main`.
Registry credentials never enter these requests.

## Publish an approved key

1. Obtain the new SPKI SHA-256 hash from the relay operator's certificate configuration.
2. Add the hash to `security/relay-pins.json` through a reviewed pull request.
3. Keep all active edge keys in the list during a rotation.
4. Merge the approved change to main.
5. Verify that the `Publish approved relay keys` workflow succeeds.
6. Remove retired keys through another reviewed pull request.

A live TLS probe alone does not prove that the operator authorized a replacement key.
The initial proposed hash matches the CA-valid relay certificate observed during development.
The operator must confirm this hash before merge.

The workflow signs only the reviewed keys. It never discovers or approves keys from the network.
It refreshes the seven-day authorization each day and publishes two assets under the `relay-trust` release.
The prerelease does not replace the latest CLI release.
The CLI retains normal TOFU for library callers without a signed key provider.

## Rollout and failure behavior

Publish the signed assets before distributing the CLI with this change.
Then release the CLI through the normal signed release process.
Existing CLI versions still need an upgrade for automatic rotation.

The CLI makes one bounded authorization fetch before each TLS attempt.
Shutdown cancels a pending authorization request and returns successfully.
An approved live key replaces a retired saved pin without an extra TLS attempt.
It atomically stores an approved replacement with owner-only permissions.
Unknown keys, expired authorization, invalid signatures, and invalid TLS certificates stop the command.
Network failures during authorization stop the command with guidance to retry.
The CLI never deletes a saved pin to recover from an error.

The seven-day window limits replay of authorization lists.
The live key must appear in the verified list, even when it matches a saved pin.
Removing a key blocks new connections once clients receive the updated list.
An earlier signed list can authorize a removed key until that list expires.
Key removal does not close an established tunnel.
A GitHub repository administrator with control of the trusted main-branch workflow can authorize relay keys.
The publication of both assets has a short consistency window. A digest mismatch fails closed during that window.

## Publication health and release checks

Every canonical connection attempt depends on GitHub asset availability and valid authorization.
The CLI fetches two capped assets. Tunnel traffic does not use GitHub.
Monitor the daily workflow result and the published manifest's `expires_at` value.
A disabled or failing workflow blocks new connections after the last list expires.
If publication fails, rerun the main-branch workflow before authorization expires.

Before a CLI release, verify a freshly published pair with the shipping CLI.
Exercise first use, a matching saved pin, and an approved replacement for every active edge key.
Also verify that a removed key fails and shutdown cancels an authorization fetch.
