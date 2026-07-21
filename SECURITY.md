# Security Policy

LPM treats packages, registry responses, downloaded artifacts, and project files such as lockfiles as untrusted input. The local user controls the LPM process, its configuration, environment, arguments, and writable filesystem; those are not isolation boundaries by themselves.

## Supported versions

Security fixes are made for the latest published LPM release. Earlier releases are unsupported unless a release announcement explicitly says otherwise. Please reproduce a suspected vulnerability on the latest release when practical, but do not delay a private report if you cannot.

## Reporting a vulnerability

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/lpm-dev/rust-client/security/advisories/new). Do not open a public issue or discussion.

Include the affected version and platform, the violated security boundary, reproduction steps or a minimal proof of concept, potential impact, and any known mitigations. Remove unrelated credentials and personal or private project data. If the report concerns credential exposure, do not include a live credential.

Please allow time for triage and coordinated remediation before publishing details. LPM does not currently operate a paid bug-bounty program.

## In scope

- Escaping an LPM sandbox or bypassing lifecycle-script approval or execution policy.
- Archive extraction traversal, unsafe link handling, or writes outside the intended extraction or installation root.
- Installing or executing bytes that do not match lockfile integrity, release manifests, or other enforced integrity metadata.
- Credential or token disclosure through logs, URLs, process arguments, files, or unintended registry requests.
- Authentication or registry-routing flaws that grant unintended access or send credentials to the wrong origin.
- Bypassing provenance, Sigstore, checksum, or release-identity verification.
- Causing package code to execute before approval or outside the permissions promised by the selected sandbox mode.
- Remotely triggerable denial of service with materially asymmetric attacker cost.

## Out of scope

- Actions available to a user who already controls LPM's arguments, environment, configuration, and writable files, unless they cross another documented security boundary.
- Behavior of package code after the user explicitly approves it, when it remains within the permissions promised by the selected sandbox mode.
- Resource exhaustion that requires a local user to supply pathological input and consumes resources roughly proportional to that input.
- Social engineering or compromise of systems and services outside LPM-controlled surfaces.
- Vulnerabilities that affect only unsupported LPM versions and cannot be reproduced on the latest release.

When scope is unclear, report privately and explain the boundary you believe is affected.
