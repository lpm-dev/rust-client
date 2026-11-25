# Sigstore conformance cases

Each directory is a case copied unchanged from the Sigstore client
conformance suite, `test/assets/bundle-verify/` in
[sigstore/sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
at commit `e275ffb5aab734681fe82b919cc4a9a1dd27fa2c`. The suite is licensed
under the Apache License 2.0.

A case holds the bundle (`bundle.sigstore.json`), the trust root it verifies
against (`trusted_root.json`), and the suite's description of what it tests
(`README`). A name ending in `_fail` is a bundle every client must refuse.

Most cases were signed against Sigstore's staging services, so their trust
roots are staging trust roots. To refresh a case, copy its directory from a
newer suite commit and update the commit above.
