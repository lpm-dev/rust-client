# Credentialed npm route evaluation

An `.npmrc` credential for registry.npmjs.org routed every public npm package through the custom-registry path. This report measures first installs with such a credential before and after this change, alongside an anonymous install of the change.

## Method

The T3 fixture was installed from an empty cache and store, 24 balanced samples per variant after two unscored gates, with four timing diagnostics each. Times are nearest-rank median and p95 wall milliseconds.

| Variant | Binary | `.npmrc` |
|---|---|---|
| `token-888` | #888 head (`30b48150…`) | `//registry.npmjs.org/:_authToken=lpm-bench-token` |
| `token-889` | this change (`2add2ccb…`) | same credential |
| `anon-889` | this change | no credential |

Requests replay a frozen capture of registry.npmjs.org through the benchmark's HTTPS proxy, paced at 100 Mbit/s with 40 ms response latency ("shaped") or 1 Gbit/s with 30 ms ("fast"). The capture holds all 454 responses the three variants request. It was recorded through the unpaced proxy, and every tarball was verified against its integrity. The credential is fake: the proxy accepts exactly that bearer token, keys and captures requests without it, rejects every other credential, and records which requests carried it.

Each variant's `.npmrc` is selected through `NPM_CONFIG_USERCONFIG`. The shaped and fast runners wait for the pacer to drain before a phase change, so responses to abandoned requests finish outside the next sample.

## Results

| Profile | `token-888` | `token-889` | Paired | `anon-889` |
|---|---:|---:|---:|---:|
| Shaped, 100 Mbit/s, 40 ms | 13,518.6 / 13,548.4 | 11,867.2 / 11,923.3 | −1,647.0 (24/24) | 11,867.4 / 12,078.0 |
| Fast, 1 Gbit/s, 30 ms | 3,831.9 / 3,921.9 | 3,158.5 / 3,284.6 | −659.4 (24/24) | 3,153.4 / 3,281.6 |

With the credential, the change is as fast as the anonymous install. All three variants installed identical package selections and object contents in every sample.

Per install, from the proxy's request log:

| Variant | Requests carrying the token | Metadata requests | `/latest` documents | Abbreviated packuments | Metadata wire bytes | Tarball wire bytes |
|---|---:|---:|---:|---:|---:|---:|
| `token-888` | 315 of 315 | 220 | 0 | 174 | 36.7 MB | 123.5 MB |
| `token-889` | 359 of 359 | 264 | 69 | 69 | 21.8 MB | 123.5 MB |
| `anon-889` | 0 of 359 | 264 | 69 | 69 | 21.8 MB | 123.5 MB |

Before the change, the credentialed install fetched abbreviated packuments where the direct paths use latest documents and selected history. It therefore transferred 41% more metadata, and it skipped speculative downloads and the fetch overlap with resolution. After the change the credentialed install sends the same requests as the anonymous one, with the token on every request.

## Registry behavior

Separately, live requests to registry.npmjs.org with and without a bearer token returned the same public packument bodies and latest documents. Both were `cf-cache-status: HIT` with `cache-control: public, max-age=300`, and their times overlapped. The credential does not bypass the CDN.

## Limitations

This covers first installs of one fixture. The replay proxy models pacing and response latency, not TCP behavior or the live CDN. Metadata requests were already cached in warm states, so the change matters mainly for cold resolution and downloads.

## Artifacts

The adjacent `-summary.json` holds every number in this report. The `-tools.tar.gz` archive contains the harness copies and their changes: the fake-token acceptance in the proxy, the per-variant `.npmrc`, and the idle wait before phase changes. It also has the driver, the summarizer, the scored rows and the per-profile summaries. Generated TLS material is not included. Absolute paths identify this run.
