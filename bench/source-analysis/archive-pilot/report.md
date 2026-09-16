# Frozen-detector archive pilot

## Result

The pilot confirms gaps in credential-file theft detection and conditional encrypted-payload execution.
It also shows why archive labels cannot serve directly as malware ground truth.
The detector, severity rules, policies, and scan limits remain unchanged.

Of 400 selected archives, 399 passed acquisition and produced scanner output.
Seventeen produced a Critical source warning. All 28 legitimate functional controls produced zero Critical source warnings.
These counts **do not estimate malware recall or the population false-positive rate**.

Thirteen cases received additional source review.
Nine contain source-supported attack chains. Eight of those nine receive no Critical warning.
The ninth, `helmet-pro`, receives an obfuscation warning rather than a download-to-execution finding.
The remaining reviews cover a conditional loader, an external-stage loader, and two ambiguous destruction labels.
These purposive reviews are not an independently sampled recall denominator.
The other 387 candidates retain their unreviewed archive labels, including the acquisition failure.

The [summary](summary.json), [per-case results](results.jsonl), and [source reviews](source-reviews.json) preserve these distinctions.
Payloads, excerpts, archive credentials, and private storage locations remain outside tracked files.

## Inventory and selection

The snapshot contains 33,787 source records: 25,766 Datadog, 2,027 OpenSSF, and 5,994 LPM records.
Six LPM records arrived after the earlier inventory count of 5,988.
Deduplication leaves 33,252 archive hashes and 33,247 package-version identities.
Different archive bytes for the same package version remain separate variants.
Every record retains its provenance, source labels, available advisory references, and confidence type.
An AI confidence score is retained as a model score, not as verified label confidence.

The pilot selects one archive per metadata group.
The four focus strata use archived review text to find candidates. They do not establish the behavior or its intent.
Another 60 candidates come from OpenSSF and 100 from Datadog.
Source overlap remains in the provenance: these strata are disjoint selection buckets, not disjoint archive providers.

| Selection stratum | Selected | Scanned | Critical warning | No selected JS/TS |
| --- | ---: | ---: | ---: | ---: |
| Credential-file hints | 60 | 60 | 0 | 1 |
| Install/downloader hints | 60 | 60 | 5 | 2 |
| Encryption/activation hints | 60 | 60 | 3 | 13 |
| Destruction hints | 60 | 60 | 3 | 1 |
| Additional OpenSSF | 60 | 60 | 0 | 3 |
| Additional Datadog | 100 | 99 | 6 | 17 |
| **Total** | **400** | **399** | **17** | **37** |

The [selection](selection.json), [inventory summary](inventory-summary.json), and [protocol](protocol.json) were committed before detector output was examined.
Commit `d0436b54` records this freeze.
Candidate selection excludes previously scanned package names and recognized package families through their connected metadata groups.
It is purposive and source-biased, not a random npm sample.

### Reserved validation candidates

The inventory reserves 6,906 archives without opening or scanning them in this pilot.
Grouping joins package names/scopes, shared advisory identifiers, and available cited source hashes.
Prior-corpus groups remain excluded from the reserve.

This is a **provisional reserve**, not a completed independent validation set.
Most remote archives lack code fingerprints in their metadata.
Before validation, source similarity and campaign evidence must connect related payloads across the reserve, pilot, and prior studies.
Any reserved group linked to examined material must be quarantined from independent validation.
No result in this report claims independent validation on the reserved set.

Within the pilot, matching normalized source files reduce 400 metadata groups to 363 conservative code-linked components.
Normalization ignores comments and literal values. Shared libraries can combine unrelated attacks, so these components are not attributed campaigns.
The 17 Critical warnings occur in 11 such components.
All three credential-exfiltration findings share one component and the same environment-upload evidence location.
Counting them as three independent successes would overstate detection diversity.

## Reviewed attack chains

| Family | Reviewed examples | Frozen result | Interpretation |
| --- | --- | --- | --- |
| Credential-file theft | `price-scripping-js`, `wallet-watcher`, `debugcli`, `test__123q1`, `autbank-core` | Zero Critical findings | File contents or extracted secrets reach HTTP uploads, encrypted uploads, or report archives |
| Install-time remote execution | `core-js-buffer` | Zero Critical findings | A developer-environment check gates download, decryption, file creation, and Python execution |
| Install-time response execution | `helmet-pro` | Critical obfuscation | A detached helper fetches response data and passes it into a function constructor |
| Encrypted selective execution | `mutex-core`, `matrixflow-js` | Zero Critical findings | Caller data must match a hash before bundled bytes are decrypted and launched |

The [source reviews](source-reviews.json) pin each package version, archive hash, and relevant file hash.
They also record activation conditions and limits.
For example, `autbank-core` reads `.env` relative to the lifecycle working directory, which is not automatically the consumer root.
The encrypted launchers have unknown activation keys and unknown decrypted effects.
Their source confirms the launcher chain, not a successful runtime compromise.

Two additional loader reviews require separate treatment:

- `greensaver` stores a fetch/decrypt/eval stage in base64 `.map` files, outside the scanner's source selection.
  Static base64 decoding confirms the stage. Its hard-coded relative paths can prevent activation from the normal lifecycle working directory.
- `kelly-sizing` retrieves a tarball, installs its dependencies, and loads its module during postinstall.
  The external stage is absent. This proves remote loading but does not independently establish that stage's malicious effects.

No package scripts, payloads, or native binaries were executed.
No embedded payload destination was contacted. Cloud retrieval used only read-only archive GET requests.

## Label quality and destructive behavior

Fifty of the 60 destruction-hint candidates carry the LPM label `ai_agent_control_hijack`.
Only three carry `destructive_action`; one of those concerns browser document replacement.
The hint search also matches negated phrases and cleanup descriptions.
This is a screening limitation, not evidence that these 60 packages perform malicious filesystem destruction.

Two detailed reviews demonstrate the distinction:

- `@1interface/shared-core` removes relative `node_modules/react` directories in postinstall.
  The archived review assumes these paths always target consumer-root dependencies.
  Standard lifecycle working-directory behavior does not support that assumption.
- `@vpxa/aikit` removes an entire MCP configuration file when it contains an AI Kit entry.
  The guard exists, contrary to the archived description of unconditional deletion.
  Deleting the whole file can lose unrelated settings, but this does not establish a malicious destruction campaign.

These cases remain ambiguous. They are neither confirmed malware misses nor certifications that the packages are safe.
The pilot establishes **no new source-reviewed filesystem-wiper family**.
Destructive-family detection strength therefore remains unmeasured by this pilot.
The earlier destructive incident tests remain regression evidence, not new validation.

For 246 selected cases, archived LPM reviews are available.
Of these, 109 include source citations. All 438 cited source hashes match the acquired files.
Hash correspondence supports provenance; it does not validate the review's reasoning or intent classification.
The [label audit](label-audit.json) records these checks.

## Comparable legitimate controls

The 16 prior controls cover registry credentials, browser installers, native-build downloaders, and neighboring uncompromised releases.
Twelve additional controls cover the two added focus areas:

| Behavior | Additional controls |
| --- | --- |
| Cryptographic data processing | `crypto-js`, `sjcl`, `tweetnacl`, `libsodium-wrappers` |
| Environment-selected configuration decryption | `dotenv-vault`, `@dotenvx/dotenvx` |
| Explicit deletion and filesystem operations | `rimraf`, `del`, `fs-extra`, `trash`, `clean-webpack-plugin`, `shx` |

All 28 pinned controls produce zero Critical source warnings, with no parser or budget failures.
The [control review](control-review.json) records the legitimate function and relevant source hashes.
Some controls delegate work to dependencies that this package-level scan does not inspect.
These are functional contrasts, not complete dependency audits or proof of vulnerability-free packages.
They also reuse known ecosystem families, so this is not a fresh benign-family validation set.

## Coverage and cost

The scanner processes 16,275 selected source files containing 367,083,728 bytes.
There are 27 parser failures across 14 packages, and six packages reach an existing scan limit.
Thirty-seven packages contain no selected JS/TS source.
Unsupported languages, excluded paths, bundled native code, and absent remote stages remain separate coverage limits.
`inputIncomplete: false` describes read completeness for the scanner's selection; it does not establish complete installation-chain coverage.

The Datadog archive for `n8n-nodes-zalo-fevox@0.6.6` contains two matching package roots.
The harness rejects this ambiguity. It neither chooses a root silently nor replaces the selected case.
All 100 remote archive downloads passed their recorded size and SHA-256 checks.
The [coverage inventory](coverage.json) records per-case exclusions, parser results, limits, and unsupported scripts.

| Measurement | Observed value |
| --- | ---: |
| Total scanner-internal time | 5.576 s |
| Median per-package scan | 4.506 ms |
| 95th-percentile per-package scan | 62.037 ms |
| Maximum per-package scan | 349.222 ms |
| Highest scanner-process peak RSS | 308.75 MiB |
| Acquisition, extraction, process startup, and scan | 70.55 s |
| Separate archive inspection and fingerprinting | 110.07 s |

Measurements come from one Mac run and include no before/after comparison.
Remote retrieval time is excluded from the acquisition-and-scan total.
Each package uses a fresh scanner process with four Rayon threads and a 120-second deadline.
The RSS measurement covers the scanner process, not archive retrieval or Python fingerprinting.
Sequential temporary extraction bounds disk use. About 2 GiB of inactive Cargo artifacts were reclaimed before the pilot.

## Recommended next step

1. Build a reviewed reference set from the confirmed credential-file and gated-loader chains, with the matched controls retained.
2. Improve archive labels and campaign grouping before increasing the sample count.
   Use positive behavior evidence, lifecycle reachability, working-directory semantics, and absent-stage tracking instead of review-text keywords alone.
3. Acquire independently documented filesystem-wiper cases before drawing conclusions about that family.
4. After approval, implement bounded credential-file data flow and conditional decrypt-to-execution detection with benign-control regressions.
5. Complete cross-corpus code grouping before evaluating a frozen candidate against the untouched reserve.

The [findings](findings.md) separate reported detector gaps from completed harness corrections.
No detector fixes are included in this evaluation.

## Reproduction and checks

The [freeze record](freeze.json) pins detector commit `12d0ba41331e6e29367ac49ac258626a85762cbd` and the preserved scanner hash.
All 43 harness tests pass, including archive bounds, provenance grouping, read-only retrieval, and recursive publication redaction.
Thirteen reviewed cases were scanned again after harness hardening; their normalized analyses match the original results.
All 400 selected archives satisfy the strengthened acquisition bounds.
The [check record](checks.json) records the final harness hashes and the scope of verification.

Use new private output directories and the pinned scanner:

```sh
python3 bench/source-analysis/test_corpus.py

python3 bench/source-analysis/archive_pilot.py inspect \
  --selection /private/path/selected.json \
  --downloads /private/path/verified-archives \
  --output /private/path/inspection

python3 bench/source-analysis/archive_pilot.py scan \
  --selection /private/path/selected.json \
  --downloads /private/path/verified-archives \
  --binary /private/path/frozen-source-corpus \
  --output /private/path/scans

python3 bench/source-analysis/corpus.py download \
  --manifest bench/source-analysis/archive-pilot/controls.json \
  --cache /private/path/controls
```

The private selection adds local or R2 locations to the published hash-pinned selection.
`archive_inventory.py --help` documents snapshot generation from the supplied archive layouts.
`archive_fetch.mjs` accepts the private selection, destination, env-file path, and an SDK installation root.
It needs Node 22 or later and `@aws-sdk/client-s3`, and issues only `GetObjectCommand` requests.
It never prints credentials or private storage URLs.
The existing security control-plane SDK installation supplied that dependency for this run.

Rust source is unchanged. The study uses the preserved binary and does not rebuild the Rust workspace.
