# Archive-pilot findings

This is an evaluation-only study. Detector changes require a separate implementation decision.

## Measured detector and study observations

| ID | Observation | Evidence | Disposition |
| --- | --- | --- | --- |
| AP-01 | Credential-file reads are not followed through the reviewed HTTP upload paths | Five reviewed credential-file cases; all parse without limits and produce no Critical warning | Measured and reported |
| AP-02 | A conditional decrypt-to-file-to-process chain remains capability evidence | `core-js-buffer`, `mutex-core`, `matrixflow-js`; no Critical warning | Measured and reported |
| AP-03 | A generic warning can fire without identifying the attack chain | `helmet-pro` receives Critical obfuscation but no response-to-execution finding | Measured and reported |
| AP-04 | Packaged non-source stages and absent remote stages limit conclusions | Encoded `.map` stage, external Python/tarball stages, 37 zero-source archives, 27 parser failures, six limited scans | Measured and reported |
| AP-05 | Archive labels and keyword hints do not establish the selected attack family | 50 of 60 destruction candidates carry an agent-control label; two source reviews contradict parts of their archived rationale | Measured and reported |
| AP-06 | Duplicate payloads inflate package-level success counts | All three credential-exfiltration warnings share one code-linked component and the same evidence location | Measured and reported |

The current `behavioral/threats.rs::is_candidate` recognizes `fetch` and repository-content upload sinks.
Its selected sources are private-key values and the process environment, not arbitrary credential-file reads.
Node HTTP request writes, file archives, multipart uploads, and encryption transformations extend beyond that supported flow.
The three reported credential-exfiltration alerts describe complete environment uploads, not newly detected credential-file theft.

`behavioral/source.rs` records cryptography, filesystem, network, and process capabilities.
It does not connect a hash predicate, decrypted bytes, a written path, and a spawned interpreter into the reviewed threat relationship.
The readable mutex launcher is available even though two other selected files fail parsing.
No inference about the unknown decrypted payload is required to describe that loader relationship.

`behavioral/mod.rs` selects supported JS/TS files and excludes maps and other languages before parsing.
Its coverage metadata must be interpreted within that selection.
The existing `protestware` rule is not a general classifier for every deletion operation.
The pilot supplies insufficient confirmed destructive-family evidence to justify broadening it.

All six observations are reported. None represents an implemented detector fix or a population recall estimate.
No evaluation item remains pending.
Full label adjudication and independent reserved-set validation are subsequent experiments, not claims made by this pilot.

## Harness review ledger

These findings affect the new study harness. They were resolved before publication.

| ID | Source | Category | Location | Claim and evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AH-01 | Primary review | Security | `archive_pilot.py::extract_zip` | Package-root discovery read manifest candidates before applying an overall expanded-byte bound. A failing fixture places extra bytes outside the selected root. | Verified | `test_zip_bounds_all_members_before_reading_manifest_candidates` | `40765ad1` | Included in concept PR |
| AH-02 | Primary review | Correctness | `archive_pilot.py::prepare` | Local archive acquisition did not enforce the protocol's compressed-byte limit. A failing oversized-record test demonstrates the missing check. | Verified | `test_local_archives_obey_the_compressed_byte_limit` | `40765ad1` | Included in concept PR |
| AH-03 | Primary review | Correctness | `archive_pilot.py::sanitize` | Domain redaction omitted nested oversized-source metadata. A failing nested-field test demonstrates the omission. | Verified | `test_public_results_remove_domains_inside_oversized_source_metadata` | `40765ad1` | Included in concept PR |

Totals: three findings received, three verified and fixed, zero rejected, zero externally blocked, zero pending.
No subagents were used.
Additional preventive checks reject invalid archive hashes and duplicate selected identities before result files are written.
The original freeze remains intact. The final check record separately pins the corrected harness.
All selected archives satisfy the added bounds; the reviewed-case repeat confirms unchanged scanner analyses.
