# Targeted archive detection ledger

The primary agent owns this concept. No subagents participated.
Labels and detection share one Rust pull request. A linked docs pull request describes the public tags.

| ID | Source | Category | Location | Evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ARC-001 | Pilot label review | Correctness | Archive labels and grouping | Keyword hints included cleanup and browser behavior. Shared utility files could join unrelated payloads. | Verified | Reviewed source hashes, explicit label status, grouping tests | `896ed0c2` | Open concept PR |
| ARC-002 | Archive source review | Security | Credential reads and HTTP bodies | Frozen detector misses the credential-file body in `autbank-core`. | Verified | Credential read, report-object, and request-body regressions | `896ed0c2` | Open concept PR |
| ARC-003 | Archive source review | Security | Decrypted file execution | Frozen detector misses the launcher in `core-js-buffer`. | Verified | Decrypt/write/spawn and interpreter-helper regressions | `896ed0c2` | Open concept PR |
| ARC-004 | Paired source patterns | Security | Downloaded response execution | Frozen detector misses a response passed to a Function constructor. | Verified | Download/evaluate and unrelated-data controls | `896ed0c2` | Open concept PR |
| ARC-005 | Additional source review | Security | Broad filesystem deletion | Two `cache-cleanup-module` versions remove project contents behind remote authorization. | Verified | Helper-chain and scoped-cleanup regressions, original archive scans | `896ed0c2` | Open concept PR |
| ARC-006 | Implementation review | Correctness | Mutation and reachability | Replaced fields, dead uploads, callback reads, unused eval arguments, and non-executable process arguments can create false warnings. | Verified | Failing-before-fix control regressions | `896ed0c2` | Open concept PR |
| ARC-007 | Implementation review | Correctness | Imported method identity | Alias names can hide imported filesystem methods from candidate filters. | Verified | ESM and CommonJS alias regressions | `896ed0c2` | Open concept PR |
| ARC-008 | Exploratory debug scan | Correctness | Parser build profile | OXC debug parsing asserts on a pure comment in `investing` before detector analysis. The unchanged parser call and dependency predate this concept. Release parsing succeeds. | Rejected | Identical parser code and lockfile, isolated debug failure, successful release scan | Not applicable | Recorded limitation |
| ARC-009 | Implementation review | Correctness | Eval value types | JavaScript eval ignores Buffer and ArrayBuffer values. The first candidate reported execution without a string conversion. | Verified | Failing-before-fix eval Buffer control, explicit text and Function-constructor controls | `2c3ea4c5` | Open concept PR |
| ARC-010 | Implementation review | Correctness | Credential path components | Suffix matching treated public.aws/credentials and similar public paths as credential files. | Verified | Failing-before-fix path controls and credential-upload regressions | `0f918d2c` | Open concept PR |

Totals: 10 primary-review findings, 9 verified and fixed, 1 rejected with evidence, 0 externally blocked, 0 pending.
The rejected parser finding concerns an unchanged dependency and parser entry point. It is not a claim that the debug parser is defect-free.

## Detection limits

These findings define supported source patterns. They do not promise detection of every archived package.
The report retains all misses, unsupported stages, parser failures, and scan limits.
An encrypted launcher warning does not identify the effects of its absent or unknown decrypted payload.
The wiper operation requires an explicit API call and remote authorization. Its two versions count as one code family.
