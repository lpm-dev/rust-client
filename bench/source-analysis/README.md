# Source analysis corpus

This harness scans 1,000 frozen npm package versions without executing package code.
It uses the same directory scanner as `lpm audit` and opted-in install analysis.

## Audit output

Source capabilities describe API use. They do not establish execution or malicious intent.
Normal audit and install output lists these capabilities separately from security findings.
Explicit capability policies retain their existing severity levels.
Install output retains its existing verbosity filter for informational capabilities.

- `lpm audit` performs source analysis even when install analysis is disabled.
- `install-time-source-analysis = true` enables source analysis during installation.
- `install-time-source-analysis = false` disables source analysis during installation. This is the default.
- `lpm query ':eval,:child-process,:shell,:dynamic-require'` selects packages by capability.
- `lpm audit --fail-on=behavior` retains the explicit high/critical behavior policy, including capabilities.
- `lpm audit --fail-on=all` also includes capabilities in its explicit policy.

**JSON migration:** Source capabilities now appear in `packages[].capabilities`, with a new `total_capabilities` count.
They no longer contribute to `issues`, `total_issues`, `packages_with_issues`, or security severity counts.
Each capability has `rule_id`, `name`, `policy_severity`, `source`, and `evidence` fields.
Consumers that enforce API restrictions must use `capabilities` or the explicit policies.

Evidence includes a package-relative path, reason, and apparent file context.
Precise matches include a one-based line, byte column, and bounded excerpt with comments masked.
At most three examples per rule survive aggregation, in deterministic path order.
Whole-file heuristics omit precise positions. Oversized samples also omit positions and set `sampled` to `true`.
A heuristic score is not a probability of maliciousness.
Registry-only evidence can be empty. Local evidence survives a matching registry result.

## Reproduce a scan

Use Python 3.10 or newer and the repository's pinned Rust toolchain.
The archive harness needs no third-party Python packages.

1. Run the harness tests.

   ```sh
   python3 bench/source-analysis/test_corpus.py
   ```

2. Download and verify the frozen package archives.

   ```sh
   python3 bench/source-analysis/corpus.py download \
     --manifest bench/source-analysis/top-1000.json \
     --cache /tmp/lpm-source-corpus
   ```

3. Build the scanner example in an isolated target directory. Make sure that at least 10 GiB is free first.

   ```sh
   df -h /tmp
   CARGO_TARGET_DIR=/tmp/lpm-source-target \
     cargo +1.94.0 build --release --locked -p lpm-security --example source_corpus
   cp /tmp/lpm-source-target/release/examples/source_corpus /tmp/source-corpus-candidate
   ```

4. Run the tuning split.

   ```sh
   python3 bench/source-analysis/run.py \
     --acquired /tmp/lpm-source-corpus/acquired.json \
     --binary /tmp/source-corpus-candidate \
     --split tuning --output /tmp/source-tuning.jsonl
   ```

5. Freeze the candidate before the first validation run. Use `--split validation` and a new output path.

6. Compare matching baseline and candidate results.

   ```sh
   python3 bench/source-analysis/compare.py \
     --baseline /tmp/source-baseline.jsonl \
     --candidate /tmp/source-candidate.jsonl \
     --output /tmp/source-comparison.jsonl
   ```

The runner records binary and manifest hashes, thread count, elapsed time, and exit status.
It verifies output identities and refuses to replace existing results.
On macOS, the `.stderr` file includes peak resident memory from `/usr/bin/time -l`.
For performance comparisons, warm both binaries first. Alternate execution order with identical inputs and thread counts.

## Corpus selection

`top-1000.json` records exact versions, archive URLs, integrity digests, and resolution timestamps.
The ranking is the June 8, 2026 snapshot from
[`wooorm/npm-high-impact`](https://github.com/wooorm/npm-high-impact/blob/6ca165357f4cf1e127f38065455fc1c7680f8b16/lib/top-download.js).
It is a historical download ranking, not a current download count.
Versions were resolved from npm's `latest` metadata on September 15, 2026.

A deterministic name-family hash assigns 769 packages to tuning and 231 to validation.
Scopes and selected related names stay together. Embedded third-party code can still cross the split.
Popularity is not a benign label. This corpus cannot establish a malicious-package detection rate.

For a future snapshot, use `corpus.py freeze` with a new manifest path and a fresh metadata cache.
Never replace a manifest used in a published comparison.

## Interpretation and limits

The parser distinguishes local names from process APIs and module loaders.
It follows imports, aliases, conditional expressions, `promisify`, `createRequire`, and bounded assignment propagation.
Shell evidence comes from `exec`, `execSync`, supported shell helpers, or explicit shell options.
A process import alone does not establish shell use.

This is bounded static analysis. It does not execute branches or fully follow values between functions and modules.
Runtime options, deep aliases, generated code, and custom wrappers can hide capabilities.
Unparsed source retains conservative pattern matching and reports incomplete syntax coverage.
The scanner samples oversized files and reports byte or file limits as partial coverage.
Existing directory and declaration-file exclusions remain in effect.

The [source controls](../../crates/lpm-security/tests/fixtures/source-capabilities.json) contain benign syntax and synthetic threat patterns.
The normal security tests run these controls, including obfuscation and locale-dependent termination.
These controls test specific patterns. They do not measure detection of arbitrary malicious packages.

See [the results report](report.md) for the baseline comparison, review limits, and measurements.
