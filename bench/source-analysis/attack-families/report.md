# Credential-file theft and install-time downloader evaluation

## Result

The frozen detector produces no Critical source warning for either selected incident.
It reports relevant capabilities, but it does not identify the malicious relationship between those capabilities.
All 16 legitimate controls also produce zero Critical source warnings.

This pass evaluates and reports. It makes no detector, severity, policy, cache, or scan-limit changes.

| Historical input | Scanner result | Missing behavior |
| --- | --- | --- |
| Reconstructed `eslint-scope@3.7.2` package with recovered first stage | Network and `eval` capabilities; informational high entropy | Downloaded response flows into execution |
| Recovered ESLint second stage, scanned separately | Filesystem, network, and environment capabilities | Home `.npmrc` contents flow into unrelated HTTP request headers |
| Reconstructed `ua-parser-js@0.7.29` package | Child-process and shell capabilities; informational minification and URLs | Install hook launches platform scripts that download and run native payloads |

These are three stage inputs from two incidents, not three independent attacks.
Neither original malicious npm archive was available. The first and third rows use documented reconstructions, not authenticated full archives.
The ESLint second stage was fetched at runtime and was absent from its published package.
Its standalone scan cannot establish what a package-only scan could detect during installation.

The result establishes gaps on the available evidence. It does not estimate malware recall or a population false-positive rate.
The [summary](summary.json), [historical results](historical-results.jsonl), and [control results](control-results.jsonl) preserve the measurements.
Published results omit source excerpts. The payloads remain outside tracked files.

## What the result means for users

This study measures local source analysis. Registry advisories can identify a compromised version even when source analysis misses its behavior.
The study does not measure those advisories, sandbox enforcement, or dependency-script approval.

Default audit policy does not fail solely because a package has `eval` or shell capabilities.
Explicit capability policies can reject such operations, including their legitimate uses.
These controls show why promoting every capability to a Critical security warning would recreate false positives.

Zero Critical warnings on the controls is useful regression evidence, but it is insufficient when the malicious inputs also receive none.
All 16 control package names and families appeared in the earlier corpus. One exact version also appeared there.
This study is not the proposed evaluation on previously unseen package families.

## Historical evidence and reconstruction

### ESLint incident

The [GitHub advisory](https://github.com/advisories/GHSA-hxxf-q3w9-4xgw) identifies the compromised `eslint-scope@3.7.2` release.
The [ESLint postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/) documents the malicious publication.
A [contemporary maintainer Gist](https://gist.github.com/hzoo/51cb84afdc50b14bffa6c6dc49826b3e/8e4e7bcc93e644ff1b885c9fab32c31979c2c859) preserves the downloader, recovered second stage, and lifecycle-script change.

The first reconstruction starts from the verified `eslint-scope@3.7.1` archive.
It adds the recovered `lib/build.js`, the documented `postinstall` entry, and the affected version number.
Other differences in the unavailable original archive remain unknown.

The second-stage input contains the recovered `pastebin.js` and generated private package metadata for the scanner.
It remains separate from the package reconstruction. Combining both stages would invent package contents that were not shipped together.
The Gist files retain their retrieved bytes and immutable revision hashes.

### UAParser incident

The [GitHub advisory](https://github.com/advisories/GHSA-pjwm-rvh2-c87w) identifies the compromised releases.
The [maintainer issue](https://github.com/faisalman/ua-parser-js/issues/536) links the incident discussion and version comparison.
An [archived Diffend comparison](https://github.com/tstromberg/supplychain-attack-data/blob/a87dcc3559ca89f289ce22542805b7badea68cc2/oss/attacks/uaparser-js/refs/04-my-diffend-io.html) preserves the relevant changes.

The reconstruction applies this comparison to the verified `ua-parser-js@0.7.28` archive.
It changes `package.json` and adds `preinstall.js`, `preinstall.sh`, and `preinstall.bat`.
The comparison marks `src/ua-parser.js` unchanged. Its original bytes remain intact.
The reconstruction checks every context line, hunk count, and line offset against the clean archive.
Changed files use LF line endings. The resulting tree is not claimed to match the original tarball byte for byte.

This study downloaded no native payloads. The scanner read source as data.
This study ran no samples or lifecycle hooks, and it made no requests to payload destinations.
The [reference manifest](references.json) pins the retrieved evidence by URL, size, and SHA-256.
The [input manifest](historical-inputs.json) records every reconstructed file hash.

## Comparable legitimate controls

| Group | Pinned versions | Purpose |
| --- | --- | --- |
| Neighboring releases | `eslint-scope@3.7.1`, `3.7.3`; `ua-parser-js@0.7.28`, `0.7.30` | Contrast the incident changes with nearby unaffected releases |
| Credential handling | `npm@6.14.18`, `@npmcli/config@9.0.0`, `npm-registry-fetch@18.0.2`, `registry-auth-token@5.1.0` | Read configuration and select credentials for registry authentication |
| Download tools | `esbuild@0.25.0`, `playwright@1.51.1`, `puppeteer@24.4.0`, `electron@35.0.0`, `prebuild-install@7.1.3` | Download platform tools, browsers, or native builds |
| Download implementations | `playwright-core@1.51.1`, `@puppeteer/browsers@2.9.0`, `@electron/get@2.0.3` | Include implementation code behind thin package entry points |

The [protocol](protocol.json) fixes these 16 versions before scanning. No unavailable control was replaced.
The [control manifest](controls.json) pins registry integrity data, and [acquisition records](control-acquisition.json) pin archive hashes.
The [control review](control-review.json) records the relevant behavior and hashed source locations for every control.

These are controls for specific legitimate functions, not proof that every package is free of vulnerabilities.
Playwright includes an explicit browser-install operation; it is not treated as an automatic npm install hook.
Some credential and download helpers delegate work to unscanned dependencies.
The selected implementation packages reduce that limitation but do not form complete dependency graphs.

## Coverage

All 747 selected source files parse successfully. They contain 9,442,515 bytes.
The scanner reports no read gaps, parse failures, oversized samples, or package limits for these inputs.

That coverage describes the JavaScript/TypeScript selection, not the entire archive or installation chain.
The malicious `preinstall.sh` and `preinstall.bat` are present in the UAParser reconstruction but excluded by extension.
Its JavaScript launcher is scanned. The native payloads are external and absent.
The ESLint credential payload is also external to the first-stage package.

Hidden paths, declarations, source maps, and selected directories remain excluded by existing rules.
In particular, bundled `node_modules` files in the npm control do not count as inspected.
The [coverage inventory](coverage.json) records selected bytes, exclusion counts, excluded scripts, and prior-corpus overlap for every input.

## Gaps and recommended order

The [findings](findings.md) trace three measured gaps through the frozen implementation.
All three are reported observations. No detection fix is part of this approved evaluation.

1. **Credential-file data flow.** Recognize selected credential-file reads and follow their contents into supported HTTP requests.
   Preserve legitimate registry authentication controls. A filename match alone must not become a Critical warning.
2. **Remote response execution.** Link an HTTP response to `eval`, a function constructor, or another supported execution call.
   Preserve ordinary response parsing and local code-generation controls. Network access plus `eval` in unrelated code is insufficient.
3. **Installation-chain coverage.** Identify lifecycle entry points and report when they delegate to unsupported shell or batch files.
   This coverage result does not require calling every downloader malicious. A behavioral warning needs evidence from the actual chain.

The first two improvements need bounded data-flow tests with similar benign inputs.
The third needs a product decision on shell/batch analysis versus explicit incomplete-chain reporting.
Broader historical samples remain necessary before claiming detection of either entire attack family.

## Reproduction and checks

The detector is merged commit `12d0ba41331e6e29367ac49ac258626a85762cbd`.
The preserved scanner SHA-256 is `c993cc8e9d02c2a8c5dc5e737545f36e80d38724fd80d53fe902092452190728`.
The [freeze record](freeze.json) pins its source, the protocol, references, control selection, and prepared inputs before scanning.
Commit `fd8fc47a` records that freeze. No detector tuning followed these results.

Use new output directories. These commands download package archives as data and run only the scanner:

```sh
python3 bench/source-analysis/test_corpus.py

python3 bench/source-analysis/corpus.py download \
  --manifest bench/source-analysis/attack-families/controls.json \
  --cache /tmp/lpm-attack-family-controls

python3 bench/source-analysis/attack-families/prepare.py \
  --controls /tmp/lpm-attack-family-controls/acquired.json \
  --output /tmp/lpm-attack-family-historical

python3 bench/source-analysis/run.py \
  --acquired /tmp/lpm-attack-family-historical/acquired.json \
  --binary /path/to/frozen-source-corpus \
  --split all --threads 4 --output /tmp/lpm-attack-historical-results.jsonl

python3 bench/source-analysis/run.py \
  --acquired /tmp/lpm-attack-family-controls/acquired.json \
  --binary /path/to/frozen-source-corpus \
  --split all --threads 4 --output /tmp/lpm-attack-control-results.jsonl
```

The [parent README](../README.md#reproduce-a-scan) gives scanner build instructions.
Build from the frozen detector commit when the preserved binary is unavailable. Record the new binary hash because builds can differ.

All 24 harness tests pass, including six incident-reconstruction tests.
A second independent reconstruction produces identical file inventories and hashes.
The scanner output identities match all 19 requested inputs. Every control archive has the expected package name and version.
The [check record](checks.json) summarizes these checks and their scope.

The two scan processes take approximately 0.08 seconds for historical inputs and 0.49 seconds for controls.
Their peak resident memory is 13.86 MiB and 79.94 MiB, respectively, on the study Mac.
These single observations include startup and do not establish a performance improvement or regression.
The [run records](run-metadata.json) preserve exact timing, memory, binary hashes, and result hashes.

The detector and CLI are unchanged, so this pass does not repeat Rust builds or the previous 12,000-package scan.
The previous [threat-detection report](../threat-detection/report.md) retains its original performance costs and regression findings.
