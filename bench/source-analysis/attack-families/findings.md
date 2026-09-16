# Frozen-detector observations

Scope: evaluate credential-file theft and install-time downloaders, then report gaps.
The user selected evaluation before implementation. No product fixes are included.

| ID | Observation | Evidence | Disposition |
| --- | --- | --- | --- |
| AF-01 | Credential-file contents sent through Node HTTP APIs receive no credential-exfiltration finding | Recovered ESLint second stage, `pastebin.js`; one parsed file, zero Critical findings | Measured and reported |
| AF-02 | Downloaded JavaScript passed into `eval` remains separate capabilities | Reconstructed ESLint first stage, `lib/build.js`; network and `eval`, zero Critical findings | Measured and reported |
| AF-03 | A lifecycle launcher can delegate the malicious download to unsupported languages while selected-source coverage remains complete | Reconstructed UAParser input; `preinstall.js` scanned, `.sh` and `.bat` excluded | Measured and reported |

Three detector or coverage gaps were measured. No analysis item remains pending.
Original malicious archives remain unavailable; the report limits conclusions to the recovered and reconstructed inputs.
These are evaluation observations, not claims that fixes were delivered.

## AF-01: Credential-file theft

The recovered payload reads the home `.npmrc` file and places its contents in two `Referer` request headers.
The scanner reports filesystem, environment, and network capabilities, but no credential-exfiltration tag.

In the frozen implementation, `behavioral/threats.rs::is_candidate` selects `fetch` and repository-content upload calls.
Node `https.get` is outside that set. Credential-file reads also fall outside its selected private-key and environment sources.
The source parses completely, so this miss is not a parser or resource-limit failure.

Expected future coverage: selected credential-file contents reaching an unrelated request header or body can establish a suspicious flow.
Comparable controls must include config readers, registry credential selection, authenticated requests, public file uploads, and overwritten or sanitized values.
The source-flow explanation must identify the file read and upload destination, rather than rely on the token variable name.

The runtime payload was not present in the original npm package. Detecting it in isolation would not fix first-stage package detection.

## AF-02: Remote response execution

The recovered downloader receives HTTP response chunks and passes each chunk into `eval`.
The scanner reports both capabilities and an informational entropy tag. It does not link the response to execution.

`behavioral/source.rs` records source capabilities. The current threat analysis follows selected secret values into uploads, not downloaded values into execution.
The complete first-stage file is selected and parsed.

Expected future coverage: a supported HTTP response that reaches an execution call can establish a suspicious relationship.
Controls must retain normal JSON parsing, text downloads, local template compilation, shadowed `eval` names, and disconnected network/execution code.
Legitimate tools that intentionally load remote code also need review before a universal Critical policy is justified.

## AF-03: Installation-chain coverage

The reconstructed `package.json` starts `preinstall.js`, which launches a platform shell or batch file.
Those scripts contain the native-payload download and launch operations.
The JavaScript file produces child-process and shell capabilities, while the payload scripts do not enter source analysis.

`behavioral/mod.rs::SOURCE_EXTENSIONS` contains JavaScript and TypeScript extensions only.
`PackageAnalyzer::should_scan` excludes `.sh` and `.bat` before parsing.
`behavioral/manifest.rs` analyzes dependency and license fields; it does not trace lifecycle script references.

Expected future coverage: distinguish complete supported-source analysis from a fully inspected installation chain.
An unsupported reachable script is a coverage gap, not proof of malware.
Controls must include Electron, esbuild, browser installers, platform selection, configurable mirrors, and integrity checks.
The scanner must not treat a legitimate download and launch as malicious merely because both operations are present.

## Reproduction evidence

- [Protocol](protocol.json): selected incidents, stages, and controls before scanning.
- [Freeze](freeze.json): merged source and preserved binary hashes.
- [Historical inputs](historical-inputs.json): recovered and reconstructed file hashes.
- [Historical results](historical-results.jsonl): scanner tags and evidence locations, with excerpts omitted.
- [Control review](control-review.json): comparable legitimate behavior and source locations.
- [Coverage](coverage.json): selected-source counts and excluded scripts.

No historical package or payload was executed. No detector change was made after measurement.
