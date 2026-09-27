# Node version reuse

Every install that checks `engines.node` ran `node --version`. That included installs that change nothing, where the probe was about half the command's time. This change reuses the version that the previous install recorded when a real Node binary is unchanged. Up-to-date T3 installs fall from 21.4 to 8.4 ms locally and from 25.2 to 14.6 ms with `CI` set.

## Where the time went

Sixty consecutive up-to-date T3 installs were sampled at 10 kHz. The dependency engine filter waited 9.8 ms per install for a thread running `node --version`. `node --version` alone took 10.5 ms, most of it Node's own startup. Replacing Node on `PATH` with a native stub that prints the same version cut the install from 22.1 to 13.8 ms.

The install hash already stored the version inside its dependency engine key (`e:1:24.19.0`) with a fingerprint of the executable (`n:`). Freshness checks reused the key when the fingerprint matched, but the engine filter still probed Node for the version.

The probe also waited for the child by polling every 2 ms.

## The change

**Real Node binaries reuse the recorded version.** When the executable's current fingerprint matches the recorded one, the version from the key stands in for the probe. This applies to the install pipeline, including the root `engines.node` check, and to the no-op fast lane. `lpm install --force` probes again. An executable counts as a Node binary when it:

- is named `node` (`node.exe` on Windows),
- starts with a native executable header,
- is at least 16 MiB,
- has a single hard link, and
- has no Scoop `.shim` file beside it.

**Launchers are still probed on every install.** Shell scripts, symlinks to differently named programs, and hard-linked or small shims can print a new version without changing on disk. The existing workflow test `unchanged_install_probes_once_and_rejects_changed_shim_output` pins this down: its shim reads an arbitrary project file, and an unchanged install must notice the new output.

**The fingerprint covers what selects a version.** Besides the executable's path and metadata, it covers:

- each link target from the `PATH` entry to the executable;
- `.nvmrc`, `.node-version`, `.tool-versions`, `.prototools` and mise configuration files in the working directory and every ancestor;
- the `volta` and `devEngines` fields of each `package.json` on that path;
- global asdf, nodenv, Volta, proto and mise defaults;
- `ASDF_`, `MISE_`, `RTX_`, `NODENV_`, `VOLTA_` and `PROTO_` variables.

A native shim that passes the binary checks therefore still changes its fingerprint when its inputs select another version. For launchers the fingerprint also covers the working directory and script `PATH`. Runtimes that LPM manages under `~/.lpm/runtimes/node` are identified by the executable alone, so workspace members keep sharing one probe.

**The fast lane refreshes the stored fingerprint** when it changed but the version held. The first install after this change probes once, because the fingerprint format changed.

**Probes wait on events.** `output_capped` now blocks in `poll(2)` until output or end of file on Unix, and waits on the process handle on Windows.

## Results

Release builds of #890 and this change on an M-series Mac, with Node 24.19.0 installed as a real binary. Each project was installed once from the live registry, then copied per variant so the two builds never shared an install hash. Every command ran through the same small wrapper script. Background load from a browser was present, so times are medians with nearest-rank p95.

Up-to-date installs, 40 runs each. "Local" is a plain `lpm install`, which takes the fast lane. `CI` set runs the full pipeline, as the six-state harness does.

| Project | Mode | #890 | This change | Bun |
|---|---|---:|---:|---:|
| T3 | local | 21.4 / 22.3 | 8.4 / 9.4 | 9.9 / 10.8 |
| T3 | `CI` set | 25.2 / 26.3 | 14.6 / 19.6 | |
| native-sharp | local | 19.3 / 19.8 | 6.5 / 7.0 | 5.2 / 6.4 |
| native-sharp | `CI` set | 24.6 / 31.2 | 10.7 / 14.9 | |

Other T3 states with `CI` set, 30 runs each:

| State | #890 | This change |
|---|---:|---:|
| Package cache removed | 25.6 / 30.3 | 13.7 / 15.4 |
| `node_modules` removed, `.lpm` kept | 82.4 / 101.5 | 75.9 / 87.9 |

With both `node_modules` and `.lpm` removed, as in the harness's CI-warm state, no version is recorded and Node must be probed. Over 60 interleaved pairs the medians were 84.4 and 85.3 ms, a paired +0.7 ms with this change faster in 23. The internal timer showed 61.5 against 60.5 ms. The change is neutral there within noise.

Component measurements:

- **Probe wait:** 200 interleaved probes each through the old and new `output_capped`. Real Node went from 12.78 to 10.63 ms median, and a native stub from 2.67 to 1.24 ms.
- **Fingerprint:** computing it for T3's script `PATH` took 201 µs median. A reused install computes it once.

## Measured and not adopted

**Starting the probe early.** Starting it before the lockfile plan whenever the previous lockfile had engines would overlap it with setup. But an install whose new dependency set has no engines would then still execute Node. `engine_free_installs_do_not_execute_node` and the shim workflow test forbid that, and executing a shim can have side effects such as a runtime download. On CI-warm, the probe comes directly after lockfile plan selection with little work in between, so waiting for certain need gains little.

**Reusing versions for launchers.** Version files and variables cannot cover every input a launcher reads.

## Limitations

The first install, fresh checkout and CI-cold states probe Node once as before and gain only the faster probe wait. A machine-wide cache of versions keyed by fingerprint could remove that probe on warm CI runners with identical images, but it would need its own cache category and cleanup command.

## Artifacts

The adjacent `-summary.json` holds every measurement in this report. The `-tools.tar.gz` archive contains the benchmark script, the probe and fingerprint microbenchmarks, and the raw `hyperfine` and paired-run data. Absolute paths in the scripts identify this run.
