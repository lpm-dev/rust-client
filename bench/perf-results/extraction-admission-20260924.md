# Ready-file extraction admission

A shared queue gives completed large archives an earlier extraction opportunity. It alternates large and ordinary ready files, preserving FIFO order within each class. Streaming retains its existing admission path and weight.

The same preserved release binary was measured with the scheduler disabled and enabled. Each fixture and state has 24 balanced rounds including Bun. Scoring on macOS (M5 Pro, APFS) used immutable local HTTPS registry replay with two warm gates and no concurrent workloads. These are local replay measurements, not live-registry timings.

| Fixture | State | Baseline median / p95 (ms) | Ready median / p95 (ms) | Bun median / p95 (ms) | Baseline / ready RSS (MiB) |
|---|---|---:|---:|---:|---:|
| t3-install | ci-cold-cache | 1568.0 / 1822.3 | 1515.0 / 1616.6 | 1410.6 / 1569.7 | 204.4 / 208.2 |
| t3-install | first-install | 1730.3 / 2213.8 | 1653.2 / 1922.1 | 1510.2 / 1910.9 | 341.7 / 342.7 |
| peer-heavy/vite-react | first-install | 304.0 / 371.3 | 309.3 / 341.4 | 227.8 / 254.4 | 191.5 / 189.9 |
| peer-heavy/vite-react | ci-cold-cache | 281.6 / 332.7 | 272.8 / 305.5 | 191.2 / 224.8 | 88.4 / 88.7 |
| native/sharp-image | first-install | 123.9 / 131.2 | 126.2 / 129.5 | 67.7 / 72.0 | 57.6 / 58.0 |
| native/sharp-image | ci-cold-cache | 81.6 / 84.8 | 81.8 / 86.5 | 54.3 / 61.6 | 46.3 / 46.5 |
| peer-heavy/nestjs-deep | first-install | 336.1 / 355.6 | 338.0 / 353.1 | 229.0 / 296.9 | 77.1 / 77.7 |
| peer-heavy/nestjs-deep | ci-cold-cache | 324.3 / 381.8 | 322.5 / 340.1 | 231.2 / 287.5 | 52.0 / 52.5 |

T3 improves in both cold states. Smaller-fixture paired median changes range from a 6.6 ms gain to a 0.1 ms loss. Their wall-time medians remain close. T3 CI-cold median RSS rises by 3.8 MiB; its observed RSS p95 rises from 224.2 to 240.3 MiB. First-install RSS remains close.

Observed p95 is descriptive at this sample count. The experiments do not establish p99 behavior. Package inventories, lockfile bytes, and LPM content-sidecar maps match across variants. These checks do not independently hash every installed file.

Separate T3 CI-cold diagnostics (four instrumented runs per variant) show median SWC extraction-admission wait falling from 1,246 to 100 ms. Streaming weight remains three in both variants. The queue reduces waiting; it does not remove filesystem contention during linking.

Cancellation regressions also verify that URL/Git and buffered V1 extraction keep their permits inside blocking workers until completion. Those fixes are present in both benchmark variants, so the table does not estimate their performance effect.

The measured enabled scheduler matches the final algorithm. The final source changes its default to enabled and adds a workspace cancellation regression; `LPM_INTERNAL_READY_FILE_ADMISSION=0` retains the disabled control.

Raw summary values, paired differences, binary identity, controls, and parity hashes are in [the measurement record](extraction-admission-20260924.json).
