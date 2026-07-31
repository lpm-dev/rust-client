# README VitePress Install Benchmark

> **Historical methodology warning (added July 30, 2026):** this result is not
> an equal-work workspace comparison. npm, pnpm, and Bun recursively installed
> the tracked workspace, while this LPM revision installed only the root
> importer and skipped workspace-member dependencies. The LPM columns are
> root-only and are not comparable with the other managers. The harness also
> deleted generated lockfiles before every measured warm run for all four
> managers, so the historical warm row is cache/store-warm but lockfile-cold.
> This artifact is retained only as a historical record.

- Fixture: `bench/fixtures/vitepress-docs`
- Samples: `10`
- Modes: `cold,warm,up-to-date`
- Managers: `lpm,bun,pnpm,npm`
- LPM firewall modes: `off,report`
- Raw output: `/tmp/lpm-readme-vitepress-20260710T140139`
- Raw rows: `150`
- Failed rows: `0`

| Benchmark | npm | pnpm | bun | lpm | lpm + Firewall monitor |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cold install (unequal historical workload) | 17,354ms | 6,125ms | 2,455ms | 2,945ms | 3,043ms |
| Warm install | 3,819ms | 3,301ms | 451ms | 387ms | 324ms |
| Up-to-date install | 282ms | 522ms | 77ms | 14ms | 14ms |

Full harness summary:

| Fixture | Spec | Mode | OK | Wall med/min | Resolve med/min | Firewall med/min | FW chunks | FW chunk sum | FW chunk max | Fetch med/min | Link med/min | Pkgs | FW checked | FW warn/block/unknown | Metadata MB | Version docs | Parity mismatches | Warnings exp/unknown |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vitepress | bun | cold | 10/10 | 2454.5/2046 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/0 |
| vitepress | bun | up-to-date | 10/10 | 76.5/66 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/0 |
| vitepress | bun | warm | 10/10 | 450.5/357 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/0 |
| vitepress | lpm-current-firewall-report | cold | 10/10 | 3043/2635 | 1260/1028 | 1273.5/1038 | 10 | 166/133 | 59.5/35 | 1459.5/1005 | 64.5/18 | 535 | 535 | 0/0/0 | 70.5/70.5 | n/a | n/a | 0/0 |
| vitepress | lpm-current-firewall-report | up-to-date | 10/10 | 14/13 | 0/0 | n/a | n/a | n/a | n/a | 0/0 | 0/0 | n/a | n/a | n/a | 0/0 | n/a | n/a | 0/0 |
| vitepress | lpm-current-firewall-report | warm | 10/10 | 324/304 | 48/46 | 66.5/54 | 10 | 365/321 | 51/43 | 28/22 | 69/55 | 535 | 535 | 0/0/0 | 0/0 | n/a | n/a | 0/0 |
| vitepress | lpm-current | cold | 10/10 | 2945/2535 | 1337.5/1125 | 0/0 | 0 | 0/0 | 0/0 | 1192.5/894 | 106/76 | 535 | 0 | 0/0/0 | 70.5/70.5 | n/a | n/a | 0/0 |
| vitepress | lpm-current | up-to-date | 10/10 | 13.5/12 | 0/0 | n/a | n/a | n/a | n/a | 0/0 | 0/0 | n/a | n/a | n/a | 0/0 | n/a | n/a | 0/0 |
| vitepress | lpm-current | warm | 10/10 | 386.5/357 | 51/43 | 0/0 | 0 | 0/0 | 0/0 | 23.5/18 | 9.5/7 | 535 | 0 | 0/0/0 | 0/0 | n/a | n/a | 0/0 |
| vitepress | npm | cold | 10/10 | 17353.5/14902 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/12 |
| vitepress | npm | up-to-date | 10/10 | 281.5/249 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/0 |
| vitepress | npm | warm | 10/10 | 3818.5/3369 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/12 |
| vitepress | pnpm | cold | 10/10 | 6124.5/5120 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/9 |
| vitepress | pnpm | up-to-date | 10/10 | 522/484 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/4 |
| vitepress | pnpm | warm | 10/10 | 3301/2951 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0/9 |
