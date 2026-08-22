# Metadata retention and update planning

Date: 2026-08-21
Host: macOS on Apple silicon
Toolchain: Rust 1.94.0
Profile: release, LTO, one code-generation unit

## Result

The update-planning changes reduced median peak RSS by 71.97% in the large-packument fixture.
The candidate saved 178.81 MiB and also reduced median wall time by 2.53%.

| Binary | Median wall time | Median peak RSS |
| --- | ---: | ---: |
| Baseline | 0.79 s | 248.44 MiB |
| Candidate | 0.77 s | 69.62 MiB |
| Change | -2.53% | -71.97% |

The result supports bounded completion-order planning and immediate packument projection.
It also includes the effect of the parsed-version index and move-based candidate planning.

## Method

The fixture contained 48 direct dependencies and matching lockfile roots.
Each metadata response was 1,695,509 bytes and contained 201 version records.
One response had a 750 ms delay, and the other responses completed without an added delay.

The baseline started all metadata requests and retained completed packuments behind the delayed response.
The candidate used four planning slots and projected each completed packument before it requested more metadata.

The mock registry generated all response bodies before the measured samples.
Each run used a new project home, LPM home, and metadata cache.
Each command produced 48 successful dry-run plans from the same response data.

The measurement used seven alternating A/B pairs.
Odd pairs ran the baseline first, and even pairs ran the candidate first.
macOS `/usr/bin/time -l` recorded wall time and peak RSS.

## Preserved binaries

| Binary | SHA-256 |
| --- | --- |
| `/tmp/lpm-area6-baseline` | `7dc2147f85f32b7e30efd52afa16b2c7a99959419269c5e1094b78e5320f9fbc` |
| `/tmp/lpm-area6-current` | `dddd3b7943b39c301e453d569708e1cec8a033e4fee0a90ba851193c0d4130cb` |

The raw sample table is in `/tmp/lpm-area6-upgrade-planning-results.tsv`.

## Samples

| Pair | First binary | Baseline time | Baseline RSS | Candidate time | Candidate RSS |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Baseline | 0.83 s | 248.36 MiB | 1.24 s | 62.27 MiB |
| 2 | Candidate | 0.79 s | 248.28 MiB | 0.77 s | 70.67 MiB |
| 3 | Baseline | 0.79 s | 250.34 MiB | 0.77 s | 66.36 MiB |
| 4 | Candidate | 0.79 s | 248.44 MiB | 0.77 s | 76.20 MiB |
| 5 | Baseline | 0.79 s | 259.22 MiB | 0.77 s | 65.16 MiB |
| 6 | Candidate | 0.79 s | 255.05 MiB | 0.78 s | 69.62 MiB |
| 7 | Baseline | 0.79 s | 242.69 MiB | 0.77 s | 71.72 MiB |

The first candidate wall-time sample was slower than the other candidate samples.
The median excludes this single-run effect without removing the sample.
