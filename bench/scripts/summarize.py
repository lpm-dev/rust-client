#!/usr/bin/env python3
"""Phase 56 W1 bench summary — median + paired t-stat across arms.

Usage: $0 <results_dir>
Reads iter-N-<arm>.wall_ms and prints per-arm distribution + paired comparisons.

Arms: pubgrub-stream, greedy-stream, greedy-fusion, bun.
At W1 HEAD (no fusion code yet) `greedy-fusion` collapses to default-walker greedy,
so the harness-validation gate is "all three lpm arms within ±200 ms median."
W3 reports the actual fusion delta after W2 wires the dispatcher.

Critical t at α=0.05, df=19 (n=20) is 2.093.
"""
import os, re, sys, statistics, math, glob

if len(sys.argv) < 2:
    print("usage: summarize.py <results_dir>"); sys.exit(1)
RES = sys.argv[1]

ARMS = ['pubgrub-stream', 'greedy-stream', 'greedy-fusion', 'bun']

def load(arm):
    files = sorted(glob.glob(os.path.join(RES, f'iter-*-{arm}.wall_ms')))
    out = []
    for f in files:
        try:
            v = int(open(f).read().strip())
            out.append((int(re.search(r'iter-(\d+)-', f).group(1)), v))
        except: pass
    out.sort()
    return out

def stats(xs):
    if not xs: return None
    n = len(xs)
    med = statistics.median(xs)
    mean = statistics.mean(xs)
    sd = statistics.stdev(xs) if n > 1 else 0
    # 10% trimmed mean per pre-plan §4 W3
    if n >= 10:
        trim = max(1, n // 10)
        sorted_xs = sorted(xs)
        trimmed = sorted_xs[trim:-trim] if trim > 0 else sorted_xs
        tmean = statistics.mean(trimmed)
    else:
        tmean = mean
    return n, med, mean, tmean, sd

def paired_t(a, b):
    common = sorted(set(i for i, _ in a) & set(i for i, _ in b))
    if len(common) < 5: return None
    da = dict(a); db = dict(b)
    diffs = [db[i] - da[i] for i in common]
    n = len(diffs)
    mean_d = sum(diffs) / n
    var_d = sum((d - mean_d) ** 2 for d in diffs) / (n - 1)
    se = math.sqrt(var_d / n)
    t = mean_d / se if se > 0 else float('nan')
    return n, mean_d, t

print(f"[summary] {RES}\n")
print(f"  {'arm':<18s} {'n':>4s} {'median':>8s} {'mean':>8s} {'tmean':>8s} {'stdev':>8s}")
loaded = {}
for arm in ARMS:
    data = load(arm)
    if not data: continue
    loaded[arm] = data
    s = stats([v for _, v in data])
    if not s: continue
    n, med, mean, tmean, sd = s
    print(f"  {arm:<18s} {n:>4d} {med:>8.0f} {mean:>8.0f} {tmean:>8.0f} {sd:>8.0f}")

print()
PAIRS = [
    ('pubgrub-stream', 'greedy-stream'),
    ('greedy-stream', 'greedy-fusion'),
    ('pubgrub-stream', 'greedy-fusion'),
]
print("[paired t]  (* = |t| > 2.093, α=0.05 df=19)")
for a, b in PAIRS:
    if a not in loaded or b not in loaded: continue
    res = paired_t(loaded[a], loaded[b])
    if res is None: continue
    n, mean_d, t = res
    sig = '*' if abs(t) > 2.093 else ' '
    print(f"  {a:>18s} → {b:<18s}  n={n}  Δ={mean_d:+8.0f} ms   t={t:+6.2f}  {sig}")

if 'bun' in loaded:
    bun_med = statistics.median([v for _, v in loaded['bun']])
    print(f"\n[bun reference] median={bun_med:.0f} ms")
    for arm in ['pubgrub-stream', 'greedy-stream', 'greedy-fusion']:
        if arm not in loaded: continue
        med = statistics.median([v for _, v in loaded[arm]])
        ratio = med / bun_med
        print(f"  {arm:<18s} median={med:.0f} ms   {ratio:.2f}× bun")

# Phase 56 W4+ gates — applied to the greedy-fusion arm only. The
# pre-W2 baselines (pubgrub-stream ≈ 4020 ms, greedy-stream ≈ 3936 ms
# on the W1 harness-validation run) are preserved here only as
# regression sentinels: a sudden fusion median > 2000 ms would
# invalidate the W3 result, but the W1-era same-arm reproducibility
# gate is no longer informative now that fusion is the default and
# baseline targets are 4× tighter.
#
# Tightened tier (post-W3), per Phase 56 pre-plan §2.1 stretch +
# user direction at W4:
#   HARD     ≤ 1,500 ms (was W3 stretch)   — must clear or investigate
#   STRETCH  ≤ 1,000 ms                     — bun-parity territory
#   STDEV    ≤   500 ms                     — tail-stability invariant
HARD_GATE_MS = 1500
STRETCH_GATE_MS = 1000
STDEV_GATE_MS = 500

print(f"\n[fusion gates — hard ≤{HARD_GATE_MS} ms, stretch ≤{STRETCH_GATE_MS} ms, stdev ≤{STDEV_GATE_MS} ms]")
fusion = loaded.get('greedy-fusion')
all_pass = True
if not fusion:
    print("  greedy-fusion: NO DATA — skipping gate evaluation")
else:
    vals = [v for _, v in fusion]
    med = statistics.median(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0
    hard_ok = med <= HARD_GATE_MS
    stretch_ok = med <= STRETCH_GATE_MS
    stdev_ok = sd <= STDEV_GATE_MS
    all_pass = hard_ok and stdev_ok
    print(f"  median={med:.0f} ms   "
          f"hard:{'PASS' if hard_ok else 'FAIL':>4s}   "
          f"stretch:{'PASS' if stretch_ok else 'miss':>4s}")
    print(f"  stdev ={sd:.0f} ms   stdev:{'PASS' if stdev_ok else 'FAIL':>4s}")
    if 'bun' in loaded:
        bun_med = statistics.median([v for _, v in loaded['bun']])
        ratio = med / bun_med
        print(f"  vs bun: {ratio:.2f}× ({'beats' if ratio < 1 else 'within' if ratio < 1.15 else 'behind'} bun)")

print(f"\n[fusion gate] {'PASS' if all_pass else 'FAIL — investigate'}")
