# Hoisted-mode compatibility audit fixtures

Real-world fixture set for the Phase 2 hoisted-mode compatibility audit.
See [`DOCS/new-features/37-rust-client-hoisted-compat-audit-preplan.md`](https://github.com/tolga-ergin/lpm/blob/main/DOCS/new-features/37-rust-client-hoisted-compat-audit-preplan.md)
in the lpm repo for full methodology.

Each fixture is a minimal `package.json` that exercises one specific
real-world failure mode. Three risk buckets:

- `peer-heavy/` — graphs where multiple packages share a peer dep
  (React DOM + React, Next + ESLint config + plugins, Vite + plugin + React)
- `tooling/` — plugin-discovery via parent-walk (ESLint, Babel, Rollup)
- `native/` — postinstall hooks downloading platform binaries (sharp, better-sqlite3)

## Running

```bash
# Single fixture
./run-audit.sh peer-heavy/react-ssr

# All fixtures (dispatches to each in turn)
./run-all.sh
```

The harness does not pass `--allow-new` by default. To run the CI-style
cooldown-bypass posture locally, install the managed audit policy first
and opt in explicitly:

```bash
sudo ./bench/install-audit-security-policy.sh
LPM_AUDIT_ALLOW_NEW=1 ./bench/audit-fixtures/run-all.sh
```

Outputs land in `results/<fixture>-<mode>-<timestamp>.json`.

Each result JSON also carries a typed `classification` for non-pass
outcomes so suite summaries can distinguish runtime mismatches,
fixture limitations, package-surface mismatches, and genuine
unclassified failures without changing the hoisted-vs-isolated gate.

## Pass criteria (per fixture × linker mode)

1. `lpm install` exits 0
2. Every direct dep has a `node_modules/<dep>/package.json`
3. `node -e "require('<dep>')"` exits 0 for every direct dep
4. The fixture's `smoke.sh` exits 0 (functional check)
5. Postinstall hooks completed (relevant for `native/`)

A fixture passes a linker mode iff all five hold. Any single failure logs
the specific criterion + reason, and the summary groups symmetric
non-pass outcomes by typed category while still failing CI only for
mode-asymmetric regressions.
