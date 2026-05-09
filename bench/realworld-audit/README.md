# Real-world project audit

Closes Phase 66 confidence-followup §1a. Companion to `bench/audit-fixtures` —
where the fixture suite tests **isolated dep-graph shapes** (one risk
per fixture), this suite tests **whole real-world projects** end to
end. Same mode-asymmetric signal: `PASS/FAIL` or `FAIL/PASS` between
isolated and hoisted is a regression; symmetric failures are upstream
ecosystem incompat or lpm bugs equally on both modes.

## Usage

```bash
# build lpm-rs once
cargo build --release -p lpm-cli

# run a single project
./bench/realworld-audit/run-realworld.sh next-blog-starter

# run the whole suite
./bench/realworld-audit/run-all.sh

# filter by substring
./bench/realworld-audit/run-all.sh next
```

## Layout

```
bench/realworld-audit/
├── README.md                  # this file
├── projects.json              # manifest of projects + pinned refs
├── run-realworld.sh           # single-project runner
├── run-all.sh                 # whole-suite runner
├── .cache/   (gitignored)     # cloned source trees, keyed by project name + ref
└── results/  (gitignored)     # timestamped JSON per (project, mode) run
```

## Adding a project

Edit `projects.json` and add an entry:

```json
{
    "name": "my-project-starter",
    "category": "framework-starter",
    "why": "One sentence: what risk shape this exercises that the others don't.",
    "git_url": "https://github.com/owner/repo.git",
    "git_ref": "v1.2.3",
    "subpath": ".",
    "pre_install": "node -e \"...\"",
    "smoke": "npx --no-install <project-cli> build"
}
```

- **`name`** — kebab-case identifier; used as the cache directory name.
- **`category`** — free-form tag for reporting. Suggested: `framework-starter`,
  `ssg`, `backend`, `monorepo`, `native+js`, `cli`.
- **`why`** — one sentence of risk-shape rationale. Lives in the
  manifest so a future-you reading `git diff` understands purpose.
- **`git_url`** + **`git_ref`** — clone source. `git_ref` can be a tag,
  branch, or full SHA. Tags/branches use `--depth 1`; SHAs fall back
  to a full clone + checkout.
- **`subpath`** — relative path inside the repo where install + smoke
  run. Use `"."` for repo-root projects, `"examples/foo"` for
  monorepo subdirectories.
- **`pre_install`** — optional bash command run inside the work dir
  before `lpm install`. Use sparingly — typically to normalize a
  template's `package.json` (set name + private) or strip an
  org-only `.npmrc`.
- **`smoke`** — bash command exercising the project. Should fail
  loudly on anything that hoisted-mode regressions would surface
  (build, typecheck, run a representative test). `npx --no-install`
  guards against falling back to a network npm fetch when a binary
  isn't on the materialized layout.

The harness wipes `~/.lpm/cache` and `~/.lpm/store` between modes for
a true cold install. Lockfiles (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, `bun.lockb`, `lpm.lock`) are stripped so each mode
sees the same input.

## When a project fails

1. **PASS/FAIL or FAIL/PASS** — real hoisted regression. Investigate
   in `lpm-linker` / `lpm-resolver`. Don't paper over with a
   project-side workaround. The result JSON in `results/` carries
   the install + smoke log tail; the work dir at
   `/tmp/lpm-realworld-work/<project>-<mode>/` survives across runs
   and has the full `.lpm-install.log` + `.lpm-smoke.log`.
2. **Both PASS** — done.
3. **Both FAIL** — adjacent issue. Three sub-cases:
   - lpm bug affecting both modes equally (file as a roadmap item).
   - Project-ecosystem incompat (pin to a known-good ref).
   - Network / env (retry; consider a `requirements.sh` if
     persistent). `requirements.sh`-style env gating isn't
     implemented yet — first symmetric-FAIL of that kind is the
     trigger to add it.

## Why this is workflow-dispatch only

This suite clones whole projects and runs their typecheck/build —
each project is 1–5 minutes. CI runs it manually (workflow_dispatch)
and on a weekly schedule, not on every PR. Cost vs signal calculus:
the audit-fixtures suite catches ~95% of mode-asymmetric regressions
in <2 minutes; this suite is the long-tail safety net.
