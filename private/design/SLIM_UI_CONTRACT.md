# Slim UI redesign — implementation contract

Single source of truth for finishing the slim-TUI redesign. Two halves:

- **Part 1 — RULES**: stable conventions (color system, palette, helpers,
  authority order). Read before touching any command.
- **Part 2 — TODO**: full, unprioritized, atomic checklist. One checkbox =
  one command × one concern, with file pointer + design line + current
  behavior. Pick up any row cold.

Scope decisions locked for this effort:

- **B2 data-features are IN SCOPE** — where the design shows data the
  command doesn't compute yet (health response-time, uninstall prune/disk
  counts, env sync timestamps, tunnel request stream, etc.), build the data
  **and** the UI. Do not fake or stub the data.
  Current exception: backend/API extensions for tunnel region and search
  quality/ecosystem are deferred; `env ls` remains important for the command
  slice.
- **Full semantic color system** — add the body-color helpers to
  `install_ui`, then apply the role→color map to **every** command.
- The five interactive commands stay on **cliclack** (see Rule 2).

Authority: **mdx design block = structure**, **HTML = color**, **code =
behavior truth**. When they disagree, see Rule 7.

---

# Part 1 — RULES

## Rule 1 — The semantic color system (the core of this redesign)

The design is not "colored glyphs + plain text." Every text token has a
**role**, and the role determines the color. Decoded from the design HTML
(`~/Desktop/terminal/html`), the roles are:

| Role | Color | ANSI | Design RGB | Applies to |
|------|-------|------|-----------|-----------|
| Phase glyph `›` / URLs | blue | `blue` | `95,175,255` | `›`, every `http(s)://…` value |
| Success / status-value / terminus number / `✓ ● +` | green | `green` | `95,215,135` | `enabled`, `yes`, `trusted`, `valid`, `healthy`, `listening`, `current`, durations `168ms`/`2.41s`, counts in terminus, usage bars |
| Section header / `!` warn / badge / `~` / `↑minor` | gold | `yellow`+bold | `215,175,95` | `usage`, `scopes`, `registries`, `checks`, `Vulnerabilities`, `effective floor`, `Commands:`, `admin` badge, `private` visibility |
| Subject / tool / acted-on target | yellow | `yellow` | `215,215,135` | `Vitest`, `Biome 2.4.8`, `Oxlint`, `tsdown`, `CycloneDX`, `lodash@4.17.21`, `localhost:3000`, version targets `1.4.2` |
| Path / scope / identifier / key / flag | cyan | `cyan` | `125,207,255` | `@lpm.dev/acme.*`, `GHSA-…`, JSON keys, `--token`, search query, quality pkg name |
| Label / hint / separator / metadata | dim | `dimmed` | `119,119,119` | `email`, `plan`, `status`, `·`, `→`, `(orphaned)`, `severity unknown` |
| Normal value | plain | — | `207,207,207` | `Pro`, list package names, file names, `87` |
| Shell keyword / masked secret | purple / red | `magenta`/`red` | `187,154,247` / `255,95,87` | `export`,`local` (purple); `***` (red) |

**`section` vs `subject`** are both yellow-family; in truecolor they differ
(gold vs light-yellow). Render `section` as **yellow + bold**, `subject` as
**plain yellow** so they're distinguishable on 16-color terminals too.

## Rule 2 — Slim vs cliclack split (unchanged, verify it stays correct)

- **Slim UI** (`install_ui::*`): non-interactive commands that print
  progress/status and never prompt.
- **cliclack** (`crate::output::*`): the five interactive commands —
  `login`, `approve-scripts`, `config scripts`, `init` (prompts), `add`
  (source picker). These KEEP cliclack; the `?`/`○`/`●`/`✔` glyphs in their
  mockups are cliclack's own widget glyphs and are correct.
- A command that does both: cliclack for the prompt, slim UI for progress.

## Rule 3 — Palette additions

- **`●` is now sanctioned** as a status/bullet glyph: green when
  active/healthy/listening, dim when inactive. Used by `whoami` registries,
  `ports`, `health`, `dev`, `filter`, `mcp setup`.
- No other new glyphs without a decision here first.

## Rule 4 — Helpers to add to `install_ui` (do this FIRST; everything depends on it)

Current surface: `phase / done / failed / warn / plus / minus / dim / bold /
green / red / usage_bar / yellow_badge / format_duration / packages_word /
short_registry_host / format_audit_advisory`.

Add (color helpers honor `lpm_common::color::enabled()` like the existing ones):

- [x] `yellow(text) -> String` — subject/tool/target role.
- [x] `section(text) -> String` — section-header role (yellow + bold). Replaces
      the ad-hoc `.bold()` currently used for section titles.
- [x] `cyan(text) -> String` — path/scope/identifier/key/flag role.
- [x] `url(text) -> String` — blue, for `http(s)://…` values.
- [x] `status_ok(text) -> String` — green, for status values (`enabled`,
      `healthy`, …). (May alias `green`; named for intent/grep-ability.)
- [x] `bullet(active: bool) -> String` — `●` green when active, dim when not.
- [x] Recolor `diff_entry`: `+` → **green**, `-` → **red** (currently plain).
      Keep the dimmed `@version`/hint suffix.
- [x] Update the module-doc palette table (lines 10-16) + `SLIM_UI.md` glyph
      table to include `●` and the body-color roles.

## Rule 5 — Stream contract (one real bug to fix)

Every slim-UI line goes to **stderr**. Table/tree "answer" output (outdated,
graph, query results) may stay on stdout for piping. **`audit` is the
exception to fix**: its section bodies print to **stdout** via `println!`
while the framing goes to stderr — there is no `| jq` reason for audit to
split, and it contradicts the stream contract. Move audit's human bodies to
`eprintln!`/`install_ui::*`.

## Rule 6 — Spinners (animate → settle) + no per-step chatter

- **In-progress phases animate** as a braille spinner (blue) while the work
  runs, then **settle** to `›` (informational phase, persists) or
  `✓`/`✗`/`!` (terminus). The design HTML spinner frames (`⠦⠴⠇⠸` for
  `fmt/lint/run/swift-registry/add/…`) ARE the intended live state; the mdx
  shows the settled transcript. (This supersedes the earlier "no spinners"
  rule — `SLIM_UI.md` "Spinner lifecycle" is now the canonical description.)
- **TTY-gated — preserves the piping guarantee.** Animate only on an
  interactive TTY with color enabled. Piped / redirected / `NO_COLOR` /
  `--color=never` / non-TTY / `--json` → print the static `›`/`✓` line
  immediately, **byte-identical** to the non-spinner output. stderr only,
  CR + clear-line, no escape codes into pipes, never stdout. Instantaneous
  steps (<~100 ms, e.g. "Auto-detected Vitest") print static.
- **Spin these long-running phases:** resolve, install, download, audit
  scan + OSV check, pack, bundle, deploy materialize, store verify,
  self-update check, publish upload, migrate convert, use download, tunnel
  open, swift-registry configure, plugin download. Quick informational
  phases stay static.
- Still **drop per-step chatter** when the terminus conveys the state (the
  `rebuild` `→ phase: cmd` lines, `publish` `Packing…/Uploading…` chatter).
  Aggregate, don't itemize per package.

## Rule 7 — Mockup authority & the three accuracy traps

The mockups are illustrations, not a uniform spec. Before implementing a
command, classify its design block:

- **Truncated capture** (HTML stopped at the typed command or a spinner):
  `install, cache status, check, download, info, query, use, bundle, setup
  ci, patch-remove, skills list, fmt, lint, run, bench, swift-registry, add`.
  → use the **mdx** for structure; HTML only for color. Don't read "no
  output" into a truncated capture. Note: a captured **spinner frame**
  (`⠦⠴⠇⠸`) is the *live in-progress* state, not an artifact — implement it
  per Rule 6 (spinner → settle); the mdx shows the settled `›` transcript.
- **Design shows MORE than the command computes (B2)**: build the data (in
  scope). Listed per-command in Part 2 with a `B2:` tag.
- **Design shows LESS than the command produces (B3)**: the extra real
  sections are kept and inherit the color roles — do NOT delete them to match
  the trimmed mockup. Tagged `B3:` in Part 2.

## Rule 8 — Definition of done (per command)

1. Structure matches the mdx design block (glyphs, lines, order, spacing).
2. Every text token carries its Rule-1 role color.
3. Completion-time terminus present with green elapsed where the design shows
   it.
4. B2 data computed for real; B3 extra sections retained + colored.
5. Human body on stderr (Rule 5); `--json` output byte-identical to before.
6. A workflow/subprocess test covers the human output (the redesign added 37
   such test files — extend them, don't regress).
7. Long-running phases animate on a TTY and degrade to the static line when
   piped / non-TTY / `--json` (Rule 6).

---

# Part 2 — TODO (full, unprioritized)

Legend: **[struct]** structure mismatch · **[color]** apply Rule-1 roles ·
**[time]** missing/!elapsed completion line · **[B2]** needs data/feature ·
**[B3]** keep extra real output · **[stream]** stderr fix · **[split]**
slim/cliclack. File:line are approximate — confirm before editing.

> Note: **[color] applies to ALL ~60 commands** once helpers land (Rule 4).
> To avoid 60 identical rows, each command lists only its *notable* color
> tokens; the blanket rule is: section headers → `section`, status values →
> `status_ok`, tool/target → `yellow`, paths/scopes/keys → `cyan`, URLs →
> `url`, labels/hints → `dim`. A command with ONLY a generic color pass is
> marked `[color] generic`.

## Foundation (do first)

- [x] Rule 4 — add all `install_ui` helpers + recolor `+`/`-` + `●` + doc update.
- [x] **Spinner primitive** in `install_ui` (Rule 6 / `SLIM_UI.md` "Spinner
      lifecycle") — animated braille (blue) at the glyph position that settles
      to `›`/`✓`/`✗`/`!`. Requirements: TTY-gated (animate only on interactive
      stderr + color on; otherwise print the static line immediately, byte-
      identical to today); stderr-only CR + clear-line, no escape codes in
      pipes, never stdout; a guard/handle API the call sites use
      (`let sp = install_ui::spin(msg); … sp.done(msg)`), with `phase()`
      auto-settling the previous spinner to `›` before printing the next.
      Hand-roll the animation thread (don't pull cliclack); `indicatif` is
      acceptable only if it gives clean TTY gating + the exact glyph-settle
      behavior. Add a non-TTY test asserting output is byte-identical to the
      static path.

## Group A — install / audit / resolve family

### audit  — `commands/audit/mod.rs`  (biggest single job)
- [x] [struct] Replace verbose discovery header (`Scanning N…`, `lockfile`,
      `npm packages:` ~L1087-1126) with the two-line `✓ Analyzed 207 packages ·
      lpm.lock` + `✓ Checked against OSV database`.
- [x] [struct] Drop `(OSV)` suffix on `Vulnerabilities` header (L1192).
- [x] [struct] Vuln rows: `!` (gold) glyph not `ℹ` (L1198), severity as
      `severity unknown` not `[UNKNOWN]`; drop the standalone `ℹ vulnerability
      details:` line (L1218).
- [x] [struct] Suspicious: wrap package list to a 2nd indented line (L1278).
- [x] [struct] Behavioral flags: `·` separators not `, ` (source is the
      analyzer `format!("uses {…}")` at L583/L945 — change to drop "uses " and
      join with ` · `); collapse misc tail to `eval() / dynamic require
      (misc)`; preview `@pkg +N` form (L1304). Implemented in the human
      renderer so `--json` issue messages stay stable.
- [x] [struct] `also:` lead-in line, ` · ` separators, no `ℹ` glyph (L1336).
- [x] [struct] Summary `·` separators + `207 scanned` wording (L1398-1403).
- [x] [struct] Remove trailing `Run lpm audit --json…` hint (L1408).
- [x] [stream] Move all section bodies from `println!` → stderr (Rule 5).
- [x] [color] headers→`section` (gold), `!`→gold, GHSA→`cyan`, counts→gold,
      pkg lists→`dim`, `OSV`→`yellow`.
- [x] [B3] keep dependency-confusion + `--secrets` sections, colored.

### resolve — `commands/resolve.rs`
- [x] [B2/struct] Render `└─` transitive **tree** (nest e.g. scheduler under
      react), `name@version` form, drop the `v` prefix + `npm`/`lpm` kind
      label + leading indent (L79-99).
- [x] [color] version target → `yellow`, tree glyphs/`@` → `dim`. Terminus
      `✓ Resolved N in 0.83s` already correct.

### query — `commands/query.rs`
- [x] [B2/struct] Add per-package `tags:` second line (`tags: eval,
      child-process, …`) — currently folded into `(…)` parenthetical, never a
      2nd line (L383).
- [x] [color] pkg→plain, tags→`dim`. Terminus `!` already gold-correct (L386).

### outdated — `commands/outdated.rs`  (struct MATCH)
- [x] [color] generic — Wanted→`status_ok`/green, Latest(major)→red, section
      label→`dim` (L219-238).

### graph — `commands/graph.rs`  (struct MATCH)
- [x] [color] root version → `yellow`, tree glyphs/`@` → `dim` (L185-196).

### info — `commands/info.rs`
- [x] [struct] integrity ellipsis: `…` (not ASCII `...`) and preserve tail
      `…mQ=` (L45-49).
- [x] [B3] keep distribution/downloads/versions/published sections — color
      them; do not trim to the mockup (L72-101).
- [x] [color] field labels→`dim`, values→plain, dep names aligned (already).

### install — `commands/install.rs` + `install_ui.rs`  (reference, struct MATCH)
- [ ] [color] registry host in phase → `yellow`, `+` diff now green (Rule 4),
      `(vX available)` hint → `dim` (already), terminus elapsed green (already).

### uninstall — `commands/uninstall.rs` + `uninstall_ui.rs`
- [x] [B2] Compute orphaned transitives → print `- pkg@ver (orphaned)`
      list; remove orphaned `node_modules` entries too.
- [x] [B2] Pruned dir line `✓ Cleaned empty directories`.
- [ ] [B2] Security line `✓ found 0 vulnerabilities (was N)`. Needs a
      persisted vulnerability count or an explicit audit pass; not part of the
      client-only uninstall cleanup.
- [ ] [B2] Disk freed line `✓ Freed X on disk`. Needs deletion-size accounting
      before removal.
- [x] [struct] First phase line `› Resolving dependency graph (N packages)`;
      `-` lines must carry `@version` (currently `minus(name, None, None)`).
- [x] [color] target version → `yellow`, removed names → plain, `(orphaned)` →
      `dim`, terminus duration → green.

### remove — `commands/remove.rs`  (redesign not applied at all)
- [x] [struct] Add `› Removing tracked source files for {pkg}` phase, `-`
      (red) per removed file, `✓ Cleaned empty directories`, `✓ Done · removed
      N files in {elapsed}` (L156-159 currently bare `✓ Removed` + dim paths).
- [x] [time] add elapsed (no timing today).
- [x] [color] pkg→`yellow`, file paths→`dim`, `-`→red.

## Group B — tool runners

### bench — `commands/tools.rs` + `tools_ui.rs`  (DONE, reference for [time])
- [x] [color] `Vitest bench runner` → `yellow` (currently plain, tools_ui:38).

### test — `tools.rs`/`tools_ui.rs`
- [x] [color] `Vitest` → `yellow`. Terminus `done_test` retained intentionally
      (Rule 7 / runner-uniform) — leave.

### fmt / lint / check  — `tools.rs`/`tools_ui.rs`  ([time] DONE, glyph swaps DONE)
- [x] [color] tool name (`Biome 2.4.8`/`Oxlint 1.57.0`/`tsc --noEmit`) →
      `yellow` (currently plain, tools_ui:18-24).

### run — `commands/run.rs`
- [x] [time/struct] Single-task path: add `✓ build · success in 4.82s`
      terminus + the `cache miss / command next build` metadata block (run.rs
      ~127-193; `print_task_result` is multi-task only).
- [x] [color] script name → `yellow`, `cache`/`command` labels → `dim`.

### exec — `commands/run.rs`
- [x] [time] add `✓ Done · exited 0 in 412ms` terminus — `exec_file` returns
      through the CLI wrapper, which now owns the completion line.
- [x] [color] runtime (`Node.js 22.12.0`) → `yellow`, file → plain.

### dlx — `commands/run.rs`  (struct MATCH, design has no terminus)
- [x] [color] `cowsay` target → `yellow`, `(fresh)`→green, `0`/`168ms`→green.

### quality — `commands/quality.rs`  (struct MATCH)
- [x] [color] pkg name → `cyan`, `score`/`tier` values → `status_ok`,
      `checks` header → `section`, `+NN` points → green, `✓` per-check green.

## Group C — security / doctor

### doctor — `commands/doctor.rs`  (glyphs+terminus DONE)
- [x] [struct] Column-align detail to the longest check name — L934 prints
      `{name} {detail}` with a single space, no width pad. (Compute max name
      width once.)
- [x] [color] check names → plain, detail → `dim` (already), terminus counts:
      failures→red, warnings→gold.

### health — `commands/health.rs`  (B2 DONE)
- [x] [B2/struct] Build the `Registry {url} / Status ● healthy / Response
      87 ms` table; measure round-trip for the `Response` value; terminus
      `✓ Registry is reachable`.
- [x] [color] `Registry` url → `url`/blue, `●`+`healthy` → green, labels→`dim`.

### sbom — `commands/sbom.rs`  (DONE)
- [x] [struct] Add `› Generating CycloneDX SBOM from lpm.lock`, the
      `packages/format/output` block, `✓ Included patch and provenance
      metadata`, `✓ Done · wrote SBOM in {elapsed}` (emit_sbom L1103-1117).
- [x] [time] add elapsed.
- [x] [color] `CycloneDX` → `yellow`, labels → `dim`, path → `dim`.

### rebuild — `commands/rebuild.rs`  (DONE)
- [x] [struct] Collapse per-package to one line `✓ esbuild@0.25.1 postinstall`;
      drop the `→ phase: cmd` chatter (Rule 6); add `skipped: N blocked
      package` + `hint: run lpm approve-scripts` lines (L1065-1181).
- [x] [time] add `✓ Done · rebuild finished in {elapsed}`.
- [x] [color] pkg→plain, script phase→`dim`, `skipped:` value→gold.

### store verify — `commands/store.rs`  (B2 DONE)
- [x] [B2/struct] Add `links N / objects N` count block + `✓ Checked every
      referenced object hash` intermediate line (L195-545).
- [x] [color] labels→`dim`, counts→plain, terminus green/red.

### security status — `commands/security.rs`  (struct ~MATCH)
- [x] [color] section headers (`effective floor`,`active unlocks`)→`section`,
      policy values (`deny`,`false`)→gold, labels→`dim`.
- [x] [B3] keep policy-sources + runtime-overrides sections, colored.

### cert status — `commands/cert.rs`  (struct MATCH)
- [x] [color] `Root CA`/`Project cert`→`section`, `trusted`/`valid`→
      `status_ok`, labels→`dim`.

### trust diff — `commands/trust.rs`  (struct MATCH)
- [x] [color] `added`/`changed`→`section`, `+`→green, `~`→gold, new hash
      (`sha…new`)→`yellow`, old hash/`→`→`dim`, terminus `!`→gold.

### approve-scripts — `commands/approve_scripts.rs`  ([split] correct — cliclack)
- [ ] [verify] confirm summary glyphs (`✔`/`↷`/`✓ Done · … › lpm.trustedDependencies`)
      render via cliclack as the mockup shows; no slim conversion.

## Group D — auth / identity

### whoami — `commands/whoami.rs` + `whoami_ui.rs`  (showcase, most divergent)
- [x] [struct] `whoami_ui::detail` routes through `install_ui::phase` → every
      label row gets a stray `›` (whoami_ui.rs:19-21). Change `detail` to an
      aligned `  {label:<W}  {value}` with NO glyph.
- [x] [struct] Bare `tolga` header (not `✓ Logged in as …`); labels
      `email/plan/mfa/pool access` (not `Plan/Pool/2FA`); add `✓ Identity
      loaded` terminus.
- [x] [struct] Registries: `● {name}` green bullets (currently `list_item`
      with no bullet); include lpm.dev in the **human** path (today it's
      JSON-only — `build_registries_json` L201 vs human L182-189).
- [x] [color] section headers `usage/scopes/registries`→`section` (gold),
      `enabled`/`yes`→`status_ok`, scopes→`cyan` (already), `admin`→
      `yellow_badge` (already), bars→green (already).
- [x] [B3] keep over-limit + token-expiry warnings.

### dev — `commands/dev.rs` + `dev_ui.rs`
- [ ] [struct] Readiness rows use `dev_ui::detail`→`install_ui::phase` (`›`);
      design wants `● Node / ● Deps / ● Env` green bullets. Switch to `bullet`.
- [ ] [color] values→plain, `(from .nvmrc)`/`(2ms)`→`dim`.
- [ ] [B3] keep the cert-trust prompt block (dev.rs:27-50) — color its labels.

### login — `commands/login.rs`  ([split] browser flow, keep)
- [ ] [struct] Add `✓ Browser authentication complete` + `user:/registry:/
      storage:` detail block (not produced today, L39-206).
- [ ] [color] URLs→`url`/blue, `registry:` value→`yellow`, labels→`dim`.

### logout — `commands/logout.rs`
- [ ] [struct] Phase `› Clearing stored lpm.dev session`; add `✓ Revoked
      server-side token`; terminus `✓ Done · signed out of lpm.dev` (today
      `✓ Successfully logged out.`).
- [ ] [color] `lpm.dev`→`yellow`.

### self-update — `commands/self_update.rs`  (struct ~MATCH)
- [ ] [color] `latest`→`status_ok`/green, update command→`yellow`, target
      version→`yellow`, labels→`dim`.

### upgrade — `commands/upgrade.rs`  (struct MATCH)
- [ ] [color] `↑` minor→gold / patch→green, version target→`yellow`, ranges/
      `→`→`dim`. (Arrow coloring partially present — verify minor=gold.)

### token-rotate — `commands/token.rs`
- [x] [struct] Add the two middle `✓ Old token invalidated` + `✓ New token
      stored in Keychain` lines (today jumps phase→terminus, L14-46).
- [x] [color] `lpm.dev`→`yellow`, `Keychain`→plain.

### migrate — `commands/migrate.rs`  (MISS — untouched, still old `[n/total]` UI)
- [ ] [struct] Full rewrite to slim: `› Detecting current package manager`
      + `source:/backups:` block, `✓ Converted lockfile` + `wrote:` rows,
      `› Running lpm install…`, `✓ Done · migration completed successfully`.
      Remove the bold banner + step counters + "Next steps:" footer.
- [ ] [color] `pnpm-lock.yaml`/`lpm install`→`yellow`, labels→`dim`.

### use — `commands/use.rs` + `use_ui.rs`  (mdx says "should be" — aspirational)
- [ ] [B2/struct] Build: `› Resolving node@22 → 22.12.0 (lts/jod)`, download
      progress bar + `sha256:`, `✓ Extracting/Linking/Pinning`, `✓ Now using
      node 22.12.0 · {elapsed}`, PATH advisory. Needs download-progress +
      timing wiring.
- [x] [color] version→`yellow`, sha→`dim`.

### global — `commands/global.rs`  (SETTLED: build the table)
- [x] [B2/struct] Build the `Package/Current/Wanted/Latest/Bins` table
      (`emit_outdated_human` L380+ currently prints `N outdated:` + rows).
      Data work: `OutdatedRow.latest` is today the **within-range** value
      (= the mockup's **Wanted**) — rename/repurpose it as Wanted, and add a
      new **absolute Latest** (dist-tag `latest`, else max parseable version,
      independent of `saved_spec`) plus the **Bins** column (bin names from the
      global manifest, as `lpm global bin` already knows). Dynamic column
      widths like `lpm outdated`.
- [x] [color] Wanted→`status_ok`/green, Latest major-bump→red / ==Wanted→gold,
      Current/Bins→`dim`, header row→`dim`.

## Group E — env / cache / infra

### cache status — `commands/remote_cache.rs`  (struct MATCH, usage_bar wired)
- [ ] [color] section headers `Local cache`/`Remote cache`→`section`,
      `enabled`/`status` values→`status_ok`, bar→green (already), labels→`dim`.

### ci env — `commands/ci.rs`
- [x] [struct] Add `✓ Emitted N environment variables for generic CI` terminus
      on the stdout-print path (today only `--output=file` has a `✓`, diff
      wording, L88).
- [ ] [color] `export`→purple, var name→`cyan`, value→`yellow`/gold, `***`→red.
      Deferred for stdout formats because `ci env` output is machine-consumed
      by shells and CI env files.

### deploy — `commands/deploy.rs`  (struct MATCH)
- [ ] [color] `api` filter target→`yellow`, `/prod/api`→`yellow`,
      `node_modules installed: yes`→`status_ok`, labels→`dim`.

### pool — `commands/pool.rs`  (struct MATCH)
- [ ] [color] `Pool Revenue Stats`/`packages (N):`→`section`/green, scopes→
      `cyan` (already), `$18.42`→green, download counts→plain, labels→`dim`.

### ports — `commands/ports.rs`
- [x] [struct] Add `●` status dot before each status (now sanctioned)
      (status built L78-88 without glyph).
- [x] [color] port number→`yellow`, `●`+`listening`/`ready`→green, labels→`dim`.

### tunnel — `commands/tunnel.rs`  (PARTIAL)
- [ ] [B2/struct] Add `· region {x}` suffix on opening phase. Needs region
      fetch; **deferred** with backend/API extension.
- [x] [B2/struct] Live `→ METHOD path STATUS {ms}` request stream on the start path.
- [ ] [B2/struct] `press o to open inspector, q to quit` footer (today
      `Ctrl+C`, L281). Needs keypress shutdown wiring.
- [x] [color] `localhost:3000`→`yellow`, public URL/inspector→`url`/blue,
      method (POST gold / GET blue), status (2xx green / 4xx red), `o`/`Ctrl+C`→
      `yellow`, `ms`/`→`→`dim`.

### env ls — `commands/env.rs`
- [x] [B2/struct] Replace `Required/Alias` columns with `Synced/Updated`
      (using vault sync timestamp data); add `Active environment: default`
      footer + `Use lpm env list --env <name>…` hint; drop the `---` dashed
      separator (L1646-1799).
- [x] [color] env names→plain, `yes`→`status_ok`, counts/times→`dim`,
      `Active environment:` value→green.

### config scripts — `commands/config.rs`  ([split] cliclack — correct)
- [x] [struct] Terminus wording `✓ Done · script-policy = "triage"` (today
      `✓ Set script-policy = triage`, no `Done ·`, no quotes, L889-901).
- [x] [color] quoted value→gold.

## Group F — publish / registry / misc

### publish — `commands/publish.rs`  (heavy chatter)
- [ ] [struct] Replace narrate-every-step (`Publishing as…`, `Packing
      tarball…`, `Uploading…`, `Preparing Sigstore…`) per Rule 6; add
      `✓ Secret scan passed` (today debug-only L443), `✓ Quality score: 91/100`
      (today a category table), `› Uploading tarball to lpm.dev` +
      `target/visibility/dist-tag` block; terminus `✓ Done · published … in
      2.41s` (today `✓ Published … (2.4s)` L848-853).
- [ ] [struct] (SETTLED: one line + failing checks) On success print the
      single `✓ Quality score: 91/100` line; do NOT print the full per-category
      table (`print_quality_checks` L1585) on the publish path. If the score is
      below threshold or any check fails/misses, list ONLY the failing checks
      beneath the score line (`! License present  missing`). The full
      per-category breakdown stays in `lpm quality`, not publish.
- [ ] [color] target pkg→`yellow`, `visibility: private`→gold, elapsed→green.
- [ ] [split] confirm + 2FA prompts stay cliclack (correct).

### pack — `commands/pack.rs`  (struct MATCH, tsdown passthrough)
- [ ] [color] `tsdown`→`yellow`, terminus elapsed green (already).

### download — `commands/download.rs`
- [x] [stream] file list prints to stdout (L125-131) — move to stderr.
- [x] [struct] integrity ellipsis `…` not `...` (short_integrity L153).
- [x] [color] `output:`/`files extracted:` labels→`dim`, target→`yellow`.

### search — `commands/search.rs`  (PARTIAL)
- [x] [struct] Drop the `N package(s) for "query":` header; per-result =
      name line + indented description + metadata line `latest 1.4.2 · quality
      91 · ecosystem js`; drop `v` prefix + inline mode badge + `↓ downloads`
      (L45-95).
- [x] [color] query→`cyan`, pkg name→`cyan`, desc→`dim`, `quality NN`→green/
      gold by score, `·`→`dim`.

### skills list — `commands/skills.rs`  (PARTIAL)
- [ ] [struct] Align filenames to a **global** column (today per-package max,
      L93-97).
- [ ] [color] package name→`cyan` (currently `.cyan()` ad-hoc — route through
      helper), file→plain, size→`dim`.

### swift-registry — `commands/swift_registry.rs`  (struct MATCH, has copy test)
- [ ] [color] `lpmdev` scope target→`yellow`; keep the pinned-copy test green.

### mcp setup — `commands/mcp.rs`
- [x] [B2/struct] List ALL editors incl. unconfigured with `○ {name} skipped
      (config not found)` rows (today only configured editors, L305-318);
      align name↔status.
- [x] [color] `✓` green configured / `○` dim skipped, `skipped (…)`→gold,
      `Server name:` value (`lpm-registry`)→`yellow`.

### plugin list — `commands/plugin.rs`  (struct MATCH)
- [ ] [color] `Latest` when newer→`yellow`, `update available`→gold,
      `current`→`status_ok`, labels→`dim`.

### plugin update — `commands/plugin.rs` + `lpm-plugin` crate
- [ ] [struct] Add `› Downloading {tool} {ver}` phase + `✓ Verified SHA-256
      checksum` line (today only the `✓ Updated …` terminus; checksum is
      `tracing`-level in `download.rs:150`).
- [ ] [color] version→`yellow`, `→`→`dim`.

### patch / patch-commit — `commands/patch.rs`  (struct MATCH)
- [ ] [color] target `lodash@4.17.21`→`yellow`, `source:/staging:` paths→
      `dim`, the `lpm patch-commit …` hint→`yellow`, `package.json › lpm.
      patchedDependencies` key→`cyan`.

### patch-remove — `commands/patch.rs`  (PARTIAL — HTML truncated, use mdx)
- [ ] [struct] Align `manifest:`/`file:` labels (mixed `{:<8}` overflow).
- [ ] [color] generic.

### init — `commands/init.rs`  ([split] prompts stay cliclack)
- [ ] [struct] `✓ Wrote package.json` (today `Created`); add `✓ Added lpm.lockb
      binary to .gitattributes` (today silent, L79); add `✓ Done · initialized
      {full-name}` terminus.
- [ ] [color] prompt answers green (cliclack), full name→`cyan`.

### add — `commands/add.rs`  ([split] picker stays cliclack; MISS otherwise)
- [ ] [struct] Build the designed flow: `› Downloading source package {pkg}`,
      `› Detecting project structure` + aligned `Framework:/Install path:/
      Import alias:` block, `✓ Files copied` + `+ file` list, `› Installing
      declared dependencies` + `+ pkg@version` list, `✓ Done · added N files
      and M dependencies in {elapsed}`.
- [ ] [time] add elapsed (none today).
- [ ] [struct] file-conflict warning uses `⚠` (L1392) → change to `!`.
- [ ] [color] target→`yellow`, `+`→green, paths→`dim`.

### filter — `commands/filter.rs`
- [ ] [struct] Prefix each member with `● ` (now sanctioned) — today bare name
      for piping (L316-319). Keep bare form under `--json`/non-TTY pipe; `●`
      for human TTY.
- [ ] [color] `●`→green, member→plain.

### remove/uninstall/resolve/query  — see Group A.

## Group G — passthrough / low-touch (color pass + verify)

- [ ] bundle — `commands/bundle.rs` — HTML truncated; Rolldown passthrough.
      Verify phase `› Bundling …` + `✓ Done · … in {elapsed}`; [color] generic.
- [ ] schema — `commands/schema.rs` — (SETTLED: TTY-gated colorizer) Build a
      small JSON syntax-colorizer over `serde_json::Value` (keys→`cyan`, string
      values→gold, numbers/bools→plain, punctuation→`dim`). Output is stdout
      (the pipeable "answer", L42) so **gate on `stdout` being a TTY** — piped /
      redirected / non-TTY / `NO_COLOR` → emit plain `to_string_pretty` bytes,
      unchanged. Write it as a reusable helper (other JSON-answer surfaces can
      reuse it); add a non-TTY byte-identical test.
- [ ] completions — `commands/completions.rs` — shell-script output is consumed
      by the shell; the design coloring is illustrative only. Leave as plain
      script output. [verify] no human-facing terminus needed.
- [ ] setup local — `commands/setup.rs` — struct ~MATCH; [color] `.npmrc`→
      plain, `30 days`→`yellow`, labels→`dim`.
- [ ] setup ci — `commands/setup.rs` — HTML truncated; use mdx; [color] generic.
- [ ] cache prune — `commands/cache_prune.rs` — [color] generic + verify
      `✓ Done · … in {elapsed}`.

## Cross-cutting verification (after all command rows)

- [ ] `--json` output byte-identical for every touched command.
- [ ] `NO_COLOR` / `--color=never` strips every new color (helpers gate on
      `lpm_common::color::enabled()`).
- [ ] No `println!` for human progress remains except the sanctioned
      table/tree "answer" surfaces (outdated/graph/query/pool/quality).
- [ ] `SLIM_UI.md` glyph/color tables updated to match Rule 1 + `●`.
- [ ] Run the full CI gate (clippy `--workspace --all-targets`, fmt, nextest)
      per CLAUDE.md pre-merge checklist.
