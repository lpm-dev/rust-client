# Plan — H1. Pairing-code phishing → vault wrapping-key compromise

Source finding: `private/security-findings-between-lpmdev-rust-client.md` (H1, currently `- [ ]` unfixed).

Cross-repo scope:
- `lpm-dev/rust-client` — CLI confirmation UX in `crates/lpm-cli/src/commands/env.rs::pair`, transport types in `crates/lpm-vault/src/sync.rs`
- `tolgaergin/a-package-manager` — server routes under `app/api/vault/pair/`, audit logging, rate limiting, step-up auth, email notification

---

## 1. Verification — what the code does today

### Browser
`components/DashboardPages/Common/Secrets/DevicePairingPrompt/DevicePairingPrompt.jsx:81-150`
1. Generates a P-256 ECDH keypair via Web Crypto (private key non-extractable, kept in IndexedDB).
2. `POST /api/vault/pair` with `{ browserPublicKey, deviceLabel: navigator.userAgent.slice(0,200) }` using the Supabase cookie session.
3. Displays the returned 6-char code (32-char alphabet, no `I/O/0/1`, `randomBytes(6)` → ~30 bits of entropy).
4. Polls `GET /api/vault/pair/{code}` every 2 s, ECDH-decrypts the wrap key on `approved`, stores in IndexedDB.

### Server
- `app/api/vault/pair/route.js:16-56` — create pending session (Supabase cookie auth).
- `app/api/vault/pair/[code]/route.js:51-103` — poll (cookie OR bearer).
- `app/api/vault/pair/[code]/route.js:110-199` — CLI approves (bearer, must be session-backed via `requireSessionToken`).
- `app/api/vault/pair/revoke-all/route.js` — bulk revoke (bearer, session-backed).
- DB: `db/schema/vault.js:242-272 vaultDashboardSessions` — stores `userId`, `pairingCode` (unique), `browserPublicKey`, `encryptedWrappingKey`, `ephemeralPublicKey`, `status` (pending/approved/consumed/expired), `deviceLabel`, `expiresAt` (5 min), `createdAt`, `consumedAt`.

### CLI
`crates/lpm-cli/src/commands/env.rs:920-995`
1. Validates code shape (6 ASCII alphanumeric), uppercases.
2. `resolve_session_bearer` (rejects `LPM_TOKEN` / `--token` / CI / legacy via `SessionRequired`).
3. `GET /api/vault/pair/{code}` → reads `browserPublicKey`.
4. Pulls the local wrapping key from the OS keychain.
5. ECDH-wraps for the browser pubkey.
6. `POST /api/vault/pair/{code}` with `{ encryptedWrappingKey, ephemeralPublicKey }`.
7. Prints "browser paired successfully" — **no confirmation prompt, no fingerprint display, no out-of-band binding step**.

### What the finding's "What" line gets partially wrong, and what's still real

The headline attack as written ("victim runs attacker-printed `lpm env pair XXXXXX` → victim's wrap key flows to attacker's browser") is **partially mitigated today** by a check the finding doesn't mention:

```js
// app/api/vault/pair/[code]/route.js:68 (GET) and :160 (POST)
if (session.userId !== tokenRecord.userId) {
  return NextResponse.json({ error: "Pairing session not found" }, { status: 404 })
}
```

So a pairing created in the attacker's own dashboard session (`userId=attacker`) 404s when the victim's CLI presents `userId=victim`. The wrap key never leaves the victim's CLI in that specific scenario.

**Residual attack surface that IS still real and still High:**

| # | Attack | Lands? |
|---|---|---|
| A | Attacker calls `POST /api/vault/pair` *as the victim* via reflected XSS or supply-chain-compromised dashboard JS, embedding `browserPublicKey=attacker_pub` | **Yes** — `userId=victim`, attacker pubkey bound, victim's CLI approval delivers the wrap key to the attacker |
| B | Malicious browser extension with access to `lpm.dev` tabs issues the POST silently with attacker pubkey | **Yes** — same shape |
| C | CSRF on `POST /api/vault/pair` | Mostly closed by Supabase cookie `SameSite=Lax` default, but no explicit CSRF defense — gap |
| D | Unattended unlocked machine — browser still logged in, attacker runs `lpm login` (no 2FA), then `lpm env pair XXXXXX` | **Yes** — and worse than a local secret dump because it leaves the attacker an *ongoing* read capability via IndexedDB |

**Defense-design gaps independent of attack class:**

1. CLI shows nothing about the pairing target before sending the wrap. No `deviceLabel`, no key fingerprint, no `createdAt`, no IP, no confirmation. The server's pending response (`route.js:80-85`) doesn't even include `deviceLabel`, so the CLI couldn't display it if it wanted to.
2. **No rate limit** on any pair route (grep `rateLimiters` in `app/api/vault/pair/`: zero hits). If the userId-binding check ever regresses, blast radius is global.
3. **No audit row** — `logVaultAction` not invoked anywhere in this directory. Victim cannot detect or attribute a rogue pair after the fact.
4. **No out-of-band notification** (email / push) on a new pair. Even with 2FA, a stolen long-lived session token allows a silent pair.

---

## 2. Is pairing-code the right primitive?

**Yes.** Pairing is the right primitive for an E2E-encrypted vault. Replacing it with 2FA is the wrong shape: 2FA proves "you have the second factor right now", pairing proves "this specific browser and this specific CLI are both bound to the same human, and the browser is given a key it can decrypt without the server ever seeing the plaintext". Giving that up turns the dashboard into a server-side decryptor and quietly loses E2E.

What CAN improve is the **human-verifiability** of the pair:

| Scheme | Phishing resistance | Friction | Verdict |
|---|---|---|---|
| 6-char code, dashboard → CLI (today) | Weak — single-channel | 1 paste | No mutual confirmation |
| 6-char code, CLI → dashboard (flipped) | Same | 1 paste | Same weakness, flipped direction |
| TOTP-style 2FA in place of code | Solves replay, not channel-binding | Hardware/app dep | Wrong tool for the binding problem |
| **Number / emoji matching (Microsoft Authenticator pattern)** | **Strong** | **1 glance + 1 paste** | **Recommended** |
| WebAuthn / passkey-anchored pairing | Strongest | Hardware + full UX overhaul | Out of proportion vs marginal win over number-matching |

**Decision: keep the 6-char code as the routing primitive, add number-matching + a CLI confirmation prompt for binding.**

---

## 3. Plan

### Step group 1 — close the headline attack class
*Cross-repo. ~1 day. No schema migration. This is the H1 closer.*

**Server (`a-package-manager`):**

1. **Surface binding metadata in the pending GET response.** Edit `app/api/vault/pair/[code]/route.js:80-85` to include `deviceLabel`, `createdAt`, `browserKeyFingerprint` (first 8 bytes of `sha256(base64-decoded browserPublicKey)`, hex `XX:XX:XX:XX:XX:XX:XX:XX`), and `createdFromIp` (truncated, last octet zeroed for IPv4 / last 80 bits zeroed for IPv6 — privacy-respecting but useful).

2. **Add `matchNumber` (00–99) derived deterministically from `sha256(pairingCode || browserPublicKey)[0..2] % 100`.** Include it in the create-response (so the browser can render it next to the code) and in the pending poll (so the CLI can render the same value). Stable, deterministic, no extra DB columns.

3. **Rate-limit all three pair routes.** New `vaultPair` bucket in `lib/security/rate-limit.js`: 10/min/IP AND 20/min/user (both must pass, matching the `H3` pattern already in the repo per the findings doc). Apply at the top of `app/api/vault/pair/route.js`, `app/api/vault/pair/[code]/route.js`, `app/api/vault/pair/revoke-all/route.js`.

4. **Emit audit log entries.** `logVaultAction` calls for `pair_create`, `pair_approve`, `pair_consume`, `pair_revoke_all` with `pairing_code_hash`, `device_label`, `ip` (truncated), `user_agent`. Surfaces in the dashboard activity log → victim can detect rogue pairs.

**Browser (`a-package-manager`, same PR):**

5. **Display `matchNumber` next to the pairing code** in `DevicePairingPrompt.jsx`. Render as a large, contrast-distinct two-digit number under the code, with caption "Match this number on your terminal".

**CLI (`lpm-dev/rust-client`):**

6. **Interactive confirmation between fetch and approve** in `crates/lpm-cli/src/commands/env.rs:946-979`. Use `dialoguer::Confirm` (already a workspace dep via other commands). Default no. Re-prompt on empty input. Output shape:

   ```
   Pair this browser?
     Device:      Chrome on macOS
     Created:     12s ago, from IP 203.0.113.0/24
     Fingerprint: 9a:c3:f1:80:42:7e:b5:11
     Verify the dashboard shows the number: 47

   Continue? [y/N]:
   ```

7. **Sanitize `deviceLabel`** with control-char stripping before display (server stores `navigator.userAgent.slice(0, 200)`, which is attacker-influenced via UA spoofing in the browser tab).

8. **Extend `PairingSession` in `crates/lpm-vault/src/sync.rs:1025-1030`** with the new fields (`device_label`, `created_at`, `created_from_ip`, `browser_key_fingerprint`, `match_number`). All `Option<String>` to keep backward-compat with older servers (CLI degrades gracefully by skipping unavailable fields in the prompt).

**Tests:**

- **Server unit** (a-package-manager): rate-limit hit on all three routes; audit row written for each transition; `matchNumber` is deterministic and identical across create and poll responses; truncated-IP shape.
- **Server contract**: fingerprint + matchNumber + deviceLabel + createdAt + createdFromIp all present in pending GET response; absent on `consumed` / `approved` / `expired`.
- **Client workflow** (`tests/workflows/tests/env_pair.rs`, new file): pair confirms with `y`, aborts with `n`/empty/EOF/garbage, prompt displays fingerprint + matchNumber + sanitized deviceLabel, control bytes in `deviceLabel` are stripped (not rendered to the terminal), missing optional fields don't break the prompt (older-server compatibility).

### Step group 2 — close the unattended-machine class
*Server-only. ~1 day. No schema migration.*

9. **Step-up auth on `POST /api/vault/pair`.** Require recent (`<5 min`) password re-entry or passkey confirmation before issuing a new pairing code, even with a valid Supabase session. Reuses whatever step-up mechanism exists; if none, this is the time to introduce one (likely a `vault_step_up_at` column on `users` or a short-lived signed cookie).

10. **Email notification on `pair_approve`.** "A new browser was paired to your vault from IP X (Chrome on macOS) at HH:MM. If this wasn't you, run `lpm env unpair` and reset your password." Reuses existing email transport.

### Step group 3 — defense-in-depth
*Server-only. ~half-day.*

11. **Per-row pair revoke.** `DELETE /api/vault/pair/[id]` so the dashboard's paired-browsers list can revoke a single rogue pair without losing the legitimate active session. (Today `unpair_all` is all-or-nothing.)

12. **Explicit CSRF token on `POST /api/vault/pair`.** Even with `SameSite=Lax`, the defense-in-depth gap is worth a header check (e.g., a `Sec-Fetch-Site` enforcement or a double-submit token).

### Step group 4 — strategic, separate decision
*Product call, not a security fix. Track separately.*

13. **Mandatory 2FA at `lpm login`** (or at minimum a forced-upgrade banner). Closes the "attacker runs `lpm login` on unattended machine" half of D, plus several other findings in the doc.

---

## 4. PR sequencing

Per memory `feedback_no_stacked_prs.md` — one branch per repo per batch, named for the scope.

- **`security/H1-pair-confirmation`** — step group 1 only.
  - `lpm-dev/rust-client` branch (steps 6, 7, 8)
  - `a-package-manager` branch (steps 1, 2, 3, 4, 5)
  - Both open at the same time, cross-link in PR descriptions, surface both halves explicitly so neither reads as deferred (per `feedback_proactive_next_step_when_work_is_multi_repo.md`).
  - This is the entry that flips the H1 checkbox from `- [ ]` to `- [x]`.

- **`security/pair-step-up-and-notify`** — step group 2 + 3, `a-package-manager` only. Separate because the code area, reviewer, and risk profile are different from group 1.

- **`product/mandatory-2fa`** — step group 4, tracked outside the security-findings scope.

---

## 5. What this does NOT close

- A fully compromised admin session token on the victim's account can still pair after step-up auth (step-up grants a 5-min window that the attacker, holding the cookie, also gets). Closing this requires hardware-backed step-up (passkey) — listed but not selected for cost reasons.
- An attacker with persistent IndexedDB read (e.g., post-XSS) can read the wrap key even without pairing. That's the XSS finding's domain, not H1's.
- Audit-log tamper resistance — `logVaultAction` writes to the same DB the attacker may also be able to write to. Out of scope here; covered by general audit-log integrity discussion elsewhere.
