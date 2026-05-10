//! Advisor prompt template.
//!
//! Short, single-shot, structured. The advisor is told the role, the
//! package context, the script body, and the exact verdict format.
//! Deliberately concise: every advisor invocation costs tokens (cloud)
//! or compute (local), and the verdict surface is three words. We
//! don't need a thousand-token system prompt to ask one question.

use crate::AmberScript;

/// Build the advisor prompt for one amber script.
///
/// Format is fixed across providers so the verdict parser can be
/// adapter-agnostic. Verdict line must be exactly one of
/// `APPROVE` / `MANUAL` / `ABSTAIN` — see [`crate::parse_verdict`].
pub fn build_prompt(script: &AmberScript<'_>) -> String {
    format!(
        "You are reviewing a single npm package lifecycle script for safety.\n\
         Reply with EXACTLY ONE WORD on the final line — no commentary, no markdown.\n\
         \n\
         APPROVE  — the script does only safe local operations (compile, generate,\n  \
                    file copy, no-op placeholder, local build helper).\n\
         MANUAL   — the script needs human review (network fetch / binary download,\n  \
                    eval, nested package-manager install, shell pipe to fetcher,\n  \
                    unusual obfuscation, anything you would not run unattended).\n\
         ABSTAIN  — you cannot determine safety from the script text alone.\n\
         \n\
         Package: {name}@{version}\n\
         Lifecycle phase: {phase}\n\
         \n\
         Script body:\n\
         ---\n\
         {body}\n\
         ---\n\
         \n\
         Verdict:",
        name = script.package_name,
        version = script.package_version,
        phase = script.phase,
        body = script.script_body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_contains_required_sections() {
        let s = AmberScript {
            package_name: "core-js",
            package_version: "3.39.0",
            phase: "postinstall",
            script_body: "node -e \"try{require('./postinstall')}catch(e){}\"",
        };
        let p = build_prompt(&s);
        assert!(p.contains("core-js@3.39.0"));
        assert!(p.contains("postinstall"));
        assert!(p.contains("node -e"));
        assert!(p.contains("APPROVE"));
        assert!(p.contains("MANUAL"));
        assert!(p.contains("ABSTAIN"));
        assert!(p.ends_with("Verdict:"));
    }
}
