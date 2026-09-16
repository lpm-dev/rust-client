# Expanded source-analysis finding ledger

Nine findings were verified and fixed. None were rejected, externally blocked, or left pending.
The primary agent performed the review; no subagents participated.
All fixes belong to one source-analysis concept and are included in this pull request.

Each correction began with a failing regression. Package removals do not establish that a package is safe.

| ID | Source | Category | Location | Claim and evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EXP-001 | Primary tuning review | Correctness | `behavioral/source.rs`, `bindings.rs` | Local method declarations named `eval` produced evaluator matches, including arithmetic interpreters. | Verified | `local_eval_methods_and_shadowed_function_constructors_are_not_runtime_evaluation` | `7473fa5d` | Included |
| EXP-002 | Primary tuning review | Correctness | `behavioral/bindings.rs` | Locally defined `Function` classes matched the global constructor pattern in LaunchDarkly, Pulumi, and pprof-format. | Verified | Same scoped-name regression and permanent source controls | `7473fa5d` | Included |
| EXP-003 | Primary control review | Correctness | `behavioral/bindings.rs` | Aliased, indirect, optional, and escaped global evaluators were missed. Plain `Function(...)` calls were also missed. | Verified | `runtime_evaluation_survives_aliases_indirection_and_global_member_access` | `7473fa5d` | Included |
| EXP-004 | Primary differential review | Correctness | `behavioral/bindings.rs` | The early candidate removed WDIO REPL's tag despite `vm.runInContext`. Supported VM compilers and evaluators now retain the capability. | Verified | `node_vm_source_evaluation_and_compilation_retain_runtime_capabilities` | `7473fa5d` | Included |
| EXP-005 | Primary original-corpus review | Correctness | `behavioral/bindings.rs`, `source.rs` | Resolving only known globals lost `whatwg-url`'s `globalObject.eval`. Unresolved receivers now retain explicitly qualified evidence. | Verified | `eval_on_an_unresolved_global_object_retains_conservative_capability_evidence` | `7473fa5d` | Included |
| EXP-006 | Primary implementation review | Correctness | `behavioral/bindings.rs` | Getters and writes through receiver aliases invalidated assumptions about local `eval` methods. | Verified | `eval_getters_and_mutated_receivers_retain_conservative_capabilities` | `7473fa5d` | Included |
| EXP-007 | Primary tuning review | Correctness | `behavioral/bindings.rs` | A borrowed `Function.apply` helper falsely identified runtime generation in Fengari Interop. Evidence now points to its actual `Function(...)` call. | Verified | `borrowed_invocation_helpers_do_not_imply_runtime_evaluation`, `runtime_evaluation_evidence_skips_borrowed_invocation_helpers` | `7473fa5d` | Included |
| EXP-008 | Primary acquisition review | Security | `bench/source-analysis/historical.py` | Removing a ZIP prefix could leave an absolute path after a doubled slash. The extractor now rejects that path before writing. | Verified | Archive boundary regression in `test_corpus.py`; path, type, identity, and size controls | `7473fa5d` | Included |
| EXP-009 | Primary initial-validation review | Correctness | `behavioral/supply_chain.rs` | Quoted decoder examples in `js-beautify@2.0.3` produced a critical obfuscation warning. Counts and dispatcher evidence now use executable syntax positions. | Verified | `quoted_decoder_examples_do_not_establish_critical_obfuscation`, `quoted_dispatcher_examples_do_not_establish_obfuscation`; historical controls retained | `9689df6d` | Included |

The integration test `install_cache_and_audit_agree_on_scoped_runtime_evaluation` covers installation, cache refresh, audit JSON, and explicit capability policies.
Schema version 8 invalidates source analyses cached under the previous rules.

## Limits kept separate from verified defects

- Three historical compromised versions do not produce critical source warnings. This detector does not model their full attacks.
- Forwarding methods and browser evaluation callbacks require analysis across calls or modules. Removing a lexical match does not prove absence of evaluation.
- Quoted code can execute later. This scanner does not recursively analyze arbitrary strings as programs.
- The initial validation set became tuning evidence after EXP-009. A fresh 2,000-package set independently evaluated the final frozen detector.

These limits are reported in the [results](report.md). They are not claims that the affected packages are benign.
