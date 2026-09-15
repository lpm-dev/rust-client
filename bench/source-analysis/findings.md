# Source analysis finding ledger

Nine findings were verified and fixed. None were rejected, externally blocked, or left pending.
All changes belong to one source-analysis concept branch. The branch is not merged.
No subagents participated in this review.

Each regression failed before its corresponding production correction.
The resolution commits are `d87e9982` and `6569ea1c`.

| ID | Source | Category | Location | Claim and evidence | Disposition | Regression coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SRC-001 | Primary corpus review | Correctness | `behavioral/source.rs`, `bindings.rs` | Local `exec` helpers or callbacks produced process tags in Wrap ANSI, Diff, Prettier, and Core JS. | Verified | `local_exec_helpers_and_callbacks_are_not_child_processes` | `d87e9982` | Unmerged concept branch |
| SRC-002 | Primary corpus review | Correctness | `behavioral/source.rs`, `bindings.rs` | CSS `this.import` and method declarations named `require` matched module-loader patterns. | Verified | `methods_and_declarations_named_import_or_require_are_not_dynamic_loads` | `d87e9982` | Unmerged concept branch |
| SRC-003 | Primary corpus review | Correctness | `behavioral/source.rs`, `bindings.rs` | Static bundled calls such as `require(3)` matched dynamic-loading patterns. Some packages retain a valid loader tag at another location. | Verified | `literal_module_ids_in_bundled_loaders_are_static` | `d87e9982` | Unmerged concept branch |
| SRC-004 | Primary corpus review | Correctness | `behavioral/source.rs`, `bindings.rs` | A process import produced a shell tag, including Commander calls that use `spawn` without a shell. | Verified | `spawning_a_process_without_a_shell_does_not_imply_shell_execution` | `d87e9982` | Unmerged concept branch |
| SRC-005 | Primary implementation review | Correctness | `audit/types.rs`, `behavior.rs`, `scan.rs` | Deduplication discarded local evidence when a registry result had the same message. The regression reproduced an empty evidence list. | Verified | `registry_behavior_duplicates_retain_local_source_evidence` | `d87e9982` | Unmerged concept branch |
| SRC-006 | Primary differential review | Correctness | `behavioral/bindings.rs` | The first candidate missed Sharp's shell options in constants and object spreads. | Verified | `shell_options_follow_constants_spreads_and_conditional_values`, `explicit_false_shell_option_overrides_a_spread` | `d87e9982` | Unmerged concept branch |
| SRC-007 | Primary validation review | Correctness | `behavioral/bindings.rs` | The first validation candidate missed a deferred `createRequire` assignment in `import-in-the-middle`. | Verified | `loaders_and_process_aliases_assigned_after_declaration_remain_detectable` | `d87e9982` | Unmerged concept branch |
| SRC-008 | Primary final code review | Correctness | `behavioral/bindings.rs` | Library helper calls such as Execa `parseCommand` and ShellJS `which` incorrectly implied process execution. | Verified | `process_library_helpers_do_not_imply_process_or_shell_execution`, `execa_entry_points_and_shelljs_exec_retain_process_capabilities` | `d87e9982` | Unmerged concept branch |
| SRC-009 | Primary differential review | Correctness | `behavioral/bindings.rs` | The candidate classified `require('u' + 'rl')` in `@pkgr/core` as dynamic. Fixed string expressions now remain static, with process-module recognition preserved. | Verified | `constant_string_module_specifiers_are_static`, `constant_string_process_imports_retain_capabilities` | `6569ea1c` | Unmerged concept branch |

Source-only API findings now appear as capabilities. Explicit policies still use the shared severity definitions.
Evidence retention, serialization, directory/streaming parity, and sampled-file positions also have regression coverage.
The [report](report.md) distinguishes verified matcher errors from uncertain shell removals and describes validation limits.
