# Credential-exfiltration finding ledger

Ten findings were verified and fixed. Zero were rejected, externally blocked, or left pending.
The primary agent reviewed the detector and controls. No subagents participated.
All findings belong to the credential-exfiltration detection concept.
Historical package contents remain private and are never executed.

| ID | Source | Category | Location | Claim and evidence | Disposition | Coverage | Commit | PR status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| THR-001 | Historical review | Security | Source analysis | The compromised XRPL bundle sends a generated wallet seed in an HTTP header without a critical source warning. | Verified | `wallet_seed_in_an_outbound_header_is_a_security_finding` | `f44b769b` | Included in this PR |
| THR-002 | Historical review | Security | Source analysis | The compromised Solana helper encodes and uploads secret-key arguments without a critical source warning. | Verified | `secret_passed_through_a_static_encoding_helper_is_a_security_finding` | `f44b769b` | Included in this PR |
| THR-003 | Historical review | Security | Source analysis | The tinycolor payload sends the complete environment through a bundled repository-upload helper. | Verified | `entire_environment_uploaded_through_a_repository_helper_is_a_security_finding`; `bundled_class_helper_preserves_the_environment_upload_flow` | `f44b769b` | Included in this PR |
| THR-004 | Historical review | Correctness | Scan limits | Head-and-tail sampling omits the upload implementation in the 3.7 MB tinycolor bundle. | Verified | `source_in_the_middle_of_a_four_megabyte_bundle_is_analyzed` | `f44b769b` | Included in this PR |
| THR-005 | Implementation review | Correctness | Value propagation | Overwritten values, duplicate properties, and unused fetch options can establish false upload flows. | Verified | `overwritten_secrets_and_unused_fetch_options_do_not_report_leaks` | `f44b769b` | Included in this PR |
| THR-006 | Implementation review | Correctness | Receiver resolution | Object mutations and static/instance method collisions can link unrelated values. Invalidating unrelated class properties can also hide a real upload. | Verified | `mutated_objects_and_distinct_method_receivers_do_not_link_unrelated_values`; `unrelated_class_properties_do_not_hide_a_secret_upload` | `f44b769b` | Included in this PR |
| THR-007 | Implementation review | Correctness | Source identification | Local functions with wallet API names can return public values and produce false warnings. | Verified | `local_functions_with_wallet_api_names_do_not_establish_secret_origins` | `f44b769b` | Included in this PR |
| THR-008 | Implementation review | Performance | Binding and method lookup | Repeated reference scans and linear method lookup can multiply work for heavily reused bindings. | Verified | Precomputed write and method indexes; source and install benchmarks | `f44b769b` | Included in this PR |
| THR-009 | Implementation review | Correctness | Oversized-file sampling | Concatenated head and tail samples can create a nonexistent flow across separate functions. A failing synthetic regression reproduces it. | Verified | `disjoint_file_samples_do_not_establish_a_secret_flow` | `f44b769b` | Included in this PR |
| THR-010 | Final implementation review | Correctness | Request field resolution | A computed property can replace a secret body or headers. The detector followed the replaced value. The failing regression pins property order and retains an explicit final secret body. | Verified | `computed_properties_that_can_replace_a_payload_do_not_establish_a_secret_flow` | `f44b769b` | Included in this PR |

The workflow `install_audit_and_query_report_secret_uploads_as_critical_findings` checks the installation summary, stored analysis, audit JSON evidence, default audit failure, and query policies.

For THR-008, write classification scans resolved references once. Later value lookups use a set lookup instead of another reference scan.
Class methods also use an index by class, receiver kind, and property name.
This bounds repeated lookup work without claiming that the index alone caused the measured end-to-end result.
