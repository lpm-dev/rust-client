use serde_json::{Value, json};

use super::*;
use crate::lpm_env_release;

const OVERRIDES_MARKER: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;

fn base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Call `function` with `request` and return its status and JSON output,
/// releasing the result.
fn call(
    function: unsafe extern "C" fn(*const u8, usize) -> LPMEnvResult,
    request: &Value,
) -> (u32, Value) {
    let input = serde_json::to_vec(request).unwrap();
    // SAFETY: The input stays live throughout the synchronous call.
    let result = unsafe { function(input.as_ptr(), input.len()) };
    // SAFETY: The result is live and unreleased until the release below.
    let output =
        serde_json::from_slice(unsafe { std::slice::from_raw_parts(result.data, result.length) })
            .unwrap();
    let status = result.status;
    // SAFETY: This is the sole release of the returned result.
    unsafe { lpm_env_release(result) };
    (status, output)
}

fn marker_name(vault_id: &str) -> String {
    lpm_env_companion::account::marker_account(vault_id)
}

fn record_name(kind: &str, part: Option<u16>) -> String {
    lpm_env_companion::account::record_account(kind, "proj", part)
}

#[test]
fn every_account_fixture_is_described_as_the_crate_parses_it() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        account: String,
        valid: bool,
        #[serde(rename = "type")]
        role: Option<String>,
        vault_id: Option<String>,
        kind: Option<String>,
        part: Option<u16>,
        access_class: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Fixture {
        cases: Vec<Case>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../lpm-env-companion/tests/fixtures/accounts.json"
    ))
    .unwrap();
    let names: Vec<&str> = fixture
        .cases
        .iter()
        .map(|case| case.account.as_str())
        .collect();
    let (status, output) = call(lpm_env_companion_accounts, &json!({ "names": names }));
    assert_eq!(status, 0);
    for (case, described) in fixture
        .cases
        .iter()
        .zip(output["accounts"].as_array().unwrap())
    {
        if !lpm_env_companion::account::is_in_companion_namespace(&case.account) {
            assert!(described.is_null(), "{}", case.account);
            continue;
        }
        assert_eq!(described["valid"], case.valid, "{}", case.account);
        if !case.valid {
            assert_eq!(described.as_object().unwrap().len(), 1, "{}", case.account);
            continue;
        }
        assert_eq!(described["role"], json!(case.role), "{}", case.account);
        assert_eq!(
            described["vaultId"],
            json!(case.vault_id),
            "{}",
            case.account
        );
        assert_eq!(described["kind"], json!(case.kind), "{}", case.account);
        assert_eq!(described["part"], json!(case.part), "{}", case.account);
        let access = case.access_class.as_deref().unwrap_or("open");
        assert_eq!(described["access"], access, "{}", case.account);
    }
    let (_, outside) = call(lpm_env_companion_accounts, &json!({ "names": ["proj"] }));
    assert_eq!(outside["accounts"], json!([null]));
}

#[test]
fn account_names_have_one_spelling_and_refuse_anything_else() {
    let (status, output) = call(
        lpm_env_companion_account_names,
        &json!({ "accounts": [
            { "role": "marker", "vaultId": "proj" },
            { "role": "record", "vaultId": "proj", "kind": "history", "part": 15 },
            { "role": "staged", "vaultId": "proj", "kind": "overrides" },
        ] }),
    );
    assert_eq!(status, 0);
    assert_eq!(
        output["names"],
        json!([
            marker_name("proj"),
            record_name("history", Some(15)),
            lpm_env_companion::account::staged_account("overrides", "proj", None),
        ])
    );
    for invalid in [
        json!({ "role": "record", "vaultId": "proj", "kind": "Overrides" }),
        json!({ "role": "record", "vaultId": "proj", "kind": "features" }),
        json!({ "role": "record", "vaultId": "proj", "kind": "history", "part": 4096 }),
        json!({ "role": "record", "vaultId": "proj" }),
        json!({ "role": "marker", "vaultId": "proj", "kind": "overrides" }),
        json!({ "role": "marker", "vaultId": "not a vault/id" }),
    ] {
        let (status, output) = call(
            lpm_env_companion_account_names,
            &json!({ "accounts": [invalid] }),
        );
        assert_eq!(status, 2, "{invalid}");
        assert_eq!(output["code"], "companion.invalid_account", "{invalid}");
    }
}

#[test]
fn a_healthy_project_is_valid_and_allows_everything() {
    let (status, output) = call(
        lpm_env_companion_assess,
        &json!({
            "vaultId": "proj",
            "marker": base64(OVERRIDES_MARKER.as_bytes()),
            "inventory": [marker_name("proj"), record_name("overrides", None), marker_name("other")],
        }),
    );
    assert_eq!(status, 0);
    assert_eq!(output["marker"], "valid");
    assert_eq!(output["state"], "active");
    assert_eq!(output["needsResume"], false);
    assert_eq!(output["level"], "ignore");
    assert_eq!(output["unsupported"], Value::Null);
    assert_eq!(
        output["features"],
        json!([{ "name": "overrides", "version": 1, "ifUnsupported": "refuse", "kinds": ["overrides"], "state": "active", "supported": true }])
    );
    assert_eq!(output["damage"], json!([]));
    assert_eq!(
        output["allows"],
        json!({ "readExcludingOverrides": true, "readApplyingOverrides": true, "write": true })
    );
}

#[test]
fn every_marker_fixture_assesses_with_its_recorded_level() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        name: String,
        vault_id: String,
        json: String,
        valid: bool,
        level: Option<String>,
        needs_resume: Option<bool>,
    }
    #[derive(serde::Deserialize)]
    struct Fixture {
        cases: Vec<Case>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../lpm-env-companion/tests/fixtures/markers.json"
    ))
    .unwrap();
    for case in fixture.cases {
        let (status, output) = call(
            lpm_env_companion_assess,
            &json!({ "vaultId": case.vault_id, "marker": base64(case.json.as_bytes()) }),
        );
        assert_eq!(status, 0, "{}", case.name);
        assert_eq!(
            output["marker"],
            if case.valid { "valid" } else { "invalid" },
            "{}",
            case.name
        );
        assert_eq!(output["level"], json!(case.level), "{}", case.name);
        if let Some(needs_resume) = case.needs_resume {
            assert_eq!(output["needsResume"], needs_resume, "{}", case.name);
        }
        if !case.valid {
            assert_eq!(
                output["damage"][0]["code"], "invalidMarker",
                "{}",
                case.name
            );
            assert_eq!(
                output["damage"][0]["repair"],
                json!({ "action": "discardProject" }),
                "{}",
                case.name
            );
        }
        let refuses_everything = !case.valid || case.level.as_deref() == Some("refuse");
        let reads = !refuses_everything && case.needs_resume != Some(true);
        assert_eq!(
            output["allows"]["readExcludingOverrides"], reads,
            "{}",
            case.name
        );
        let writes = reads && case.level.as_deref() == Some("ignore");
        assert_eq!(output["allows"]["write"], writes, "{}", case.name);
    }
}

#[test]
fn an_unsupported_feature_names_itself_and_its_level() {
    let newer = OVERRIDES_MARKER.replace(r#""version":1"#, r#""version":2"#);
    let (_, output) = call(
        lpm_env_companion_assess,
        &json!({ "vaultId": "proj", "marker": base64(newer.as_bytes()) }),
    );
    assert_eq!(
        output["unsupported"],
        json!({ "feature": "overrides", "version": 2, "level": "refuse" })
    );
    assert_eq!(output["features"][0]["supported"], false);
    assert_eq!(
        output["allows"],
        json!({ "readExcludingOverrides": false, "readApplyingOverrides": false, "write": false })
    );
}

#[test]
fn damage_carries_its_repair_and_only_damaged_overrides_still_allow_excluding_reads() {
    let (_, missing) = call(
        lpm_env_companion_assess,
        &json!({ "vaultId": "proj", "marker": base64(OVERRIDES_MARKER.as_bytes()), "inventory": [] }),
    );
    assert_eq!(
        missing["damage"],
        json!([{ "code": "missingRecord", "kind": "overrides", "repair": { "action": "removeFeature", "feature": "overrides" } }])
    );
    assert_eq!(
        missing["repairs"],
        json!([{ "action": "removeFeature", "feature": "overrides" }])
    );
    assert_eq!(
        missing["allows"],
        json!({ "readExcludingOverrides": true, "readApplyingOverrides": false, "write": false })
    );

    let (_, markerless) = call(
        lpm_env_companion_assess,
        &json!({ "vaultId": "proj", "inventory": [record_name("overrides", None)] }),
    );
    assert_eq!(markerless["marker"], "absent");
    assert_eq!(
        markerless["damage"],
        json!([{ "code": "unlistedRecord", "kind": "overrides", "repair": { "action": "discardProject" } }])
    );
    assert_eq!(
        markerless["repairs"],
        json!([{ "action": "discardProject" }])
    );

    let (_, invalid_record) = call(
        lpm_env_companion_assess,
        &json!({
            "vaultId": "proj",
            "marker": base64(OVERRIDES_MARKER.as_bytes()),
            "overrides": { "bytes": base64(b"[]") },
        }),
    );
    assert_eq!(invalid_record["damage"][0]["code"], "invalidRecord");
    assert!(invalid_record["damage"][0]["reason"].is_string());

    let (_, access) = call(
        lpm_env_companion_assess,
        &json!({ "vaultId": "proj", "accessDamage": "contradictory approval" }),
    );
    assert_eq!(
        access["damage"],
        json!([{ "code": "access", "reason": "contradictory approval", "repair": null }])
    );
    assert_eq!(access["repairs"], json!([]));
    assert_eq!(access["allows"]["readExcludingOverrides"], false);
}

#[test]
fn an_interrupted_step_allows_nothing_until_it_is_resumed() {
    let deleting = OVERRIDES_MARKER.replace(
        r#""state":"active","features""#,
        r#""state":"deleting","features""#,
    );
    let (_, output) = call(
        lpm_env_companion_assess,
        &json!({ "vaultId": "proj", "marker": base64(deleting.as_bytes()) }),
    );
    assert_eq!(output["needsResume"], true);
    assert_eq!(output["state"], "deleting");
    assert_eq!(
        output["allows"],
        json!({ "readExcludingOverrides": false, "readApplyingOverrides": false, "write": false })
    );

    let mut parts: Vec<String> = (0..40)
        .map(|part| record_name("future-log", Some(part)))
        .collect();
    parts.push(record_name("overrides", None));
    let (status, plan) = call(
        lpm_env_companion_plan,
        &json!({ "action": "resume", "vaultId": "proj", "marker": base64(deleting.as_bytes()), "inventory": parts }),
    );
    assert_eq!(status, 0);
    assert_eq!(
        plan["notice"],
        json!({ "kind": "deletion", "features": [] })
    );
    let transactions = plan["transactions"].as_array().unwrap();
    assert!(transactions.len() >= 2);
    assert_eq!(
        transactions[0]["deletes"][0],
        record_name("overrides", None)
    );
    assert!(
        transactions
            .iter()
            .all(|transaction| transaction["moves"] == json!([]))
    );
    assert_eq!(transactions.last().unwrap()["deletesMarker"], true);
    assert_eq!(plan["result"], Value::Null);
}

#[test]
fn a_deletion_plan_leaves_room_for_the_callers_own_changes() {
    let (status, plan) = call(
        lpm_env_companion_plan,
        &json!({
            "action": "delete",
            "vaultId": "proj",
            "marker": base64(OVERRIDES_MARKER.as_bytes()),
            "inventory": [record_name("overrides", None)],
            "ownOperations": 3,
        }),
    );
    assert_eq!(status, 0);
    assert_eq!(
        plan["transactions"],
        json!([{ "deletes": [record_name("overrides", None)], "moves": [], "writesMarker": null, "deletesMarker": true }])
    );

    let (_, absent) = call(
        lpm_env_companion_plan,
        &json!({ "action": "delete", "vaultId": "proj", "inventory": [] }),
    );
    assert_eq!(absent["transactions"], json!([]));
}

#[test]
fn a_deletion_plan_refuses_own_changes_that_leave_no_room() {
    for own in [json!(32), json!(u64::MAX)] {
        let (status, refused) = call(
            lpm_env_companion_plan,
            &json!({
                "action": "delete",
                "vaultId": "proj",
                "marker": base64(OVERRIDES_MARKER.as_bytes()),
                "inventory": [record_name("overrides", None)],
                "ownOperations": own,
            }),
        );
        assert_ne!(status, 0, "{own}");
        assert_eq!(refused["code"], "companion.refused", "{own}");
    }
}

#[test]
fn feature_and_unlisted_removals_need_a_valid_marker() {
    let inventory = json!([record_name("overrides", None), record_name("notes", None)]);
    let (status, removal) = call(
        lpm_env_companion_plan,
        &json!({ "action": "removeFeature", "vaultId": "proj", "marker": base64(OVERRIDES_MARKER.as_bytes()), "inventory": inventory, "feature": "overrides" }),
    );
    assert_eq!(status, 0);
    assert_eq!(
        removal["transactions"][0]["deletes"],
        json!([record_name("overrides", None)])
    );
    let result: Value = serde_json::from_slice(
        &STANDARD
            .decode(removal["result"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["features"], json!({}));

    let (status, unlisted) = call(
        lpm_env_companion_plan,
        &json!({ "action": "removeUnlisted", "vaultId": "proj", "marker": base64(OVERRIDES_MARKER.as_bytes()), "inventory": inventory }),
    );
    assert_eq!(status, 0);
    assert_eq!(
        unlisted["transactions"],
        json!([{ "deletes": [record_name("notes", None)], "moves": [], "writesMarker": null, "deletesMarker": false }])
    );

    let (status, refused) = call(
        lpm_env_companion_plan,
        &json!({ "action": "removeUnlisted", "vaultId": "proj", "marker": base64(b"{}"), "inventory": inventory }),
    );
    assert_eq!(status, 5);
    assert_eq!(refused["code"], "companion.refused");
    let (status, _) = call(
        lpm_env_companion_plan,
        &json!({ "action": "removeFeature", "vaultId": "proj", "marker": base64(OVERRIDES_MARKER.as_bytes()), "inventory": inventory }),
    );
    assert_eq!(status, 2);
}

#[test]
fn a_transaction_check_refuses_unlisted_writes_and_needs_each_live_marker() {
    let marker = marker_name("proj");
    let (status, _) = call(
        lpm_env_companion_check_transaction,
        &json!({
            "changes": [
                { "account": marker, "bytes": base64(OVERRIDES_MARKER.as_bytes()) },
                { "account": record_name("overrides", None), "bytes": "" },
                { "account": "proj", "bytes": base64(b"{}") },
            ],
            "markers": { "proj": null },
        }),
    );
    assert_eq!(status, 0);

    let (status, deletion) = call(
        lpm_env_companion_check_transaction,
        &json!({ "changes": [{ "account": record_name("overrides", None), "bytes": null }], "markers": {} }),
    );
    assert_eq!(status, 0, "deleting records reads no marker: {deletion}");

    let (status, refused) = call(
        lpm_env_companion_check_transaction,
        &json!({
            "changes": [{ "account": record_name("notes", None), "bytes": "" }],
            "markers": { "proj": base64(OVERRIDES_MARKER.as_bytes()) },
        }),
    );
    assert_eq!(status, 5);
    assert!(
        refused["message"]
            .as_str()
            .unwrap()
            .contains("without a feature that lists it")
    );

    let (status, missing) = call(
        lpm_env_companion_check_transaction,
        &json!({ "changes": [{ "account": record_name("overrides", None), "bytes": "" }], "markers": {} }),
    );
    assert_eq!(status, 2);
    assert_eq!(missing["code"], "companion.missing_marker");

    let (status, orphans) = call(
        lpm_env_companion_check_transaction,
        &json!({
            "changes": [{ "account": marker, "bytes": null }],
            "markers": { "proj": base64(OVERRIDES_MARKER.as_bytes()) },
            "names": [marker, record_name("overrides", None)],
        }),
    );
    assert_eq!(status, 5);
    assert!(orphans["message"].as_str().unwrap().contains("would leave"));

    let (status, missing) = call(
        lpm_env_companion_check_transaction,
        &json!({
            "changes": [{ "account": marker, "bytes": null }],
            "markers": { "proj": base64(OVERRIDES_MARKER.as_bytes()) },
        }),
    );
    assert_eq!(status, 2);
    assert_eq!(missing["code"], "companion.missing_names");
}

#[test]
fn malformed_requests_are_invalid_input() {
    for request in [
        json!({ "names": "proj" }),
        json!({ "names": [], "extra": true }),
    ] {
        assert_eq!(call(lpm_env_companion_accounts, &request).0, 2, "{request}");
    }
    for request in [
        json!({ "vaultId": "proj", "marker": "not base64!" }),
        json!({ "vaultId": "../proj" }),
    ] {
        assert_eq!(call(lpm_env_companion_assess, &request).0, 2, "{request}");
    }
    // SAFETY: A null pointer with a length is refused before it's read.
    let result = unsafe { lpm_env_companion_assess(std::ptr::null(), 4) };
    assert_eq!(result.status, 2);
    // SAFETY: This is the sole release of the returned result.
    unsafe { lpm_env_release(result) };
    let oversized = vec![b' '; INPUT_LIMIT + 1];
    // SAFETY: The input stays live throughout the synchronous call.
    let result = unsafe { lpm_env_companion_plan(oversized.as_ptr(), oversized.len()) };
    assert_eq!(result.status, 2);
    // SAFETY: This is the sole release of the returned result.
    unsafe { lpm_env_release(result) };
}

#[test]
fn the_header_declares_every_companion_function_and_the_input_limit() {
    let header = include_str!("../../include/lpm_env.h");
    assert!(header.contains("#define LPM_ENV_INPUT_LIMIT (2 * 1024 * 1024)"));
    assert_eq!(INPUT_LIMIT, 2 * 1024 * 1024);
    for function in [
        "lpm_env_companion_accounts(const uint8_t *input, size_t input_length);",
        "lpm_env_companion_account_names(const uint8_t *input, size_t input_length);",
        "lpm_env_companion_assess(const uint8_t *input, size_t input_length);",
        "lpm_env_companion_plan(const uint8_t *input, size_t input_length);",
        "lpm_env_companion_check_transaction(const uint8_t *input, size_t input_length);",
    ] {
        assert!(header.contains(function), "{function}");
    }
}
