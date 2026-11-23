use std::collections::BTreeMap;

use super::*;
use crate::frame::{FRAME_MAGIC, FRAME_VERSION, decode_frame};
use crate::{lpm_env_check, lpm_env_release};

const VAULT: &str = "proj";
const MARKER_ACCOUNT: &str = "__vault_features_v1__:cHJvag";
const RECORD_ACCOUNT: &str = "__vault_companion_v1__:overrides:cHJvag";
const OVERRIDES_MARKER: &str = r#"{"schemaVersion":1,"vaultId":"proj","state":"active","features":{"overrides":{"version":1,"ifUnsupported":"refuse","kinds":["overrides"],"state":"active"}}}"#;

fn frame(request: &Value, blobs: &[&[u8]]) -> Vec<u8> {
    let request = serde_json::to_vec(request).expect("json");
    let mut out = Vec::new();
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.extend_from_slice(&((blobs.len() + 1) as u32).to_be_bytes());
    out.extend_from_slice(&(request.len() as u32).to_be_bytes());
    out.extend_from_slice(&request);
    for blob in blobs {
        out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        out.extend_from_slice(blob);
    }
    out
}

/// Call `function`, release its result, and return its status, response
/// and blobs.
fn call(
    function: unsafe extern "C" fn(*const u8, usize) -> LPMEnvResult,
    request: &Value,
    blobs: &[&[u8]],
) -> (u32, Value, Vec<Vec<u8>>) {
    let input = frame(request, blobs);
    // SAFETY: The input stays alive for the synchronous call.
    let result = unsafe { function(input.as_ptr(), input.len()) };
    // SAFETY: The result is unreleased and owned here.
    let raw = unsafe { std::slice::from_raw_parts(result.data, result.length) }.to_vec();
    let status = result.status;
    // SAFETY: Released exactly once.
    unsafe { lpm_env_release(result) };
    if status != 0 {
        return (
            status,
            serde_json::from_slice(&raw).expect("refusal json"),
            Vec::new(),
        );
    }
    let decoded = decode_frame(&raw, usize::MAX).expect("an output frame");
    (
        status,
        serde_json::from_slice(decoded.request).expect("response json"),
        decoded.blobs.iter().map(|blob| blob.to_vec()).collect(),
    )
}

/// A store the way the app keeps one: account names to bytes.
#[derive(Default)]
struct Store(BTreeMap<String, Vec<u8>>);

impl Store {
    fn get(&self, account: &str) -> Option<&[u8]> {
        self.0.get(account).map(Vec::as_slice)
    }

    /// Plan `edits` as the app does: with the marker and the record read,
    /// asking again with the names when the plan says so, then commit.
    fn change(&mut self, edits: Value, values: &[&[u8]]) -> (u32, Value) {
        let marker = self.get(MARKER_ACCOUNT).map(<[u8]>::to_vec);
        let record = self.get(RECORD_ACCOUNT).map(<[u8]>::to_vec);
        let mut blobs: Vec<&[u8]> = values.to_vec();
        let mut request = json!({ "vaultId": VAULT, "hasValues": true, "edits": edits });
        if let Some(marker) = &marker {
            blobs.push(marker);
            request["marker"] = json!(blobs.len());
        }
        if let Some(record) = &record {
            blobs.push(record);
            request["record"] = json!(blobs.len());
        }
        let (mut status, mut response, mut out) = call(lpm_env_overrides_plan, &request, &blobs);
        if status == 0 && response["result"] == "needsNames" {
            request["names"] = json!(self.0.keys().collect::<Vec<_>>());
            (status, response, out) = call(lpm_env_overrides_plan, &request, &blobs);
        }
        if status == 0 && response["result"] == "planned" {
            assert_eq!(response["journal"], true);
            let mut next = self.0.clone();
            for write in response["writes"].as_array().expect("writes") {
                let index = write["blob"].as_u64().expect("blob") as usize;
                next.insert(
                    write["account"].as_str().expect("account").to_owned(),
                    out[index - 1].clone(),
                );
            }
            for delete in response["deletes"].as_array().expect("deletes") {
                next.remove(delete.as_str().expect("account"));
            }
            self.0 = next;
            out.clear();
        }
        (status, response)
    }

    fn read(&self, values: bool) -> (u32, Value, Vec<Vec<u8>>) {
        self.read_of(true, values)
    }

    /// Read as the app does, saying whether the project's values item exists.
    fn read_of(&self, has_values: bool, values: bool) -> (u32, Value, Vec<Vec<u8>>) {
        let mut blobs: Vec<&[u8]> = Vec::new();
        let mut request = json!({ "vaultId": VAULT, "hasValues": has_values, "values": values });
        if let Some(marker) = self.get(MARKER_ACCOUNT) {
            blobs.push(marker);
            request["marker"] = json!(blobs.len());
        }
        if let Some(record) = self.get(RECORD_ACCOUNT) {
            blobs.push(record);
            request["record"] = json!(blobs.len());
        }
        call(lpm_env_overrides_read, &request, &blobs)
    }
}

#[test]
fn a_batch_at_every_limit_with_a_full_service_of_names_is_one_input() {
    let marker = vec![b'm'; MAX_RECORD_BYTES];
    let record = vec![b'r'; MAX_RECORD_BYTES];
    let values: Vec<Vec<u8>> = (0..MAX_EDITS)
        .map(|index| vec![b'0' + (index % 10) as u8; MAX_BATCH_VALUE_BYTES / MAX_EDITS])
        .collect();
    let mut blobs: Vec<&[u8]> = vec![&marker, &record];
    blobs.extend(values.iter().map(Vec::as_slice));
    let names: Vec<String> = (0..lpm_env_companion::budgets::ADMISSION_CAP)
        .map(|index| {
            format!(
                "{index:0>width$}",
                width = lpm_env_companion::account::MAX_ACCOUNT_BYTES
            )
        })
        .collect();
    let edits: Vec<Value> = (0..MAX_EDITS)
        .map(|index| json!({"action": "set", "environment": "dev", "key": format!("K{index}"), "value": index + 3}))
        .collect();

    let (status, response, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "marker": 1, "record": 2, "names": names, "edits": edits}),
        &blobs,
    );

    assert_ne!(status, 2, "{response}");
    assert_eq!(
        response["code"], "overrides.damaged",
        "judged, not refused unread"
    );
}

#[test]
fn environments_changed_together_share_one_budget_across_the_batch() {
    let renames = |count: usize| -> Vec<Value> {
        (0..count)
            .map(|index| json!({"from": format!("e{index}"), "to": format!("f{index}")}))
            .collect()
    };
    let plan = |edits: Value| {
        call(
            lpm_env_overrides_plan,
            &json!({"vaultId": VAULT, "hasValues": true, "edits": edits}),
            &[],
        )
    };
    let (status, response, _) = plan(json!([
        {"action": "environmentsChanged", "renamed": renames(MAX_EDITS), "removed": []}
    ]));
    assert_eq!(status, 0, "{response}");
    let (status, response, _) = plan(json!([
        {"action": "environmentsChanged", "renamed": renames(MAX_EDITS + 1), "removed": []}
    ]));
    assert_eq!(status, 2, "{response}");
    let half = json!({"action": "environmentsChanged", "renamed": renames(MAX_EDITS / 2 + 1), "removed": []});
    let (status, response, _) = plan(json!([half, half]));
    assert_eq!(status, 2, "{response}");
}

#[test]
fn a_plan_refuses_for_the_marker_first_then_for_each_edit_in_order() {
    let large = vec![b'x'; MAX_RECORD_BYTES + 1];
    let damaged_marker: &[u8] = b"not a marker";
    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "marker": 2, "edits": [
            {"action": "set", "environment": "dev", "key": "fixture-not-a-key", "value": 1},
        ]}),
        &[&large, damaged_marker],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(
        refused["code"], "overrides.damaged",
        "the marker before the edit"
    );

    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "edits": [
            {"action": "unset", "environment": "not an environment", "key": "A"},
            {"action": "set", "environment": "dev", "key": "B", "value": 1},
        ]}),
        &[&large],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.invalid_environment");
    assert_eq!(
        refused["edit"], 0,
        "the first edit's refusal before the second's"
    );

    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": false, "edits": [
            {"action": "set", "environment": "dev", "key": "B", "value": 1},
        ]}),
        &[&large],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(
        refused["code"], "overrides.no_values",
        "no value is read without values"
    );

    let with_nul: &[u8] = b"fixture\0value";
    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "edits": [
            {"action": "set", "environment": "dev", "key": "A", "value": 1},
            {"action": "set", "environment": "dev", "key": "fixture-not-a-key", "value": 1},
        ]}),
        &[with_nul],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.nul_value");
    assert_eq!(
        refused["edit"], 0,
        "the first edit's value before the second's key"
    );
}

#[test]
fn a_plan_refuses_malformed_value_blobs_as_input_before_the_marker() {
    let damaged_marker: &[u8] = b"not a marker";
    let not_text: &[u8] = &[0xff, 0xfe];
    for (value, blobs) in [
        (99, vec![damaged_marker]),
        (2, vec![damaged_marker, not_text]),
    ] {
        let (status, refused, _) = call(
            lpm_env_overrides_plan,
            &json!({"vaultId": VAULT, "hasValues": true, "marker": 1, "edits": [
                {"action": "set", "environment": "dev", "key": "A", "value": value},
            ]}),
            &blobs,
        );
        assert_eq!(status, 2, "value blob {value}: {refused}");
    }
}

#[test]
fn a_plan_without_values_refuses_a_nul_as_a_plan_with_them_does() {
    let with_nul: &[u8] = b"fixture\0value";
    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": false, "edits": [
            {"action": "set", "environment": "dev", "key": "A", "value": 1},
        ]}),
        &[with_nul],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.nul_value");
    assert_eq!(refused["edit"], 0);
}

#[test]
fn a_plan_says_whether_the_project_has_values() {
    let (status, response, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "edits": [{"action": "clearAll"}]}),
        &[],
    );
    assert_eq!(status, 2, "{response}");
}

#[test]
fn a_read_lists_no_overrides_beside_no_values_after_the_marker_s_refusals() {
    let mut store = Store::default();
    let (status, planned) = store.change(
        json!([{"action": "set", "environment": "dev", "key": "A", "value": 1}]),
        &[b"mine"],
    );
    assert_eq!(status, 0, "{planned}");

    let (status, read, values) = store.read_of(false, true);
    assert_eq!(status, 0, "{read}");
    assert_eq!(
        read["environments"],
        json!([]),
        "overrides live beside values, so a record left without them is never listed"
    );
    assert!(values.is_empty());

    let damaged_marker: &[u8] = b"not a marker";
    let (status, refused, _) = call(
        lpm_env_overrides_read,
        &json!({"vaultId": VAULT, "hasValues": false, "marker": 1}),
        &[damaged_marker],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.damaged");

    let (status, refused, _) = call(lpm_env_overrides_read, &json!({"vaultId": VAULT}), &[]);
    assert_eq!(
        status, 2,
        "every read says whether there are values: {refused}"
    );
}

/// The most memory this process has held at once, in bytes.
#[cfg(unix)]
fn peak_resident_bytes() -> usize {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: `getrusage` fills `usage` when it returns zero.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    // SAFETY: The call above succeeded.
    let peak = usize::try_from(unsafe { usage.assume_init() }.ru_maxrss).unwrap_or(0);
    if cfg!(target_os = "macos") {
        peak
    } else {
        peak * 1024
    }
}

/// How much the peak memory grew while a plan refused `request`, a JSON
/// object of nearly the whole input limit, built as `head`, `item`s and
/// `tail`. Each test runs in a process of its own, so the peak is the
/// call's alone.
#[cfg(unix)]
fn peak_growth_refusing(head: &str, item: &str, tail: &str) -> usize {
    let room = OVERRIDES_INPUT_LIMIT - 1024;
    let mut request = Vec::with_capacity(room);
    request.extend_from_slice(head.as_bytes());
    while request.len() + item.len() + 1 + tail.len() < room {
        request.extend_from_slice(item.as_bytes());
        request.push(b',');
    }
    request.extend_from_slice(item.as_bytes());
    request.extend_from_slice(tail.as_bytes());
    let mut input = Vec::with_capacity(request.len() + 16);
    input.extend_from_slice(&FRAME_MAGIC);
    input.push(FRAME_VERSION);
    input.extend_from_slice(&1_u32.to_be_bytes());
    input.extend_from_slice(&(request.len() as u32).to_be_bytes());
    input.extend_from_slice(&request);
    drop(request);

    let before = peak_resident_bytes();
    // SAFETY: The input stays alive for the synchronous call.
    let result = unsafe { lpm_env_overrides_plan(input.as_ptr(), input.len()) };
    let status = result.status;
    // SAFETY: Released exactly once.
    unsafe { lpm_env_release(result) };
    assert_eq!(status, 2, "refused as invalid input");
    peak_resident_bytes().saturating_sub(before)
}

#[cfg(unix)]
#[test]
fn edits_past_the_limit_are_refused_before_they_are_held() {
    let grown = peak_growth_refusing(
        r#"{"vaultId":"proj","hasValues":true,"edits":["#,
        r#"{"action":"clearAll"}"#,
        "]}",
    );
    assert!(grown < 8 * 1024 * 1024, "{grown} bytes held");
}

#[cfg(unix)]
#[test]
fn renames_past_the_limit_are_refused_before_they_are_held() {
    let grown = peak_growth_refusing(
        r#"{"vaultId":"proj","hasValues":true,"edits":[{"action":"environmentsChanged","removed":[],"renamed":["#,
        r#"{"from":"a","to":"b"}"#,
        "]}]}",
    );
    assert!(grown < 8 * 1024 * 1024, "{grown} bytes held");
}

#[test]
fn a_listing_past_any_service_s_names_is_refused_before_it_is_kept() {
    let names = vec![""; MAX_NAMES + 1];
    let (status, response, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "names": names, "edits": []}),
        &[],
    );
    assert_eq!(status, 2, "{response}");
}

#[test]
fn the_header_declares_both_override_functions_and_their_input_limit() {
    let header = include_str!("../../include/lpm_env.h");
    assert!(header.contains("#define LPM_ENV_OVERRIDES_INPUT_LIMIT (16 * 1024 * 1024)"));
    assert_eq!(OVERRIDES_INPUT_LIMIT, 16 * 1024 * 1024);
    for function in [
        "LPMEnvResult lpm_env_overrides_read(const uint8_t *input, size_t input_length);",
        "LPMEnvResult lpm_env_overrides_plan(const uint8_t *input, size_t input_length);",
    ] {
        assert!(header.contains(function), "{function}");
    }
}

#[test]
fn a_set_unset_and_removal_round_trip_through_an_app_store() {
    let mut store = Store::default();
    let (status, planned) = store.change(
        json!([
            {"action": "set", "environment": "development", "key": "API_URL", "value": 1},
            {"action": "unset", "environment": "development", "key": "SENTRY_DSN"},
        ]),
        &[b"http://localhost:4000"],
    );
    assert_eq!(status, 0, "{planned}");
    assert_eq!(planned["result"], "planned");
    assert_eq!(planned["activated"], true);
    assert_eq!(planned["markerAfter"], "present");
    assert!(
        !planned.to_string().contains("localhost:4000"),
        "a value never travels in JSON: {planned}"
    );
    assert_eq!(store.get(MARKER_ACCOUNT), Some(OVERRIDES_MARKER.as_bytes()));

    let (status, read, values) = store.read(true);
    assert_eq!(status, 0, "{read}");
    assert_eq!(
        read["environments"],
        json!([{
            "environment": "development",
            "set": [{"key": "API_URL", "passed": true, "value": 1}],
            "unset": [{"key": "SENTRY_DSN", "passed": true}],
        }])
    );
    assert_eq!(values, [b"http://localhost:4000".to_vec()]);
    let (_, names_only, values) = store.read(false);
    assert!(values.is_empty());
    assert!(
        names_only["environments"][0]["set"][0]
            .get("value")
            .is_none()
    );

    let (status, cleared) = store.change(
        json!([{"action": "clearEnvironment", "environment": "development"}]),
        &[],
    );
    assert_eq!(status, 0, "{cleared}");
    assert_eq!(cleared["markerAfter"], "absent");
    assert_eq!(cleared["deletes"], json!([RECORD_ACCOUNT, MARKER_ACCOUNT]));
    assert!(
        store.0.is_empty(),
        "nothing is left once the last override goes"
    );
    let (status, read, _) = store.read(true);
    assert_eq!(status, 0);
    assert_eq!(read["environments"], json!([]));
}

#[test]
fn reading_a_name_lpm_never_passes_says_so() {
    let mut store = Store::default();
    store.0.insert(
        MARKER_ACCOUNT.to_owned(),
        OVERRIDES_MARKER.as_bytes().to_vec(),
    );
    store.0.insert(
        RECORD_ACCOUNT.to_owned(),
        br#"{"schemaVersion":1,"vaultId":"proj","environments":{"default":{"set":{"NODE_OPTIONS":"--inspect"},"unset":["CLASSPATH"]}}}"#.to_vec(),
    );
    let (status, read, _) = store.read(false);
    assert_eq!(status, 0, "{read}");
    assert_eq!(read["environments"][0]["set"][0]["passed"], false);
    assert_eq!(read["environments"][0]["unset"][0]["passed"], false);
}

#[test]
fn reading_damaged_unsupported_or_unfinished_overrides_is_refused() {
    let cases: [(Option<&str>, Option<&str>, &str); 4] = [
        (
            Some(OVERRIDES_MARKER),
            Some("{not json"),
            "overrides.damaged",
        ),
        (
            None,
            Some(r#"{"schemaVersion":1,"vaultId":"proj","environments":{}}"#),
            "overrides.damaged",
        ),
        (
            Some(&OVERRIDES_MARKER.replace(r#""version":1"#, r#""version":2"#)),
            None,
            "overrides.unsupported",
        ),
        (
            Some(&OVERRIDES_MARKER.replace(r#""state":"active"}}"#, r#""state":"removing"}}"#)),
            None,
            "overrides.needs_resume",
        ),
    ];
    for (marker, record, code) in cases {
        let mut store = Store::default();
        if let Some(marker) = marker {
            store
                .0
                .insert(MARKER_ACCOUNT.to_owned(), marker.as_bytes().to_vec());
        }
        if let Some(record) = record {
            store
                .0
                .insert(RECORD_ACCOUNT.to_owned(), record.as_bytes().to_vec());
        }
        let (status, refused, _) = store.read(true);
        assert_eq!(status, 5, "{code}: {refused}");
        assert_eq!(refused["code"], code);
        assert!(!refused.to_string().contains("not json"), "{refused}");
    }
}

#[test]
fn malformed_requests_are_invalid_input() {
    for (request, blobs) in [
        (json!({"vaultId": "../proj", "edits": []}), Vec::new()),
        (
            json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "set", "environment": "dev", "key": "A", "value": 1}]}),
            vec![&[0xff_u8, 0xfe][..]],
        ),
        (
            json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "set", "environment": "dev", "key": "A", "value": 2}]}),
            vec![&b"x"[..]],
        ),
        (
            json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "rename"}]}),
            Vec::new(),
        ),
        (
            json!({"vaultId": VAULT, "record": 1, "edits": []}),
            Vec::new(),
        ),
        (
            json!({"vaultId": VAULT, "hasValues": true, "edits": vec![json!({"action": "clearAll"}); MAX_EDITS + 1]}),
            Vec::new(),
        ),
    ] {
        let (status, response, _) = call(lpm_env_overrides_plan, &request, &blobs);
        assert_eq!(status, 2, "{request}: {response}");
        assert_eq!(response["code"], "overrides.invalid_input");
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    cases: Vec<FixtureCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureCase {
    name: String,
    vault_id: String,
    #[serde(default)]
    has_values: Option<bool>,
    marker: Option<String>,
    record: Option<String>,
    names: Option<Vec<String>>,
    edits: Vec<Value>,
    expect: Value,
}

#[test]
fn every_override_change_fixture_plans_through_the_engine_as_recorded() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../lpm-env-companion/tests/fixtures/override-changes.json"
    ))
    .expect("fixtures decode");
    for case in fixture.cases {
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        let edits: Vec<Value> = case
            .edits
            .iter()
            .map(|edit| {
                let mut edit = edit.clone();
                if let Some(value) = edit.get("value").and_then(Value::as_str) {
                    blobs.push(value.as_bytes().to_vec());
                    edit["value"] = json!(blobs.len());
                }
                edit
            })
            .collect();
        let mut request = json!({
            "vaultId": case.vault_id,
            "hasValues": case.has_values.unwrap_or(true),
            "edits": edits,
        });
        if let Some(marker) = &case.marker {
            blobs.push(marker.as_bytes().to_vec());
            request["marker"] = json!(blobs.len());
        }
        if let Some(record) = &case.record {
            blobs.push(record.as_bytes().to_vec());
            request["record"] = json!(blobs.len());
        }
        if let Some(names) = &case.names {
            request["names"] = json!(names);
        }
        let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        let (status, response, out) = call(lpm_env_overrides_plan, &request, &blob_refs);
        let expect = &case.expect;
        match expect["result"].as_str().expect("a result") {
            "refused" => {
                assert_eq!(status, 5, "{}: {response}", case.name);
                assert_eq!(response["code"], expect["code"], "{}", case.name);
            }
            result => {
                assert_eq!(status, 0, "{}: {response}", case.name);
                assert_eq!(response["result"], result, "{}", case.name);
                if let Some(effects) = expect.get("effects") {
                    assert_eq!(&response["effects"], effects, "{}", case.name);
                }
                if result == "planned" {
                    let writes: BTreeMap<String, String> = response["writes"]
                        .as_array()
                        .expect("writes")
                        .iter()
                        .map(|write| {
                            let index = write["blob"].as_u64().expect("blob") as usize;
                            (
                                write["account"].as_str().expect("account").to_owned(),
                                String::from_utf8(out[index - 1].clone()).expect("UTF-8"),
                            )
                        })
                        .collect();
                    let expected: BTreeMap<String, String> =
                        serde_json::from_value(expect["writes"].clone()).expect("writes");
                    assert_eq!(writes, expected, "{}", case.name);
                    assert_eq!(response["deletes"], expect["deletes"], "{}", case.name);
                    assert_eq!(
                        response["markerAfter"], expect["markerAfter"],
                        "{}",
                        case.name
                    );
                    assert_eq!(response["activated"], expect["activated"], "{}", case.name);
                }
            }
        }
    }
}

fn check(schema: &str, input: &Value) -> (u32, Value) {
    let input = serde_json::to_vec(input).expect("json");
    // SAFETY: Both ranges stay alive for the synchronous call.
    let result =
        unsafe { lpm_env_check(schema.as_ptr(), schema.len(), input.as_ptr(), input.len()) };
    // SAFETY: The result is unreleased and owned here.
    let raw = unsafe { std::slice::from_raw_parts(result.data, result.length) }.to_vec();
    let status = result.status;
    // SAFETY: Released exactly once.
    unsafe { lpm_env_release(result) };
    (status, serde_json::from_slice(&raw).expect("check json"))
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn the_check_judges_what_a_run_gets_with_the_overrides_and_names_them() {
    let schema = r#"{"vars":{"API_URL":{"format":"url"},"TOKEN":{"required":true}}}"#;
    let record = br#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"API_URL":"not a url"},"unset":["TOKEN"]}}}"#;
    let environments = json!({
        "default": {"API_URL": "https://team.example", "TOKEN": "team"},
        "staging": {},
    });
    let (status, team) = check(schema, &json!({ "environments": environments }));
    assert_eq!(status, 0, "{team}");
    assert_eq!(team["environments"]["staging"]["problems"], json!([]));

    let (status, effective) = check(
        schema,
        &json!({
            "environments": environments,
            "overrides": {"vaultId": VAULT, "marker": base64(OVERRIDES_MARKER.as_bytes()), "record": base64(record), "hasValues": true},
        }),
    );
    assert_eq!(status, 0, "{effective}");
    let staging = &effective["environments"]["staging"];
    assert_eq!(staging["readsDefaultEnvironment"], true);
    assert_eq!(
        staging["problems"],
        json!([
            {"key": "API_URL", "code": "env.invalid_format", "format": "url", "personalOverride": true},
            {"key": "TOKEN", "code": "env.required", "personalOverride": true},
        ])
    );
    assert_eq!(staging["appliedOverrides"], json!(["API_URL", "TOKEN"]));
    assert!(
        effective["environments"]["default"]
            .get("appliedOverrides")
            .is_none()
    );
    assert!(!effective.to_string().contains("not a url"));
}

#[test]
fn the_check_applies_no_overrides_beside_no_values_after_the_marker_s_refusals() {
    let schema = r#"{"vars":{"TOKEN":{"required":true}}}"#;
    let record = br#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{},"unset":["TOKEN"]}}}"#;
    let environments = json!({"default": {"TOKEN": "team"}, "staging": {}});
    let overrides = |marker: &[u8], has_values: Option<bool>| {
        let mut overrides =
            json!({"vaultId": VAULT, "marker": base64(marker), "record": base64(record)});
        if let Some(has_values) = has_values {
            overrides["hasValues"] = json!(has_values);
        }
        json!({"environments": environments, "overrides": overrides})
    };

    let (status, checked) = check(schema, &overrides(OVERRIDES_MARKER.as_bytes(), Some(false)));
    assert_eq!(status, 0, "{checked}");
    let staging = &checked["environments"]["staging"];
    assert_eq!(
        staging["problems"],
        json!([]),
        "a record left without values is never applied"
    );
    assert!(staging.get("appliedOverrides").is_none());

    let (status, refused) = check(schema, &overrides(b"not a marker", Some(false)));
    assert_eq!(status, 1, "{refused}");
    assert_eq!(refused["code"], "overrides.damaged");

    let (status, refused) = check(schema, &overrides(OVERRIDES_MARKER.as_bytes(), None));
    assert_eq!(
        status, 2,
        "every check with overrides says whether there are values: {refused}"
    );
}

#[test]
fn the_check_refuses_overrides_it_cant_apply() {
    let (status, refused) = check(
        r#"{"vars":{"A":{}}}"#,
        &json!({
            "environments": {"default": {"A": "1"}},
            "overrides": {"vaultId": VAULT, "marker": base64(OVERRIDES_MARKER.as_bytes()), "record": base64(b"{not json"), "hasValues": true},
        }),
    );
    assert_eq!(status, 1, "{refused}");
    assert_eq!(refused["code"], "overrides.damaged");
}

#[test]
fn a_batch_sets_as_many_values_as_it_has_edits_and_a_read_returns_them_all() {
    let mut store = Store::default();
    let values: Vec<Vec<u8>> = (0..200)
        .map(|index| format!("fixture-{index}").into_bytes())
        .collect();
    let edits: Vec<Value> = (0..200)
        .map(|index| json!({"action": "set", "environment": "development", "key": format!("KEY_{index:03}"), "value": index + 1}))
        .collect();
    let blobs: Vec<&[u8]> = values.iter().map(Vec::as_slice).collect();
    let (status, planned) = store.change(json!(edits), &blobs);
    assert_eq!(status, 0, "{planned}");
    assert_eq!(planned["result"], "planned");
    let (status, read, returned) = store.read(true);
    assert_eq!(status, 0, "{read}");
    assert_eq!(returned.len(), 200);
    assert_eq!(returned[0], b"fixture-0");
}

#[test]
fn a_value_larger_than_a_record_or_values_past_the_input_bound_are_refused_before_copying() {
    let mut store = Store::default();
    let large = vec![b'x'; 100 * 1024 + 1];
    let (status, refused) = store.change(
        json!([
            {"action": "set", "environment": "development", "key": "SMALL", "value": 1},
            {"action": "set", "environment": "development", "key": "LARGE", "value": 2},
        ]),
        &[b"fixture", &large],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.too_large");
    assert_eq!(refused["edit"], 1);
    assert_eq!(refused["key"], "LARGE");

    let shared = vec![b'x'; 64 * 1024];
    let edits: Vec<Value> = (0..MAX_EDITS)
        .map(|index| json!({"action": "set", "environment": "development", "key": format!("K{index}"), "value": 1}))
        .collect();
    let (status, refused) = store.change(json!(edits), &[&shared]);
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.too_large");
    assert_eq!(
        refused["edit"], 64,
        "the first edit past the input bound, before any more is copied"
    );
}

#[test]
fn a_refusal_names_the_edit_and_what_it_was_about_never_a_value() {
    let mut store = Store::default();
    let (status, refused) = store.change(
        json!([
            {"action": "set", "environment": "development", "key": "A", "value": 1},
            {"action": "remove", "environment": "development", "key": "B"},
            {"action": "set", "environment": "development", "key": "NODE_OPTIONS", "value": 1},
        ]),
        &[b"fixture-secret"],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.denied_name");
    assert_eq!(refused["edit"], 2);
    assert_eq!(refused["key"], "NODE_OPTIONS");
    assert!(!refused.to_string().contains("fixture-secret"));

    let (status, refused) = store.change(
        json!([{"action": "environmentDuplicated", "from": "dev", "to": "dev"}]),
        &[],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.same_environment");
    assert_eq!(refused["environment"], "dev");
    assert_eq!(
        refused["message"],
        "environment \"dev\" can't be copied to itself"
    );
}

#[test]
fn needs_names_says_what_to_list_and_brings_the_effects_for_a_confirmation() {
    let mut store = Store::default();
    let (status, _) = store.change(
        json!([{"action": "set", "environment": "development", "key": "A", "value": 1}]),
        &[b"fixture"],
    );
    assert_eq!(status, 0);
    let mut request = json!({"vaultId": VAULT, "hasValues": true, "marker": 1, "record": 2, "edits": [{"action": "clearAll"}]});
    let marker = store.get(MARKER_ACCOUNT).unwrap().to_vec();
    let record = store.get(RECORD_ACCOUNT).unwrap().to_vec();
    let (status, response, _) = call(lpm_env_overrides_plan, &request, &[&marker, &record]);
    assert_eq!(status, 0, "{response}");
    assert_eq!(response["result"], "needsNames");
    assert_eq!(response["needs"], "project");
    assert_eq!(
        response["effects"],
        json!([{"kind": "cleared", "environment": null, "removed": 1}])
    );
    request["edits"] =
        json!([{"action": "set", "environment": "development", "key": "A", "value": 3}]);
    let (_, created, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "set", "environment": "development", "key": "A", "value": 1}]}),
        &[b"fixture"],
    );
    assert_eq!(created["needs"], "projectAndService");
}

#[test]
fn an_unfinished_project_is_refused_with_what_to_do() {
    let mut store = Store::default();
    store.0.insert(
        MARKER_ACCOUNT.to_owned(),
        OVERRIDES_MARKER
            .replace(r#""state":"active"}}"#, r#""state":"removing"}}"#)
            .into_bytes(),
    );
    let (status, refused, _) = store.read(false);
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.needs_resume");
    assert_eq!(
        refused["message"],
        "finish the env project's interrupted change first"
    );
}

#[test]
fn the_check_says_an_invalid_vault_id_is_invalid_input() {
    let (status, refused) = check(
        r#"{"vars":{"A":{}}}"#,
        &json!({
            "environments": {"default": {"A": "1"}},
            "overrides": {"vaultId": "../proj"},
        }),
    );
    assert_eq!(status, 2, "{refused}");
    assert_eq!(refused["code"], "env.invalid_input");
}

#[test]
fn environments_changed_together_keep_their_own_overrides() {
    let mut store = Store::default();
    let (status, _) = store.change(
        json!([
            {"action": "set", "environment": "a", "key": "K", "value": 1},
            {"action": "set", "environment": "b", "key": "K", "value": 2},
        ]),
        &[b"fixture-a", b"fixture-b"],
    );
    assert_eq!(status, 0);
    let (status, swapped) = store.change(
        json!([{"action": "environmentsChanged", "renamed": [{"from": "a", "to": "b"}, {"from": "b", "to": "a"}], "removed": []}]),
        &[],
    );
    assert_eq!(status, 0, "{swapped}");
    assert_eq!(
        swapped["effects"],
        json!([{"kind": "environmentsChanged", "moved": [
            {"from": "a", "to": "b", "moved": 1, "replaced": 0, "kept": 0},
            {"from": "b", "to": "a", "moved": 1, "replaced": 0, "kept": 0},
        ], "removed": []}])
    );
    let (_, read, values) = store.read(true);
    assert_eq!(read["environments"][0]["environment"], "a");
    let index = read["environments"][0]["set"][0]["value"].as_u64().unwrap() as usize;
    assert_eq!(values[index - 1], b"fixture-b");
}

#[test]
fn a_project_without_values_plans_removals_and_refuses_the_rest() {
    let (status, removed, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": false, "edits": [{"action": "remove", "environment": "dev", "key": "A"}]}),
        &[],
    );
    assert_eq!(status, 0, "{removed}");
    assert_eq!(removed["result"], "unchanged");
    assert_eq!(removed["effects"][0]["changed"], false);
    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": false, "edits": [{"action": "set", "environment": "dev", "key": "A", "value": 1}]}),
        &[b"fixture"],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.no_values");
    for edits in [
        json!([
            {"action": "set", "environment": "dev", "key": "A", "value": 1},
            {"action": "remove", "environment": "dev", "key": "A"},
        ]),
        json!([
            {"action": "unset", "environment": "dev", "key": "A"},
            {"action": "clearAll"},
        ]),
    ] {
        let (status, refused, _) = call(
            lpm_env_overrides_plan,
            &json!({"vaultId": VAULT, "hasValues": false, "edits": edits}),
            &[b"fixture"],
        );
        assert_eq!(status, 5, "{edits}: {refused}");
        assert_eq!(
            refused["code"], "overrides.no_values",
            "{edits}: a later edit never takes back an override without values"
        );
    }
}

#[test]
fn a_too_large_refusal_never_repeats_an_invalid_key_and_names_the_limit_it_met() {
    let large = vec![b'x'; 100 * 1024 + 1];
    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "set", "environment": "dev", "key": "fixture-secret-pasted", "value": 1}]}),
        &[&large],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.invalid_key");
    assert!(
        !refused.to_string().contains("fixture-secret-pasted"),
        "{refused}"
    );

    let shared = vec![b'x'; 64 * 1024];
    let edits: Vec<Value> = (0..MAX_EDITS)
        .map(|index| json!({"action": "set", "environment": "dev", "key": format!("K{index}"), "value": 1}))
        .collect();
    let (status, refused, _) = call(
        lpm_env_overrides_plan,
        &json!({"vaultId": VAULT, "hasValues": true, "edits": edits}),
        &[&shared],
    );
    assert_eq!(status, 5, "{refused}");
    assert_eq!(refused["code"], "overrides.too_large");
    assert_eq!(refused["limit"], MAX_BATCH_VALUE_BYTES);
    assert!(
        refused["message"].as_str().unwrap().contains("4 MiB"),
        "{refused}"
    );
}

#[test]
fn a_value_many_sets_name_is_read_once_for_its_text_and_once_for_what_it_holds() {
    let value = vec![b'x'; 1024];
    let edits: Vec<Value> = (0..MAX_EDITS)
        .map(|index| json!({"action": "set", "environment": "dev", "key": format!("K{index}"), "value": 1}))
        .collect();
    for has_values in [false, true] {
        super::VALUE_SCANS.with(|scans| scans.set(0));
        let (status, _, _) = call(
            lpm_env_overrides_plan,
            &json!({"vaultId": VAULT, "hasValues": has_values, "edits": edits}),
            &[&value],
        );
        assert_eq!(status, 5, "with hasValues {has_values}");
        assert_eq!(
            super::VALUE_SCANS.with(std::cell::Cell::get),
            2,
            "with hasValues {has_values}, every set names the one value"
        );
    }
}

#[test]
fn requests_take_only_their_documented_objects_and_leave_out_what_is_absent() {
    let clear = json!({"action": "clearAll"});
    let plans = [
        json!([VAULT, null, null, null, true, [clear]]),
        json!({"vaultId": VAULT, "hasValues": true, "edits": [["clearAll"]]}),
        json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "clearAll", "environment": null}]}),
        json!({"vaultId": VAULT, "hasValues": true, "edits": [{"action": "clearAll", "value": null}]}),
        json!({"vaultId": VAULT, "hasValues": true, "marker": null, "edits": [clear]}),
        json!({"vaultId": VAULT, "hasValues": true, "names": null, "edits": [clear]}),
        json!({"vaultId": VAULT, "hasValues": true, "edits": [
            {"action": "environmentsChanged", "renamed": [["dev", "prod"]], "removed": []},
        ]}),
    ];
    for plan in plans {
        let (status, refused, _) = call(lpm_env_overrides_plan, &plan, &[]);
        assert_eq!(status, 2, "{plan}: {refused}");
        assert_eq!(refused["code"], "overrides.invalid_input", "{plan}");
    }
    for read in [
        json!([VAULT, null, null, true]),
        json!({"vaultId": VAULT, "hasValues": true, "record": null}),
    ] {
        let (status, refused, _) = call(lpm_env_overrides_read, &read, &[]);
        assert_eq!(status, 2, "{read}: {refused}");
    }
    let schema = r#"{"vars":{}}"#;
    for overrides in [
        json!([VAULT, null, null, true]),
        json!({"vaultId": VAULT, "hasValues": true, "marker": null}),
    ] {
        let (status, refused) = check(
            schema,
            &json!({"environments": {"default": {}}, "overrides": overrides}),
        );
        assert_eq!(status, 2, "{overrides}: {refused}");
    }
}
