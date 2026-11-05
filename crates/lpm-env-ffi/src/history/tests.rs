use std::collections::BTreeMap;

use super::*;
use crate::lpm_env_release;

const VAULT: &str = "proj";

/// Encode a request frame the way the app does.
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
    let decoded = decode_frame(&raw).expect("an output frame");
    (
        status,
        serde_json::from_slice(decoded.request).expect("response json"),
        decoded.blobs.iter().map(|blob| blob.to_vec()).collect(),
    )
}

fn payload_bytes(environments: &[(&str, &[(&str, &str)])]) -> Vec<u8> {
    let environments: BTreeMap<&str, BTreeMap<&str, &str>> = environments
        .iter()
        .map(|(name, keys)| (*name, keys.iter().copied().collect()))
        .collect();
    serde_json::to_vec(&json!({ "environments": environments })).expect("payload")
}

/// The records the app's store holds, by account.
#[derive(Default)]
struct Store {
    records: BTreeMap<String, Vec<u8>>,
}

impl Store {
    fn apply(&mut self, response: &Value, blobs: &[Vec<u8>]) {
        for write in response["writes"].as_array().expect("writes") {
            let index = write["blob"].as_u64().expect("blob") as usize;
            self.records.insert(
                write["account"].as_str().expect("account").to_owned(),
                blobs[index - 1].clone(),
            );
        }
    }

    fn get(&self, account: &lpm_env_companion::account::CompanionAccount) -> Option<&[u8]> {
        self.records.get(&account.name()).map(Vec::as_slice)
    }

    fn head(&self) -> Head {
        Head::parse(
            HISTORY,
            VAULT,
            self.get(&lpm_env_companion::history::head_account(VAULT))
                .expect("head"),
        )
        .expect("head")
    }

    /// The common request fields and blobs for reading history, with
    /// `values` as the current payload.
    fn reading(&self, values: &[u8], mut rest: Value) -> (Value, Vec<Vec<u8>>) {
        let mut blobs = vec![
            self.get(&lpm_env_companion::history::head_account(VAULT))
                .expect("head")
                .to_vec(),
            self.get(&lpm_env_companion::history::key_account(VAULT))
                .expect("key")
                .to_vec(),
            values.to_vec(),
        ];
        let parts: Vec<Value> = self
            .head()
            .parts
            .iter()
            .map(
                |part| match self.get(&lpm_env_companion::history::part_account(VAULT, *part)) {
                    Some(bytes) => {
                        blobs.push(bytes.to_vec());
                        json!({ "part": part, "blob": blobs.len() })
                    }
                    None => json!({ "part": part }),
                },
            )
            .collect();
        let object = rest.as_object_mut().expect("object");
        object.insert("vaultId".to_owned(), json!(VAULT));
        object.insert("head".to_owned(), json!(1));
        object.insert("key".to_owned(), json!(2));
        object.insert("values".to_owned(), json!(3));
        object.insert("parts".to_owned(), json!(parts));
        (rest, blobs)
    }
}

fn change(id: u8, action: &str) -> Value {
    json!({
        "id": hex::encode([id; 16]),
        "time": 1_762_000_000_000_i64 + i64::from(id),
        "action": action,
    })
}

fn record(store: &mut Store, id: u8, before: &[u8], after: &[u8]) -> Value {
    let creating = store.records.is_empty();
    let mut owned: Vec<Vec<u8>> = vec![before.to_vec(), after.to_vec()];
    let request = if creating {
        json!({
            "vaultId": VAULT,
            "change": change(id, "set"),
            "before": 1,
            "after": 2,
            "create": { "approval": "automatic", "ringLimit": 16 },
        })
    } else {
        for account in [
            lpm_env_companion::history::head_account(VAULT),
            lpm_env_companion::history::key_account(VAULT),
            lpm_env_companion::history::part_account(VAULT, store.head().tail()),
        ] {
            owned.push(store.get(&account).expect("record").to_vec());
        }
        json!({
            "vaultId": VAULT,
            "change": change(id, "set"),
            "before": 1,
            "after": 2,
            "append": { "head": 3, "key": 4, "tail": 5, "growth": "unasked" },
        })
    };
    let blobs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    let (status, response, out) = call(lpm_env_history_record, &request, &blobs);
    assert_eq!(status, 0, "{response}");
    assert_eq!(response["result"], "write", "{response}");
    assert_eq!(response["journal"], creating);
    store.apply(&response, &out);
    response
}

#[test]
fn malformed_frames_and_requests_are_invalid_input() {
    for input in [
        Vec::new(),
        b"LPMF".to_vec(),
        [b"LPMF".as_slice(), &[2], &1_u32.to_be_bytes()].concat(),
        [b"LPMF".as_slice(), &[1], &0_u32.to_be_bytes()].concat(),
        [
            b"LPMF".as_slice(),
            &[1],
            &1_u32.to_be_bytes(),
            &9_u32.to_be_bytes(),
            b"{}",
        ]
        .concat(),
        [frame(&json!({}), &[]).as_slice(), &[0]].concat(),
    ] {
        // SAFETY: The input stays alive for the synchronous call.
        let result = unsafe { lpm_env_history_record(input.as_ptr(), input.len()) };
        assert_eq!(result.status, 2);
        // SAFETY: Released exactly once.
        unsafe { lpm_env_release(result) };
    }
    let (status, _, _) = call(lpm_env_history_record, &json!({ "vaultId": VAULT }), &[]);
    assert_eq!(status, 2);
}

#[test]
fn the_app_records_reads_reveals_rolls_back_and_removes_through_the_binary_interface() {
    let mut store = Store::default();
    let empty = payload_bytes(&[("production", &[])]);
    let one = payload_bytes(&[("production", &[("API_KEY", "secret-one")])]);
    let two = payload_bytes(&[("production", &[("API_KEY", "secret-two")])]);
    record(&mut store, 1, &empty, &one);
    let appended = record(&mut store, 2, &one, &two);
    assert_eq!(appended["shape"], "steady");

    let (request, blobs) = store.reading(&two, json!({}));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, timeline, _) = call(lpm_env_history_timeline, &request, &blob_refs);
    assert_eq!(status, 0, "{timeline}");
    assert_eq!(timeline["readable"], 2);
    assert_eq!(timeline["rows"][0]["id"], hex::encode([2; 16]));
    let text = timeline.to_string();
    assert!(
        !text.contains("secret-one") && !text.contains("secret-two"),
        "{text}"
    );

    let (request, blobs) = store.reading(&two, json!({ "ids": [hex::encode([2; 16])] }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, revealed, values) = call(lpm_env_history_reveal, &request, &blob_refs);
    assert_eq!(status, 0, "{revealed}");
    let before = revealed["entries"][0]["values"][0][0]["before"]
        .as_u64()
        .expect("before") as usize;
    assert_eq!(values[before - 1], b"secret-one");
    assert!(
        !revealed.to_string().contains("secret-one"),
        "values stay out of JSON"
    );

    let rollback = json!({ "kind": "key", "entry": hex::encode([2; 16]), "environment": "production", "key": "API_KEY" });
    let (request, blobs) = store.reading(&two, json!({ "rollback": rollback }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, plan, plan_blobs) = call(lpm_env_history_rollback, &request, &blob_refs);
    assert_eq!(status, 0, "{plan}");
    let row = &plan["plan"]["environments"][0]["rows"][0];
    assert_eq!(row["change"], "changed");
    let target = row["target"].as_u64().expect("target") as usize;
    assert_eq!(plan_blobs[target - 1], b"secret-one");
    let fingerprint = plan["plan"]["fingerprint"].clone();

    let (request, blobs) = store.reading(
        &two,
        json!({ "rollback": rollback, "apply": { "fingerprint": fingerprint } }),
    );
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, applied, applied_blobs) = call(lpm_env_history_rollback, &request, &blob_refs);
    assert_eq!(status, 0, "{applied}");
    let write = &applied["writes"][0];
    assert_eq!(write["name"], "production");
    assert_eq!(write["values"][0]["key"], "API_KEY");
    let value_index = write["values"][0]["value"].as_u64().expect("a value blob") as usize;
    assert_eq!(applied_blobs[value_index - 1], b"secret-one");
    assert!(
        !applied.to_string().contains("secret-one"),
        "each value is its own blob, never JSON"
    );

    let changed = payload_bytes(&[("production", &[("API_KEY", "elsewhere")])]);
    let (request, blobs) = store.reading(
        &changed,
        json!({ "rollback": rollback, "apply": { "fingerprint": fingerprint } }),
    );
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, refusal, _) = call(lpm_env_history_rollback, &request, &blob_refs);
    assert_eq!(
        (status, refusal["code"].as_str()),
        (5, Some("history.changed_since_review"))
    );

    let chosen = json!({ "entry": hex::encode([2; 16]), "environment": "production", "key": "API_KEY", "side": "before" });
    let (request, blobs) = store.reading(&two, json!({ "chosen": chosen }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, review, _) = call(lpm_env_history_removal, &request, &blob_refs);
    assert_eq!(status, 0, "{review}");
    let selection = review["review"]["defaultSelection"].clone();
    let (request, blobs) = store.reading(
        &two,
        json!({ "start": {
            "review": review["review"],
            "selection": selection,
            "approval": "automatic",
            "fingerprint": review["review"]["fingerprint"],
        } }),
    );
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, started, started_blobs) = call(lpm_env_history_removal, &request, &blob_refs);
    assert_eq!(status, 0, "{started}");
    assert_eq!(started["journal"], true);
    store.apply(&started, &started_blobs);

    let (request, blobs) = store.reading(&two, json!({ "step": "check", "approval": "automatic" }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (_, check, _) = call(lpm_env_history_maintenance, &request, &blob_refs);
    assert_eq!(check["needsFinishing"], true);
    for part in check["parts"].as_array().expect("parts").clone() {
        let (request, blobs) = store.reading(&two, json!({ "step": "rotatePart", "part": part }));
        let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        let (status, rotated, rotated_blobs) =
            call(lpm_env_history_maintenance, &request, &blob_refs);
        assert_eq!(status, 0, "{rotated}");
        store.apply(&rotated, &rotated_blobs);
    }
    let (request, blobs) = store.reading(&two, json!({ "step": "finish" }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, finished, finished_blobs) =
        call(lpm_env_history_maintenance, &request, &blob_refs);
    assert_eq!(status, 0, "{finished}");
    store.apply(&finished, &finished_blobs);

    let (request, blobs) = store.reading(&two, json!({ "ids": [hex::encode([2; 16])] }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (_, revealed, _) = call(lpm_env_history_reveal, &request, &blob_refs);
    assert_eq!(
        revealed["entries"][0]["values"][0][0]["before"],
        Value::Null,
        "removed"
    );
    assert_eq!(
        revealed["entries"][0]["environments"][0]["keys"][0]["before"],
        "removed"
    );
}

#[test]
fn check_reports_history_state_and_damage_beyond_the_listing() {
    let mut store = Store::default();
    let empty = payload_bytes(&[("e", &[])]);
    let one = payload_bytes(&[("e", &[("A", "1")])]);
    record(&mut store, 1, &empty, &one);
    let marker = store
        .get(&lpm_env_companion::account::CompanionAccount::Marker {
            vault_id: VAULT.to_owned(),
        })
        .expect("marker")
        .to_vec();
    let key = store
        .get(&lpm_env_companion::history::key_account(VAULT))
        .expect("key")
        .to_vec();
    let request = json!({ "vaultId": VAULT, "marker": 1, "head": 2, "key": 3 });
    let (status, check, _) = call(
        lpm_env_history_check,
        &request,
        &[&marker, b"not a head", &key],
    );
    assert_eq!(status, 0, "{check}");
    assert_eq!(check["history"], "on");
    assert_eq!(check["damage"].as_array().map(Vec::len), Some(1));
}

#[test]
fn admission_counts_records_plans_trims_and_says_what_creation_gets() {
    let mut names: Vec<String> = (0..4_093)
        .map(|index| {
            format!(
                "__vault_companion_v1__:notes:{}",
                URL_SAFE_NO_PAD.encode(format!("p{index}"))
            )
        })
        .collect();
    let (status, admission, _) = call(
        lpm_env_history_admission,
        &json!({ "names": names, "operation": "creation" }),
        &[],
    );
    assert_eq!(status, 0, "{admission}");
    assert_eq!(
        (
            admission["creation"].as_str(),
            admission["ringLimit"].as_u64()
        ),
        (Some("full"), Some(16))
    );
    names.push(lpm_env_companion::history::part_account(VAULT, 0).name());
    let (_, admission, _) = call(
        lpm_env_history_admission,
        &json!({ "names": names, "operation": "creation" }),
        &[],
    );
    assert_eq!(admission["creation"], "reduced");
}

#[test]
fn check_asks_for_the_parts_it_needs_and_names_each_damage_for_assess() {
    let mut store = Store::default();
    let empty = payload_bytes(&[("e", &[])]);
    let one = payload_bytes(&[("e", &[("A", "1")])]);
    record(&mut store, 1, &empty, &one);
    let marker = store
        .get(&lpm_env_companion::account::CompanionAccount::Marker {
            vault_id: VAULT.to_owned(),
        })
        .expect("marker")
        .to_vec();
    let head = store
        .get(&lpm_env_companion::history::head_account(VAULT))
        .expect("head")
        .to_vec();
    let key = store
        .get(&lpm_env_companion::history::key_account(VAULT))
        .expect("key")
        .to_vec();
    let blobs: [&[u8]; 3] = [&marker, &head, &key];
    let request = json!({ "vaultId": VAULT, "marker": 1, "head": 2, "key": 3 });
    let (status, asked, _) = call(lpm_env_history_check, &request, &blobs);
    assert_eq!(status, 0, "{asked}");
    assert_eq!(asked["needsParts"], json!([0]));
    assert_eq!(asked["damage"], Value::Null, "no verdict without the parts");

    let request =
        json!({ "vaultId": VAULT, "marker": 1, "head": 2, "key": 3, "parts": [{ "part": 0 }] });
    let (status, check, _) = call(lpm_env_history_check, &request, &blobs);
    assert_eq!(status, 0, "{check}");
    assert_eq!(check["needsParts"], Value::Null);
    let damage = check["damage"].as_array().expect("damage");
    assert_eq!(damage.len(), 1, "a missing tail with nothing before it");
    assert_eq!(damage[0]["kind"], "history");

    let names: Vec<String> = store.records.keys().cloned().collect();
    let assess = json!({
        "vaultId": VAULT,
        "marker": base64::engine::general_purpose::STANDARD.encode(&marker),
        "inventory": names,
        "historyDamage": [{ "kind": damage[0]["kind"], "reason": damage[0]["reason"] }],
    });
    let assessed = assess_json(&assess);
    assert_eq!(
        assessed["repairs"],
        json!([{ "action": "removeFeature", "feature": "history" }]),
        "{assessed}"
    );
    assert_eq!(
        assessed["allows"]["write"], true,
        "history damage never blocks values"
    );
}

fn assess_json(request: &Value) -> Value {
    let input = serde_json::to_vec(request).expect("request");
    // SAFETY: The pointer and length describe the live request buffer.
    let mut output =
        unsafe { crate::companion::lpm_env_companion_assess(input.as_ptr(), input.len()) };
    // SAFETY: The engine returned this boxed slice and it's read before release.
    let bytes = unsafe { std::slice::from_raw_parts(output.data, output.length) };
    let value: Value = serde_json::from_slice(bytes).expect("assess JSON");
    assert_eq!(output.status, 0, "{value}");
    // SAFETY: Released once, after reading.
    unsafe { crate::lpm_env_clear_output(&mut output) };
    // SAFETY: Released once.
    unsafe { crate::lpm_env_release(output) };
    value
}

#[test]
fn growth_admission_answers_for_the_ring_it_names() {
    let mut names: Vec<String> = (0..3_000)
        .map(|index| {
            format!(
                "__vault_companion_v1__:notes:{}",
                URL_SAFE_NO_PAD.encode(format!("p{index}"))
            )
        })
        .collect();
    let mut shrunk = Head::new(VAULT, 2);
    shrunk.parts = vec![0, 1];
    let head = shrunk.encode(HISTORY).expect("head");
    let request = json!({ "names": names, "operation": "growth", "vaultId": VAULT, "head": 1 });
    let (status, admission, _) = call(lpm_env_history_admission, &request, &[&head]);
    assert_eq!(status, 0, "{admission}");
    assert_eq!(
        admission["growth"], true,
        "back below 3,584 records, it grows again"
    );
    names.extend((3_000..3_800).map(|index| {
        format!(
            "__vault_companion_v1__:notes:{}",
            URL_SAFE_NO_PAD.encode(format!("p{index}"))
        )
    }));
    let request = json!({ "names": names, "operation": "growth", "vaultId": VAULT, "head": 1 });
    let (_, admission, _) = call(lpm_env_history_admission, &request, &[&head]);
    assert_eq!(
        admission["growth"], false,
        "between 3,584 and 4,096 a shrunk ring keeps its size, so rings don't flap"
    );
}

#[test]
fn a_rollback_onto_a_name_another_environment_holds_is_refused() {
    let mut store = Store::default();
    let empty = payload_bytes(&[("stage", &[])]);
    let first = payload_bytes(&[("stage", &[("K", "1")])]);
    record(&mut store, 1, &empty, &first);
    let renamed = payload_bytes(&[("staging", &[("K", "1")])]);
    let mut owned: Vec<Vec<u8>> = vec![first.clone(), renamed];
    for account in [
        lpm_env_companion::history::head_account(VAULT),
        lpm_env_companion::history::key_account(VAULT),
        lpm_env_companion::history::part_account(VAULT, store.head().tail()),
    ] {
        owned.push(store.get(&account).expect("record").to_vec());
    }
    let mut renaming = change(2, "renameEnvironment");
    renaming["renames"] = json!([{ "environment": { "from": "stage", "to": "staging" } }]);
    let request = json!({
        "vaultId": VAULT,
        "change": renaming,
        "before": 1,
        "after": 2,
        "append": { "head": 3, "key": 4, "tail": 5, "growth": "unasked" },
    });
    let blobs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    let (status, response, out) = call(lpm_env_history_record, &request, &blobs);
    assert_eq!(status, 0, "{response}");
    store.apply(&response, &out);

    let taken = payload_bytes(&[("stage", &[("J", "2")]), ("staging", &[("K", "1")])]);
    let rollback = json!({ "kind": "environment", "entry": hex::encode([1; 16]), "environment": "staging", "environmentNamed": "now", "side": "after" });
    let (request, blobs) = store.reading(&taken, json!({ "rollback": rollback }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, refusal, _) = call(lpm_env_history_rollback, &request, &blob_refs);
    assert_eq!(
        (status, refusal["code"].as_str()),
        (5, Some("history.name_taken")),
        "{refusal}"
    );
}

#[test]
fn a_removal_starts_only_from_the_review_it_was_shown() {
    let mut store = Store::default();
    let empty = payload_bytes(&[("e", &[])]);
    let one = payload_bytes(&[("e", &[("A", "true"), ("B", "true")])]);
    record(&mut store, 1, &empty, &one);
    let two = payload_bytes(&[("e", &[("A", "false"), ("B", "true")])]);
    record(&mut store, 2, &one, &two);
    let chosen =
        json!({ "entry": hex::encode([2; 16]), "environment": "e", "key": "A", "side": "before" });
    let (request, blobs) = store.reading(&two, json!({ "chosen": chosen }));
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (status, review, _) = call(lpm_env_history_removal, &request, &blob_refs);
    assert_eq!(status, 0, "{review}");
    let review = review["review"].clone();
    let this_key = review["places"]
        .as_array()
        .expect("places")
        .iter()
        .position(|place| place["key"] == "A")
        .expect("A");
    let other_key = review["places"]
        .as_array()
        .expect("places")
        .iter()
        .position(|place| place["key"] == "B")
        .expect("B");
    let start = |review: &Value| {
        let (request, blobs) = store.reading(
            &two,
            json!({ "start": {
                "review": review,
                "selection": [this_key],
                "approval": "automatic",
                "fingerprint": review["fingerprint"],
            } }),
        );
        let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        let (status, response, _) = call(lpm_env_history_removal, &request, &blob_refs);
        (status, response["code"].as_str().map(str::to_owned))
    };
    let mut forgeries = Vec::new();
    let mut other_digests = review.clone();
    other_digests["places"][this_key]["digests"] = review["places"][other_key]["digests"].clone();
    forgeries.push(("another place's digests", other_digests));
    let mut renamed = review.clone();
    renamed["places"][this_key]["key"] = json!("NOT_A_KEY");
    forgeries.push(("another name", renamed));
    let mut current = review.clone();
    assert_eq!(
        review["places"][other_key]["current"], true,
        "B holds it now"
    );
    current["places"][other_key]["current"] = json!(false);
    forgeries.push(("another current flag", current));
    let mut value = review.clone();
    value["value"] = review["places"][this_key]["digests"][0].clone();
    forgeries.push(("another value", value));
    for (what, forged) in &forgeries {
        assert_eq!(
            start(forged),
            (5, Some("history.changed_since_review".to_owned())),
            "{what}"
        );
    }
    assert_eq!(start(&review).0, 0, "the review as shown starts");
}
