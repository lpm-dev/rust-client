//! The local history fixtures both clients test against, generated from the
//! engine with fixed randomness so they always match it. LPM Vault reads the
//! copy the engine export ships, and the compatibility job runs every state
//! here through the oldest engine still in use.
//!
//! Run with `LPM_UPDATE_HISTORY_FIXTURES=1` to rewrite the file after a
//! deliberate format change.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::account::CompanionAccount;
use crate::append_log::{HISTORY, Head, Removing};
use crate::history::codec::Action;
use crate::history::test_support::{Project, Store, VAULT};
use crate::history::{RecordWrite, head_account, key_account, off_entry, part_account, removal};
use crate::keyring::tests::CountingRandom;
use crate::keyring::{self, Approval, KeyRecord, PartIdentity};
use crate::marker::{FeatureState, Marker};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/history.json");

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn key_records() -> Value {
    let stable = KeyRecord::generate(Approval::Automatic, &mut CountingRandom(1)).expect("record");
    let stable_bytes = stable.encode().to_vec();
    let mut rotating = KeyRecord::decode(&stable_bytes).expect("decodes");
    rotating
        .begin_rotation(Approval::Protected, &mut CountingRandom(150))
        .expect("rotation");
    let rotating_bytes = rotating.encode().to_vec();
    let mut version = stable_bytes.clone();
    version[4] = 2;
    let mut generation = stable_bytes.clone();
    generation[55..59].copy_from_slice(&[0, 0, 0, 0]);
    json!([
        { "name": "stable", "bytes": b64(&stable_bytes), "valid": true, "rotating": false },
        { "name": "rotating", "bytes": b64(&rotating_bytes), "valid": true, "rotating": true },
        { "name": "unknown version", "bytes": b64(&version), "valid": false },
        { "name": "generation zero", "bytes": b64(&generation), "valid": false },
        { "name": "truncated", "bytes": b64(&stable_bytes[..90]), "valid": false },
    ])
}

fn envelopes() -> Value {
    let record = KeyRecord::generate(Approval::Automatic, &mut CountingRandom(1)).expect("record");
    let identity = PartIdentity {
        vault_id: VAULT,
        kind: HISTORY.kind,
        part: 3,
        schema_version: HISTORY.schema_version,
    };
    let sealed = keyring::seal(
        record.current(),
        &identity,
        b"part plaintext",
        &mut CountingRandom(9),
    )
    .expect("sealed");
    let mut header = sealed.clone();
    header[4] = 2;
    let mut tag = sealed.clone();
    let last = tag.len() - 1;
    tag[last] ^= 1;
    let case = |name: &str, bytes: &[u8], part: u16, opens: bool| {
        json!({
            "name": name,
            "keyRecord": "stable",
            "vaultId": VAULT,
            "kind": HISTORY.kind,
            "part": part,
            "schemaVersion": HISTORY.schema_version,
            "sealed": b64(bytes),
            "plaintext": opens.then(|| b64(b"part plaintext")),
        })
    };
    json!([
        case("opens as itself", &sealed, 3, true),
        case("another part number", &sealed, 4, false),
        case("an unknown envelope version", &header, 3, false),
        case("a changed tag", &tag, 3, false),
    ])
}

fn records(store: &Store) -> Value {
    Value::Object(
        store
            .records
            .iter()
            .map(|(account, bytes)| (account.clone(), json!(b64(bytes))))
            .collect(),
    )
}

fn state(name: &str, store: &Store, values: &Project, note: &str) -> Value {
    let payload = json!({ "environments": values.environments });
    json!({
        "name": name,
        "note": note,
        "records": records(store),
        "values": b64(&serde_json::to_vec(&payload).expect("payload")),
    })
}

fn put_marker(store: &mut Store, marker: &Marker) {
    store.put(RecordWrite::new(
        CompanionAccount::Marker {
            vault_id: VAULT.to_owned(),
        },
        marker.encode().expect("marker"),
    ));
}

/// Every state history can be in, mid-crash ones included.
fn states() -> Value {
    let mut out = Vec::new();
    let mut store = Store::new();
    let empty = Project::with(&[("production", &[]), ("staging", &[])]);
    let mut project = Project::with(&[("production", &[("API_KEY", "one")]), ("staging", &[])]);
    store
        .record(Action::Set, &empty, &project, &[])
        .expect("created");
    out.push(state(
        "created",
        &store,
        &project,
        "the first change created history",
    ));

    let mut next = project.clone();
    next.set("staging", "API_KEY", "one");
    store
        .record(Action::Set, &project, &next, &[])
        .expect("appended");
    project = next;
    out.push(state("appended", &store, &project, "a steady append"));

    let mut round = 0_u32;
    while store.head().parts.len() < 2 {
        round += 1;
        assert!(round < 64, "the ring rolls over within a few large changes");
        let mut next = project.clone();
        next.set(
            "production",
            "LARGE",
            &format!("{round}{}", "x".repeat(6 * 1024)),
        );
        store
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
    }
    out.push(state(
        "rolled over",
        &store,
        &project,
        "the ring grew into part 1",
    ));

    let mut interrupted = Store {
        records: store.records.clone(),
        ..Store::new()
    };
    interrupted.delete(&part_account(VAULT, interrupted.head().tail()));
    out.push(state(
        "rollover interrupted",
        &interrupted,
        &project,
        "a rollover wrote its head and crashed before its part; the next append recovers",
    ));

    let opened = crate::history::read::Opened::open(
        VAULT,
        store.get(&head_account(VAULT)).expect("head"),
        store.get(&key_account(VAULT)).expect("key"),
    )
    .expect("opens");
    let mut removing = Store {
        records: store.records.clone(),
        ..Store::new()
    };
    let mut head = removing.head();
    head.removing = Some(Removing {
        value: opened.keys.value(b"one"),
        places: vec![opened.keys.place("production", "API_KEY")],
    });
    removing.put(RecordWrite::new(
        head_account(VAULT),
        head.encode(HISTORY).expect("head"),
    ));
    let mut key = removing.key();
    key.begin_rotation(Approval::Automatic, &mut CountingRandom(200))
        .expect("rotation");
    removing.put(RecordWrite {
        account: key_account(VAULT),
        bytes: key.encode(),
    });
    out.push(state(
        "removal started",
        &removing,
        &project,
        "a removal's first transaction committed; readers scrub, and any client finishes it",
    ));

    let opened = crate::history::read::Opened::open(
        VAULT,
        removing.get(&head_account(VAULT)).expect("head"),
        removing.get(&key_account(VAULT)).expect("key"),
    )
    .expect("opens");
    let first = opened.head.parts[0];
    let rewritten = removal::rotate_part(
        &opened,
        first,
        removing.get(&part_account(VAULT, first)),
        &mut CountingRandom(33),
    )
    .expect("rotates")
    .expect("a part under the old key");
    removing.put(rewritten);
    out.push(state(
        "removal partway",
        &removing,
        &project,
        "one part is under the new key, the other still under the old",
    ));

    let mut turning_off = Store {
        records: store.records.clone(),
        ..Store::new()
    };
    let mut marker = turning_off.marker().expect("marker");
    marker
        .features
        .get_mut(crate::history::FEATURE)
        .expect("history")
        .state = FeatureState::Removing;
    marker
        .features
        .insert(crate::history::OFF_FEATURE.to_owned(), off_entry());
    put_marker(&mut turning_off, &marker);
    out.push(state(
        "turning off",
        &turning_off,
        &project,
        "a batched turn-off committed its first transaction; resuming removes history and keeps it off",
    ));

    let mut off = Store::new();
    let mut marker = Marker::empty(VAULT, crate::marker::ProjectState::Active);
    marker
        .features
        .insert(crate::history::OFF_FEATURE.to_owned(), off_entry());
    put_marker(&mut off, &marker);
    out.push(state(
        "off",
        &off,
        &project,
        "history is off: the entry, no records",
    ));
    Value::Array(out)
}

fn heads() -> Value {
    let valid = Head::new(VAULT, 16).encode(HISTORY).expect("head");
    let text = String::from_utf8(valid).expect("UTF-8");
    json!([
        { "name": "new ring", "json": text, "valid": true },
        { "name": "repeated part", "json": text.replace("[0]", "[0,0]"), "valid": false },
        { "name": "missing removing", "json": text.replace(",\"removing\":null", ""), "valid": false },
        { "name": "ring limit 17", "json": text.replace("\"ringLimit\":16", "\"ringLimit\":17"), "valid": false },
    ])
}

fn generate() -> String {
    let fixture = json!({
        "schemaVersion": 1,
        "vaultId": VAULT,
        "keyRecords": key_records(),
        "heads": heads(),
        "envelopes": envelopes(),
        "states": states(),
    });
    let mut text = serde_json::to_string_pretty(&fixture).expect("json");
    text.push('\n');
    text
}

#[test]
fn history_fixtures_match_the_engine() {
    let generated = generate();
    if std::env::var_os("LPM_UPDATE_HISTORY_FIXTURES").is_some() {
        std::fs::write(PATH, &generated).expect("write fixtures");
    }
    let committed = std::fs::read_to_string(PATH).unwrap_or_default();
    assert!(
        committed == generated,
        "tests/fixtures/history.json is stale; run with LPM_UPDATE_HISTORY_FIXTURES=1"
    );
}

#[test]
fn every_fixture_state_reads_as_its_note_says() {
    let fixture: Value = serde_json::from_str(&generate()).expect("json");
    for state in fixture["states"].as_array().expect("states") {
        let records: std::collections::BTreeMap<String, Vec<u8>> = state["records"]
            .as_object()
            .expect("records")
            .iter()
            .map(|(account, bytes)| {
                (
                    account.clone(),
                    STANDARD
                        .decode(bytes.as_str().expect("base64"))
                        .expect("base64"),
                )
            })
            .collect();
        let marker = records
            .get(&crate::account::marker_account(VAULT))
            .map(|bytes| Marker::parse(VAULT, bytes).expect("a valid marker"));
        let inventory: Vec<CompanionAccount> = records
            .keys()
            .filter_map(|name| CompanionAccount::parse(name))
            .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
            .collect();
        let assessment = crate::assessment::assess(
            VAULT,
            crate::assessment::Observed {
                marker: records
                    .get(&crate::account::marker_account(VAULT))
                    .map(Vec::as_slice),
                inventory: Some(&inventory),
                ..crate::assessment::Observed::default()
            },
        );
        assert!(
            assessment.authorize(crate::gate::Operation::Write).is_ok(),
            "{}: {:?}",
            state["name"],
            assessment.damage
        );
        if let Some(marker) = marker
            && crate::lifecycle::needs_resume(&marker)
        {
            crate::lifecycle::plan_resume(marker, inventory).expect("resumable");
        }
    }
}
