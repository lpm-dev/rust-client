//! Run every local history state this release writes, mid-crash states
//! included, through an older companion engine's assessment and resume. Each
//! must be a valid project at level `ignore` that allows writes, with no
//! damage, and every interrupted step must finish: none may be `Unfinished`,
//! which only a project-wide discard repairs, and which would lose "off".
//! Every journal transaction history commits must pass the older engine's
//! transaction check, which that release's recovery runs before it replays
//! a journal.
//!
//! Given the personal override change fixtures too, every transaction a
//! change plans must pass that check, and the project it leaves must never
//! be damaged. While it has overrides, which this release writes as a
//! version the older engine doesn't support, the older engine must refuse
//! its values and still maintain it; once it has none, the older engine
//! reads and writes it as before.
//!
//! The source uses only API the older engine has, so it builds against it.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lpm_env_companion::account::{CompanionAccount, marker_account, record_account};
use lpm_env_companion::assessment::{Observed, assess};
use lpm_env_companion::gate::{GateError, Operation};
use lpm_env_companion::invariants::check_transaction;
use lpm_env_companion::lifecycle::{self, LifecycleStore, Mutation};
use lpm_env_companion::marker::{Level, Marker};

struct Store(BTreeMap<String, Vec<u8>>);

impl LifecycleStore for Store {
    fn read(&mut self, account: &CompanionAccount) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.get(&account.name()).cloned())
    }

    fn commit(&mut self, mutations: Vec<Mutation>) -> Result<(), String> {
        for mutation in mutations {
            match mutation {
                Mutation::Write { account, value } => {
                    self.0.insert(account.name(), value.to_vec());
                }
                Mutation::Delete { account } => {
                    self.0.remove(&account.name());
                }
            }
        }
        Ok(())
    }
}

fn inventory(records: &BTreeMap<String, Vec<u8>>) -> Vec<CompanionAccount> {
    records
        .keys()
        .filter_map(|name| CompanionAccount::parse(name))
        .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
        .collect()
}

fn check(vault_id: &str, name: &str, records: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let marker_name = marker_account(vault_id);
    let accounts = inventory(records);
    let assessment = assess(
        vault_id,
        Observed {
            marker: records.get(&marker_name).map(Vec::as_slice),
            inventory: Some(&accounts),
            ..Observed::default()
        },
    );
    if let Some(damage) = assessment.every_damage().next() {
        return Err(format!("{name}: damaged: {damage}"));
    }
    assessment
        .authorize(Operation::Write)
        .map_err(|error| format!("{name}: writes refused: {error}"))?;
    let Some(bytes) = records.get(&marker_name) else {
        return Ok(());
    };
    let marker = Marker::parse(vault_id, bytes).map_err(|error| format!("{name}: {error}"))?;
    if marker.level() != Level::Ignore {
        return Err(format!("{name}: level {:?}, not ignore", marker.level()));
    }
    if lifecycle::needs_resume(&marker) {
        let mut store = Store(records.clone());
        lifecycle::resume(&mut store, marker, accounts)
            .map_err(|error| format!("{name}: unfinished: {}", error.into_message()))?;
        check(vault_id, &format!("{name}, resumed"), &store.0)?;
    }
    Ok(())
}

fn decoded(text: &serde_json::Value) -> Vec<u8> {
    STANDARD
        .decode(text.as_str().expect("base64"))
        .expect("base64")
}

fn records_of(value: &serde_json::Value) -> BTreeMap<String, Vec<u8>> {
    value
        .as_object()
        .expect("records")
        .iter()
        .map(|(account, bytes)| (account.clone(), decoded(bytes)))
        .collect()
}

fn replay_check(transaction: &serde_json::Value) -> Result<(), String> {
    let name = transaction["name"].as_str().expect("name");
    let records = records_of(&transaction["records"]);
    let values: Vec<(String, Option<Vec<u8>>)> = transaction["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .map(|change| {
            (
                change["account"].as_str().expect("account").to_owned(),
                (!change["value"].is_null()).then(|| decoded(&change["value"])),
            )
        })
        .collect();
    let changes: Vec<(&str, Option<&[u8]>)> = values
        .iter()
        .map(|(account, value)| (account.as_str(), value.as_deref()))
        .collect();
    check_transaction(
        &changes,
        |vault_id| Ok(records.get(&marker_account(vault_id)).cloned()),
        |_| Ok(inventory(&records)),
    )
    .map_err(|refusal| format!("{name}: recovery would refuse it: {refusal}"))
}

/// Plan by plan, the project a personal override change leaves, through
/// the older engine: its transaction passes the check recovery runs, and the
/// project is never damaged. One that still has overrides is refused for its
/// values and maintained; one without reads and allows writes.
fn override_change_check(case: &serde_json::Value) -> Result<(), String> {
    let name = case["name"].as_str().expect("name");
    let vault_id = case["vaultId"].as_str().expect("vaultId");
    let marker_name = marker_account(vault_id);
    let record_name = record_account("overrides", vault_id, None);
    let mut before = BTreeMap::new();
    for (account, field) in [(&marker_name, "marker"), (&record_name, "record")] {
        if let Some(text) = case[field].as_str() {
            before.insert(account.clone(), text.as_bytes().to_vec());
        }
    }
    let expect = &case["expect"];
    let writes = expect["writes"].as_object().expect("writes");
    let deletes = expect["deletes"].as_array().expect("deletes");
    let mut changes: Vec<(String, Option<Vec<u8>>)> = writes
        .iter()
        .map(|(account, text)| {
            (
                account.clone(),
                Some(text.as_str().expect("record").as_bytes().to_vec()),
            )
        })
        .collect();
    changes.extend(
        deletes
            .iter()
            .map(|account| (account.as_str().expect("account").to_owned(), None)),
    );
    let borrowed: Vec<(&str, Option<&[u8]>)> = changes
        .iter()
        .map(|(account, value)| (account.as_str(), value.as_deref()))
        .collect();
    check_transaction(
        &borrowed,
        |vault_id| Ok(before.get(&marker_account(vault_id)).cloned()),
        |_| Ok(inventory(&before)),
    )
    .map_err(|refusal| format!("{name}: recovery would refuse it: {refusal}"))?;
    let mut after = before;
    for (account, value) in changes {
        match value {
            Some(value) => {
                after.insert(account, value);
            }
            None => {
                after.remove(&account);
            }
        }
    }
    let accounts = inventory(&after);
    let assessment = assess(
        vault_id,
        Observed {
            marker: after.get(&marker_name).map(Vec::as_slice),
            inventory: Some(&accounts),
            overrides: Some(after.get(&record_name).map(Vec::as_slice)),
            ..Observed::default()
        },
    );
    if let Some(damage) = assessment.every_damage().next() {
        return Err(format!("{name}: damaged: {damage}"));
    }
    let has_overrides = match after.get(&marker_name) {
        Some(bytes) => Marker::parse(vault_id, bytes)
            .map_err(|error| format!("{name}: {error}"))?
            .feature("overrides")
            .is_some(),
        None => false,
    };
    if has_overrides {
        for operation in [Operation::ReadApplyingOverrides, Operation::Write] {
            match assessment.authorize(operation) {
                Err(GateError::Unsupported {
                    level: Level::Refuse,
                    ..
                }) => {}
                other => {
                    return Err(format!(
                        "{name}: {operation:?} wasn't refused as unsupported: {other:?}"
                    ));
                }
            }
        }
        return assessment
            .authorize(Operation::Maintenance)
            .map_err(|error| format!("{name}: maintenance refused: {error}"));
    }
    for operation in [Operation::ReadApplyingOverrides, Operation::Write] {
        assessment
            .authorize(operation)
            .map_err(|error| format!("{name}: {operation:?} refused: {error}"))?;
    }
    lpm_env_companion::overrides::evaluate_all(
        &assessment.gate,
        vault_id,
        after.get(&record_name).map(Vec::as_slice),
    )
    .map(|_| ())
    .map_err(|damage| format!("{name}: overrides unreadable: {damage}"))
}

fn main() {
    let path = std::env::args().nth(1).expect("the history fixtures' path");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read fixtures"))
            .expect("fixtures are JSON");
    let vault_id = fixture["vaultId"].as_str().expect("vaultId");
    let mut failures = Vec::new();
    let states = fixture["states"].as_array().expect("states");
    for state in states {
        let name = state["name"].as_str().expect("name");
        let records = records_of(&state["records"]);
        match check(vault_id, name, &records) {
            Ok(()) => println!("ok: {name}"),
            Err(failure) => failures.push(failure),
        }
    }
    let transactions = fixture["transactions"].as_array().expect("transactions");
    for transaction in transactions {
        match replay_check(transaction) {
            Ok(()) => println!("ok: {}", transaction["name"].as_str().expect("name")),
            Err(failure) => failures.push(failure),
        }
    }
    let mut override_changes = 0;
    if let Some(path) = std::env::args().nth(2) {
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read fixtures"))
                .expect("fixtures are JSON");
        for case in fixture["cases"].as_array().expect("cases") {
            if case["expect"]["result"] != "planned" {
                continue;
            }
            override_changes += 1;
            match override_change_check(case) {
                Ok(()) => println!("ok: {}", case["name"].as_str().expect("name")),
                Err(failure) => failures.push(failure),
            }
        }
    }
    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("FAIL {failure}");
        }
        std::process::exit(1);
    }
    println!(
        "{} states read, {} transactions and {override_changes} personal override changes accepted by the older engine",
        states.len(),
        transactions.len()
    );
}
