//! Run every local history state this release writes, mid-crash states
//! included, through an older companion engine's assessment and resume. Each
//! must be a valid project at level `ignore` that allows writes, with no
//! damage, and every interrupted step must finish: none may be `Unfinished`,
//! which only a project-wide discard repairs, and which would lose "off".
//! Every journal transaction history commits must pass the older engine's
//! transaction check, which that release's recovery runs before it replays
//! a journal.
//!
//! The source uses only API the older engine has, so it builds against it.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use lpm_env_companion::account::{CompanionAccount, marker_account};
use lpm_env_companion::assessment::{Observed, assess};
use lpm_env_companion::gate::Operation;
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
    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("FAIL {failure}");
        }
        std::process::exit(1);
    }
    println!(
        "{} states read and {} transactions accepted by the older engine",
        states.len(),
        transactions.len()
    );
}
