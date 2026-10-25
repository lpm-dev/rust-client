//! `lpm env repair`: show what's damaged in a project's newer data and
//! repair it, where LPM Vault isn't there to do it.

use lpm_common::LpmError;
use lpm_vault::{CompanionRepair, CompanionReview};

use crate::{install_ui, output};

pub(super) fn env_repair(
    project_dir: &std::path::Path,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let review = lpm_vault::review_companion_data(project_dir)
        .map_err(LpmError::Script)?
        .ok_or_else(|| {
            LpmError::Script(
                "this directory has no env project, so there's nothing to repair".to_owned(),
            )
        })?;
    if review.problems.is_empty() {
        if json_output {
            print_json(&review, &[]);
        } else {
            output::success("this env project's newer data isn't damaged");
        }
        return Ok(());
    }
    let repairs = review.repairs();
    if json_output {
        if repairs.is_empty() || !yes {
            print_json(&review, &[]);
            return Err(LpmError::ExitCode(1));
        }
    } else {
        print_review(&review);
        if repairs.is_empty() {
            return Err(LpmError::Script(
                "only LPM Vault can set this env project's CLI approval right; switch it there"
                    .to_owned(),
            ));
        }
        if !yes {
            if !is_interactive() {
                return Err(LpmError::Script(
                    "repairing deletes the damaged data; run lpm env repair --yes to repair it"
                        .to_owned(),
                ));
            }
            let confirmed = cliclack::confirm("Repair this env project's newer data?")
                .initial_value(false)
                .interact()
                .map_err(|error| LpmError::Script(format!("prompt failed: {error}")))?;
            if !confirmed {
                output::info("nothing was changed");
                return Ok(());
            }
        }
    }
    let repaired =
        lpm_vault::repair_companion_data(project_dir, &review).map_err(LpmError::Script)?;
    if json_output {
        print_json(&review, &repaired);
    } else {
        for repair in &repaired {
            output::success_line(install_ui::terminal_line!(
                "repaired: {}",
                install_ui::field(&repair.describe())
            ));
        }
    }
    Ok(())
}

fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn print_review(review: &CompanionReview) {
    output::warn("this env project's newer data is damaged:");
    for problem in &review.problems {
        println!("    {}", install_ui::red(&problem.description));
        let fix = match &problem.repair {
            Some(repair) => repair.describe(),
            None => "switch the project's CLI approval in LPM Vault to set it again".to_owned(),
        };
        println!(
            "      {} {}",
            install_ui::dim("repair:"),
            install_ui::field(&fix)
        );
    }
}

fn repair_json(repair: &CompanionRepair) -> serde_json::Value {
    match repair {
        CompanionRepair::DiscardProject => serde_json::json!({"action": "discardProject"}),
        CompanionRepair::RemoveFeature(feature) => {
            serde_json::json!({"action": "removeFeature", "feature": feature})
        }
        CompanionRepair::RemoveUnlisted => serde_json::json!({"action": "removeUnlisted"}),
    }
}

fn print_json(review: &CompanionReview, repaired: &[CompanionRepair]) {
    let problems: Vec<serde_json::Value> = review
        .problems
        .iter()
        .map(|problem| {
            serde_json::json!({
                "damage": problem.description,
                "repair": problem.repair.as_ref().map(repair_json),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "success": review.problems.is_empty() || !repaired.is_empty(),
            "problems": problems,
            "repaired": repaired.iter().map(repair_json).collect::<Vec<_>>(),
        })
    );
}
