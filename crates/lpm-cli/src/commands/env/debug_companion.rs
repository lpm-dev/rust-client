//! `lpm env debug-companion`: plant a companion storage state for trying
//! LPM and LPM Vault against the same data by hand. Debug builds only; on
//! macOS the binary must be signed for the shared Keychain group, as
//! `scripts/build-signed-macos.sh` signs it.

use lpm_common::LpmError;
use lpm_vault::DebugCompanionState;

use crate::output;

pub(super) fn plant(
    project_dir: &std::path::Path,
    state: &str,
    environment: Option<&str>,
    set: &[String],
    unset: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let planted = DebugCompanionState::named(state, environment, set, unset)
        .and_then(|state| lpm_vault::plant_debug_companion_state(project_dir, &state))
        .map_err(LpmError::Script)?;
    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "state": state, "planted": planted})
        );
    } else {
        output::success(&planted);
    }
    Ok(())
}
