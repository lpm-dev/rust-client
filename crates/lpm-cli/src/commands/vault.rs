use lpm_common::LpmError;

const VAULT_UNAVAILABLE_MESSAGE: &str =
    "LPM Vault is not publicly available yet. Use `lpm env` for secrets management.";

/// Run the hidden `lpm vault` command.
#[allow(unused_variables)]
pub async fn run(action: &str, json_output: bool) -> Result<(), LpmError> {
    let _ = (action, json_output);
    Err(LpmError::Script(VAULT_UNAVAILABLE_MESSAGE.into()))
}
