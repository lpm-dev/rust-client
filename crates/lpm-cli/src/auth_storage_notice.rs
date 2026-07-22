pub fn attach(session: lpm_auth::SessionManager, json_output: bool) -> lpm_auth::SessionManager {
    if json_output {
        return session;
    }

    attach_for_human(session)
}

#[cfg(target_os = "macos")]
fn attach_for_human(session: lpm_auth::SessionManager) -> lpm_auth::SessionManager {
    session.with_auth_storage_access_notice(|kind| {
        crate::install_ui::phase_untrusted(kind.macos_notice_message());
    })
}

#[cfg(not(target_os = "macos"))]
fn attach_for_human(session: lpm_auth::SessionManager) -> lpm_auth::SessionManager {
    session
}
