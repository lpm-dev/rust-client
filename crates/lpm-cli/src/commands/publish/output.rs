use super::types::{LpmPublicationStatus, PublishResult, PublishTarget};
use crate::{install_ui, quality};
use std::collections::HashMap;

pub(super) fn publish_result_json(result: &PublishResult) -> serde_json::Value {
    let mut object = serde_json::Map::with_capacity(8);
    object.insert(
        "registry".to_string(),
        serde_json::Value::String(result.target.clone()),
    );
    object.insert(
        "success".to_string(),
        serde_json::Value::Bool(result.success),
    );
    object.insert(
        "error".to_string(),
        result
            .error
            .as_ref()
            .map_or(serde_json::Value::Null, |error| {
                serde_json::Value::String(error.clone())
            }),
    );
    if let Some(auth) = result.auth {
        object.insert(
            "auth".to_string(),
            serde_json::Value::String(auth.to_string()),
        );
    }
    if let Some(status) = &result.publication_status {
        object.insert(
            "publication_status".to_string(),
            serde_json::Value::String(status.as_str().to_string()),
        );
    }
    if let Some(current_latest_version) = &result.current_latest_version {
        object.insert(
            "current_latest_version".to_string(),
            serde_json::Value::String(current_latest_version.clone()),
        );
    }
    if let Some(wait) = &result.publication_wait {
        object.insert(
            "publication_wait".to_string(),
            serde_json::json!({
                "success": wait.success,
                "status": wait.status.as_ref().map(LpmPublicationStatus::as_str),
                "current_latest_version": wait.current_latest_version.as_deref(),
                "error": wait.error.as_deref(),
            }),
        );
    }
    object.insert(
        "duration_ms".to_string(),
        serde_json::json!(result.duration.as_millis() as u64),
    );
    serde_json::Value::Object(object)
}

pub(super) fn publish_check_json(
    quality_result: Option<&quality::QualityResult>,
    targets: &[PublishTarget],
    target_names: &HashMap<String, String>,
) -> serde_json::Value {
    let mut json = quality_result
        .and_then(|qr| serde_json::to_value(qr).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({ "quality": null }));

    let obj = json
        .as_object_mut()
        .expect("publish check JSON seed must be an object");
    obj.insert("success".to_string(), serde_json::Value::Bool(true));
    obj.insert("check".to_string(), serde_json::Value::Bool(true));
    obj.insert(
        "targets".to_string(),
        serde_json::Value::Array(
            targets
                .iter()
                .map(|target| {
                    let key = target.key();
                    serde_json::json!({
                        "registry": target.output_key(),
                        "name": target_names.get(&key),
                    })
                })
                .collect(),
        ),
    );

    json
}

pub(super) fn format_upload_message(registry: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!("Uploading tarball to {}", install_ui::yellow(registry))
}

pub(super) fn print_upload_details(
    target_name: &str,
    version: &str,
    visibility: &str,
    dist_tag: &str,
) {
    publish_detail(
        "target",
        install_ui::yellow(&format!("{target_name}@{version}")),
    );
    publish_detail("visibility", format_publish_visibility(visibility));
    publish_detail("dist-tag", install_ui::yellow(dist_tag));
}

pub(super) struct DryRunSummary<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
    pub(super) target_names: &'a HashMap<String, String>,
    pub(super) file_count: usize,
    pub(super) tarball_size: usize,
    pub(super) quality_result: Option<&'a quality::QualityResult>,
    pub(super) has_skills: bool,
    pub(super) ecosystem: &'a str,
    pub(super) targets: &'a [PublishTarget],
}

pub(super) fn print_dry_run_summary(summary: &DryRunSummary<'_>) {
    install_ui::detail("");
    install_ui::phase("Dry run — no changes will be made");
    publish_detail(
        "package",
        install_ui::yellow(&format!("{}@{}", summary.name, summary.version)),
    );
    for target in summary.targets {
        let key = target.key();
        if let Some(target_name) = summary.target_names.get(&key) {
            publish_detail(
                &format!("{} name", target.output_key()),
                install_ui::yellow(target_name),
            );
        }
    }
    publish_detail(
        "files",
        format_dry_run_files_value(summary.file_count, summary.tarball_size),
    );
    if let Some(qr) = summary.quality_result {
        publish_detail(
            "quality",
            &crate::install_ui::terminal_line!(
                "{}/{}",
                install_ui::status_ok(&qr.score.to_string()),
                qr.max_score
            ),
        );
    }
    if summary.has_skills {
        publish_detail("skills", install_ui::status_ok("included"));
    }
    publish_detail("ecosystem", install_ui::yellow(summary.ecosystem));
    let target_keys = summary
        .targets
        .iter()
        .map(PublishTarget::output_key)
        .collect::<Vec<_>>();
    publish_detail("targets", install_ui::yellow(&target_keys.join(", ")));
    install_ui::detail("");
}

pub(super) fn publish_detail<T: install_ui::TerminalValue>(label: &str, value: T) {
    let label = format!("{label:<10}");
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "    {} {}",
        install_ui::dim(&label),
        value
    ));
}

pub(super) fn format_dry_run_files_value(
    file_count: usize,
    tarball_size: usize,
) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "{} files {}",
        install_ui::status_ok(&file_count.to_string()),
        install_ui::dim(&format!(
            "({})",
            lpm_common::format_bytes(tarball_size as u64)
        ))
    )
}

pub(super) fn format_publish_retry_detail(target: &PublishTarget) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim("Retry:"),
        install_ui::yellow(&format!("lpm publish {}", target.retry_flag()))
    )
}

pub(super) fn format_lpm_publication_notice(
    status: &LpmPublicationStatus,
) -> Option<install_ui::TerminalLine> {
    match status {
        LpmPublicationStatus::Active => None,
        LpmPublicationStatus::PendingReview | LpmPublicationStatus::Processing => {
            Some(crate::install_ui::terminal_line!(
                "Upload succeeded. The public version is awaiting LPM.dev Registry publication review."
            ))
        }
        LpmPublicationStatus::ManualReview => Some(crate::install_ui::terminal_line!(
            "Upload succeeded. LPM.dev Registry publication requires manual review."
        )),
        LpmPublicationStatus::Rejected
        | LpmPublicationStatus::Quarantined
        | LpmPublicationStatus::Unpublished => Some(crate::install_ui::terminal_line!(
            "Upload succeeded, but the version is not publicly available."
        )),
        LpmPublicationStatus::Other(_) => Some(crate::install_ui::terminal_line!(
            "Upload succeeded. LPM.dev Registry returned an unrecognized publication status; public availability was not confirmed."
        )),
    }
}

pub(super) fn format_single_publish_success_summary(
    published_name: &str,
    version: &str,
    elapsed: &str,
    publication_status: Option<&LpmPublicationStatus>,
) -> install_ui::TerminalLine {
    let package = install_ui::yellow(&format!("{published_name}@{version}"));
    let elapsed = install_ui::green(elapsed);
    match publication_status {
        Some(LpmPublicationStatus::PendingReview | LpmPublicationStatus::Processing) => {
            crate::install_ui::terminal_line!(
                "Done · uploaded {} in {}; awaiting LPM.dev Registry publication review",
                package,
                elapsed
            )
        }
        Some(
            LpmPublicationStatus::ManualReview
            | LpmPublicationStatus::Rejected
            | LpmPublicationStatus::Quarantined
            | LpmPublicationStatus::Unpublished,
        ) => crate::install_ui::terminal_line!(
            "Done · uploaded {} in {}; version is not publicly available",
            package,
            elapsed
        ),
        Some(LpmPublicationStatus::Other(_)) => crate::install_ui::terminal_line!(
            "Done · uploaded {} in {}; LPM.dev Registry publication status unconfirmed",
            package,
            elapsed
        ),
        Some(LpmPublicationStatus::Active) | None => {
            crate::install_ui::terminal_line!("Done · published {} in {}", package, elapsed)
        }
    }
}

pub(super) fn format_multi_publish_success_summary(
    target_count: usize,
    elapsed: &str,
    publication_status: Option<&LpmPublicationStatus>,
) -> install_ui::TerminalLine {
    let elapsed = install_ui::green(elapsed);
    match publication_status {
        Some(LpmPublicationStatus::PendingReview | LpmPublicationStatus::Processing) => {
            crate::install_ui::terminal_line!(
                "Done · completed {} registry uploads in {}; LPM.dev Registry publication review pending",
                target_count,
                elapsed
            )
        }
        Some(
            LpmPublicationStatus::ManualReview
            | LpmPublicationStatus::Rejected
            | LpmPublicationStatus::Quarantined
            | LpmPublicationStatus::Unpublished,
        ) => crate::install_ui::terminal_line!(
            "Done · completed {} registry uploads in {}; LPM.dev version is not publicly available",
            target_count,
            elapsed
        ),
        Some(LpmPublicationStatus::Other(_)) => crate::install_ui::terminal_line!(
            "Done · completed {} registry uploads in {}; LPM.dev Registry publication status unconfirmed",
            target_count,
            elapsed
        ),
        Some(LpmPublicationStatus::Active) | None => crate::install_ui::terminal_line!(
            "Done · published to {} registries in {}",
            target_count,
            elapsed
        ),
    }
}

pub(super) fn format_multi_publish_partial_summary(
    succeeded: usize,
    target_count: usize,
    publication_status: Option<&LpmPublicationStatus>,
) -> install_ui::TerminalLine {
    match publication_status {
        Some(LpmPublicationStatus::PendingReview | LpmPublicationStatus::Processing) => {
            crate::install_ui::terminal_line!(
                "Completed {} of {} registry uploads. LPM.dev Registry publication review pending.",
                succeeded,
                target_count
            )
        }
        Some(
            LpmPublicationStatus::ManualReview
            | LpmPublicationStatus::Rejected
            | LpmPublicationStatus::Quarantined
            | LpmPublicationStatus::Unpublished,
        ) => crate::install_ui::terminal_line!(
            "Completed {} of {} registry uploads. The LPM.dev version is not publicly available.",
            succeeded,
            target_count
        ),
        Some(LpmPublicationStatus::Other(_)) => crate::install_ui::terminal_line!(
            "Completed {} of {} registry uploads. LPM.dev Registry publication status unconfirmed.",
            succeeded,
            target_count
        ),
        Some(LpmPublicationStatus::Active) | None => crate::install_ui::terminal_line!(
            "Published to {} of {} registries.",
            succeeded,
            target_count
        ),
    }
}

pub(super) fn lpm_visibility(_pkg_json: &serde_json::Value) -> &'static str {
    "private"
}

pub(super) fn visibility_from_access(access: &str) -> &str {
    if access == "restricted" {
        "private"
    } else {
        access
    }
}

pub(super) fn format_publish_visibility(visibility: &str) -> install_ui::TerminalFragment {
    match visibility {
        "public" => install_ui::status_ok("public"),
        other => install_ui::yellow(other),
    }
}

pub(super) fn print_publish_quality_result(result: &quality::QualityResult) {
    install_ui::done_untrusted(&format!(
        "Quality score: {}/{}",
        result.score, result.max_score
    ));
    for check in result
        .checks
        .iter()
        .filter(|check| !check.server_only && !check.passed)
    {
        install_ui::warn_line(format_publish_quality_issue(check));
    }
}

pub(super) fn format_publish_quality_issue(
    check: &quality::QualityCheck,
) -> install_ui::TerminalLine {
    let detail = check.detail.as_deref().unwrap_or(if check.server_only {
        "pending"
    } else {
        "missing"
    });
    crate::install_ui::terminal_line!("{}  {}", &check.label, install_ui::dim(detail))
}
