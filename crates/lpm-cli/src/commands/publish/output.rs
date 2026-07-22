use super::types::{PublishResult, PublishTarget};
use crate::{install_ui, quality};
use std::collections::HashMap;

pub(super) fn publish_result_json(result: &PublishResult) -> serde_json::Value {
    let mut object = serde_json::Map::with_capacity(5);
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
                        "registry": key,
                        "name": target_names.get(&key),
                    })
                })
                .collect(),
        ),
    );

    json
}

pub(super) fn format_upload_message(registry: &str) -> String {
    format!("Uploading tarball to {}", install_ui::yellow(registry))
}

pub(super) fn print_upload_details(
    target_name: &str,
    version: &str,
    visibility: &str,
    dist_tag: &str,
) {
    publish_detail(
        "target",
        &install_ui::yellow(&format!("{target_name}@{version}")),
    );
    publish_detail("visibility", &format_publish_visibility(visibility));
    publish_detail("dist-tag", &install_ui::yellow(dist_tag));
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
        &install_ui::yellow(&format!("{}@{}", summary.name, summary.version)),
    );
    for (registry_key, target_name) in summary.target_names {
        publish_detail(
            &format!("{registry_key} name"),
            &install_ui::yellow(target_name),
        );
    }
    publish_detail(
        "files",
        &format_dry_run_files_value(summary.file_count, summary.tarball_size),
    );
    if let Some(qr) = summary.quality_result {
        publish_detail(
            "quality",
            &format!(
                "{}/{}",
                install_ui::status_ok(&qr.score.to_string()),
                qr.max_score
            ),
        );
    }
    if summary.has_skills {
        publish_detail("skills", &install_ui::status_ok("included"));
    }
    publish_detail("ecosystem", &install_ui::yellow(summary.ecosystem));
    let target_keys = summary
        .targets
        .iter()
        .map(PublishTarget::key)
        .collect::<Vec<_>>();
    publish_detail("targets", &install_ui::yellow(&target_keys.join(", ")));
    install_ui::detail("");
}

pub(super) fn publish_detail(label: &str, value: &str) {
    let label = format!("{label:<10}");
    install_ui::detail(&format!("    {} {}", install_ui::dim(&label), value));
}

pub(super) fn format_dry_run_files_value(file_count: usize, tarball_size: usize) -> String {
    format!(
        "{} files {}",
        install_ui::status_ok(&file_count.to_string()),
        install_ui::dim(&format!(
            "({})",
            lpm_common::format_bytes(tarball_size as u64)
        ))
    )
}

pub(super) fn format_publish_retry_detail(target: &PublishTarget) -> String {
    format!(
        "  {} {}",
        install_ui::dim("Retry:"),
        install_ui::yellow(&format!("lpm publish {}", target.retry_flag()))
    )
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

pub(super) fn format_publish_visibility(visibility: &str) -> String {
    match visibility {
        "public" => install_ui::status_ok("public"),
        other => install_ui::yellow(other),
    }
}

pub(super) fn print_publish_quality_result(result: &quality::QualityResult) {
    install_ui::done(&format!(
        "Quality score: {}/{}",
        result.score, result.max_score
    ));
    for check in result.checks.iter().filter(|check| !check.passed) {
        install_ui::warn(&format_publish_quality_issue(check));
    }
}

pub(super) fn format_publish_quality_issue(check: &quality::QualityCheck) -> String {
    let detail = check.detail.as_deref().unwrap_or(if check.server_only {
        "pending"
    } else {
        "missing"
    });
    format!(
        "{}  {}",
        lpm_common::sanitize_terminal_inline(&check.label),
        install_ui::dim(detail)
    )
}
