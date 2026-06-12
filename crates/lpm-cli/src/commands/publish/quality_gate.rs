use super::output::print_publish_quality_result;
use super::types::PublishQualityGateInput;
use crate::quality;
use lpm_common::LpmError;

pub(crate) fn run_publish_quality_gate(
    input: PublishQualityGateInput<'_>,
) -> Result<quality::QualityResult, LpmError> {
    let file_names: Vec<String> = input.tarball_files.iter().map(|f| f.path.clone()).collect();
    let result = quality::run_quality_checks(
        input.pkg_json,
        input.readme,
        input.project_dir,
        &file_names,
        input.detected_ecosystem,
        input.swift_manifest,
    );

    if !input.json_output {
        print_publish_quality_result(&result);
    }

    if let Some(min) = input.min_score
        && result.score < min
    {
        return Err(LpmError::Registry(format!(
            "quality score {} is below minimum {} (use --min-score to adjust)",
            result.score, min
        )));
    }

    Ok(result)
}
