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

    if let Some(min) = input.min_score {
        enforce_minimum_score(&result, min)?;
    }

    Ok(result)
}

fn enforce_minimum_score(result: &quality::QualityResult, minimum: u32) -> Result<(), LpmError> {
    if result.score < minimum {
        return Err(LpmError::Registry(format!(
            "local preflight quality score {} is below minimum {} ({} of {} locally applicable points; use --min-score to adjust)",
            result.score, minimum, result.earned_points, result.applicable_points
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(score: u32) -> quality::QualityResult {
        quality::QualityResult {
            score,
            max_score: 100,
            earned_points: score,
            applicable_points: 100,
            checks: Vec::new(),
        }
    }

    #[test]
    fn score_immediately_below_80_fails_the_default_threshold() {
        assert!(enforce_minimum_score(&result(79), 80).is_err());
    }

    #[test]
    fn score_at_80_passes_the_default_threshold() {
        enforce_minimum_score(&result(80), 80).unwrap();
    }

    #[test]
    fn score_immediately_above_80_passes_the_default_threshold() {
        enforce_minimum_score(&result(81), 80).unwrap();
    }
}
