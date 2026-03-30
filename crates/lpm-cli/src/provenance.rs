//! SLSA v1.0 provenance statement builder.
//!
//! Builds in-toto SLSA v1.0 provenance statements from CI environment
//! variables. Supports GitHub Actions and GitLab CI.

use crate::oidc::CiEnvironment;
use serde::Serialize;

/// SLSA v1.0 provenance statement (in-toto Statement v1).
#[derive(Debug, Serialize)]
pub struct SlsaStatement {
	#[serde(rename = "_type")]
	pub statement_type: String,
	pub subject: Vec<Subject>,
	#[serde(rename = "predicateType")]
	pub predicate_type: String,
	pub predicate: Predicate,
}

#[derive(Debug, Serialize)]
pub struct Subject {
	pub name: String,
	pub digest: Digest,
}

#[derive(Debug, Serialize)]
pub struct Digest {
	pub sha512: String,
}

#[derive(Debug, Serialize)]
pub struct Predicate {
	#[serde(rename = "buildDefinition")]
	pub build_definition: BuildDefinition,
	#[serde(rename = "runDetails")]
	pub run_details: RunDetails,
}

#[derive(Debug, Serialize)]
pub struct BuildDefinition {
	#[serde(rename = "buildType")]
	pub build_type: String,
	#[serde(rename = "externalParameters")]
	pub external_parameters: serde_json::Value,
	#[serde(rename = "resolvedDependencies")]
	pub resolved_dependencies: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct RunDetails {
	pub builder: Builder,
	pub metadata: RunMetadata,
}

#[derive(Debug, Serialize)]
pub struct Builder {
	pub id: String,
}

#[derive(Debug, Serialize)]
pub struct RunMetadata {
	#[serde(rename = "invocationId")]
	pub invocation_id: String,
	#[serde(rename = "startedOn")]
	pub started_on: String,
}

/// Build an SLSA v1.0 provenance statement for a package publish.
///
/// Populates fields from CI environment variables (GitHub Actions or GitLab CI).
pub fn build_slsa_statement(
	ci: &CiEnvironment,
	package_name: &str,
	version: &str,
	sha512_hex: &str,
) -> SlsaStatement {
	let (build_type, external_params, builder_id, invocation_id, started_on) = match ci {
		CiEnvironment::GitHubActions => build_github_actions_provenance(),
		CiEnvironment::GitLabCI => build_gitlab_ci_provenance(),
	};

	// Package URL (purl) for the subject
	let purl = if package_name.starts_with('@') {
		// Scoped: pkg:npm/@scope/name@version
		format!("pkg:npm/{package_name}@{version}")
	} else {
		format!("pkg:npm/{package_name}@{version}")
	};

	SlsaStatement {
		statement_type: "https://in-toto.io/Statement/v1".into(),
		subject: vec![Subject {
			name: purl,
			digest: Digest {
				sha512: sha512_hex.to_string(),
			},
		}],
		predicate_type: "https://slsa.dev/provenance/v1".into(),
		predicate: Predicate {
			build_definition: BuildDefinition {
				build_type,
				external_parameters: external_params,
				resolved_dependencies: vec![],
			},
			run_details: RunDetails {
				builder: Builder { id: builder_id },
				metadata: RunMetadata {
					invocation_id,
					started_on,
				},
			},
		},
	}
}

/// Build provenance fields from GitHub Actions environment variables.
fn build_github_actions_provenance() -> (String, serde_json::Value, String, String, String) {
	let repository = env_or("GITHUB_REPOSITORY", "unknown/unknown");
	let ref_name = env_or("GITHUB_REF", "refs/heads/main");
	let workflow = env_or("GITHUB_WORKFLOW_REF", "");
	let run_id = env_or("GITHUB_RUN_ID", "0");
	let run_attempt = env_or("GITHUB_RUN_ATTEMPT", "1");
	let server_url = env_or("GITHUB_SERVER_URL", "https://github.com");

	// Extract workflow path from GITHUB_WORKFLOW_REF (format: owner/repo/.github/workflows/file.yml@ref)
	let workflow_path = workflow
		.split('@')
		.next()
		.and_then(|full| {
			// Strip "owner/repo/" prefix
			full.find('/').and_then(|first| {
				full[first + 1..].find('/').map(|second| &full[first + 1 + second + 1..])
			})
		})
		.unwrap_or(".github/workflows/publish.yml");

	let build_type =
		"https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1".to_string();

	let external_params = serde_json::json!({
		"workflow": {
			"ref": ref_name,
			"repository": format!("{server_url}/{repository}"),
			"path": workflow_path,
		}
	});

	let builder_id = format!("{server_url}/actions/runner");
	let invocation_id = format!(
		"{server_url}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
	);
	let started_on = chrono::Utc::now().to_rfc3339();

	(build_type, external_params, builder_id, invocation_id, started_on)
}

/// Build provenance fields from GitLab CI environment variables.
fn build_gitlab_ci_provenance() -> (String, serde_json::Value, String, String, String) {
	let project_url = env_or("CI_PROJECT_URL", "https://gitlab.com/unknown/unknown");
	let ref_name = env_or("CI_COMMIT_REF_NAME", "main");
	let pipeline_id = env_or("CI_PIPELINE_ID", "0");
	let job_id = env_or("CI_JOB_ID", "0");
	let config_path = env_or("CI_CONFIG_PATH", ".gitlab-ci.yml");

	let build_type = "https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/ci/yaml/README.md".to_string();

	let external_params = serde_json::json!({
		"workflow": {
			"ref": format!("refs/heads/{ref_name}"),
			"repository": project_url,
			"path": config_path,
		}
	});

	let builder_id = "https://gitlab.com/gitlab-org/gitlab-runner".to_string();
	let invocation_id = format!("{project_url}/-/pipelines/{pipeline_id}/jobs/{job_id}");
	let started_on = env_or("CI_PIPELINE_CREATED_AT", &chrono::Utc::now().to_rfc3339());

	(build_type, external_params, builder_id, invocation_id, started_on)
}

fn env_or(key: &str, default: &str) -> String {
	std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn slsa_statement_structure() {
		let stmt = build_slsa_statement(
			&CiEnvironment::GitHubActions,
			"@scope/pkg",
			"1.0.0",
			"abc123",
		);

		assert_eq!(stmt.statement_type, "https://in-toto.io/Statement/v1");
		assert_eq!(stmt.predicate_type, "https://slsa.dev/provenance/v1");
		assert_eq!(stmt.subject.len(), 1);
		assert_eq!(stmt.subject[0].name, "pkg:npm/@scope/pkg@1.0.0");
		assert_eq!(stmt.subject[0].digest.sha512, "abc123");
	}

	#[test]
	fn slsa_statement_serializes_to_json() {
		let stmt = build_slsa_statement(
			&CiEnvironment::GitLabCI,
			"my-package",
			"2.0.0",
			"def456",
		);

		let json = serde_json::to_value(&stmt).unwrap();
		assert_eq!(json["_type"], "https://in-toto.io/Statement/v1");
		assert_eq!(json["predicateType"], "https://slsa.dev/provenance/v1");
		assert!(json["predicate"]["buildDefinition"]["buildType"]
			.as_str()
			.unwrap()
			.contains("gitlab"));
	}
}
