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

/// Build an npm-compatible provenance statement for a package publish.
///
/// Populates fields from CI environment variables (GitHub Actions or GitLab CI).
pub fn build_slsa_statement(
    ci: &CiEnvironment,
    package_name: &str,
    version: &str,
    sha512_hex: &str,
) -> serde_json::Value {
    let purl = npm_package_purl(package_name, version);
    match ci {
        CiEnvironment::GitHubActions => build_github_actions_statement(purl, sha512_hex),
        CiEnvironment::GitLabCI => build_gitlab_ci_statement(purl, sha512_hex),
    }
}

fn build_github_actions_statement(purl: String, sha512_hex: &str) -> serde_json::Value {
    let repository = env_or("GITHUB_REPOSITORY", "unknown/unknown");
    let source_ref = env_or("GITHUB_REF", "refs/heads/main");
    let workflow = env_or("GITHUB_WORKFLOW_REF", "");
    let workflow_ref = workflow
        .rsplit_once('@')
        .map(|(_, workflow_ref)| workflow_ref.trim().to_string())
        .filter(|workflow_ref| !workflow_ref.is_empty())
        .unwrap_or_else(|| env_or("GITHUB_REF", "refs/heads/main"));
    let run_id = env_or("GITHUB_RUN_ID", "0");
    let run_attempt = env_or("GITHUB_RUN_ATTEMPT", "1");
    let server_url = env_or("GITHUB_SERVER_URL", "https://github.com");
    let commit_sha = env_non_empty("GITHUB_SHA");

    // Extract workflow path from GITHUB_WORKFLOW_REF (format: owner/repo/.github/workflows/file.yml@ref)
    let workflow_path = workflow
        .split('@')
        .next()
        .and_then(|full| {
            // Strip "owner/repo/" prefix
            full.find('/').and_then(|first| {
                full[first + 1..]
                    .find('/')
                    .map(|second| &full[first + 1 + second + 1..])
            })
        })
        .unwrap_or(".github/workflows/publish.yml");

    let build_type =
        "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1".to_string();
    let builder_id = format!("{server_url}/actions/runner");
    let invocation_id =
        format!("{server_url}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}");
    let started_on = chrono::Utc::now().to_rfc3339();
    let resolved_dependencies = source_resolved_dependency(
        format!("git+{server_url}/{repository}@{source_ref}"),
        commit_sha,
    );

    serde_json::to_value(SlsaStatement {
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
                external_parameters: serde_json::json!({
                    "workflow": {
                        "ref": workflow_ref,
                        "repository": format!("{server_url}/{repository}"),
                        "path": workflow_path,
                    }
                }),
                resolved_dependencies,
            },
            run_details: RunDetails {
                builder: Builder { id: builder_id },
                metadata: RunMetadata {
                    invocation_id,
                    started_on,
                },
            },
        },
    })
    .expect("SLSA v1 statement must serialize")
}

fn build_gitlab_ci_statement(purl: String, sha512_hex: &str) -> serde_json::Value {
    let project_url = env_or("CI_PROJECT_URL", "https://gitlab.com/unknown/unknown");
    let ref_name = env_or("CI_COMMIT_REF_NAME", "main");
    let pipeline_id = env_or("CI_PIPELINE_ID", "0");
    let job_id = env_or("CI_JOB_ID", "0");
    let config_path = env_or("CI_CONFIG_PATH", ".gitlab-ci.yml");
    let commit_sha = env_non_empty("CI_COMMIT_SHA");

    let build_type =
        "https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/ci/yaml/README.md".to_string();

    let builder_id = "https://gitlab.com/gitlab-org/gitlab-runner".to_string();
    let invocation_id = format!("{project_url}/-/pipelines/{pipeline_id}/jobs/{job_id}");
    let started_on = env_or("CI_PIPELINE_CREATED_AT", &chrono::Utc::now().to_rfc3339());
    let source_ref = git_ref(&ref_name);
    let materials = source_materials(format!("git+{project_url}@{source_ref}"), commit_sha);
    let config_source_digest = commit_digest_sha1(materials.first());

    serde_json::json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{
            "name": purl,
            "digest": {
                "sha512": sha512_hex,
            },
        }],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {
                "id": builder_id,
            },
            "buildType": build_type,
            "invocation": {
                "configSource": {
                    "uri": format!("git+{project_url}"),
                    "digest": config_source_digest,
                    "entryPoint": config_path,
                },
                "parameters": {
                    "ref": source_ref,
                },
            },
            "metadata": {
                "buildInvocationId": invocation_id,
                "buildStartedOn": started_on,
            },
            "materials": materials,
        },
    })
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn git_ref(ref_name: &str) -> String {
    if ref_name.starts_with("refs/") {
        ref_name.to_string()
    } else {
        format!("refs/heads/{ref_name}")
    }
}

fn source_resolved_dependency(uri: String, commit_sha: Option<String>) -> Vec<serde_json::Value> {
    commit_sha
        .map(|sha| {
            serde_json::json!({
                "uri": uri,
                "digest": {
                    "gitCommit": sha,
                },
            })
        })
        .into_iter()
        .collect()
}

fn source_materials(uri: String, commit_sha: Option<String>) -> Vec<serde_json::Value> {
    commit_sha
        .map(|sha| {
            serde_json::json!({
                "uri": uri,
                "digest": {
                    "sha1": sha,
                },
            })
        })
        .into_iter()
        .collect()
}

fn commit_digest_sha1(material: Option<&serde_json::Value>) -> serde_json::Value {
    material
        .and_then(|material| material.get("digest"))
        .and_then(|digest| digest.get("sha1"))
        .and_then(|sha1| sha1.as_str())
        .map(|sha1| serde_json::json!({ "sha1": sha1 }))
        .unwrap_or_else(|| serde_json::json!({}))
}

pub(crate) fn npm_package_purl(package_name: &str, version: &str) -> String {
    if let Some(rest) = package_name.strip_prefix('@') {
        format!("pkg:npm/%40{rest}@{version}")
    } else {
        format!("pkg:npm/{package_name}@{version}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;

    #[test]
    fn slsa_statement_structure() {
        let json = build_slsa_statement(
            &CiEnvironment::GitHubActions,
            "@scope/pkg",
            "1.0.0",
            "abc123",
        );

        assert_eq!(json["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(json["predicateType"], "https://slsa.dev/provenance/v1");
        assert_eq!(json["subject"].as_array().unwrap().len(), 1);
        assert_eq!(json["subject"][0]["name"], "pkg:npm/%40scope/pkg@1.0.0");
        assert_eq!(json["subject"][0]["digest"]["sha512"], "abc123");
    }

    #[test]
    fn gitlab_statement_uses_npm_slsa_v0_2_shape() {
        let json = build_slsa_statement(&CiEnvironment::GitLabCI, "my-package", "2.0.0", "def456");

        assert_eq!(json["_type"], "https://in-toto.io/Statement/v0.1");
        assert_eq!(json["predicateType"], "https://slsa.dev/provenance/v0.2");
        assert!(
            json["predicate"]["buildType"]
                .as_str()
                .unwrap()
                .contains("gitlab")
        );
        assert!(json["predicate"]["invocation"]["configSource"].is_object());
        assert!(json["predicate"]["materials"].is_array());
    }

    #[test]
    fn slsa_statement_includes_github_source_commit_material() {
        let _env = ScopedEnv::update([
            ("GITHUB_REPOSITORY", Some("owner/repo".into())),
            ("GITHUB_REF", Some("refs/pull/123/merge".into())),
            (
                "GITHUB_WORKFLOW_REF",
                Some("owner/repo/.github/workflows/publish.yml@refs/tags/v1.2.3".into()),
            ),
            ("GITHUB_RUN_ID", Some("123".into())),
            ("GITHUB_RUN_ATTEMPT", Some("2".into())),
            ("GITHUB_SERVER_URL", Some("https://github.com".into())),
            ("GITHUB_SHA", Some("0123456789abcdef".into())),
        ]);

        let json = build_slsa_statement(&CiEnvironment::GitHubActions, "pkg", "1.0.0", "abc123");

        assert_eq!(
            json["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"],
            serde_json::json!("refs/tags/v1.2.3")
        );
        assert_eq!(
            json["predicate"]["buildDefinition"]["resolvedDependencies"],
            serde_json::json!([{
                "uri": "git+https://github.com/owner/repo@refs/pull/123/merge",
                "digest": {
                    "gitCommit": "0123456789abcdef"
                }
            }])
        );
    }

    #[test]
    fn slsa_statement_includes_gitlab_source_commit_material() {
        let _env = ScopedEnv::update([
            (
                "CI_PROJECT_URL",
                Some("https://gitlab.com/owner/repo".into()),
            ),
            ("CI_COMMIT_REF_NAME", Some("release".into())),
            ("CI_PIPELINE_ID", Some("123".into())),
            ("CI_JOB_ID", Some("456".into())),
            ("CI_CONFIG_PATH", Some(".gitlab-ci.yml".into())),
            ("CI_COMMIT_SHA", Some("fedcba9876543210".into())),
            (
                "CI_PIPELINE_CREATED_AT",
                Some("2026-06-23T00:00:00Z".into()),
            ),
        ]);

        let json = build_slsa_statement(&CiEnvironment::GitLabCI, "pkg", "1.0.0", "abc123");

        assert_eq!(
            json["predicate"]["invocation"]["configSource"],
            serde_json::json!({
                "uri": "git+https://gitlab.com/owner/repo",
                "digest": {
                    "sha1": "fedcba9876543210"
                },
                "entryPoint": ".gitlab-ci.yml"
            })
        );
        assert_eq!(
            json["predicate"]["materials"],
            serde_json::json!([{
                "uri": "git+https://gitlab.com/owner/repo@refs/heads/release",
                "digest": {
                    "sha1": "fedcba9876543210"
                }
            }])
        );
    }

    #[test]
    fn npm_package_purl_encodes_scoped_package_at_sign() {
        assert_eq!(
            npm_package_purl("@scope/pkg", "1.2.3"),
            "pkg:npm/%40scope/pkg@1.2.3"
        );
    }
}
