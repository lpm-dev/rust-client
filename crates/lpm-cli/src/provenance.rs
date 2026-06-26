use crate::oidc::CiEnvironment;

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
    let (workflow_path, workflow_ref) = github_workflow_path_and_ref(&repository, &workflow);
    let run_id = env_or("GITHUB_RUN_ID", "0");
    let run_attempt = env_or("GITHUB_RUN_ATTEMPT", "1");
    let server_url = env_or("GITHUB_SERVER_URL", "https://github.com");
    let runner_environment = env_or("RUNNER_ENVIRONMENT", "github-hosted");
    let invocation_id =
        format!("{server_url}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}");

    serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": purl,
            "digest": {
                "sha512": sha512_hex,
            },
        }],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "ref": workflow_ref,
                        "repository": format!("{server_url}/{repository}"),
                        "path": workflow_path,
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": env_or_empty("GITHUB_EVENT_NAME"),
                        "repository_id": env_or_empty("GITHUB_REPOSITORY_ID"),
                        "repository_owner_id": env_or_empty("GITHUB_REPOSITORY_OWNER_ID"),
                    }
                },
                "resolvedDependencies": [{
                    "uri": format!("git+{server_url}/{repository}@{source_ref}"),
                    "digest": {
                        "gitCommit": env_or_empty("GITHUB_SHA"),
                    },
                }],
            },
            "runDetails": {
                "builder": {
                    "id": format!("https://github.com/actions/runner/{runner_environment}"),
                },
                "metadata": {
                    "invocationId": invocation_id,
                },
            },
        }
    })
}

fn build_gitlab_ci_statement(purl: String, sha512_hex: &str) -> serde_json::Value {
    let project_url = env_or("CI_PROJECT_URL", "https://gitlab.com/unknown/unknown");
    let commit_sha = env_or_empty("CI_COMMIT_SHA");
    let parameters = gitlab_parameters();

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
                "id": format!("{project_url}/-/runners/{}", env_or_empty("CI_RUNNER_ID")),
            },
            "buildType": "https://github.com/npm/cli/gitlab/v0alpha1",
            "invocation": {
                "configSource": {
                    "uri": format!("git+{project_url}"),
                    "digest": {
                        "sha1": commit_sha,
                    },
                    "entryPoint": env_or_empty("CI_JOB_NAME"),
                },
                "parameters": parameters,
                "environment": {
                    "name": env_or_empty("CI_RUNNER_DESCRIPTION"),
                    "architecture": env_or_empty("CI_RUNNER_EXECUTABLE_ARCH"),
                    "server": env_or_empty("CI_SERVER_URL"),
                    "project": env_or_empty("CI_PROJECT_PATH"),
                    "job": {
                        "id": env_or_empty("CI_JOB_ID"),
                    },
                    "pipeline": {
                        "id": env_or_empty("CI_PIPELINE_ID"),
                        "ref": env_or_empty("CI_CONFIG_PATH"),
                    },
                },
            },
            "metadata": {
                "buildInvocationId": env_or_empty("CI_JOB_URL"),
                "completeness": {
                    "parameters": true,
                    "environment": true,
                    "materials": false,
                },
                "reproducible": false,
            },
            "materials": [{
                "uri": format!("git+{project_url}"),
                "digest": {
                    "sha1": commit_sha,
                },
            }],
        },
    })
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_or_empty(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn github_workflow_path_and_ref(repository: &str, workflow: &str) -> (String, String) {
    let relative_ref = workflow
        .strip_prefix(repository)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(workflow);
    let Some((path, workflow_ref)) = relative_ref.split_once('@') else {
        return (relative_ref.to_string(), String::new());
    };
    (path.to_string(), workflow_ref.to_string())
}

const GITLAB_PARAMETER_KEYS: &[&str] = &[
    "CI",
    "CI_API_GRAPHQL_URL",
    "CI_API_V4_URL",
    "CI_BUILD_BEFORE_SHA",
    "CI_BUILD_ID",
    "CI_BUILD_NAME",
    "CI_BUILD_REF",
    "CI_BUILD_REF_NAME",
    "CI_BUILD_REF_SLUG",
    "CI_BUILD_STAGE",
    "CI_COMMIT_BEFORE_SHA",
    "CI_COMMIT_BRANCH",
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_REF_PROTECTED",
    "CI_COMMIT_REF_SLUG",
    "CI_COMMIT_SHA",
    "CI_COMMIT_SHORT_SHA",
    "CI_COMMIT_TIMESTAMP",
    "CI_COMMIT_TITLE",
    "CI_CONFIG_PATH",
    "CI_DEFAULT_BRANCH",
    "CI_DEPENDENCY_PROXY_DIRECT_GROUP_IMAGE_PREFIX",
    "CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX",
    "CI_DEPENDENCY_PROXY_SERVER",
    "CI_DEPENDENCY_PROXY_USER",
    "CI_JOB_ID",
    "CI_JOB_NAME",
    "CI_JOB_NAME_SLUG",
    "CI_JOB_STAGE",
    "CI_JOB_STARTED_AT",
    "CI_JOB_URL",
    "CI_NODE_TOTAL",
    "CI_PAGES_DOMAIN",
    "CI_PAGES_URL",
    "CI_PIPELINE_CREATED_AT",
    "CI_PIPELINE_ID",
    "CI_PIPELINE_IID",
    "CI_PIPELINE_SOURCE",
    "CI_PIPELINE_URL",
    "CI_PROJECT_CLASSIFICATION_LABEL",
    "CI_PROJECT_DESCRIPTION",
    "CI_PROJECT_ID",
    "CI_PROJECT_NAME",
    "CI_PROJECT_NAMESPACE",
    "CI_PROJECT_NAMESPACE_ID",
    "CI_PROJECT_PATH",
    "CI_PROJECT_PATH_SLUG",
    "CI_PROJECT_REPOSITORY_LANGUAGES",
    "CI_PROJECT_ROOT_NAMESPACE",
    "CI_PROJECT_TITLE",
    "CI_PROJECT_URL",
    "CI_PROJECT_VISIBILITY",
    "CI_REGISTRY",
    "CI_REGISTRY_IMAGE",
    "CI_REGISTRY_USER",
    "CI_RUNNER_DESCRIPTION",
    "CI_RUNNER_ID",
    "CI_RUNNER_TAGS",
    "CI_SERVER_HOST",
    "CI_SERVER_NAME",
    "CI_SERVER_PORT",
    "CI_SERVER_PROTOCOL",
    "CI_SERVER_REVISION",
    "CI_SERVER_SHELL_SSH_HOST",
    "CI_SERVER_SHELL_SSH_PORT",
    "CI_SERVER_URL",
    "CI_SERVER_VERSION",
    "CI_SERVER_VERSION_MAJOR",
    "CI_SERVER_VERSION_MINOR",
    "CI_SERVER_VERSION_PATCH",
    "CI_TEMPLATE_REGISTRY_HOST",
    "GITLAB_CI",
    "GITLAB_FEATURES",
    "GITLAB_USER_ID",
    "GITLAB_USER_LOGIN",
    "RUNNER_GENERATE_ARTIFACTS_METADATA",
];

fn gitlab_parameters() -> serde_json::Map<String, serde_json::Value> {
    let mut parameters = serde_json::Map::with_capacity(GITLAB_PARAMETER_KEYS.len());
    for key in GITLAB_PARAMETER_KEYS {
        if let Ok(value) = std::env::var(key) {
            parameters.insert((*key).to_string(), serde_json::Value::String(value));
        }
    }
    parameters
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
        assert_eq!(
            json["predicate"]["buildType"],
            "https://github.com/npm/cli/gitlab/v0alpha1"
        );
        assert!(json["predicate"]["invocation"]["configSource"].is_object());
        assert!(json["predicate"]["materials"].is_array());
    }

    #[test]
    fn github_statement_matches_libnpmpublish_slsa_v1_shape() {
        let _env = scoped_provenance_env(&[
            ("GITHUB_REPOSITORY", Some("owner/repo".into())),
            ("GITHUB_REF", Some("refs/tags/v1.2.3".into())),
            (
                "GITHUB_WORKFLOW_REF",
                Some("owner/repo/.github/workflows/publish.yml@refs/tags/v1.2.3".into()),
            ),
            ("GITHUB_RUN_ID", Some("123".into())),
            ("GITHUB_RUN_ATTEMPT", Some("2".into())),
            ("GITHUB_SERVER_URL", Some("https://github.com".into())),
            ("GITHUB_SHA", Some("0123456789abcdef".into())),
            ("RUNNER_ENVIRONMENT", Some("github-hosted".into())),
            ("GITHUB_EVENT_NAME", Some("release".into())),
            ("GITHUB_REPOSITORY_ID", Some("100".into())),
            ("GITHUB_REPOSITORY_OWNER_ID", Some("200".into())),
        ]);

        let json = build_slsa_statement(&CiEnvironment::GitHubActions, "pkg", "1.0.0", "abc123");

        insta::assert_json_snapshot!("github_libnpmpublish_slsa_v1_statement", json);
        assert_eq!(
            json["predicate"]["buildDefinition"]["internalParameters"]["github"],
            serde_json::json!({
                "event_name": "release",
                "repository_id": "100",
                "repository_owner_id": "200",
            })
        );
        assert_eq!(
            json["predicate"]["runDetails"]["builder"]["id"],
            "https://github.com/actions/runner/github-hosted"
        );
        assert_eq!(
            json["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"],
            serde_json::json!("refs/tags/v1.2.3")
        );
        assert_eq!(
            json["predicate"]["buildDefinition"]["resolvedDependencies"],
            serde_json::json!([{
                "uri": "git+https://github.com/owner/repo@refs/tags/v1.2.3",
                "digest": {
                    "gitCommit": "0123456789abcdef"
                }
            }])
        );
    }

    #[test]
    fn gitlab_statement_matches_libnpmpublish_slsa_v0_2_shape() {
        let _env = scoped_provenance_env(&[
            ("CI", Some("true".into())),
            ("GITLAB_CI", Some("true".into())),
            ("CI_API_V4_URL", Some("https://gitlab.com/api/v4".into())),
            (
                "CI_PROJECT_URL",
                Some("https://gitlab.com/owner/repo".into()),
            ),
            ("CI_PROJECT_PATH", Some("owner/repo".into())),
            ("CI_COMMIT_SHA", Some("fedcba9876543210".into())),
            ("CI_CONFIG_PATH", Some(".gitlab-ci.yml".into())),
            ("CI_JOB_ID", Some("456".into())),
            ("CI_JOB_NAME", Some("publish".into())),
            (
                "CI_JOB_URL",
                Some("https://gitlab.com/owner/repo/-/jobs/456".into()),
            ),
            ("CI_PIPELINE_ID", Some("123".into())),
            ("CI_RUNNER_ID", Some("789".into())),
            ("CI_RUNNER_DESCRIPTION", Some("shared-runner".into())),
            ("CI_RUNNER_EXECUTABLE_ARCH", Some("linux/amd64".into())),
            ("CI_SERVER_URL", Some("https://gitlab.com".into())),
        ]);

        let json = build_slsa_statement(&CiEnvironment::GitLabCI, "pkg", "1.0.0", "abc123");

        insta::assert_json_snapshot!("gitlab_libnpmpublish_slsa_v0_2_statement", json);
        assert_eq!(
            json["predicate"]["invocation"]["configSource"],
            serde_json::json!({
                "uri": "git+https://gitlab.com/owner/repo",
                "digest": {
                    "sha1": "fedcba9876543210"
                },
                "entryPoint": "publish"
            })
        );
        assert_eq!(
            json["predicate"]["materials"],
            serde_json::json!([{
                "uri": "git+https://gitlab.com/owner/repo",
                "digest": {
                    "sha1": "fedcba9876543210"
                }
            }])
        );
        assert_eq!(
            json["predicate"]["builder"]["id"],
            "https://gitlab.com/owner/repo/-/runners/789"
        );
        assert!(
            json["predicate"]["invocation"]["parameters"]
                .as_object()
                .expect("parameters must be an object")
                .get("CI_REGISTRY")
                .is_none()
        );
        assert_eq!(
            json["predicate"]["metadata"]["completeness"],
            serde_json::json!({
                "parameters": true,
                "environment": true,
                "materials": false,
            })
        );
    }

    #[test]
    fn npm_package_purl_encodes_scoped_package_at_sign() {
        assert_eq!(
            npm_package_purl("@scope/pkg", "1.2.3"),
            "pkg:npm/%40scope/pkg@1.2.3"
        );
    }

    fn scoped_provenance_env(vars: &[(&'static str, Option<std::ffi::OsString>)]) -> ScopedEnv {
        let mut pairs: Vec<(&'static str, Option<std::ffi::OsString>)> = Vec::with_capacity(
            GITHUB_ENV_KEYS.len()
                + GITLAB_PARAMETER_KEYS.len()
                + GITLAB_ENVIRONMENT_KEYS.len()
                + vars.len(),
        );
        pairs.extend(GITHUB_ENV_KEYS.iter().map(|key| (*key, None)));
        pairs.extend(GITLAB_PARAMETER_KEYS.iter().map(|key| (*key, None)));
        pairs.extend(GITLAB_ENVIRONMENT_KEYS.iter().map(|key| (*key, None)));
        pairs.extend(vars.iter().cloned());
        ScopedEnv::update(pairs)
    }

    const GITHUB_ENV_KEYS: &[&str] = &[
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SERVER_URL",
        "GITHUB_SHA",
        "RUNNER_ENVIRONMENT",
        "GITHUB_EVENT_NAME",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER_ID",
    ];

    const GITLAB_ENVIRONMENT_KEYS: &[&str] = &["CI_RUNNER_EXECUTABLE_ARCH"];
}
