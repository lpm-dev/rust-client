mod publication;

use super::arguments::Scope;
use lpm_common::LpmError;
use std::path::Path;

pub(super) fn run(
    project: &Path,
    environment: Option<&str>,
    scope: &Scope,
    output: &Path,
    adapter: lpm_env_codegen::Adapter,
    check: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let result = generate(project, environment, scope, output, adapter, check);
    match result {
        Ok((identity, canonical)) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"command":"env.generate","success":true,"check":check,"directory":output,"identity":identity,"context":{"environment":canonical,"stage":scope.stage.unwrap_or_default(),"service":scope.service},"files":lpm_env_codegen::OWNED_FILES})
                );
            } else {
                println!(
                    "{}",
                    if check {
                        "Generated env modules are current"
                    } else {
                        "Generated typed server and client env modules"
                    }
                );
            }
            Ok(())
        }
        Err(error) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"command":"env.generate","success":false,"check":check,"diagnostics":[{"code":error.code(),"recoveryDirectory":error.recovery_directory()}]})
                );
                Err(LpmError::ExitCode(1))
            } else {
                Err(LpmError::EnvGeneration {
                    reason: error.to_string(),
                    help: error.recovery_hint(),
                })
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("{0}")]
    Code(&'static str),
    #[error(transparent)]
    Generate(#[from] lpm_env_codegen::GenerateError),
    #[error("env.generate_recovery_required: retained transaction at {directory:?}")]
    Recovery { directory: std::path::PathBuf },
}

impl Error {
    fn code(&self) -> String {
        match self {
            Self::Recovery { .. } => "env.generate_recovery_required".into(),
            _ => self.to_string(),
        }
    }
    fn recovery_hint(&self) -> &'static str {
        match self {
            Self::Recovery { .. } => {
                "Recover the retained transaction reported above before retrying."
            }
            Self::Code("env.schema_missing") => "Add envSchema to lpm.json, then retry.",
            Self::Code("env.generate_stale") => {
                "Run `lpm env generate` to update the generated files."
            }
            Self::Code("env.generate_unowned_directory") => {
                "Choose an empty output directory, or move the existing directory aside before retrying."
            }
            Self::Code("env.generate_path") => {
                "Choose a relative output directory inside the project. Do not use parent-directory paths."
            }
            Self::Generate(lpm_env_codegen::GenerateError::AdapterPrefix) => {
                "Use the adapter's public prefix, or choose a different adapter."
            }
            Self::Generate(
                lpm_env_codegen::GenerateError::Pattern | lpm_env_codegen::GenerateError::Budget,
            ) => "Reduce the schema or pattern size, then retry.",
            _ => {
                "Resolve the reported schema, configuration, or filesystem error, then retry `lpm env generate`."
            }
        }
    }
    fn recovery_directory(&self) -> Option<&Path> {
        match self {
            Self::Recovery { directory } => Some(directory),
            _ => None,
        }
    }
}

fn read_root(project: &Path) -> Result<String, Error> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
    use std::io::Read as _;
    let root = cap_std::fs::Dir::open_ambient_dir(project, cap_std::ambient_authority())
        .map_err(|_| Error::Code("env.root_unreadable"))?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = root
        .open_with("lpm.json", &options)
        .map_err(|_| Error::Code("env.root_unreadable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Error::Code("env.root_unreadable"))?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(Error::Code("env.root_unreadable"));
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::Code("env.root_unreadable"));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Code("env.root_unreadable"))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::Code("env.root_unreadable"));
    }
    String::from_utf8(bytes).map_err(|_| Error::Code("env.root_unreadable"))
}

fn generate(
    project: &Path,
    environment: Option<&str>,
    scope: &Scope,
    output: &Path,
    adapter: lpm_env_codegen::Adapter,
    check: bool,
) -> Result<(String, String), Error> {
    let (snapshot, canonical, artifacts) = {
        let config = {
            let root = read_root(project)?;
            lpm_runner::lpm_json::parse_lpm_json_in_detailed(project, &root)
                .map_err(|_| Error::Code("env.generate_configuration"))?
        };
        let schema = config
            .env_schema
            .as_ref()
            .ok_or(Error::Code("env.schema_missing"))?;
        let snapshot = std::sync::Arc::clone(
            config
                .env_schema_resolution
                .as_ref()
                .ok_or(Error::Code("env.schema_missing"))?,
        );
        let selected = lpm_runner::dotenv::resolve_project_environment(environment, Some(&config))
            .map_err(|_| Error::Code("env.generate_invalid_context"))?;
        let artifacts = lpm_env_codegen::generate(
            schema,
            lpm_env_codegen::Options {
                adapter,
                context: lpm_env::EvalContext {
                    environment: &selected.canonical,
                    stage: scope.stage.unwrap_or_default(),
                    service: scope.service.as_deref(),
                },
            },
        )?;
        (snapshot, selected.canonical, artifacts)
    };
    let fresh = || {
        let root = read_root(project).map_err(|_| Error::Code("env.source_changed"))?;
        if !snapshot.matches_root_content(root.as_bytes()) {
            return Err(Error::Code("env.source_changed"));
        }
        snapshot
            .verify_dependencies()
            .map_err(|_| Error::Code("env.source_changed"))
    };
    publication::write(project, output, &artifacts, check, fresh)?;
    Ok((artifacts.identity, canonical))
}
