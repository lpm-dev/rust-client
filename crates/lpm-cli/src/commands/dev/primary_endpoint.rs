use lpm_common::LpmError;
use lpm_runner::lpm_json::LpmJsonConfig;
use std::path::Path;

pub(super) struct PrimaryServiceEndpoint {
    pub(super) name: String,
    pub(super) command_port: Option<u16>,
}

pub(super) fn select(
    project_dir: &Path,
    config: &LpmJsonConfig,
    requested: bool,
) -> Result<Option<PrimaryServiceEndpoint>, LpmError> {
    let Some(name) = lpm_runner::service_graph::primary_service_name(&config.services)
        .map_err(LpmError::Script)?
    else {
        return Ok(None);
    };
    let service = &config.services[name];
    let cwd = match &service.cwd {
        Some(cwd) => lpm_runner::orchestrator::safe_resolve_cwd(project_dir, cwd)?,
        None => project_dir.to_path_buf(),
    };
    let intent = lpm_cert::framework::CommandPortPlanner::load(&cwd).port_intent(&service.command);
    let managed = requested
        || service.primary
        || service.port.is_some()
        || service.host.is_some()
        || config
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.host.as_ref())
            .is_some()
        || intent.requires_port;
    Ok(managed.then(|| PrimaryServiceEndpoint {
        name: name.to_string(),
        command_port: intent.preferred_port,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_endpoint_uses_the_service_directory_to_resolve_package_scripts() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"scripts":{"dev":"node worker.js"}}"#,
        )
        .unwrap();
        std::fs::create_dir(project.path().join("web")).unwrap();
        std::fs::write(
            project.path().join("web/package.json"),
            r#"{"scripts":{"dev":"vite --port 4321"}}"#,
        )
        .unwrap();
        let config: LpmJsonConfig =
            serde_json::from_str(r#"{"services":{"web":{"command":"npm run dev","cwd":"web"}}}"#)
                .unwrap();
        let primary = select(project.path(), &config, false).unwrap().unwrap();
        assert_eq!(primary.name, "web");
        assert_eq!(primary.command_port, Some(4321));
    }
}
