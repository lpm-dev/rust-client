use crate::commands::publish::secret_scan::format_secret_match;
use crate::commands::publish_common;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_security::behavioral::secrets::{
    SecretMatch, SecretScanBudget, SecretScanResult, scan_file_content_with_budget,
    scan_file_reader_with_budget,
};
use std::path::{Path, PathBuf};

/// The scan a deploy runs over every file it would copy, before it writes
/// anything: what `lpm publish` refuses to pack, a deploy refuses to copy,
/// unless `--allow-secrets` turns the scan off. Unlike publish's, it reads
/// any number of files and bytes, as the deploy copies them all anyway;
/// only its findings are limited, across every package the deploy copies.
pub(in crate::commands::deploy) struct DeploySecretScan {
    budget: SecretScanBudget,
    findings: Vec<DeploySecretFinding>,
}

/// A secret in a file a deploy would copy.
pub(in crate::commands::deploy) struct DeploySecretFinding {
    package: String,
    /// The package's directory.
    directory: PathBuf,
    /// The file, relative to `directory`, as `/`-separated as publish names it.
    path: String,
    secret: SecretMatch,
}

impl DeploySecretScan {
    pub(in crate::commands::deploy) fn new() -> Self {
        Self {
            budget: SecretScanBudget::for_copy(),
            findings: Vec::new(),
        }
    }

    /// Scans `file`, `size` bytes read from `reader`, of the package in
    /// `directory`.
    pub(in crate::commands::deploy) fn scan_file(
        &mut self,
        package: &str,
        directory: &Path,
        file: &str,
        reader: &mut dyn std::io::Read,
        size: u64,
    ) -> Result<(), LpmError> {
        let result = scan_file_reader_with_budget(reader, size, file, &mut self.budget).map_err(
            |error| {
                LpmError::Script(format!(
                    "deploy: cannot scan {:?} for secrets: {error}",
                    directory.join(file)
                ))
            },
        )?;
        self.record(result, package, directory, file)
    }

    /// Scans `content`, written to the output as `file` of the package in
    /// `directory`.
    pub(in crate::commands::deploy) fn scan_content(
        &mut self,
        package: &str,
        directory: &Path,
        file: &str,
        content: &[u8],
    ) -> Result<(), LpmError> {
        let result = scan_file_content_with_budget(content, file, &mut self.budget);
        self.record(result, package, directory, file)
    }

    fn record(
        &mut self,
        result: SecretScanResult,
        package: &str,
        directory: &Path,
        file: &str,
    ) -> Result<(), LpmError> {
        if let Some(limit) = result.limit_exceeded {
            return Err(LpmError::Script(format!(
                "deploy: the secret scan stopped at its {} {limit} limit before reading every \
                 file, so nothing was written; --allow-secrets deploys without the scan",
                publish_common::secret_scan_maximum(limit)
            )));
        }
        self.findings.extend(
            result
                .matches
                .into_iter()
                .map(|secret| DeploySecretFinding {
                    package: package.to_string(),
                    directory: directory.to_path_buf(),
                    path: file.to_string(),
                    secret,
                }),
        );
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::commands::deploy) fn found(&self) -> Vec<(&str, &str)> {
        self.findings
            .iter()
            .map(|finding| (finding.path.as_str(), finding.secret.pattern_name.as_str()))
            .collect()
    }

    /// Refuses the deploy, reporting what the scan found, if it found
    /// anything. Directories are shown relative to `cwd` where they are
    /// inside it.
    pub(in crate::commands::deploy) fn refuse_findings(
        &self,
        cwd: &Path,
        json_output: bool,
    ) -> Result<(), LpmError> {
        if self.findings.is_empty() {
            return Ok(());
        }
        let shown = |directory: &Path| match directory.strip_prefix(cwd) {
            Ok(inside) if inside.as_os_str().is_empty() => ".".to_string(),
            Ok(inside) => inside.display().to_string(),
            Err(_) => directory.display().to_string(),
        };
        if json_output {
            let matches: Vec<serde_json::Value> = self
                .findings
                .iter()
                .map(|finding| {
                    serde_json::json!({
                        "package": finding.package,
                        "directory": shown(&finding.directory),
                        "path": finding.path,
                        "pattern": finding.secret.pattern_name,
                        "description": finding.secret.description,
                        "line": finding.secret.line,
                        "severity": finding.secret.severity,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "success": false,
                    "error": "secret_scan_failed",
                    "matches": matches,
                    "hint": "Use --allow-secrets to bypass (not recommended)",
                })
            );
        } else {
            install_ui::warn_line(crate::install_ui::terminal_line!(
                "Secret scan found {} potential {}",
                install_ui::status_ok(&self.findings.len().to_string()),
                if self.findings.len() == 1 {
                    "leak"
                } else {
                    "leaks"
                }
            ));
            let mut package = None;
            for finding in &self.findings {
                if package != Some((&finding.package, &finding.directory)) {
                    package = Some((&finding.package, &finding.directory));
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "  {}  {}",
                        install_ui::yellow(&lpm_common::sanitize_terminal_inline(&finding.package)),
                        install_ui::dim(&lpm_common::sanitize_terminal_inline(&shown(
                            &finding.directory
                        )))
                    ));
                }
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {}",
                    format_secret_match(&finding.secret)
                ));
            }
            install_ui::failed_line(install_ui::TerminalLine::new(
                "Deploy blocked. Remove secrets, or leave their files out with `files` or \
                 `.npmignore`, before deploying.",
            ));
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "  {} If these are false positives, use {}.",
                install_ui::dim("hint"),
                install_ui::yellow("--allow-secrets")
            ));
        }
        Err(LpmError::ExitCode(1))
    }
}
