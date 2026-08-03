use std::path::{Path, PathBuf};

use crate::{LOCKFILE_VERSION, Lockfile, LockfileError, binary};

impl Lockfile {
    /// Read the lockfile view for a project, resolving a workspace member to
    /// its importer projection in the nearest ancestor union lockfile.
    pub fn read_for_project(project_dir: &Path) -> Result<ProjectLockfile, LockfileError> {
        let project_root = project_dir
            .ancestors()
            .find(|ancestor| ancestor.join("package.json").is_file())
            .unwrap_or(project_dir);
        let mut local = None;
        for root in project_root.ancestors() {
            let path = root.join(crate::LOCKFILE_NAME);
            if !path.exists() {
                continue;
            }
            if root == project_root {
                local = Some(Self::read_fast(&path).and_then(|lockfile| {
                    Ok(ProjectLockfile {
                        path,
                        importer: ".".to_string(),
                        lockfile: lockfile.project_importer(".")?,
                    })
                }));
                continue;
            }
            let lockfile = Self::read_fast(&path)?;
            let relative = project_root.strip_prefix(root).map_err(|error| {
                LockfileError::Io(format!(
                    "failed to derive importer path below {}: {error}",
                    root.display()
                ))
            })?;
            let Some(importer) = importer_path(relative) else {
                continue;
            };
            if !lockfile.importers.contains_key(&importer) {
                continue;
            }
            return Ok(ProjectLockfile {
                path,
                lockfile: lockfile.project_importer(&importer)?,
                importer,
            });
        }
        if let Some(local) = local {
            return local;
        }
        Err(LockfileError::NotFound(format!(
            "no {} found for {}",
            crate::LOCKFILE_NAME,
            project_dir.display()
        )))
    }

    /// Atomically write a standalone project view back to its owning
    /// workspace union, or to the local lockfile for standalone projects.
    pub fn write_for_project(
        project_dir: &Path,
        lockfile: Lockfile,
    ) -> Result<PathBuf, LockfileError> {
        match Self::read_for_project(project_dir) {
            Ok(project) => {
                let mut owner = Self::read_fast(&project.path)?;
                owner.replace_importer(&project.importer, lockfile)?;
                owner.write_all(&project.path)?;
                Ok(project.path)
            }
            Err(LockfileError::NotFound(_)) => {
                let path = project_dir.join(crate::LOCKFILE_NAME);
                lockfile.write_all(&path)?;
                Ok(path)
            }
            Err(error) => Err(error),
        }
    }

    /// Serialize to TOML string.
    ///
    /// **Writer guard:** refuses to serialize a Lockfile whose package
    /// shape would fail the reader-side gate. Every package's
    /// `tarball_field_hint_is_consistent()` must hold — pairing a
    /// non-Registry source with a `tarball` field-hint is rejected
    /// here so the conflation never reaches disk. Symmetric with
    /// [`Lockfile::from_toml`]'s reader gate; together they make a
    /// bidirectional invariant rather than parser-only.
    pub fn to_toml(&self) -> Result<String, LockfileError> {
        self.validate_workspace_projections()
            .map_err(|error| LockfileError::Serialize(error.to_string()))?;
        self.validate_provenance()
            .map_err(LockfileError::Serialize)?;
        if let Some(reason) = self.git_schema_error() {
            return Err(LockfileError::Serialize(reason));
        }
        for pkg in self.packages.iter().chain(self.workspace_packages.values()) {
            if !pkg.tarball_field_hint_is_consistent() {
                return Err(LockfileError::InvalidTarballHint {
                    package: pkg.name.clone(),
                });
            }
            if let Some(reason) = pkg.git_metadata_error() {
                return Err(LockfileError::Serialize(format!(
                    "package {:?} has invalid git metadata: {reason}",
                    pkg.name
                )));
            }
        }
        toml::to_string_pretty(self).map_err(|e| LockfileError::Serialize(e.to_string()))
    }

    /// Deserialize from TOML string.
    pub fn from_toml(input: &str) -> Result<Self, LockfileError> {
        let lockfile: Lockfile =
            toml::from_str(input).map_err(|e| LockfileError::Deserialize(e.to_string()))?;

        if lockfile.metadata.lockfile_version > LOCKFILE_VERSION {
            return Err(LockfileError::UnsupportedVersion {
                found: lockfile.metadata.lockfile_version,
                max_supported: LOCKFILE_VERSION,
            });
        }
        if let Some(reason) = lockfile.git_schema_error() {
            return Err(LockfileError::Deserialize(reason));
        }
        lockfile.validate_workspace_projections()?;

        // Reject empty-string optional fields at the TOML layer,
        // matching the binary writer's rejection. Without this, a
        // hand-edited or malformed `tarball = ""` / `source = ""` /
        // `integrity = ""` would parse cleanly here and only fail
        // later in `write_all` when the binary writer's
        // `insert_optional` helper fires. Failing loud at the parse
        // boundary avoids that asymmetric late failure.
        for pkg in lockfile
            .packages
            .iter()
            .chain(lockfile.workspace_packages.values())
        {
            if let Some(s) = pkg.source.as_deref()
                && s.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package '{}' has empty 'source' — empty strings \
                     are not distinguishable from `None` in the binary \
                     format and are invalid input",
                    pkg.name
                )));
            }
            if let Some(s) = pkg.integrity.as_deref()
                && s.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package '{}' has empty 'integrity' — empty strings \
                     are not distinguishable from `None` in the binary \
                     format and are invalid input",
                    pkg.name
                )));
            }
            if let Some(s) = pkg.tarball.as_deref()
                && s.is_empty()
            {
                return Err(LockfileError::Deserialize(format!(
                    "package '{}' has empty 'tarball' — empty strings \
                     are not distinguishable from `None` in the binary \
                     format and are invalid input",
                    pkg.name
                )));
            }

            // `tarball` field-hint is valid only for Registry sources.
            // Reject non-Registry shapes paired with a hint at the
            // load boundary so the conflation never propagates into
            // the install path.
            if !pkg.tarball_field_hint_is_consistent() {
                return Err(LockfileError::InvalidTarballHint {
                    package: pkg.name.clone(),
                });
            }
            if let Some(reason) = pkg.git_metadata_error() {
                return Err(LockfileError::Deserialize(format!(
                    "package {:?} has invalid git metadata: {reason}",
                    pkg.name
                )));
            }

            // Scope-pin `@lpm.dev/*` to the lpm.dev origin. The binary
            // reader runs the same check via `validate_loaded_packages`.
            if let Some(url) = pkg.lpm_scope_origin_mismatch() {
                return Err(LockfileError::InvalidScopeOrigin {
                    package: pkg.name.clone(),
                    url,
                });
            }
        }

        lockfile
            .validate_provenance()
            .map_err(LockfileError::Deserialize)?;
        Ok(lockfile)
    }

    /// Write the lockfile with an atomic same-directory replacement.
    pub fn write_to_file(&self, path: &Path) -> Result<(), LockfileError> {
        let content = self.to_toml()?;
        lpm_common::write_file_atomic(path, content)
            .map_err(|e| LockfileError::Io(format!("failed to write {}: {e}", path.display())))
    }

    /// Read lockfile from disk.
    pub fn read_from_file(path: &Path) -> Result<Self, LockfileError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| LockfileError::Io(format!("failed to read {}: {e}", path.display())))?;
        Self::from_toml(&content)
    }

    /// Write both TOML and binary lockfiles atomically.
    /// The binary file is written alongside the TOML file as `lpm.lockb`.
    ///
    /// The binary format has no section for some TOML metadata,
    /// so we gate the binary write on [`binary::binary_format_supports`].
    /// When the lockfile uses TOML-only fields, the binary file is skipped
    /// and any stale binary file from a prior install is removed so
    /// `read_fast` doesn't silently pick it over the authoritative TOML.
    pub fn write_all(&self, toml_path: &Path) -> Result<(), LockfileError> {
        self.write_to_file(toml_path)?;
        let binary_path = toml_path.with_extension("lockb");
        if binary::binary_format_supports(self) {
            binary::write_binary(self, &binary_path)?;
        } else if binary_path.exists() {
            let _ = std::fs::remove_file(&binary_path);
            tracing::debug!(
                "removed stale binary lockfile ({}): lockfile has TOML-only metadata not expressible in binary format",
                binary_path.display()
            );
        }
        Ok(())
    }

    /// Read the authoritative TOML lockfile.
    ///
    /// `lpm.lockb` remains a generated companion that `doctor` and install
    /// writeback can validate/regenerate, but it is not trusted as an install
    /// input. A committed binary cache is opaque in code review, so the
    /// human-readable TOML form is what commands execute.
    pub fn read_fast(toml_path: &Path) -> Result<Self, LockfileError> {
        Self::read_from_file(toml_path)
    }

    /// Check if a lockfile exists at the given path.
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }
}

/// A project-local view and the physical lockfile that owns it.
pub struct ProjectLockfile {
    pub path: PathBuf,
    pub importer: String,
    pub lockfile: Lockfile,
}

fn importer_path(relative: &Path) -> Option<String> {
    let mut importer = String::new();
    for component in relative.components() {
        let value = component.as_os_str().to_str()?;
        if !importer.is_empty() {
            importer.push('/');
        }
        importer.push_str(value);
    }
    (!importer.is_empty()).then_some(importer)
}

/// Ensure `.gitattributes` marks `lpm.lockb` as binary.
///
/// Creates the file if missing, appends the entry if not already present.
/// This prevents CRLF corruption on Windows and marks the file as binary for git diff.
pub fn ensure_gitattributes(project_dir: &Path) -> Result<(), LockfileError> {
    let gitattributes = project_dir.join(".gitattributes");
    let marker = "lpm.lockb binary";

    if gitattributes.exists() {
        let content = std::fs::read_to_string(&gitattributes)
            .map_err(|e| LockfileError::Io(format!("failed to read .gitattributes: {e}")))?;

        // Already has the entry
        if content.lines().any(|line| line.trim() == marker) {
            return Ok(());
        }

        // Append atomically using OpenOptions::append (no file replacement on crash)
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitattributes)
            .map_err(|e| LockfileError::Io(format!("failed to open .gitattributes: {e}")))?;

        // Ensure newline before our entry if the file doesn't end with one
        if !content.ends_with('\n') {
            writeln!(file)
                .map_err(|e| LockfileError::Io(format!("failed to write .gitattributes: {e}")))?;
        }
        writeln!(file, "\n# lpm\n{marker}")
            .map_err(|e| LockfileError::Io(format!("failed to write .gitattributes: {e}")))?;
    } else {
        // Create new
        std::fs::write(&gitattributes, format!("# lpm\n{marker}\n"))
            .map_err(|e| LockfileError::Io(format!("failed to create .gitattributes: {e}")))?;
    }

    Ok(())
}
