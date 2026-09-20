use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use lpm_common::LpmError;
use lpm_workspace::PackageJson;

pub(super) fn check(project_dir: &Path, package: &PackageJson) -> Result<(), LpmError> {
    let mode = package
        .lpm
        .as_ref()
        .and_then(|config| config.strict_deps.as_deref())
        .unwrap_or("warn");
    match mode {
        "warn" | "loose" => return Ok(()),
        "strict" => {}
        _ => {
            return Err(LpmError::Registry(
                "package.json > lpm > strictDeps: expected one of: strict, warn, loose".into(),
            ));
        }
    }

    // Source edits do not invalidate install-state caches, so this gate must run
    // before any freshness or offline return.
    let imports =
        crate::intelligence::scan_source_imports_checked(project_dir).map_err(|error| {
            LpmError::Registry(format!(
                "lpm.strictDeps could not finish checking {}: {error}",
                project_dir.display()
            ))
        })?;
    let declared: HashSet<&str> = package
        .dependencies
        .keys()
        .chain(package.dev_dependencies.keys())
        .chain(package.optional_dependencies.keys())
        .chain(package.peer_dependencies.keys())
        .map(String::as_str)
        .chain(package.name.as_deref())
        .collect();
    let builtins = crate::intelligence::node_builtin_package_names();
    let mut missing = BTreeMap::new();
    for import in &imports {
        if let Some(name) = import.package_name.as_deref()
            && !declared.contains(name)
            && !builtins.contains(name)
        {
            missing.entry(name).or_insert(import);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "lpm.strictDeps=strict: {} undeclared package import(s) in {}",
        missing.len(),
        project_dir.display()
    );
    for (name, import) in missing.iter().take(10) {
        use std::fmt::Write;
        let file = import
            .file
            .strip_prefix(project_dir)
            .unwrap_or(&import.file);
        let _ = write!(message, "\n  {name} ({}:{})", file.display(), import.line);
    }
    if missing.len() > 10 {
        use std::fmt::Write;
        let _ = write!(message, "\n  ... and {} more", missing.len() - 10);
    }
    message.push_str("\nDeclare these dependencies in package.json or correct the imports.");
    Err(LpmError::Registry(message))
}
