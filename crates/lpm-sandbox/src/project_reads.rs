use crate::SandboxSpec;
use std::path::PathBuf;

pub(crate) fn allowed_project_reads(spec: &SandboxSpec) -> Vec<PathBuf> {
    if spec.read_project_full {
        return vec![spec.project_dir.clone()];
    }
    let mut paths = Vec::with_capacity(12 + spec.secret_read_allow.len());
    for name in ["node_modules", ".lpm", ".husky"] {
        paths.push(spec.project_dir.join(name));
    }
    if let Ok(entries) = std::fs::read_dir(&spec.project_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let metadata = matches!(
                name,
                "package.json"
                    | "package-lock.json"
                    | "npm-shrinkwrap.json"
                    | "yarn.lock"
                    | "pnpm-lock.yaml"
                    | "lpm.lock"
                    | "lpm.lockb"
            ) || (name.starts_with("tsconfig") && name.ends_with(".json"));
            if metadata && entry.file_type().is_ok_and(|kind| kind.is_file()) {
                paths.push(entry.path());
            }
        }
    }
    paths.extend_from_slice(&spec.secret_read_allow);
    paths.sort_unstable();
    paths.dedup();
    paths
}
