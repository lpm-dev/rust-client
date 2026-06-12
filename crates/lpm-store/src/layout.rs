use std::path::Path;

pub(crate) fn is_complete_package_dir(dir: &Path) -> bool {
    dir.is_dir() && dir.join("package.json").exists() && dir.join(".integrity").exists()
}
