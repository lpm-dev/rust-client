use lpm_common::LpmError;
use std::path::{Path, PathBuf};

pub(super) fn for_each_cache_glob_match(
    root: &Path,
    pattern: &str,
    mut visit: impl FnMut(PathBuf) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let normalized_pattern = normalize_glob_curdir_components(pattern);
    let require_directory = normalized_pattern.ends_with('/');
    let components = compile_cache_glob_components(&normalized_pattern, pattern)?;
    if components.is_empty() {
        return Ok(());
    }
    let root_metadata = std::fs::metadata(root).map_err(|error| {
        LpmError::Task(format!(
            "failed to inspect task cache glob root {}: {error}",
            root.display()
        ))
    })?;
    let mut ancestor_directories =
        std::collections::HashSet::from([directory_identity(&root_metadata)]);
    walk_cache_glob(
        root,
        &mut PathBuf::new(),
        &components,
        0,
        require_directory,
        &mut ancestor_directories,
        pattern,
        &mut visit,
    )
}

fn normalize_glob_curdir_components(pattern: &str) -> std::borrow::Cow<'_, str> {
    if !pattern.split('/').any(|component| component == ".") {
        return std::borrow::Cow::Borrowed(pattern);
    }

    let mut normalized = String::with_capacity(pattern.len());
    for component in pattern.split('/').filter(|component| *component != ".") {
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    std::borrow::Cow::Owned(normalized)
}

enum CacheGlobComponent {
    Recursive,
    Literal(std::ffi::OsString),
    Pattern {
        utf8: glob::Pattern,
        raw: std::cell::OnceCell<globset::GlobMatcher>,
    },
}

impl CacheGlobComponent {
    fn matches_name(&self, name: &std::ffi::OsStr) -> Result<bool, LpmError> {
        let Self::Pattern { utf8, raw } = self else {
            return Ok(false);
        };
        if let Some(name) = name.to_str() {
            return Ok(utf8.matches(name));
        }
        if raw.get().is_none() {
            let compatible = globset_pattern_for_glob_crate(utf8.as_str());
            let matcher = globset::GlobBuilder::new(&compatible)
                .literal_separator(true)
                .build()
                .map_err(|error| {
                    LpmError::Task(format!(
                        "invalid task cache glob component {:?}: {error}",
                        utf8.as_str()
                    ))
                })?
                .compile_matcher();
            let _ = raw.set(matcher);
        }
        Ok(raw
            .get()
            .expect("raw task glob matcher was initialized")
            .is_match(Path::new(name)))
    }
}

fn compile_cache_glob_components(
    normalized: &str,
    original: &str,
) -> Result<Vec<CacheGlobComponent>, LpmError> {
    let mut components = Vec::with_capacity(normalized.matches('/').count() + 1);
    for component in normalized
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if component == "**" {
            if !matches!(components.last(), Some(CacheGlobComponent::Recursive)) {
                components.push(CacheGlobComponent::Recursive);
            }
            continue;
        }
        let parsed = glob::Pattern::new(component).map_err(|error| {
            LpmError::Task(format!("invalid task cache glob {original:?}: {error}"))
        })?;
        if component.contains(['*', '?', '[']) {
            components.push(CacheGlobComponent::Pattern {
                utf8: parsed,
                raw: std::cell::OnceCell::new(),
            });
        } else {
            components.push(CacheGlobComponent::Literal(component.into()));
        }
    }
    Ok(components)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the allocation-free walker carries its traversal state explicitly"
)]
fn walk_cache_glob(
    directory: &Path,
    relative: &mut PathBuf,
    components: &[CacheGlobComponent],
    index: usize,
    require_directory: bool,
    ancestor_directories: &mut std::collections::HashSet<(u64, u64)>,
    pattern: &str,
    visit: &mut impl FnMut(PathBuf) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let last = index + 1 == components.len();
    match &components[index] {
        CacheGlobComponent::Recursive if last => walk_cache_glob_descendants(
            directory,
            relative,
            require_directory,
            ancestor_directories,
            pattern,
            visit,
        ),
        CacheGlobComponent::Recursive => {
            walk_cache_glob(
                directory,
                relative,
                components,
                index + 1,
                require_directory,
                ancestor_directories,
                pattern,
                visit,
            )?;
            for entry in read_cache_glob_directory(directory, pattern)? {
                let entry = entry.map_err(|error| cache_glob_io_error(pattern, error))?;
                let Some(metadata) = followed_directory_metadata(&entry.path()) else {
                    continue;
                };
                relative.push(entry.file_name());
                let result = descend_cache_glob(
                    &entry.path(),
                    relative,
                    &metadata,
                    components,
                    index,
                    require_directory,
                    ancestor_directories,
                    pattern,
                    visit,
                );
                relative.pop();
                result?;
            }
            Ok(())
        }
        CacheGlobComponent::Literal(name) => {
            let path = directory.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(cache_glob_io_error(pattern, error)),
            }
            relative.push(name);
            let result = if last {
                if !require_directory || followed_directory_metadata(&path).is_some() {
                    visit(relative.clone())
                } else {
                    Ok(())
                }
            } else if let Some(metadata) = followed_directory_metadata(&path) {
                descend_cache_glob(
                    &path,
                    relative,
                    &metadata,
                    components,
                    index + 1,
                    require_directory,
                    ancestor_directories,
                    pattern,
                    visit,
                )
            } else {
                Ok(())
            };
            relative.pop();
            result
        }
        component @ CacheGlobComponent::Pattern { .. } => {
            for entry in read_cache_glob_directory(directory, pattern)? {
                let entry = entry.map_err(|error| cache_glob_io_error(pattern, error))?;
                let name = entry.file_name();
                if !component.matches_name(&name)? {
                    continue;
                }
                let path = entry.path();
                relative.push(&name);
                let result = if last {
                    if !require_directory || followed_directory_metadata(&path).is_some() {
                        visit(relative.clone())
                    } else {
                        Ok(())
                    }
                } else if let Some(metadata) = followed_directory_metadata(&path) {
                    descend_cache_glob(
                        &path,
                        relative,
                        &metadata,
                        components,
                        index + 1,
                        require_directory,
                        ancestor_directories,
                        pattern,
                        visit,
                    )
                } else {
                    Ok(())
                };
                relative.pop();
                result?;
            }
            Ok(())
        }
    }
}

fn walk_cache_glob_descendants(
    directory: &Path,
    relative: &mut PathBuf,
    require_directory: bool,
    ancestor_directories: &mut std::collections::HashSet<(u64, u64)>,
    pattern: &str,
    visit: &mut impl FnMut(PathBuf) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    for entry in read_cache_glob_directory(directory, pattern)? {
        let entry = entry.map_err(|error| cache_glob_io_error(pattern, error))?;
        let path = entry.path();
        let directory_metadata = followed_directory_metadata(&path);
        relative.push(entry.file_name());
        if !require_directory || directory_metadata.is_some() {
            visit(relative.clone())?;
        }
        if let Some(metadata) = directory_metadata {
            let identity = directory_identity(&metadata);
            if !ancestor_directories.insert(identity) {
                relative.pop();
                return Err(LpmError::Task(format!(
                    "task cache glob {pattern:?} contains a directory cycle at {}",
                    path.display()
                )));
            }
            let result = walk_cache_glob_descendants(
                &path,
                relative,
                require_directory,
                ancestor_directories,
                pattern,
                visit,
            );
            ancestor_directories.remove(&identity);
            if let Err(error) = result {
                relative.pop();
                return Err(error);
            }
        }
        relative.pop();
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the allocation-free walker carries its traversal state explicitly"
)]
fn descend_cache_glob(
    directory: &Path,
    relative: &mut PathBuf,
    metadata: &std::fs::Metadata,
    components: &[CacheGlobComponent],
    index: usize,
    require_directory: bool,
    ancestor_directories: &mut std::collections::HashSet<(u64, u64)>,
    pattern: &str,
    visit: &mut impl FnMut(PathBuf) -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let identity = directory_identity(metadata);
    if !ancestor_directories.insert(identity) {
        return Err(LpmError::Task(format!(
            "task cache glob {pattern:?} contains a directory cycle at {}",
            directory.display()
        )));
    }
    let result = walk_cache_glob(
        directory,
        relative,
        components,
        index,
        require_directory,
        ancestor_directories,
        pattern,
        visit,
    );
    ancestor_directories.remove(&identity);
    result
}

fn followed_directory_metadata(path: &Path) -> Option<std::fs::Metadata> {
    std::fs::metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_dir)
}

fn directory_identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;

    (metadata.dev(), metadata.ino())
}

fn read_cache_glob_directory(
    directory: &Path,
    pattern: &str,
) -> Result<std::fs::ReadDir, LpmError> {
    std::fs::read_dir(directory).map_err(|error| {
        LpmError::Task(format!(
            "failed to expand task cache glob {pattern:?} at {}: {error}",
            directory.display()
        ))
    })
}

fn cache_glob_io_error(pattern: &str, error: std::io::Error) -> LpmError {
    LpmError::Task(format!(
        "failed to expand task cache glob {pattern:?}: {error}"
    ))
}

fn globset_pattern_for_glob_crate(pattern: &str) -> String {
    let mut compatible = String::with_capacity(pattern.len());
    let mut escaped = false;
    for character in pattern.chars() {
        if escaped {
            compatible.push(character);
            escaped = false;
        } else if character == '\\' {
            compatible.push(character);
            escaped = true;
        } else if matches!(character, '{' | '}') {
            compatible.push('\\');
            compatible.push(character);
        } else {
            compatible.push(character);
        }
    }
    compatible
}
