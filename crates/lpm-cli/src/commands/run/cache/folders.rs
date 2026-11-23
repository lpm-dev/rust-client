//! The folders an `lpm` a cached task started found no env project for: how
//! the task's cache entry names them, from the task's own folder, and the
//! check each hit makes that they still have none.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use lpm_runner::override_marker::{
    FolderWithoutEnvProject as Found, MAX_FOLDERS_WITHOUT_ENV_PROJECT, Unkeyed,
};
use lpm_task::cache::FolderWithoutEnvProject as Named;

/// The folders a task's `lpm` processes found no env project for, as its
/// cache entry names them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct TaskFolders {
    /// Sorted, as an entry keeps them.
    pub(super) named: Vec<Named>,
    /// Whether one is outside the folder the task's key names paths from,
    /// whose name an entry in a remote cache would take to other computers.
    pub(super) outside_key_root: bool,
}

/// Name each of `found` from the task's folder `project_dir`. One the cache
/// can't name from there, as one on another drive, keeps the task out.
pub(super) fn name_from_task(
    project_dir: &Path,
    key_root: &Path,
    found: &[Found],
) -> Result<TaskFolders, Unkeyed> {
    let Some(first) = found.first() else {
        return Ok(TaskFolders::default());
    };
    let base = std::fs::canonicalize(project_dir)
        .map_err(|_| Unkeyed::Unreachable(first.folder.clone()))?;
    let base: Vec<Component<'_>> = base.components().collect();
    let key_root = std::fs::canonicalize(key_root).ok();
    let within_key_root = |path: &Path| {
        key_root
            .as_deref()
            .is_some_and(|root| path.starts_with(root))
    };
    let mut named = Vec::with_capacity(found.len());
    let mut outside_key_root = false;
    for entry in found {
        let name = |path: &Path| {
            relative_spelling(&base, path).ok_or_else(|| Unkeyed::Unreachable(path.to_owned()))
        };
        named.push(Named {
            folder: name(&entry.folder)?,
            from: entry.from.as_deref().map(name).transpose()?,
        });
        outside_key_root |= !within_key_root(&entry.folder)
            || entry
                .from
                .as_deref()
                .is_some_and(|from| !within_key_root(from));
    }
    named.sort_unstable();
    Ok(TaskFolders {
        named,
        outside_key_root,
    })
}

/// `folder` named from `base`, the components of a canonical path: `.` for
/// `base` itself, else a `..` for each name of `base` it's not below, then
/// its own names, joined with `/`. `None` when they don't share a root, or a
/// name isn't UTF-8 or is one an entry can't hold (see [`is_entry_name`]).
fn relative_spelling(base: &[Component<'_>], folder: &Path) -> Option<String> {
    let is_root =
        |component: &Component<'_>| matches!(component, Component::Prefix(_) | Component::RootDir);
    let folder: Vec<Component<'_>> = folder.components().collect();
    let roots = base
        .iter()
        .take_while(|component| is_root(component))
        .count();
    if roots == 0 || base[..roots] != folder[..roots.min(folder.len())] {
        return None;
    }
    let shared = base
        .iter()
        .zip(&folder)
        .take_while(|(from, to)| from == to)
        .count();
    let mut parts: Vec<&str> = std::iter::repeat_n("..", base.len() - shared).collect();
    for component in &folder[shared..] {
        match component {
            Component::Normal(name) => {
                parts.push(name.to_str().filter(|name| is_entry_name(name))?)
            }
            _ => return None,
        }
    }
    Some(if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    })
}

/// Whether `name` is a folder name an entry holds: one that means the same
/// folder joined to a path on every platform, so it holds neither separator,
/// nor the `:` that names a drive or a stream on Windows, and is no step.
fn is_entry_name(name: &str) -> bool {
    !matches!(name, "" | "." | "..") && !name.contains(['/', '\\', ':', '\0'])
}

/// Why the folders a cache entry names don't stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unstood {
    /// The task's folder is gone, so the task may build something else.
    Changed,
    /// The entry names a folder as no entry this version stores does, or
    /// more of them than one keeps, or, from a remote cache, one outside the
    /// folder the key names paths from.
    Malformed,
}

/// The check a hit makes of the folders its entry names, from the task's
/// folder.
pub(super) struct FolderCheck {
    /// The task's canonical folder, unless it's gone.
    base: Option<PathBuf>,
    /// The folder a look for a project stops below, as the `lpm` that made
    /// it stopped.
    home: Option<PathBuf>,
}

impl FolderCheck {
    pub(super) fn new(project_dir: &Path) -> Self {
        Self {
            base: std::fs::canonicalize(project_dir).ok(),
            home: dirs::home_dir(),
        }
    }

    /// Each of `named`, once, as the paths it names here, which must be
    /// below `within`, when given; or why it can't stand.
    pub(super) fn resolve(
        &self,
        named: &[Named],
        within: Option<&Path>,
    ) -> Result<Vec<Found>, Unstood> {
        if named.len() > MAX_FOLDERS_WITHOUT_ENV_PROJECT {
            return Err(Unstood::Malformed);
        }
        let Some(base) = &self.base else {
            return Err(Unstood::Changed);
        };
        let resolve = |spelling: &str| {
            resolve_spelling(base, spelling)
                .filter(|path| within.is_none_or(|within| path.starts_with(within)))
                .ok_or(Unstood::Malformed)
        };
        let mut seen = HashSet::with_capacity(named.len());
        let mut resolved = Vec::with_capacity(named.len());
        for entry in named {
            if seen.insert(entry) {
                resolved.push(Found {
                    folder: resolve(&entry.folder)?,
                    from: entry.from.as_deref().map(resolve).transpose()?,
                });
            }
        }
        Ok(resolved)
    }

    /// Whether `found` still stands: its folder has no env project, and a
    /// project-scoped command started where its `lpm` did still acts on it.
    pub(super) fn holds(&self, found: &Found) -> bool {
        if let Some(from) = &found.from {
            if !std::fs::metadata(from).is_ok_and(|metadata| metadata.is_dir()) {
                return false;
            }
            let ends_at = lpm_workspace::find_project_config_root(from, self.home.as_deref())
                .unwrap_or_else(|| from.clone());
            if !lpm_workspace::is_same_directory(&ends_at, &found.folder) {
                return false;
            }
        }
        lpm_vault::has_no_env_project(&found.folder)
    }
}

/// The folder `spelling` names from `base`, as [`relative_spelling`] names
/// one, each step taken on its own so no `.`, `..` or `/` ever reaches a
/// path, which Windows takes literally in a `\\?\` one. `None` for any other
/// spelling, or one that climbs above the root.
fn resolve_spelling(base: &Path, spelling: &str) -> Option<PathBuf> {
    let mut path = base.to_path_buf();
    if spelling == "." {
        return Some(path);
    }
    let mut named = false;
    for part in spelling.split('/') {
        match part {
            ".." if !named => {
                if !path.pop() {
                    return None;
                }
            }
            name if is_entry_name(name) => {
                named = true;
                path.push(name);
            }
            _ => return None,
        }
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(folder: PathBuf, from: Option<PathBuf>) -> Found {
        Found { folder, from }
    }

    fn named(folder: &str, from: Option<&str>) -> Named {
        Named {
            folder: folder.to_owned(),
            from: from.map(str::to_owned),
        }
    }

    #[test]
    fn a_folder_is_named_from_the_task_s_folder_by_a_relative_path_with_slashes() {
        let root = if cfg!(windows) { r"C:\repo" } else { "/repo" };
        let base_path = Path::new(root).join("packages").join("app");
        let base: Vec<Component<'_>> = base_path.components().collect();
        let name = |folder: PathBuf| relative_spelling(&base, &folder);
        assert_eq!(name(base_path.clone()).as_deref(), Some("."));
        assert_eq!(
            name(Path::new(root).join("packages").join("lib")).as_deref(),
            Some("../lib")
        );
        assert_eq!(
            name(base_path.join("tools").join("gen")).as_deref(),
            Some("tools/gen")
        );
        assert_eq!(
            name(Path::new(root).join("other")).as_deref(),
            Some("../../other")
        );
        if cfg!(windows) {
            assert_eq!(name(PathBuf::from(r"D:\repo\lib")), None, "another drive");
        } else {
            for unnamed in [r"back\slash", "drive:or-stream"] {
                assert_eq!(name(base_path.join(unnamed)), None, "{unnamed}");
            }
        }
    }

    #[test]
    fn folders_are_named_sorted_and_marked_when_one_is_outside_the_key_root() {
        let root = tempfile::tempdir().expect("temporary folder");
        let canonical = |path: &Path| std::fs::canonicalize(path).expect("canonical");
        let workspace = root.path().join("workspace");
        let app = workspace.join("app");
        let lib = workspace.join("lib");
        let outside = root.path().join("private-checkout");
        for folder in [&app, &lib, &outside] {
            std::fs::create_dir_all(folder).expect("folder");
        }

        let inside = name_from_task(
            &app,
            &workspace,
            &[
                found(canonical(&lib), None),
                found(canonical(&app), Some(canonical(&app).join("."))),
            ],
        )
        .expect("named");
        assert_eq!(
            inside,
            TaskFolders {
                named: vec![named(".", Some(".")), named("../lib", None)],
                outside_key_root: false,
            }
        );

        let with_outside = name_from_task(
            &app,
            &workspace,
            &[found(canonical(&app), Some(canonical(&outside)))],
        )
        .expect("named");
        assert_eq!(
            with_outside.named,
            [named(".", Some("../../private-checkout"))]
        );
        assert!(with_outside.outside_key_root);
    }

    #[test]
    fn only_a_spelling_an_entry_stores_names_a_folder_and_each_is_checked_once() {
        let root = tempfile::tempdir().expect("temporary folder");
        let base = std::fs::canonicalize(root.path())
            .expect("canonical")
            .join("workspace")
            .join("app");
        let check = FolderCheck {
            base: Some(base.clone()),
            home: None,
        };
        let workspace = base.parent().expect("workspace").to_owned();
        let resolved = check
            .resolve(
                &[
                    named(".", None),
                    named("../lib", Some("../lib/tools/gen")),
                    named("tools/gen", None),
                    named("../lib", Some("../lib/tools/gen")),
                    named("../../other", None),
                ],
                None,
            )
            .expect("resolved");
        assert_eq!(
            resolved,
            [
                found(base.clone(), None),
                found(
                    workspace.join("lib"),
                    Some(workspace.join("lib").join("tools").join("gen"))
                ),
                found(base.join("tools").join("gen"), None),
                found(workspace.parent().expect("root").join("other"), None),
            ],
            "a folder named twice is checked once"
        );

        // An absolute path here would reach the temporary folder, which has
        // no lpm.json, so one taken as it's spelled would hold.
        let absolute = root.path().to_string_lossy().into_owned();
        let climbs = "../".repeat(base.components().count() + 1) + "x";
        for spelling in [
            "",
            absolute.as_str(),
            r"C:\Windows",
            r"\\attacker.example\share",
            r"..\other",
            "../other/",
            "./other",
            "a//b",
            "a/../b",
            "a/./b",
            "drive:or-stream",
            "nul\0byte",
            climbs.as_str(),
        ] {
            assert_eq!(
                check.resolve(&[named(spelling, None)], None),
                Err(Unstood::Malformed),
                "{spelling:?}"
            );
            assert_eq!(
                check.resolve(&[named(".", Some(spelling))], None),
                Err(Unstood::Malformed),
                "from {spelling:?}"
            );
        }

        assert_eq!(
            check.resolve(&[named("../lib", None)], Some(&workspace)),
            Ok(vec![found(workspace.join("lib"), None)])
        );
        assert_eq!(
            check.resolve(&[named("../../other", None)], Some(&workspace)),
            Err(Unstood::Malformed),
            "outside the folder a remote entry's key names paths from"
        );
        assert_eq!(
            check.resolve(&[named(".", Some("../../other"))], Some(&workspace)),
            Err(Unstood::Malformed)
        );

        let too_many = vec![named(".", None); MAX_FOLDERS_WITHOUT_ENV_PROJECT + 1];
        assert_eq!(check.resolve(&too_many, None), Err(Unstood::Malformed));
        let gone = FolderCheck {
            base: None,
            home: None,
        };
        assert_eq!(
            gone.resolve(&[named(".", None)], None),
            Err(Unstood::Changed)
        );
    }

    #[test]
    fn a_folder_holds_while_it_has_no_env_project_and_a_look_from_where_its_lpm_started_ends_there()
    {
        let root = tempfile::tempdir().expect("temporary folder");
        let canonical = |path: &Path| std::fs::canonicalize(path).expect("canonical");
        let project = root.path().join("project");
        let start = project.join("tools").join("gen");
        std::fs::create_dir_all(&start).expect("folders");
        std::fs::write(project.join("package.json"), "{}").expect("manifest");
        let check = FolderCheck {
            base: Some(canonical(&project)),
            home: Some(canonical(root.path())),
        };
        let looked_up = found(canonical(&project), Some(canonical(&start)));
        assert!(check.holds(&looked_up));

        std::fs::write(project.join("lpm.json"), r#"{"tasks":{}}"#).expect("lpm.json");
        assert!(check.holds(&looked_up), "an lpm.json that names no vault");
        std::fs::write(
            project.join("lpm.json"),
            r#"{"vault":"550e8400-e29b-41d4-a716-446655440000"}"#,
        )
        .expect("lpm.json");
        assert!(!check.holds(&looked_up), "the folder has an env project");
        std::fs::remove_file(project.join("lpm.json")).expect("remove");

        std::fs::write(start.join("package.json"), "{}").expect("closer manifest");
        assert!(
            !check.holds(&looked_up),
            "a closer folder is a project now, so a look from where the lpm started ends there"
        );
        assert!(
            check.holds(&found(canonical(&project), None)),
            "a folder given to the lpm is checked alone"
        );
        std::fs::remove_file(start.join("package.json")).expect("remove");

        let bare = root.path().join("bare").join("deep");
        std::fs::create_dir_all(&bare).expect("bare");
        let fallback = found(canonical(&bare), Some(canonical(&bare)));
        assert!(check.holds(&fallback), "no manifest up to the home folder");
        std::fs::write(root.path().join("bare").join("lpm.json"), "{}").expect("lpm.json");
        assert!(
            !check.holds(&fallback),
            "a folder above it got a manifest, so a look from it ends there"
        );

        std::fs::remove_dir_all(&start).expect("remove");
        assert!(!check.holds(&looked_up), "where the lpm started is gone");
    }
}
