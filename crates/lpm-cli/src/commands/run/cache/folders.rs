//! The folders an `lpm` a cached task started found no env project for: how
//! the task's cache entry names them, from the task's own folder, and the
//! check that they still have none and are still found as they were.

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use lpm_runner::override_marker::{
    FolderWithoutEnvProject as Found, MAX_FOLDERS_WITHOUT_ENV_PROJECT, Unkeyed,
};
use lpm_task::cache::FolderWithoutEnvProject as Named;
use lpm_vault::override_marker::{FoundWalk, is_walk_manifests};

/// The folders a task's `lpm` processes found no env project for, as its
/// cache entry names them.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct TaskFolders {
    /// Sorted, as an entry keeps them.
    pub(super) named: Vec<Named>,
    /// Whether one, or a folder a walk passed, is outside the folder the
    /// task's key names paths from, whose name an entry in a remote cache
    /// would take to other computers.
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
        let folder = relative_spelling(&base, &entry.folder)
            .ok_or_else(|| Unkeyed::Unreachable(entry.folder.clone()))?;
        let (from, manifests) = match &entry.walk {
            None => (None, None),
            Some(walk) => {
                let from = relative_spelling(&base, &walk.start)
                    .ok_or_else(|| Unkeyed::UnreachableStart(walk.start.clone()))?;
                // Every folder the walk passed is below its last one.
                outside_key_root |=
                    walk_top(&walk.start, &walk.manifests).is_none_or(|top| !within_key_root(top));
                (Some(from), Some(walk.manifests.clone()))
            }
        };
        outside_key_root |= !within_key_root(&entry.folder);
        named.push(Named {
            folder,
            from,
            manifests,
        });
    }
    named.sort_unstable();
    Ok(TaskFolders {
        named,
        outside_key_root,
    })
}

/// The last folder a walk from `start` holding `manifests` passed.
fn walk_top<'a>(start: &'a Path, manifests: &str) -> Option<&'a Path> {
    start.ancestors().nth(manifests.len().checked_sub(1)?)
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
    /// The entry names a folder or a walk as no entry this version stores
    /// does, or more of them than one keeps, or, from a remote cache, one
    /// outside the folder the key names paths from.
    Malformed,
}

/// The check of the folders an entry names, from the task's folder.
pub(super) struct FolderCheck {
    project_dir: PathBuf,
    /// The task's canonical folder, unless it's gone, looked up for the
    /// first entry that names a folder.
    base: OnceCell<Option<PathBuf>>,
    /// Whether a folder has no env project.
    no_env_project: fn(&Path) -> bool,
}

impl FolderCheck {
    pub(super) fn new(project_dir: &Path) -> Self {
        Self {
            project_dir: project_dir.to_owned(),
            base: OnceCell::new(),
            no_env_project: lpm_vault::has_no_env_project,
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
        let base = self
            .base
            .get_or_init(|| std::fs::canonicalize(&self.project_dir).ok());
        let Some(base) = base else {
            return Err(Unstood::Changed);
        };
        let inside = |path: &Path| within.is_none_or(|within| path.starts_with(within));
        let mut seen = HashSet::with_capacity(named.len());
        let mut resolved = Vec::with_capacity(named.len());
        for entry in named {
            if !seen.insert(entry) {
                continue;
            }
            let folder = resolve_spelling(base, &entry.folder)
                .filter(|folder| inside(folder))
                .ok_or(Unstood::Malformed)?;
            let walk = match (&entry.from, &entry.manifests) {
                (None, None) => None,
                (Some(from), Some(manifests)) if is_walk_manifests(manifests) => {
                    let start = resolve_spelling(base, from).ok_or(Unstood::Malformed)?;
                    // The folder is one the walk passed, and the walk's last
                    // folder is the root it's checked within, or below it.
                    let passed = start
                        .ancestors()
                        .take(manifests.len())
                        .any(|level| level == folder);
                    if !passed || walk_top(&start, manifests).is_none_or(|top| !inside(top)) {
                        return Err(Unstood::Malformed);
                    }
                    Some(FoundWalk {
                        start,
                        manifests: manifests.clone(),
                    })
                }
                _ => return Err(Unstood::Malformed),
            };
            resolved.push(Found { folder, walk });
        }
        Ok(resolved)
    }

    /// The first of `found` that no longer stands, when one doesn't: one
    /// that has an env project now, or whose walk passes a folder holding
    /// other manifests, so a look from where its `lpm` started may find
    /// another folder, or this one another way. Each folder's lpm.json and
    /// manifests are read once, whatever number of entries name it.
    pub(super) fn first_changed<'a>(&self, found: &'a [Found]) -> Option<&'a Found> {
        let mut manifests: HashMap<&Path, char> = HashMap::new();
        let mut no_env_project: HashMap<&Path, bool> = HashMap::new();
        found.iter().find(|found| {
            let walk_holds = found.walk.as_ref().is_none_or(|walk| {
                walk.start
                    .ancestors()
                    .zip(walk.manifests.chars())
                    .all(|(level, held)| {
                        *manifests
                            .entry(level)
                            .or_insert_with(|| lpm_vault::override_marker::manifests(level))
                            == held
                    })
            });
            !walk_holds
                || !*no_env_project
                    .entry(&found.folder)
                    .or_insert_with(|| (self.no_env_project)(&found.folder))
        })
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

    fn found(folder: PathBuf, walk: Option<(PathBuf, &str)>) -> Found {
        Found {
            folder,
            walk: walk.map(|(start, manifests)| FoundWalk {
                start,
                manifests: manifests.to_owned(),
            }),
        }
    }

    fn named(folder: &str, walk: Option<(&str, &str)>) -> Named {
        Named {
            folder: folder.to_owned(),
            from: walk.map(|(from, _)| from.to_owned()),
            manifests: walk.map(|(_, manifests)| manifests.to_owned()),
        }
    }

    fn checking(base: Option<PathBuf>) -> FolderCheck {
        FolderCheck {
            project_dir: PathBuf::new(),
            base: OnceCell::from(base),
            no_env_project: lpm_vault::has_no_env_project,
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
    fn folders_are_named_sorted_and_marked_when_one_or_its_walk_leaves_the_key_root() {
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
                found(canonical(&app), Some((canonical(&app).join("src"), "01"))),
            ],
        )
        .expect("named");
        assert_eq!(
            inside,
            TaskFolders {
                named: vec![named(".", Some(("src", "01"))), named("../lib", None)],
                outside_key_root: false,
            }
        );

        let start_outside = name_from_task(
            &app,
            &workspace,
            &[found(canonical(&outside), Some((canonical(&outside), "1")))],
        )
        .expect("named");
        assert_eq!(
            start_outside.named,
            [named(
                "../../private-checkout",
                Some(("../../private-checkout", "1"))
            )]
        );
        assert!(start_outside.outside_key_root);

        let walk_above = name_from_task(
            &app,
            &workspace,
            &[found(canonical(&app), Some((canonical(&app), "0000")))],
        )
        .expect("named");
        assert!(
            walk_above.outside_key_root,
            "a walk that went on past the workspace, as one that found no manifest does"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_start_folder_no_entry_can_name_is_said_to_be_where_the_lpm_started() {
        let root = tempfile::tempdir().expect("temporary folder");
        let canonical = std::fs::canonicalize(root.path()).expect("canonical");
        let start = canonical.join("odd:name");
        assert_eq!(
            name_from_task(
                root.path(),
                root.path(),
                &[found(canonical, Some((start.clone(), "01")))],
            ),
            Err(Unkeyed::UnreachableStart(start))
        );
    }

    #[test]
    fn only_a_spelling_an_entry_stores_names_a_folder_and_each_is_checked_once() {
        let root = tempfile::tempdir().expect("temporary folder");
        let base = std::fs::canonicalize(root.path())
            .expect("canonical")
            .join("workspace")
            .join("app");
        let check = checking(Some(base.clone()));
        let workspace = base.parent().expect("workspace").to_owned();
        let resolved = check
            .resolve(
                &[
                    named(".", None),
                    named("../lib", Some(("../lib/tools/gen", "001"))),
                    named("tools/gen", None),
                    named("../lib", Some(("../lib/tools/gen", "001"))),
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
                    Some((workspace.join("lib").join("tools").join("gen"), "001"))
                ),
                found(base.join("tools").join("gen"), None),
                found(workspace.parent().expect("root").join("other"), None),
            ],
            "a folder named twice is resolved once"
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
                check.resolve(&[named(".", Some((spelling, "1")))], None),
                Err(Unstood::Malformed),
                "from {spelling:?}"
            );
        }
        for (walk, what) in [
            (("tools", ""), "no manifests"),
            (("tools", "0x"), "manifests no folder holds"),
            (("tools", "0"), "a walk that ends before the folder"),
            (("../lib", "01"), "a walk that never passes the folder"),
        ] {
            assert_eq!(
                check.resolve(&[named(".", Some(walk))], None),
                Err(Unstood::Malformed),
                "{what}"
            );
        }
        let mut no_manifests = named(".", None);
        no_manifests.from = Some(".".to_owned());
        assert_eq!(
            check.resolve(&[no_manifests], None),
            Err(Unstood::Malformed),
            "a start without manifests"
        );

        assert_eq!(
            check.resolve(&[named("../lib", None)], Some(&workspace)),
            Ok(vec![found(workspace.join("lib"), None)])
        );
        assert_eq!(
            check.resolve(&[named(".", Some(("tools", "001")))], Some(&workspace)),
            Ok(vec![found(base.clone(), Some((base.join("tools"), "001")))])
        );
        for (entry, what) in [
            (named("../../other", None), "a folder"),
            (named(".", Some(("../../other", "1"))), "a start"),
            (named(".", Some(("tools", "0000"))), "a walk's last folder"),
        ] {
            assert_eq!(
                check.resolve(&[entry], Some(&workspace)),
                Err(Unstood::Malformed),
                "{what} outside the folder a remote entry's key names paths from"
            );
        }

        let too_many = vec![named(".", None); MAX_FOLDERS_WITHOUT_ENV_PROJECT + 1];
        assert_eq!(check.resolve(&too_many, None), Err(Unstood::Malformed));
        assert_eq!(
            checking(None).resolve(&[named(".", None)], None),
            Err(Unstood::Changed)
        );
    }

    #[test]
    fn a_folder_stands_while_it_has_no_env_project_and_its_walk_passes_the_same_manifests() {
        let root = tempfile::tempdir().expect("temporary folder");
        let canonical = |path: &Path| std::fs::canonicalize(path).expect("canonical");
        let project = root.path().join("project");
        let start = project.join("tools").join("gen");
        std::fs::create_dir_all(&start).expect("folders");
        std::fs::write(project.join("package.json"), "{}").expect("manifest");
        std::fs::write(project.join("tools").join("lpm.json"), "{}").expect("manifest");
        let check = checking(Some(canonical(&project)));
        let stands = |found: &Found| check.first_changed(std::slice::from_ref(found)).is_none();
        let walked = found(canonical(&project), Some((canonical(&start), "021")));
        assert!(stands(&walked));

        std::fs::write(project.join("lpm.json"), r#"{"tasks":{}}"#).expect("lpm.json");
        assert!(
            !stands(&walked),
            "the folder holds another manifest, so another look may stop elsewhere"
        );
        let walked = found(canonical(&project), Some((canonical(&start), "023")));
        assert!(stands(&walked), "an lpm.json that names no vault");
        std::fs::write(
            project.join("lpm.json"),
            r#"{"vault":"550e8400-e29b-41d4-a716-446655440000"}"#,
        )
        .expect("lpm.json");
        assert!(!stands(&walked), "the folder has an env project");
        std::fs::remove_file(project.join("lpm.json")).expect("remove");

        let walked = found(canonical(&project), Some((canonical(&start), "021")));
        std::fs::write(start.join("package.json"), "{}").expect("closer manifest");
        assert!(
            !stands(&walked),
            "a folder the walk passed is a package now, so a look from where the lpm started stops there"
        );
        assert!(
            stands(&found(canonical(&project), None)),
            "a folder given to the lpm is checked alone"
        );
        std::fs::remove_file(start.join("package.json")).expect("remove");
        std::fs::remove_file(project.join("tools").join("lpm.json")).expect("remove");
        assert!(
            !stands(&walked),
            "a manifest gone from a folder the walk passed, so a look by lpm.json passes it now"
        );

        let scratch = canonical(&project).join("scratch");
        assert!(
            stands(&found(canonical(&project), Some((scratch.clone(), "01")))),
            "a folder the lpm started in that's gone holds no manifest, as it held none"
        );
        assert!(
            stands(&found(scratch, None)),
            "a folder that's gone has no env project"
        );
    }

    #[test]
    fn a_check_reads_each_folder_s_lpm_json_once_however_many_walks_name_it() {
        static READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn counted(folder: &Path) -> bool {
            READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            lpm_vault::has_no_env_project(folder)
        }
        let root = tempfile::tempdir().expect("temporary folder");
        let project = std::fs::canonicalize(root.path()).expect("canonical");
        std::fs::write(project.join("package.json"), "{}").expect("manifest");
        let walks: Vec<Found> = (0..50)
            .map(|index| {
                let start = project.join(format!("start-{index}"));
                found(project.clone(), Some((start, "01")))
            })
            .collect();
        let check = FolderCheck {
            no_env_project: counted,
            ..checking(Some(project))
        };

        assert!(check.first_changed(&walks).is_none());

        assert_eq!(READS.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
