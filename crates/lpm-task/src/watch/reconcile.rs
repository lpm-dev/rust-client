use super::{WatchFilter, WatchFilterHandle};
use std::collections::HashMap;
use std::fs::{self, FileType, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    kind: FileType,
    readonly: bool,
    size: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, u32),
    #[cfg(unix)]
    changed: (i64, i64),
}

impl Stamp {
    fn new(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        let directory = metadata.is_dir();
        Self {
            kind: metadata.file_type(),
            readonly: metadata.permissions().readonly(),
            // Child churn also changes directory ctime and size, including excluded outputs.
            size: if directory { 0 } else { metadata.len() },
            modified: if directory {
                None
            } else {
                metadata.modified().ok()
            },
            #[cfg(unix)]
            identity: (metadata.dev(), metadata.ino(), metadata.mode()),
            #[cfg(unix)]
            changed: if directory {
                (0, 0)
            } else {
                (metadata.ctime(), metadata.ctime_nsec())
            },
        }
    }
}

pub(super) struct Recovery {
    filter: WatchFilterHandle,
    snapshot: Reconciler,
}

impl Recovery {
    pub(super) fn new(filter: WatchFilterHandle) -> Self {
        Self {
            filter,
            snapshot: Reconciler::default(),
        }
    }

    pub(super) fn before_run(&mut self, should_stop: &impl Fn() -> bool) {
        let filter = self
            .filter
            .0
            .read()
            .unwrap_or_else(|error| error.into_inner());
        self.snapshot.baseline(&filter, should_stop);
    }

    pub(super) fn poll(&mut self, should_stop: &impl Fn() -> bool) -> bool {
        let filter = self
            .filter
            .0
            .read()
            .unwrap_or_else(|error| error.into_inner());
        self.snapshot.poll(&filter, should_stop)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileStamp {
    link: Stamp,
    target: Option<Stamp>,
}

struct Entry {
    stamp: FileStamp,
    generation: u64,
}

#[derive(Default)]
struct Reconciler {
    entries: HashMap<PathBuf, Entry>,
    generation: u64,
    next_scan: Option<Instant>,
}

impl Reconciler {
    pub(super) fn baseline(&mut self, filter: &WatchFilter, should_stop: &impl Fn() -> bool) {
        self.scan(filter, should_stop);
    }

    pub(super) fn poll(&mut self, filter: &WatchFilter, should_stop: &impl Fn() -> bool) -> bool {
        if self.next_scan.is_some_and(|next| Instant::now() < next) {
            return false;
        }
        self.scan(filter, should_stop)
    }

    fn scan(&mut self, filter: &WatchFilter, should_stop: &impl Fn() -> bool) -> bool {
        let started = Instant::now();
        self.generation = self.generation.wrapping_add(1);
        let mut changed = false;
        if filter.literal_files.is_empty() {
            // Root config files override even an output pattern covering the whole tree.
            if filter.config_files {
                for name in ["package.json", "lpm.json"] {
                    self.inspect(&filter.root.join(name), &mut changed);
                }
            }
            self.walk(&mut filter.root.clone(), filter, &mut changed, should_stop);
        } else {
            for file in &filter.literal_files {
                self.inspect(file, &mut changed);
            }
        }
        if !should_stop() {
            self.entries.retain(|_, entry| {
                let present = entry.generation == self.generation;
                changed |= !present;
                present
            });
        }
        // Bound idle scan duty cycle on large trees and never schedule a scan in the past.
        let delay = Duration::from_secs(1).max(started.elapsed().saturating_mul(20));
        self.next_scan = Some(Instant::now() + delay);
        changed
    }

    fn inspect(&mut self, path: &Path, changed: &mut bool) {
        match fs::symlink_metadata(path) {
            Ok(metadata) => self.record(path, &metadata, changed),
            Err(error) => self.preserve_unreadable(path, &error),
        }
    }

    fn record(&mut self, path: &Path, metadata: &Metadata, changed: &mut bool) {
        let target = if metadata.is_symlink() {
            match fs::metadata(path) {
                Ok(target) => Some(Stamp::new(&target)),
                Err(error) if is_missing(&error) => None,
                Err(error) => {
                    tracing::debug!(path = %path.display(), %error, "cannot reconcile symlink target");
                    self.entries
                        .get(path)
                        .and_then(|entry| entry.stamp.target.clone())
                }
            }
        } else {
            None
        };
        let stamp = FileStamp {
            link: Stamp::new(metadata),
            target,
        };
        if let Some(entry) = self.entries.get_mut(path) {
            *changed |= entry.stamp != stamp;
            entry.stamp = stamp;
            entry.generation = self.generation;
        } else {
            self.entries.insert(
                path.to_path_buf(),
                Entry {
                    stamp,
                    generation: self.generation,
                },
            );
            *changed = true;
        }
    }

    fn walk(
        &mut self,
        path: &mut PathBuf,
        filter: &WatchFilter,
        changed: &mut bool,
        should_stop: &impl Fn() -> bool,
    ) {
        if should_stop() {
            return;
        }
        let relative = path.strip_prefix(&filter.root).unwrap_or(path);
        if excluded_tree(relative, filter) {
            return;
        }
        let metadata = match fs::symlink_metadata(&*path) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.preserve_unreadable(path, &error);
                return;
            }
        };
        if filter.matches_path(path) {
            self.record(path, &metadata, changed);
        }
        if !metadata.is_dir() {
            return;
        }
        let children = match fs::read_dir(&*path) {
            Ok(children) => children,
            Err(error) => {
                self.preserve_unreadable(path, &error);
                return;
            }
        };
        for child in children {
            if should_stop() {
                return;
            }
            match child {
                Ok(child) => {
                    path.push(child.file_name());
                    self.walk(path, filter, changed, should_stop);
                    path.pop();
                }
                Err(error) => self.preserve_unreadable(path, &error),
            }
        }
    }

    fn preserve_unreadable(&mut self, path: &Path, error: &io::Error) {
        if is_missing(error) {
            return;
        }
        // An inaccessible subtree is unknown, not deleted. Retry on the next scan.
        tracing::debug!(path = %path.display(), %error, "cannot reconcile watched path");
        for (known, entry) in &mut self.entries {
            if known.starts_with(path) {
                entry.generation = self.generation;
            }
        }
    }
}

fn is_missing(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn excluded_tree(relative: &Path, filter: &WatchFilter) -> bool {
    relative.components().any(|part| match part {
        Component::ParentDir => true,
        Component::Normal(name) => name == ".git" || name == "node_modules" || name == ".lpm",
        _ => false,
    }) || filter.output_trees.is_match(relative)
        || (!filter.all_inputs
            && !filter
                .input_prefixes
                .iter()
                .any(|prefix| prefix.starts_with(relative) || relative.starts_with(prefix)))
}

#[cfg(test)]
mod tests {
    use super::super::{WatchFilterHandle, WatchNotifications, run_watch_loop};
    use super::*;
    use std::sync::mpsc;

    fn filter(root: &Path, inputs: &[&str], outputs: &[&str]) -> WatchFilter {
        WatchFilter::new(
            root,
            &inputs.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &outputs.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn scan(snapshot: &mut Reconciler, filter: &WatchFilter) -> bool {
        snapshot.scan(filter, &|| false)
    }

    #[test]
    fn same_length_writes_and_atomic_replacements_are_detected() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("input.txt");
        fs::write(&file, "before").unwrap();
        let filter = filter(root.path(), &["input.txt"], &[]);
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        std::thread::sleep(Duration::from_millis(5));
        fs::write(&file, "after!").unwrap();
        assert!(scan(&mut snapshot, &filter));
        assert!(!scan(&mut snapshot, &filter));
        let replacement = root.path().join("replacement");
        fs::write(&replacement, "after!").unwrap();
        fs::rename(replacement, &file).unwrap();
        assert!(scan(&mut snapshot, &filter));
    }

    #[test]
    fn additions_renames_and_deletions_are_detected() {
        let root = tempfile::tempdir().unwrap();
        let filter = filter(root.path(), &["src/**/*.ts"], &[]);
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::create_dir_all(root.path().join("src/nested")).unwrap();
        let file = root.path().join("src/nested/new.ts");
        fs::write(&file, "created").unwrap();
        assert!(scan(&mut snapshot, &filter));
        let renamed = root.path().join("src/nested/renamed.ts");
        fs::rename(&file, &renamed).unwrap();
        assert!(scan(&mut snapshot, &filter));
        fs::remove_file(&renamed).unwrap();
        assert!(scan(&mut snapshot, &filter));
    }

    #[test]
    fn excluded_children_do_not_change_directory_stamps() {
        let root = tempfile::tempdir().unwrap();
        let filter = filter(root.path(), &[], &["dist/**", "**/generated.txt"]);
        fs::create_dir(root.path().join("src")).unwrap();
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        for directory in [".git", "node_modules", ".lpm", "dist"] {
            fs::create_dir(root.path().join(directory)).unwrap();
            fs::write(root.path().join(directory).join("new.js"), "output").unwrap();
        }
        for file in ["src/generated.txt", "src/editor.swp", "src/backup~"] {
            fs::write(root.path().join(file), "output").unwrap();
        }
        assert!(!scan(&mut snapshot, &filter));
        for directory in [".git", "node_modules", ".lpm", "dist"] {
            fs::remove_dir_all(root.path().join(directory)).unwrap();
        }
        assert!(!scan(&mut snapshot, &filter));
    }

    #[test]
    fn exact_directory_outputs_do_not_prune_matching_descendants() {
        let root = tempfile::tempdir().unwrap();
        let filter = filter(root.path(), &["dist/**/*.ts"], &["dist", "dist/**/*.js"]);
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::create_dir_all(root.path().join("dist/nested")).unwrap();
        fs::write(root.path().join("dist/nested/input.ts"), "input").unwrap();
        assert!(scan(&mut snapshot, &filter));
        fs::write(root.path().join("dist/nested/output.js"), "output").unwrap();
        assert!(!scan(&mut snapshot, &filter));
    }

    #[test]
    fn root_configuration_overrides_recursive_outputs_and_input_prefixes() {
        let root = tempfile::tempdir().unwrap();
        let filter = filter(root.path(), &["src/**/*.ts"], &["**"]).with_config_files();
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::write(root.path().join("lpm.json"), "{}").unwrap();
        assert!(scan(&mut snapshot, &filter));
        fs::write(root.path().join("package.json"), "{}").unwrap();
        assert!(scan(&mut snapshot, &filter));
        fs::write(root.path().join("output.txt"), "ignored").unwrap();
        assert!(!scan(&mut snapshot, &filter));
    }

    #[test]
    fn literal_paths_bypass_tree_exclusions_and_glob_parsing() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("node_modules")).unwrap();
        let file = root.path().join("node_modules/[input~");
        fs::write(&file, "initial").unwrap();
        let filter = WatchFilter::for_file(&file).unwrap();
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::write(&file, "changed!").unwrap();
        assert!(scan(&mut snapshot, &filter));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_targets_are_checked_without_recursing_symlink_directories() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target.js");
        fs::write(&target, "initial").unwrap();
        symlink(&target, root.path().join("entry.js")).unwrap();
        symlink(outside.path(), root.path().join("linked-directory")).unwrap();
        let filter = filter(root.path(), &[], &[]);
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::write(outside.path().join("unrelated.js"), "ignored").unwrap();
        assert!(!scan(&mut snapshot, &filter));
        fs::write(&target, "changed target").unwrap();
        assert!(scan(&mut snapshot, &filter));
        let other = outside.path().join("other.js");
        fs::write(&other, "different target").unwrap();
        fs::remove_file(root.path().join("entry.js")).unwrap();
        symlink(other, root.path().join("entry.js")).unwrap();
        assert!(scan(&mut snapshot, &filter));
    }

    #[cfg(unix)]
    #[test]
    fn retargeting_a_literal_symlink_to_a_loop_is_detected() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("entry.js");
        let target = root.path().join("target.js");
        fs::write(&target, "initial").unwrap();
        symlink(&target, &file).unwrap();
        let filter = WatchFilter::for_file(&file).unwrap();
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::remove_file(&file).unwrap();
        symlink(&file, &file).unwrap();
        assert!(
            scan(&mut snapshot, &filter),
            "a link metadata change must survive a target metadata error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn literal_symlinks_recover_when_the_target_parent_is_recreated() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("entry.js");
        let target = root.path().join("missing/target.js");
        symlink(&target, &link).unwrap();
        let filter = WatchFilter::for_file(&link).unwrap();
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        fs::create_dir(root.path().join("missing")).unwrap();
        fs::write(&target, "created").unwrap();
        assert!(scan(&mut snapshot, &filter));
    }

    #[test]
    fn inaccessible_subtrees_are_retained_until_a_successful_scan() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input.txt");
        fs::write(&path, "input").unwrap();
        let filter = filter(root.path(), &[], &[]);
        let mut snapshot = Reconciler::default();
        snapshot.baseline(&filter, &|| false);
        snapshot.generation += 1;
        snapshot.preserve_unreadable(
            &filter.root,
            &io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(
            snapshot
                .entries
                .values()
                .all(|entry| entry.generation == snapshot.generation)
        );
        assert!(!scan(&mut snapshot, &filter));
    }

    #[test]
    fn prefix_pruning_retains_ancestors_and_literal_braces() {
        let root = Path::new("/project");
        for pattern in [
            "src/nested/*.ts",
            "src/[ab]/*.ts",
            "src/{literal}/*.ts",
            "src/input.ts",
        ] {
            let filter = filter(root, &[pattern], &[]);
            assert!(!excluded_tree(Path::new(""), &filter));
            assert!(!excluded_tree(Path::new("src"), &filter));
            assert!(excluded_tree(Path::new("unrelated"), &filter));
        }
    }

    #[test]
    fn configuration_changes_during_planning_survive_filter_replacement() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("lpm.json");
        fs::write(&config, "initial configuration").unwrap();
        let handle =
            WatchFilterHandle::new(filter(root.path(), &["old.txt"], &[]).with_config_files());
        let mut recovery = Recovery::new(handle.clone());
        recovery.before_run(&|| false);
        let _planned_configuration = fs::read_to_string(&config).unwrap();
        fs::write(&config, "configuration changed during planning").unwrap();
        handle.replace(filter(root.path(), &["new.txt"], &[]).with_config_files());
        recovery.snapshot.next_scan = None;
        assert!(
            recovery.poll(&|| false),
            "filter replacement swallowed a configuration edit made after planning"
        );
    }

    #[test]
    fn new_filter_baseline_preserves_edits_made_during_execution() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("old.txt");
        let new = root.path().join("new.txt");
        fs::write(&old, "old").unwrap();
        fs::write(&new, "before").unwrap();
        let filter = WatchFilterHandle::new(filter(root.path(), &["old.txt"], &[]));
        let (notifications, receiver) = WatchNotifications::new(filter.clone());
        let state = notifications.state.clone();
        let cycle_filter = filter.clone();
        let new_rules = self::filter(root.path(), &["new.txt"], &[]);
        let mut new_rules = Some(new_rules);
        let (ran_tx, ran_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let watched = new.clone();
        let thread = std::thread::spawn(move || {
            run_watch_loop(
                receiver,
                Box::new(move || {
                    let initial = new_rules.is_some();
                    if let Some(rules) = new_rules.take() {
                        cycle_filter.replace(rules);
                    }
                    ran_tx.send(fs::read_to_string(&watched).unwrap()).unwrap();
                    if initial {
                        release_rx.recv().unwrap();
                    }
                }),
                state,
                Some(filter),
                || stop_rx.try_recv().is_ok(),
            )
        });
        assert_eq!(
            ran_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "before"
        );
        fs::write(&new, "during").unwrap();
        release_tx.send(()).unwrap();
        let rerun = ran_rx.recv_timeout(Duration::from_secs(3));
        stop_tx.send(()).unwrap();
        thread.join().unwrap().unwrap();
        drop(notifications);
        assert_eq!(rerun.as_deref(), Ok("during"));
    }
}
