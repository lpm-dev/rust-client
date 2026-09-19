//! Debounced file watching for finite task runs.

mod reconcile;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

/// Callback invoked initially and after relevant file changes settle.
pub type OnChange = Box<dyn FnMut() + Send>;

/// Compiled input and output rules for a watched directory.
pub struct WatchFilter {
    root: PathBuf,
    inputs: GlobSet,
    outputs: GlobSet,
    output_trees: GlobSet,
    input_prefixes: Vec<PathBuf>,
    all_inputs: bool,
    config_files: bool,
    literal_files: Vec<PathBuf>,
}

impl WatchFilter {
    /// Compile globs once, including output directory roots.
    pub fn new(root: &Path, inputs: &[String], outputs: &[String]) -> Result<Self, String> {
        let mut input_builder = GlobSetBuilder::new();
        let mut input_prefixes = Vec::with_capacity(inputs.len());
        for pattern in inputs {
            let pattern = normalize_watch_glob(pattern);
            input_builder.add(compile_watch_glob(&pattern)?);
            input_prefixes.push(
                pattern
                    .split('/')
                    .take_while(|part| !part.contains(['*', '?', '[']))
                    .collect(),
            );
        }
        let mut output_builder = GlobSetBuilder::new();
        let mut output_trees = GlobSetBuilder::new();
        for pattern in outputs {
            let pattern = normalize_watch_glob(pattern);
            output_builder.add(compile_watch_glob(&pattern)?);
            if pattern == "**" {
                output_trees.add(compile_watch_glob("")?);
            }
            if pattern.ends_with("/**") {
                output_trees.add(compile_watch_glob(pattern.trim_end_matches("/**"))?);
                output_builder.add(compile_watch_glob(pattern.trim_end_matches("/**"))?);
            }
        }
        Ok(Self {
            root: std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()),
            inputs: input_builder.build().map_err(|error| error.to_string())?,
            outputs: output_builder.build().map_err(|error| error.to_string())?,
            output_trees: output_trees.build().map_err(|error| error.to_string())?,
            input_prefixes,
            all_inputs: inputs.is_empty(),
            config_files: false,
            literal_files: Vec::new(),
        })
    }

    fn for_file(file: &Path) -> Result<Self, String> {
        let file = normalize_file_path(file)?;
        let root = file.parent().ok_or("watched file has no parent")?;
        let mut filter = Self::new(root, &[], &[])?;
        let mut current = file;
        for _ in 0..40 {
            if filter.literal_files.contains(&current) {
                break;
            }
            filter.literal_files.push(current.clone());
            let Ok(target) = std::fs::read_link(&current) else {
                break;
            };
            let target = if target.is_absolute() {
                target
            } else {
                current
                    .parent()
                    .ok_or("symlink has no parent")?
                    .join(target)
            };
            let Ok(target) = normalize_file_path(&target) else {
                break;
            };
            current = target;
        }
        if let Ok(target) = std::fs::canonicalize(&filter.literal_files[0])
            && !filter.literal_files.contains(&target)
        {
            filter.literal_files.push(target);
        }
        Ok(filter)
    }

    /// Observe task configuration changes even outside the declared inputs.
    pub fn with_config_files(mut self) -> Self {
        self.config_files = true;
        self
    }

    fn matches(&self, event: &notify::Event) -> bool {
        event.need_rescan()
            || (is_relevant_event(&event.kind)
                && event.paths.iter().any(|path| self.matches_path(path)))
    }

    fn matches_path(&self, path: &Path) -> bool {
        if !self.literal_files.is_empty() {
            return self.literal_files.iter().any(|file| file == path);
        }
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return false;
        };
        if relative.components().any(|part| match part {
            Component::ParentDir => true,
            Component::Normal(name) => name == ".git" || name == "node_modules" || name == ".lpm",
            _ => false,
        }) {
            return false;
        }
        let name = relative.file_name().unwrap_or_default().to_string_lossy();
        if name.ends_with(".swp") || name.ends_with('~') {
            return false;
        }
        if self.config_files
            && (relative == Path::new("package.json") || relative == Path::new("lpm.json"))
        {
            return true;
        }
        !self.outputs.is_match(relative) && (self.all_inputs || self.inputs.is_match(relative))
    }
}

fn normalize_file_path(file: &Path) -> Result<PathBuf, String> {
    let parent = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|error| error.to_string())?;
    let name = file.file_name().ok_or("watched file has no name")?;
    Ok(parent.join(name))
}

fn normalize_watch_glob(pattern: &str) -> String {
    pattern
        .split(std::path::is_separator)
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn compile_watch_glob(pattern: &str) -> Result<Glob, String> {
    glob::Pattern::new(pattern).map_err(|error| error.to_string())?;
    // Task-cache globs treat braces and Unix backslashes as literal characters.
    let mut compatible = String::with_capacity(pattern.len());
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '{' => compatible.push_str("[{]"),
            '}' => compatible.push_str("[}]"),
            '[' => {
                let class_start = compatible.len();
                compatible.push('[');
                if characters.peek() == Some(&'!') {
                    compatible.push(characters.next().unwrap_or('!'));
                }
                if characters.peek() == Some(&']') {
                    compatible.push(characters.next().unwrap_or(']'));
                }
                for part in characters.by_ref() {
                    compatible.push(part);
                    if part == ']' {
                        break;
                    }
                }
                if compatible[class_start..].starts_with("[^") {
                    let class = &compatible[class_start..];
                    let body = &class[1..class.len() - 1];
                    let candidate = body
                        .chars()
                        .find(|character| !matches!(character, '^' | '!' | '-'));
                    let parsed = glob::Pattern::new(class).map_err(|error| error.to_string())?;
                    if let Some(first) = candidate.or_else(|| parsed.matches("-").then_some('-')) {
                        // Duplicate a literal member before '^', preserving all original ranges.
                        compatible.insert(class_start + 1, first);
                    } else {
                        let replacement = match (parsed.matches("^"), parsed.matches("!")) {
                            (true, true) => "{^,!}",
                            (true, false) => "^",
                            (false, true) => "!",
                            (false, false) => "\0",
                        };
                        compatible.truncate(class_start);
                        compatible.push_str(replacement);
                    }
                }
            }
            _ => compatible.push(character),
        }
    }
    GlobBuilder::new(&compatible)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .map_err(|error| error.to_string())
}

/// Replaceable rules shared by the task callback and notification thread.
#[derive(Clone)]
pub struct WatchFilterHandle(Arc<RwLock<WatchFilter>>);

impl WatchFilterHandle {
    /// Create a shared filter.
    pub fn new(filter: WatchFilter) -> Self {
        Self(Arc::new(RwLock::new(filter)))
    }

    /// Replace a complete, validated filter before executing the next task.
    pub fn replace(&self, filter: WatchFilter) {
        *self.0.write().unwrap_or_else(|error| error.into_inner()) = filter;
    }

    fn matches(&self, event: &notify::Event) -> bool {
        self.0
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .matches(event)
    }
}

#[derive(Default)]
struct PendingChange {
    last_relevant: Option<Instant>,
    error: Option<String>,
}

#[derive(Clone, Default)]
struct WatchState(Arc<Mutex<PendingChange>>);

impl WatchState {
    fn take_ready(&self, now: Instant) -> Result<bool, String> {
        let mut pending = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(error) = pending.error.take() {
            return Err(error);
        }
        if pending
            .last_relevant
            .is_some_and(|last| now.saturating_duration_since(last) >= Duration::from_millis(200))
        {
            pending.last_relevant = None;
            return Ok(true);
        }
        Ok(false)
    }

    fn start_initial_run(&self) -> Result<(), String> {
        let mut pending = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(error) = pending.error.take() {
            return Err(error);
        }
        Ok(())
    }
}

struct WatchNotifications {
    state: WatchState,
    filter: WatchFilterHandle,
    wake: mpsc::SyncSender<()>,
}

impl WatchNotifications {
    fn new(filter: WatchFilterHandle) -> (Self, mpsc::Receiver<()>) {
        let (wake, receiver) = mpsc::sync_channel(1);
        (
            Self {
                state: WatchState::default(),
                filter,
                wake,
            },
            receiver,
        )
    }

    fn submit(&self, event: notify::Result<notify::Event>) {
        let error = match event {
            Ok(event) if self.filter.matches(&event) => None,
            Ok(_) => return,
            Err(error) => {
                let mut message = error.to_string();
                message.truncate(message.floor_char_boundary(4096));
                Some(message)
            }
        };
        let mut pending = self
            .state
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(error) = error {
            if pending.error.is_none() {
                pending.error = Some(error);
            }
        } else {
            pending.last_relevant = Some(Instant::now());
        }
        drop(pending);
        let _ = self.wake.try_send(());
    }
}

/// Watch inputs and rerun after 200 ms of quiet. Each callback runs to completion.
pub fn watch_and_run(
    watch_dir: &Path,
    on_change: OnChange,
    input_globs: &[String],
    shutdown: Option<mpsc::Receiver<()>>,
) -> Result<(), String> {
    let filter = WatchFilterHandle::new(WatchFilter::new(watch_dir, input_globs, &[])?);
    watch_and_run_with_filter(watch_dir, on_change, filter, shutdown)
}

/// Watch with rules that the callback can replace between runs.
pub fn watch_and_run_with_filter(
    watch_dir: &Path,
    on_change: OnChange,
    filter: WatchFilterHandle,
    shutdown: Option<mpsc::Receiver<()>>,
) -> Result<(), String> {
    watch_and_run_until(watch_dir, on_change, filter, move || {
        shutdown
            .as_ref()
            .is_some_and(|receiver| receiver.try_recv().is_ok())
    })
}

/// Keep observing changes until the caller requests a stop.
pub fn watch_and_run_until(
    watch_dir: &Path,
    on_change: OnChange,
    filter: WatchFilterHandle,
    should_stop: impl Fn() -> bool,
) -> Result<(), String> {
    let watch_dir = std::fs::canonicalize(watch_dir).map_err(|error| error.to_string())?;
    let (notifications, receiver) = WatchNotifications::new(filter.clone());
    let state = notifications.state.clone();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |event| notifications.submit(event))
            .map_err(|error| format!("failed to create file watcher: {error}"))?;
    watcher
        .watch(&watch_dir, RecursiveMode::Recursive)
        .map_err(|error| format!("failed to watch directory: {error}"))?;
    run_watch_loop(
        receiver,
        on_change,
        state,
        cfg!(target_os = "macos").then_some(filter),
        should_stop,
    )
}

/// Watch a literal entrypoint and refresh its symlink targets before each run.
pub fn watch_file_and_run(
    file: &Path,
    mut on_change: OnChange,
    should_stop: impl Fn() -> bool,
) -> Result<(), String> {
    let file = normalize_file_path(file)?;
    let filter = WatchFilterHandle::new(WatchFilter::for_file(&file)?);
    let (notifications, receiver) = WatchNotifications::new(filter.clone());
    let state = notifications.state.clone();
    let errors = state.clone();
    let recovery_filter = filter.clone();
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |event| notifications.submit(event))
            .map_err(|error| format!("failed to create file watcher: {error}"))?;
    let mut roots = HashSet::new();
    refresh_file_watch(&file, &mut watcher, &mut roots, &filter)?;
    run_watch_loop(
        receiver,
        Box::new(move || {
            if let Err(error) = refresh_file_watch(&file, &mut watcher, &mut roots, &filter) {
                errors
                    .0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .error = Some(error);
                return;
            }
            on_change();
        }),
        state,
        cfg!(target_os = "macos").then_some(recovery_filter),
        should_stop,
    )
}

fn refresh_file_watch(
    file: &Path,
    watcher: &mut RecommendedWatcher,
    roots: &mut HashSet<PathBuf>,
    filter: &WatchFilterHandle,
) -> Result<(), String> {
    let next_filter = WatchFilter::for_file(file)?;
    let next_roots: HashSet<_> = next_filter
        .literal_files
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    for root in next_roots.difference(roots) {
        watcher
            .watch(root, RecursiveMode::NonRecursive)
            .map_err(|error| error.to_string())?;
    }
    filter.replace(next_filter);
    for root in roots.difference(&next_roots) {
        watcher.unwatch(root).map_err(|error| error.to_string())?;
    }
    *roots = next_roots;
    Ok(())
}

fn run_watch_loop(
    receiver: mpsc::Receiver<()>,
    mut on_change: OnChange,
    state: WatchState,
    recovery: Option<WatchFilterHandle>,
    should_stop: impl Fn() -> bool,
) -> Result<(), String> {
    let stopped = std::cell::Cell::new(false);
    let should_stop = || {
        let stop = stopped.get() || should_stop();
        stopped.set(stop);
        stop
    };
    state.start_initial_run()?;
    if should_stop() {
        return Ok(());
    }
    let mut recovery = recovery.map(reconcile::Recovery::new);
    if let Some(recovery) = &mut recovery {
        recovery.before_run(&should_stop);
    }
    if should_stop() {
        return Ok(());
    }
    on_change();
    loop {
        if should_stop() {
            return Ok(());
        }
        if let Some(recovery) = &mut recovery
            && recovery.poll(&should_stop)
        {
            state
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .last_relevant = Some(Instant::now());
        }
        // Clear only immediately before execution, preserving edits made while a task runs.
        if state.take_ready(Instant::now())? {
            if let Some(recovery) = &mut recovery {
                recovery.before_run(&should_stop);
            }
            if should_stop() {
                return Ok(());
            }
            on_change();
            continue;
        }
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("file watcher disconnected".into());
            }
        }
    }
}

fn is_relevant_event(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
    )
}

/// Match a path against input globs, relative to the project directory.
pub fn matches_input_globs(path: &Path, project_dir: &Path, globs: &[String]) -> bool {
    let relative = path.strip_prefix(project_dir).unwrap_or(path);
    globs.iter().any(|pattern| {
        Glob::new(pattern).is_ok_and(|glob| glob.compile_matcher().is_match(relative))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn matches_watch_event(event: &notify::Event, root: &Path, inputs: &[String]) -> bool {
        WatchFilter::new(root, inputs, &[]).unwrap().matches(event)
    }

    #[test]
    fn file_outputs_do_not_exclude_parent_directory_changes() {
        let filter =
            WatchFilter::new(Path::new("/project"), &[], &["**/generated.txt".into()]).unwrap();
        let event = notify::Event::new(EventKind::Create(notify::event::CreateKind::Folder))
            .add_path(Path::new("/project/src/new").to_path_buf());
        assert!(filter.matches(&event));
    }

    #[test]
    fn replaced_watch_rules_exclude_old_inputs_and_new_outputs() {
        let root = Path::new("/project");
        let filter = WatchFilterHandle::new(
            WatchFilter::new(root, &["old/**".into()], &[])
                .unwrap()
                .with_config_files(),
        );
        let (notifications, receiver) = WatchNotifications::new(filter.clone());
        filter.replace(
            WatchFilter::new(root, &["new/**".into()], &["new/generated/**".into()])
                .unwrap()
                .with_config_files(),
        );
        for path in ["old/input.txt", "new/generated", "new/generated/output.txt"] {
            notifications.submit(Ok(notify::Event::new(EventKind::Modify(
                notify::event::ModifyKind::Any,
            ))
            .add_path(root.join(path))));
        }
        assert!(receiver.try_recv().is_err());
        for path in ["new/input.txt", "lpm.json", "package.json"] {
            notifications.submit(Ok(notify::Event::new(EventKind::Modify(
                notify::event::ModifyKind::Any,
            ))
            .add_path(root.join(path))));
            assert!(receiver.try_recv().is_ok(), "{path}");
        }
    }

    #[test]
    fn literal_watch_rules_exclude_siblings_but_accept_rescans() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        std::fs::create_dir(root.join("scripts")).unwrap();
        for entry in [
            "scripts/../entry.js",
            "scripts/[entry].js",
            "scripts/unclosed[.js",
        ] {
            let filter = WatchFilter::for_file(&root.join(entry)).unwrap();
            let event = |path| {
                notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any)).add_path(path)
            };
            assert!(
                !filter.matches(&event(root.join("scripts/e.js"))),
                "{entry}"
            );
            assert!(
                filter.matches(&event(normalize_file_path(&root.join(entry)).unwrap())),
                "{entry}"
            );
            assert!(filter.matches(
                &notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan)
            ));
        }
    }

    #[test]
    fn subtree_output_roots_are_excluded_for_untyped_and_rename_events() {
        let filter =
            WatchFilter::new(Path::new("/project"), &[], &["artifacts/*/**".into()]).unwrap();
        for kind in [
            EventKind::Create(notify::event::CreateKind::Any),
            EventKind::Remove(notify::event::RemoveKind::Any),
            EventKind::Modify(notify::event::ModifyKind::Name(
                notify::event::RenameMode::Any,
            )),
        ] {
            let event = notify::Event::new(kind)
                .add_path(Path::new("/project/artifacts/job-1").to_path_buf());
            assert!(!filter.matches(&event), "{kind:?}");
        }
        let parent = notify::Event::new(EventKind::Create(notify::event::CreateKind::Folder))
            .add_path(Path::new("/project/artifacts").to_path_buf());
        assert!(filter.matches(&parent));
    }

    #[test]
    fn rescan_notifications_trigger_a_bounded_rebuild_without_paths() {
        let filter = WatchFilterHandle::new(
            WatchFilter::new(Path::new("/project"), &["src/**".into()], &[]).unwrap(),
        );
        let (notifications, receiver) = WatchNotifications::new(filter);
        for _ in 0..10_000 {
            notifications.submit(Ok(
                notify::Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan)
            ));
        }
        assert_eq!(receiver.try_iter().count(), 1);
        assert!(
            notifications
                .state
                .take_ready(Instant::now() + Duration::from_secs(1))
                .unwrap()
        );
        assert!(
            !notifications
                .state
                .take_ready(Instant::now() + Duration::from_secs(1))
                .unwrap()
        );
    }

    #[test]
    fn single_star_inputs_do_not_match_nested_directories() {
        let filter = WatchFilter::new(Path::new("/project"), &["src/*.ts".into()], &[]).unwrap();
        for (path, expected) in [("src/main.ts", true), ("src/nested/main.ts", false)] {
            let event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any))
                .add_path(Path::new("/project").join(path));
            assert_eq!(filter.matches(&event), expected, "{path}");
        }
    }

    #[test]
    fn watch_globs_match_task_cache_path_syntax() {
        for (pattern, path, expected) in [
            ("./src/*.ts", "src/main.ts", true),
            ("generated/{a,b}/**", "generated/a/file.txt", false),
            ("generated/{a,b}/**", "generated/{a,b}/file.txt", true),
            ("src/[[]name].ts", "src/[name].ts", true),
        ] {
            let filter = WatchFilter::new(Path::new("/project"), &[pattern.into()], &[]).unwrap();
            let event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any))
                .add_path(Path::new("/project").join(path));
            assert_eq!(filter.matches(&event), expected, "{pattern}: {path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_paths_preserve_inputs_and_exclude_output_roots() {
        let root = Path::new(r"C:\project");
        let filter = WatchFilter::new(root, &[r"src\*.ts".into()], &[r"dist\**".into()]).unwrap();
        for (path, expected) in [
            (r"C:\project\src\main.ts", true),
            (r"C:\project\src\deep\main.ts", false),
            (r"C:\project\dist", false),
            (r"C:\project\node_modules", false),
        ] {
            let event = notify::Event::new(EventKind::Create(notify::event::CreateKind::Any))
                .add_path(PathBuf::from(path));
            assert_eq!(filter.matches(&event), expected, "{path}");
        }
    }

    #[test]
    fn notification_errors_are_bounded_and_preserve_valid_utf8() {
        let filter =
            WatchFilterHandle::new(WatchFilter::new(Path::new("/project"), &[], &[]).unwrap());
        let (notifications, receiver) = WatchNotifications::new(filter);
        for _ in 0..100 {
            notifications.submit(Err(notify::Error::generic(&"é".repeat(10_000))));
        }
        assert_eq!(receiver.try_iter().count(), 1);
        let error = notifications.state.take_ready(Instant::now()).unwrap_err();
        assert!(error.len() <= 4096);
        assert!(!error.is_empty());
    }

    #[test]
    fn character_class_carets_remain_literal_like_task_cache_globs() {
        for (pattern, path, expected) in [
            ("src/[^a].ts", "src/a.ts", true),
            ("src/[^a].ts", "src/b.ts", false),
            ("src/[^].ts", "src/^.ts", true),
            ("src/[!^].ts", "src/a.ts", true),
        ] {
            let filter = WatchFilter::new(Path::new("/project"), &[pattern.into()], &[]).unwrap();
            let event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any))
                .add_path(Path::new("/project").join(path));
            assert_eq!(filter.matches(&event), expected, "{pattern}: {path}");
        }
    }

    #[test]
    fn repeated_recursive_output_globs_exclude_the_same_root() {
        let filter = WatchFilter::new(Path::new("/project"), &[], &["dist/**/**".into()]).unwrap();
        let event = notify::Event::new(EventKind::Remove(notify::event::RemoveKind::Any))
            .add_path(Path::new("/project/dist").to_path_buf());
        assert!(!filter.matches(&event));
    }

    #[test]
    fn metadata_changes_still_trigger_tasks() {
        let filter = WatchFilter::new(Path::new("/project"), &[], &[]).unwrap();
        let event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Metadata(
            notify::event::MetadataKind::Permissions,
        )))
        .add_path(Path::new("/project/src/script.sh").to_path_buf());
        assert!(filter.matches(&event));
    }

    #[test]
    fn mixed_paths_must_have_one_nonignored_matching_path() {
        let event = notify::Event::new(EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path(PathBuf::from("/project/node_modules/tool/index.ts"))
            .add_path(PathBuf::from("/project/docs/readme.txt"));
        assert!(!matches_watch_event(
            &event,
            Path::new("/project"),
            &["**/*.ts".into()]
        ));
    }

    #[test]
    fn ignored_directory_roots_do_not_trigger_watch() {
        for name in [".git", "node_modules", ".lpm"] {
            let event = notify::Event::new(EventKind::Create(notify::event::CreateKind::Folder))
                .add_path(Path::new("/project").join(name));
            assert!(
                !matches_watch_event(&event, Path::new("/project"), &[]),
                "{name}"
            );
        }
    }

    #[test]
    fn missed_native_notifications_still_run_changed_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.txt");
        std::fs::write(&input, "initial").unwrap();
        let filter = WatchFilterHandle::new(
            WatchFilter::new(directory.path(), &["input.txt".into()], &[]).unwrap(),
        );
        let (notifications, receiver) = WatchNotifications::new(filter.clone());
        let state = notifications.state.clone();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (ran_tx, ran_rx) = mpsc::channel();
        let watched_input = input.clone();
        let watcher = std::thread::spawn(move || {
            run_watch_loop(
                receiver,
                Box::new(move || {
                    ran_tx
                        .send(std::fs::read_to_string(&watched_input).unwrap())
                        .unwrap();
                }),
                state,
                Some(filter),
                || shutdown_rx.try_recv().is_ok(),
            )
        });
        assert_eq!(
            ran_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "initial"
        );
        std::fs::write(&input, "changed input").unwrap();
        let changed = ran_rx.recv_timeout(Duration::from_secs(3));
        let _ = shutdown_tx.send(());
        watcher.join().unwrap().unwrap();
        drop(notifications);
        assert_eq!(
            changed.as_deref(),
            Ok("changed input"),
            "an edit with no native callback was lost"
        );
    }

    #[test]
    fn startup_changes_are_retained_for_a_followup_cycle() {
        let filter =
            WatchFilterHandle::new(WatchFilter::new(Path::new("/project"), &[], &[]).unwrap());
        let (notifications, receiver) = WatchNotifications::new(filter);
        notifications.submit(Ok(notify::Event::new(EventKind::Modify(
            notify::event::ModifyKind::Any,
        ))
        .add_path(Path::new("/project/lpm.json").to_path_buf())));
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (ran_tx, ran_rx) = mpsc::channel();
        let watcher = std::thread::spawn(move || {
            run_watch_loop(
                receiver,
                Box::new(move || {
                    let _ = ran_tx.send(());
                }),
                notifications.state,
                None,
                || shutdown_rx.try_recv().is_ok(),
            )
        });
        ran_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = ran_rx.recv_timeout(Duration::from_millis(700));
        let _ = shutdown_tx.send(());
        watcher.join().unwrap().unwrap();
        assert!(
            second.is_ok(),
            "startup change was lost before the initial callback"
        );
    }

    #[test]
    fn watcher_errors_reach_the_waiting_loop() {
        let filter =
            WatchFilterHandle::new(WatchFilter::new(Path::new("/project"), &[], &[]).unwrap());
        let (notifications, _) = WatchNotifications::new(filter);
        notifications.submit(Err(notify::Error::generic("fixture watcher failed")));
        assert!(
            notifications
                .state
                .take_ready(Instant::now())
                .unwrap_err()
                .contains("fixture watcher failed")
        );
    }

    #[test]
    fn ignored_event_traffic_cannot_starve_a_pending_rebuild() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let filter =
            WatchFilterHandle::new(WatchFilter::new(Path::new("/project"), &[], &[]).unwrap());
        let (notifications, rx) = WatchNotifications::new(filter);
        let state = notifications.state.clone();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (ran_tx, ran_rx) = mpsc::channel();
        let watcher = std::thread::spawn(move || {
            run_watch_loop(
                rx,
                Box::new(move || {
                    let _ = ran_tx.send(());
                }),
                state,
                None,
                || shutdown_rx.try_recv().is_ok(),
            )
        });
        ran_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        notifications.submit(Ok(notify::Event::new(EventKind::Modify(
            notify::event::ModifyKind::Any,
        ))
        .add_path(PathBuf::from("/project/src/file.ts"))));
        let stop = Arc::new(AtomicBool::new(false));
        let producer_stop = Arc::clone(&stop);
        let producer = std::thread::spawn(move || {
            while !producer_stop.load(Ordering::Relaxed) {
                notifications.submit(Ok(notify::Event::new(EventKind::Create(
                    notify::event::CreateKind::File,
                ))
                .add_path(PathBuf::from("/project/.lpm/log"))));
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let result = ran_rx.recv_timeout(Duration::from_millis(700));
        stop.store(true, Ordering::Relaxed);
        let _ = shutdown_tx.send(());
        producer.join().unwrap();
        let _ = watcher.join().unwrap();
        assert!(
            result.is_ok(),
            "ignored events prevented the pending rebuild"
        );
    }

    #[test]
    fn relevant_event_filtering() {
        assert!(is_relevant_event(&EventKind::Modify(
            notify::event::ModifyKind::Data(notify::event::DataChange::Content)
        )));
        assert!(is_relevant_event(&EventKind::Create(
            notify::event::CreateKind::File
        )));
        assert!(is_relevant_event(&EventKind::Remove(
            notify::event::RemoveKind::File
        )));
        assert!(!is_relevant_event(&EventKind::Access(
            notify::event::AccessKind::Read
        )));
    }

    #[test]
    fn glob_matching() {
        let project = PathBuf::from("/project");

        assert!(matches_input_globs(
            &PathBuf::from("/project/src/index.js"),
            &project,
            &["src/**".into()]
        ));

        assert!(!matches_input_globs(
            &PathBuf::from("/project/dist/output.js"),
            &project,
            &["src/**".into()]
        ));

        assert!(matches_input_globs(
            &PathBuf::from("/project/package.json"),
            &project,
            &["package.json".into()]
        ));
    }

    #[test]
    fn glob_matching_node_modules_excluded() {
        let project = PathBuf::from("/project");

        // node_modules shouldn't match src/**
        assert!(!matches_input_globs(
            &PathBuf::from("/project/node_modules/react/index.js"),
            &project,
            &["src/**".into()]
        ));
    }

    // -- watch filters by input globs --

    #[test]
    fn glob_matching_filters_non_matching_files() {
        let project = PathBuf::from("/project");

        // src/main.rs matches "src/**"
        assert!(matches_input_globs(
            &PathBuf::from("/project/src/main.rs"),
            &project,
            &["src/**".into()]
        ));

        // README.md does NOT match "src/**"
        assert!(!matches_input_globs(
            &PathBuf::from("/project/README.md"),
            &project,
            &["src/**".into()]
        ));
    }

    // -- shutdown mechanism --

    #[test]
    fn watch_shuts_down_on_signal() {
        let dir = tempfile::tempdir().unwrap();
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();

        let watch_dir = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            watch_and_run(&watch_dir, Box::new(|| {}), &[], Some(shutdown_rx))
        });

        // Give the watcher a moment to start, then signal shutdown
        std::thread::sleep(Duration::from_millis(100));
        shutdown_tx.send(()).unwrap();

        let result = handle.join().unwrap();
        assert!(result.is_ok(), "watch_and_run should return Ok on shutdown");
    }

    // -- Input glob filtering is comprehensive --

    #[test]
    fn glob_matching_multiple_patterns() {
        let project = PathBuf::from("/project");
        let globs = vec!["src/**".into(), "lib/**".into(), "package.json".into()];

        // Matches src/**
        assert!(matches_input_globs(
            &PathBuf::from("/project/src/utils/helper.ts"),
            &project,
            &globs
        ));
        // Matches lib/**
        assert!(matches_input_globs(
            &PathBuf::from("/project/lib/core.js"),
            &project,
            &globs
        ));
        // Matches package.json
        assert!(matches_input_globs(
            &PathBuf::from("/project/package.json"),
            &project,
            &globs
        ));
        // Does NOT match
        assert!(!matches_input_globs(
            &PathBuf::from("/project/dist/output.js"),
            &project,
            &globs
        ));
        assert!(!matches_input_globs(
            &PathBuf::from("/project/README.md"),
            &project,
            &globs
        ));
    }

    #[test]
    fn glob_matching_empty_globs_matches_nothing() {
        let project = PathBuf::from("/project");
        // Empty globs = match nothing (the watch loop short-circuits to "match all"
        // when input_globs is empty, but the matcher itself returns false)
        assert!(!matches_input_globs(
            &PathBuf::from("/project/src/index.js"),
            &project,
            &[]
        ));
    }
}
