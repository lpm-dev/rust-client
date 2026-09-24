use std::{
    collections::BTreeMap,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use serde::Serialize;
use tracing::{
    Event, Id, Subscriber,
    field::{Field, Visit},
    span::Attributes,
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

pub(super) struct ExportGuard;

impl Drop for ExportGuard {
    fn drop(&mut self) {
        finish("incomplete");
    }
}

pub(super) const TARGET: &str = "lpm_install_timeline";
const RECORD_LIMIT: usize = 50_000;
static ACTIVE: OnceLock<Arc<Capture>> = OnceLock::new();

#[derive(Clone)]
pub(super) struct TimelineLayer(Arc<Capture>);

struct Capture {
    origin: Instant,
    directory: PathBuf,
    state: Mutex<State>,
}

struct State {
    records: Vec<Record>,
    next_id: u64,
    open_spans: usize,
    dropped_records: usize,
    dropped_correlations: usize,
    limit: usize,
    frozen: bool,
}

#[derive(Clone, Copy)]
struct SpanIdentity(u64);

#[derive(Serialize)]
struct Record {
    at_us: u64,
    kind: &'static str,
    id: Option<u64>,
    parent: Option<u64>,
    name: &'static str,
    fields: BTreeMap<&'static str, u64>,
}

#[derive(Default)]
struct NumericFields(BTreeMap<&'static str, u64>);

impl Visit for NumericFields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if matches!(
            field.name(),
            "sequence"
                | "attempt"
                | "bytes"
                | "status"
                | "success"
                | "cached"
                | "blocking"
                | "weight"
        ) {
            self.0.insert(field.name(), value);
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_u64(field, u64::from(value));
    }

    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

#[derive(Serialize)]
struct Artifact {
    schema_version: u32,
    origin: &'static str,
    outcome: &'static str,
    cutoff_us: u64,
    open_spans: usize,
    dropped_records: usize,
    dropped_correlations: usize,
    record_limit: usize,
    records: Vec<Record>,
}

impl Capture {
    fn new(directory: PathBuf, limit: usize) -> Self {
        Self {
            origin: Instant::now(),
            directory,
            state: Mutex::new(State {
                records: Vec::new(),
                next_id: 1,
                open_spans: 0,
                dropped_records: 0,
                dropped_correlations: 0,
                limit,
                frozen: false,
            }),
        }
    }

    fn elapsed_us(&self) -> u64 {
        self.origin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }

    fn freeze(&self, outcome: &'static str) -> Option<Artifact> {
        self.freeze_before_lock(outcome, || {})
    }

    fn freeze_before_lock(
        &self,
        outcome: &'static str,
        before_lock: impl FnOnce(),
    ) -> Option<Artifact> {
        before_lock();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cutoff_us = self.elapsed_us();
        if state.frozen {
            return None;
        }
        state.frozen = true;
        Some(Artifact {
            schema_version: 1,
            origin: "subscriber_initialized",
            outcome,
            cutoff_us,
            open_spans: state.open_spans,
            dropped_records: state.dropped_records,
            dropped_correlations: state.dropped_correlations,
            record_limit: state.limit,
            records: std::mem::take(&mut state.records),
        })
    }

    fn export(&self, artifact: &Artifact) -> std::io::Result<()> {
        self.export_with(|writer| {
            serde_json::to_writer(writer, artifact).map_err(std::io::Error::from)
        })
    }

    fn export_with(
        &self,
        write: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.directory)?;
        let mut file = tempfile::Builder::new()
            .prefix(".lpm-install-timeline-")
            .tempfile_in(&self.directory)?;
        {
            let mut writer = BufWriter::new(file.as_file_mut());
            write(&mut writer)?;
            writer.flush()?;
        }
        for attempt in 0..100 {
            let path = self
                .directory
                .join(format!("install-{}-{attempt}.json", std::process::id()));
            match file.persist_noclobber(path) {
                Ok(_) => return Ok(()),
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    file = error.file;
                }
                Err(error) => return Err(error.error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "timeline output slots exhausted",
        ))
    }
}

impl State {
    fn push(&mut self, record: Record) {
        if self.records.len() < self.limit {
            self.records.push(record);
        } else {
            self.dropped_records += 1;
        }
    }
}

fn recorded_parent<S>(id: Option<&Id>, ctx: &Context<'_, S>) -> Option<u64>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let parent = match id {
        Some(id) => ctx.span(id),
        None => ctx.lookup_current(),
    }?;
    for ancestor in parent.scope() {
        if let Some(identity) = ancestor.extensions().get::<SpanIdentity>() {
            return Some(identity.0);
        }
    }
    None
}

impl<S> Layer<S> for TimelineLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let at_us = self.0.elapsed_us();
        let parent = if attrs.is_root() {
            None
        } else {
            recorded_parent(attrs.parent(), &ctx)
        };
        let mut fields = NumericFields::default();
        attrs.record(&mut fields);
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.frozen {
            return;
        }
        let number = state.next_id;
        state.next_id += 1;
        state.open_spans += 1;
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanIdentity(number));
        }
        state.push(Record {
            at_us,
            kind: "span_open",
            id: Some(number),
            parent,
            name: attrs.metadata().name(),
            fields: fields.0,
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let at_us = self.0.elapsed_us();
        let parent = if event.is_root() {
            None
        } else {
            recorded_parent(event.parent(), &ctx)
        };
        let mut fields = NumericFields::default();
        event.record(&mut fields);
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.frozen {
            return;
        }
        if event.metadata().name() == "metadata_correlation_dropped" {
            state.dropped_correlations += 1;
            return;
        }
        state.push(Record {
            at_us,
            kind: "event",
            id: None,
            parent,
            name: event.metadata().name(),
            fields: fields.0,
        });
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let at_us = self.0.elapsed_us();
        let identity = ctx
            .span(&id)
            .and_then(|span| span.extensions().get::<SpanIdentity>().copied());
        let Some(identity) = identity else {
            return;
        };
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.frozen {
            return;
        }
        state.open_spans = state.open_spans.saturating_sub(1);
        state.push(Record {
            at_us,
            kind: "span_close",
            id: Some(identity.0),
            parent: None,
            name: "span_closed",
            fields: BTreeMap::new(),
        });
    }
}

pub(super) fn start(command: &super::args::Commands) -> Option<TimelineLayer> {
    if !matches!(
        command,
        super::args::Commands::Install(_) | super::args::Commands::Ci(_)
    ) {
        return None;
    }
    let directory = std::env::var_os("LPM_INSTALL_TIMELINE_DIR").filter(|s| !s.is_empty())?;
    let capture = Arc::new(Capture::new(PathBuf::from(directory), RECORD_LIMIT));
    ACTIVE.set(Arc::clone(&capture)).ok()?;
    Some(TimelineLayer(capture))
}

pub(super) fn finish(outcome: &'static str) {
    if let Some(capture) = ACTIVE.get()
        && let Some(artifact) = capture.freeze(outcome)
        && capture.export(&artifact).is_err()
    {
        eprintln!("warning: could not write the install timeline artifact");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::{filter::filter_fn, layer::SubscriberExt as _};

    fn capture(limit: usize) -> Arc<Capture> {
        Arc::new(Capture::new(PathBuf::new(), limit))
    }

    #[test]
    fn streaming_read_activity_leaves_room_for_finalization() {
        use flate2::{Compression, write::GzEncoder};
        let payload = vec![0x5a; 16 * 1024 * 1024];
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::none()));
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "package/payload", payload.as_slice())
            .unwrap();
        let archive = tar.into_inner().unwrap().finish().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let capture = capture(2400);
        let layer = TimelineLayer(Arc::clone(&capture))
            .with_filter(filter_fn(|metadata| metadata.target() == TARGET));
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            lpm_extractor::extract_tarball_from_reader_streaming_digests(
                archive.as_slice(),
                directory.path(),
            )
            .unwrap();
            tracing::event!(name: "finalization_complete", target: "lpm_install_timeline", tracing::Level::TRACE, {});
        });
        let artifact = capture.freeze("success").unwrap();
        assert_eq!(artifact.dropped_records, 0);
        assert_eq!(
            artifact.records.last().unwrap().name,
            "finalization_complete"
        );
    }

    #[test]
    fn freeze_cutoff_covers_recording_before_lock_acquisition() {
        let capture = capture(10);
        let artifact = capture
            .freeze_before_lock("success", || {
                let before = capture.elapsed_us();
                while capture.elapsed_us() <= before {
                    std::hint::spin_loop();
                }
                capture.state.lock().unwrap().push(Record {
                    at_us: capture.elapsed_us(),
                    kind: "event",
                    id: None,
                    parent: None,
                    name: "concurrent_event",
                    fields: BTreeMap::new(),
                });
            })
            .unwrap();
        assert!(
            artifact
                .records
                .iter()
                .all(|record| record.at_us <= artifact.cutoff_us)
        );
    }

    #[test]
    fn explicit_filtered_parent_never_becomes_an_unrelated_current_span() {
        let capture = capture(20);
        let layer = TimelineLayer(Arc::clone(&capture))
            .with_filter(filter_fn(|meta| meta.target() == TARGET));
        let ordinary = tracing_subscriber::fmt::layer()
            .with_writer(std::io::sink)
            .with_filter(filter_fn(|meta| meta.target() != TARGET));
        let subscriber = tracing_subscriber::registry().with(ordinary).with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let ordinary = tracing::info_span!(target: "ordinary", "ordinary_parent");
            let diagnostic = tracing::trace_span!(target: "lpm_install_timeline", "unrelated");
            let _entered = diagnostic.enter();
            tracing::event!(name: "explicit", target: "lpm_install_timeline", parent: &ordinary, tracing::Level::TRACE, {});
        });
        let artifact = capture.freeze("success").unwrap();
        let explicit = artifact
            .records
            .iter()
            .find(|r| r.name == "explicit")
            .unwrap();
        assert!(explicit.parent.is_none());
    }

    #[test]
    fn record_limit_and_freeze_bound_late_background_events() {
        let capture = capture(2);
        let subscriber = tracing_subscriber::registry().with(TimelineLayer(Arc::clone(&capture)));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::trace_span!(target: "lpm_install_timeline", "work");
            let _entered = span.enter();
            tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            let artifact = capture.freeze("success").unwrap();
            assert_eq!(artifact.records.len(), 2);
            assert_eq!(artifact.dropped_records, 1);
            assert_eq!(artifact.open_spans, 1);
            tracing::event!(name: "late", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            assert!(capture.freeze("success").is_none());
        });
        assert!(capture.state.lock().unwrap().records.is_empty());
    }

    #[test]
    fn skipped_correlations_remain_counted_after_the_record_budget_is_full() {
        let capture = capture(0);
        let subscriber = tracing_subscriber::registry().with(TimelineLayer(Arc::clone(&capture)));
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..3 {
                tracing::event!(name: "metadata_correlation_dropped", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            }
        });
        let artifact = capture.freeze("success").unwrap();
        assert_eq!(artifact.dropped_correlations, 3);
        assert!(artifact.records.is_empty());
    }

    #[test]
    fn field_allowlist_excludes_strings_and_arbitrary_numeric_fields() {
        let capture = capture(10);
        let subscriber = tracing_subscriber::registry().with(TimelineLayer(Arc::clone(&capture)));
        tracing::subscriber::with_default(subscriber, || {
            tracing::event!(name: "safe", target: "lpm_install_timeline", tracing::Level::TRACE,
                bytes = 12u64, status = 200u64, success = true, token = "secret", path = "/private", unknown = 123u64);
        });
        let artifact = capture.freeze("success").unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        for forbidden in ["secret", "/private", "token", "unknown"] {
            assert!(!json.contains(forbidden));
        }
        assert_eq!(artifact.records[0].fields.len(), 3);
    }

    #[test]
    fn timeline_filter_remains_independent_of_ordinary_log_level() {
        for level in ["off", "lpm=warn", "trace"] {
            let capture = capture(10);
            let ordinary = tracing_subscriber::fmt::layer()
                .with_writer(std::io::sink)
                .with_filter(tracing_subscriber::EnvFilter::new(level))
                .with_filter(filter_fn(|meta| meta.target() != TARGET));
            let diagnostic = TimelineLayer(Arc::clone(&capture))
                .with_filter(filter_fn(|meta| meta.target() == TARGET));
            let subscriber = tracing_subscriber::registry()
                .with(ordinary)
                .with(diagnostic);
            tracing::subscriber::with_default(subscriber, || {
                tracing::event!(name: "captured", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            });
            assert_eq!(capture.freeze("success").unwrap().records.len(), 1);
        }
    }

    #[test]
    fn disabled_diagnostic_fields_are_not_evaluated() {
        let subscriber =
            tracing_subscriber::registry().with(tracing_subscriber::filter::LevelFilter::OFF);
        let evaluated = std::cell::Cell::new(false);
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(target: "lpm_install_timeline", bytes = { evaluated.set(true); 1u64 });
        });
        assert!(!evaluated.get());
    }

    #[test]
    fn failed_export_leaves_no_partial_artifact_or_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let capture = Capture::new(dir.path().to_owned(), 2);
        let result = capture.export_with(|writer| {
            writer.write_all(b"{partial")?;
            writer.flush()?;
            Err(std::io::Error::other("injected export failure"))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn export_is_private_and_does_not_follow_a_preplanted_symlink() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(other.path(), b"unchanged").unwrap();
        let first = dir
            .path()
            .join(format!("install-{}-0.json", std::process::id()));
        symlink(other.path(), &first).unwrap();
        let capture = Capture::new(dir.path().to_owned(), 2);
        capture.export(&capture.freeze("success").unwrap()).unwrap();
        assert_eq!(std::fs::read(other.path()).unwrap(), b"unchanged");
        let next = dir
            .path()
            .join(format!("install-{}-1.json", std::process::id()));
        assert_eq!(
            std::fs::metadata(next).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn export_never_overwrites_an_existing_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let capture = Capture::new(dir.path().to_owned(), 2);
        let artifact = capture.freeze("success").unwrap();
        capture.export(&artifact).unwrap();
        capture.export(&artifact).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        for path in std::fs::read_dir(dir.path()).unwrap() {
            let artifact: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path.unwrap().path()).unwrap()).unwrap();
            assert_eq!(artifact["schema_version"], 1);
        }
    }
    #[test]
    fn blocking_work_completion_and_resume_precede_last_span_clone_drop() {
        let capture = capture(30);
        let subscriber = tracing_subscriber::registry().with(TimelineLayer(Arc::clone(&capture)));
        tracing::subscriber::with_default(subscriber, || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .max_blocking_threads(1)
                .build()
                .unwrap();
            let gate = Arc::new(std::sync::Barrier::new(2));
            let worker_gate = Arc::clone(&gate);
            let occupied = runtime.spawn_blocking(move || {
                worker_gate.wait();
                worker_gate.wait();
            });
            gate.wait();
            let span = tracing::trace_span!(target: "lpm_install_timeline", "blocking_operation");
            let retained = span.clone();
            let worker_span = span.clone();
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            tracing::event!(name: "enqueue", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
            let job = runtime.spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, || {
                let _entered = worker_span.enter();
                tracing::event!(name: "work_start", target: "lpm_install_timeline", tracing::Level::TRACE, {});
                tracing::event!(name: "work_end", target: "lpm_install_timeline", tracing::Level::TRACE, {});
            }));
            gate.wait();
            runtime.block_on(async {
                occupied.await.unwrap();
                job.await.unwrap();
            });
            tracing::event!(name: "await_resume", target: "lpm_install_timeline", parent: &span, tracing::Level::TRACE, {});
            drop(span);
            let artifact = capture.freeze("success").unwrap();
            assert_eq!(artifact.open_spans, 1);
            let events: Vec<_> = artifact
                .records
                .iter()
                .filter(|r| r.kind == "event")
                .collect();
            assert_eq!(
                events.iter().map(|r| r.name).collect::<Vec<_>>(),
                ["enqueue", "work_start", "work_end", "await_resume"]
            );
            assert!(events.iter().all(|r| r.parent == events[0].parent));
            assert!(events.windows(2).all(|pair| pair[0].at_us <= pair[1].at_us));
            drop(retained);
        });
    }
}
