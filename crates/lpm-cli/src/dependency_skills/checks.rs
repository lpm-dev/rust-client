//! What the security provider said about the npm package versions whose
//! skills projects link. The verdicts live in LPM's cache, outside every
//! project and apart for each API LPM asks, so an install asks again only
//! when an answer is due; the asking happens outside every lock, and one
//! reconcile decides, asks and schedules from one [`Book`].
//!
//! A verdict covers the public npm release of a name and version, so it
//! applies only to a copy LPM installed from that registry: one whose
//! `lpm.lock` entry says so, read from the store's pristine copy.

use super::socket::{self, Verdict};
use crate::commands::audit::discovery::DiscoveredPackage;
use lpm_common::LpmRoot;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

const CACHE_VERSION: u32 = 2;
const MAX_CACHE_BYTES: u64 = 8 * 1024 * 1024;
/// How long a clean or malware verdict stands before LPM asks again:
/// Socket can flag a version that first looked clean, or clear a false
/// alarm. An older clean verdict keeps a copy linked while Socket can't be
/// asked, but never links a new one.
const SETTLED_SECS: u64 = 24 * 60 * 60;
/// How long LPM waits to ask again about a version Socket is analyzing.
const PENDING_SECS: u64 = 15 * 60;
/// How long LPM waits to ask again about a version Socket has no record of.
const UNKNOWN_SECS: u64 = 60 * 60;
/// How long LPM waits after Socket couldn't be asked, unless Socket named
/// a wait, which is kept between a minute and a day.
const FAILED_SECS: u64 = 15 * 60;
const MIN_RETRY_SECS: u64 = 60;
const MAX_RETRY_SECS: u64 = 24 * 60 * 60;
/// Verdicts older than this are dropped, and so are ones dated in the
/// future by more than the clock's slack.
const FORGET_SECS: u64 = 30 * 24 * 60 * 60;
const CLOCK_SLACK_SECS: u64 = 5 * 60;

const fn ms(secs: u64) -> u64 {
    secs * 1000
}

/// The public npm registry, and the mirror that serves the same packages.
const NPM_REGISTRIES: [&str; 2] = ["https://registry.npmjs.org", "https://registry.yarnpkg.com"];
/// The variable naming an npm mirror whose packages Socket's verdicts
/// cover too, because it serves the public registry's packages unchanged.
pub(crate) const MIRROR_VARIABLE: &str = "LPM_SOCKET_NPM_MIRROR";

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    schema_version: u32,
    /// By the version's PURL.
    #[serde(default)]
    verdicts: BTreeMap<String, Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<StoredFailure>,
    /// When the latest recorded round ended, failed or not, in
    /// milliseconds since the Unix epoch: an earlier round's outcome never
    /// replaces it.
    #[serde(default)]
    last_round_at_ms: u64,
}

/// One version's verdict, and when Socket's answer arrived, in
/// milliseconds since the Unix epoch: fine enough that two answers tie only
/// when they really arrived together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    #[serde(flatten)]
    pub(crate) verdict: Verdict,
    pub(crate) checked_at_ms: u64,
}

impl Entry {
    /// Whether this answer replaces `current`: it came later, or at the
    /// same millisecond and says something stricter.
    fn supersedes(&self, current: &Entry) -> bool {
        self.checked_at_ms > current.checked_at_ms
            || (self.checked_at_ms == current.checked_at_ms
                && self.verdict.strictness() > current.verdict.strictness())
    }

    /// When LPM should ask about the version again, in milliseconds.
    fn due_at_ms(&self) -> u64 {
        self.checked_at_ms.saturating_add(ms(match self.verdict {
            Verdict::Clean | Verdict::Malware { .. } => SETTLED_SECS,
            Verdict::Pending => PENDING_SECS,
            Verdict::Unknown => UNKNOWN_SECS,
        }))
    }

    fn is_settled(&self) -> bool {
        matches!(self.verdict, Verdict::Clean | Verdict::Malware { .. })
    }
}

/// Why Socket last couldn't answer, when, and when LPM asks again, in
/// milliseconds since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredFailure {
    reason: String,
    retry_at_ms: u64,
    at_ms: u64,
    /// Found on this machine before asking; never recorded for other
    /// projects.
    #[serde(skip)]
    local: bool,
    /// Found on this machine and likely to pass soon.
    #[serde(skip)]
    transient: bool,
}

/// The verdict cache's file identity, size and modification time when a
/// book read it, so an install can tell another project recorded verdicts
/// since. Every write replaces the file, so its identity, the device and
/// inode or the volume and file index, changes even when the size and a
/// coarse modification time don't.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CacheStamp {
    #[serde(default)]
    volume: u64,
    #[serde(default)]
    identity: u64,
    size: u64,
    modified_nanos: u64,
}

/// The verdict cache's stamp now: `None` when there is no cache, `Err` when
/// it exists but can't be opened, so what it holds is unknown.
pub(crate) fn cache_stamp() -> Result<Option<CacheStamp>, ()> {
    let Some(path) = socket::cache_scope().and_then(|scope| cache_path(&scope)) else {
        return Ok(None);
    };
    open_cache(&path)
        .map(|opened| opened.map(|(_, stamp)| stamp))
        .map_err(|_| ())
}

/// The verdict cache at `path` opened for reading, without blocking on a
/// special file, with its stamp from the open handle; `None` when there is
/// no cache. The cache is only ever replaced whole, so what the handle reads
/// is what the stamp describes.
fn open_cache(
    path: &Path,
) -> Result<Option<(std::fs::File, CacheStamp)>, lpm_common::BoundedReadError> {
    let unreadable = |source: std::io::Error| lpm_common::BoundedReadError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unreadable(error)),
    };
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(unreadable(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file",
        )));
    }
    let (volume, identity) = lpm_common::atomic_write::file_identity(&file).map_err(unreadable)?;
    let modified_nanos = metadata
        .modified()
        .map_err(unreadable)?
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        });
    Ok(Some((
        file,
        CacheStamp {
            volume,
            identity,
            size: metadata.len(),
            modified_nanos,
        },
    )))
}

/// The verdicts LPM keeps for the API it asks now, as one reconcile sees
/// them: read once, and added to as Socket answers.
#[derive(Debug, Clone, Default)]
pub(crate) struct Book {
    verdicts: HashMap<String, Entry>,
    failure: Option<StoredFailure>,
    /// In milliseconds since the Unix epoch.
    now_ms: u64,
    /// The stamp of the cache this book read; `None` when there was none or
    /// the read failed.
    stamp: Option<CacheStamp>,
    /// Whether the cache exists but couldn't be read, so this book says
    /// nothing about what it holds.
    read_failed: bool,
    /// Whether a later read of the cache, made to catch verdicts another
    /// project recorded meanwhile, failed: only verdicts Socket gave this
    /// run still vouch for a command.
    refresh_failed: bool,
    /// The releases, as PURLs, Socket answered for during this run.
    answered: HashSet<String>,
}

impl Book {
    pub(crate) fn load() -> Self {
        let now_ms = now_ms();
        let (file, stamp, read_failed) =
            match socket::cache_scope().map(|scope| read_cache_stamped(&scope)) {
                Some(Ok(Some((file, stamp)))) => (file.unwrap_or_default(), Some(stamp), false),
                Some(Ok(None)) | None => (CacheFile::default(), None, false),
                Some(Err(_)) => (CacheFile::default(), None, true),
            };
        Self {
            verdicts: file
                .verdicts
                .into_iter()
                .filter(|(_, entry)| is_current(entry.checked_at_ms, now_ms))
                .collect(),
            failure: file
                .failure
                .filter(|failure| !is_future(failure.at_ms, now_ms))
                .map(|failure| StoredFailure {
                    retry_at_ms: failure
                        .retry_at_ms
                        .min(now_ms.saturating_add(ms(MAX_RETRY_SECS))),
                    ..failure
                }),
            now_ms,
            stamp,
            read_failed,
            refresh_failed: false,
            answered: HashSet::new(),
        }
    }

    /// Whether the cache exists but couldn't be read.
    #[inline]
    pub(crate) fn read_failed(&self) -> bool {
        self.read_failed
    }

    /// Notes that a later read of the cache failed, so what another project
    /// recorded meanwhile is unknown.
    pub(crate) fn note_refresh_failed(&mut self) {
        self.refresh_failed = true;
    }

    /// Whether a later read of the cache failed.
    #[inline]
    pub(crate) fn refresh_failed(&self) -> bool {
        self.refresh_failed
    }

    /// Whether this book's verdict on `name@version` can vouch for what a
    /// command runs: always, unless a later read of the cache failed and
    /// Socket didn't answer for it during this run.
    pub(crate) fn vouches_now(&self, name: &str, version: &str) -> bool {
        !self.refresh_failed
            || self
                .answered
                .contains(&lpm_common::npm_package_purl(name, version))
    }

    /// The cache's stamp when this book last read it.
    #[inline]
    pub(crate) fn stamp(&self) -> Option<CacheStamp> {
        self.stamp
    }

    /// Notes that `later`, read after this book, says nothing new about the
    /// verdicts it is checked against, so this book stands for the cache as
    /// `later` read it.
    pub(crate) fn caught_up_with(&mut self, later: &Book) {
        if !later.read_failed {
            self.stamp = later.stamp;
        }
    }

    /// The verdict LPM keeps for `name` at `version`, however old.
    pub(crate) fn entry(&self, name: &str, version: &str) -> Option<&Entry> {
        self.verdicts
            .get(&lpm_common::npm_package_purl(name, version))
    }

    /// Whether the verdict for `name` at `version` is old enough to ask
    /// again.
    pub(crate) fn is_due(&self, entry: &Entry) -> bool {
        self.now_ms >= entry.due_at_ms()
    }

    /// Why Socket couldn't answer lately, while LPM waits to ask again.
    pub(crate) fn failure(&self) -> Option<&str> {
        self.active_failure().map(|failure| failure.reason.as_str())
    }

    fn active_failure(&self) -> Option<&StoredFailure> {
        self.failure
            .as_ref()
            .filter(|failure| failure.retry_at_ms > self.now_ms)
    }

    /// Whether to ask about `name` at `version` now.
    fn wants(&self, name: &str, version: &str, asking: Asking) -> bool {
        self.entry(name, version).is_none_or(|entry| {
            self.is_due(entry) || (asking == Asking::Now && !entry.is_settled())
        })
    }

    /// Adds what one round of asking produced, each answer dated when it
    /// arrived, and moves this book's clock to the round's end.
    pub(crate) fn absorb(&mut self, answers: &socket::Answers) {
        for ((name, version), observed) in &answers.verdicts {
            let purl = lpm_common::npm_package_purl(name, version);
            self.answered.insert(purl.clone());
            insert_answer(
                &mut self.verdicts,
                purl,
                Entry {
                    verdict: observed.verdict.clone(),
                    checked_at_ms: observed.at_ms,
                },
            );
        }
        if self
            .failure
            .as_ref()
            .is_none_or(|current| current.at_ms <= answers.at_ms)
        {
            self.failure = answers
                .failure
                .as_ref()
                .map(|failure| stored_failure(failure, answers.at_ms));
        }
        self.now_ms = self.now_ms.max(answers.at_ms);
        self.forget_expired();
    }

    /// Drops the verdicts that expired by this book's clock.
    fn forget_expired(&mut self) {
        let now_ms = self.now_ms;
        self.verdicts
            .retain(|_, entry| is_current(entry.checked_at_ms, now_ms));
    }

    /// Whether `other`, read later, says something about any of `relied`
    /// that would change a decision: another project recorded a newer
    /// answer that differs, or that is fresh where this book's has aged, or
    /// a verdict came due or expired between the two reads, each book
    /// judged at its own clock.
    pub(crate) fn differs_for(&self, other: &Book, relied: &BTreeSet<(String, String)>) -> bool {
        let now_ms = self.now_ms.max(other.now_ms);
        relied.iter().any(|(name, version)| {
            match (self.entry(name, version), other.entry(name, version)) {
                (None, None) => false,
                (Some(mine), None) => {
                    !is_current(mine.checked_at_ms, now_ms)
                        || self.is_due(mine) != (now_ms >= mine.due_at_ms())
                }
                (None, Some(theirs)) => is_current(theirs.checked_at_ms, now_ms),
                (Some(mine), Some(theirs)) => {
                    let winner = if theirs.supersedes(mine) {
                        theirs
                    } else {
                        mine
                    };
                    winner.verdict != mine.verdict
                        || !is_current(winner.checked_at_ms, now_ms)
                        || self.is_due(mine) != (now_ms >= winner.due_at_ms())
                }
            }
        })
    }

    /// This book with each verdict `other` holds that supersedes its own,
    /// and the failure `other` records: the cache knows whether Socket
    /// failed since. A failure found on this machine stays.
    pub(crate) fn merged_with(mut self, other: Book) -> Self {
        for (purl, entry) in other.verdicts {
            insert_answer(&mut self.verdicts, purl, entry);
        }
        if !self.failure.as_ref().is_some_and(|failure| failure.local) {
            self.failure = other.failure;
        }
        self.now_ms = self.now_ms.max(other.now_ms);
        if !other.read_failed {
            self.stamp = other.stamp;
        }
        self.forget_expired();
        self
    }
}

/// Keeps `entry` for `purl` unless what `verdicts` holds supersedes it.
fn insert_answer(verdicts: &mut HashMap<String, Entry>, purl: String, entry: Entry) {
    match verdicts.entry(purl) {
        std::collections::hash_map::Entry::Occupied(mut current) => {
            if entry.supersedes(current.get()) {
                current.insert(entry);
            }
        }
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(entry);
        }
    }
}

fn is_current(checked_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(checked_at_ms) < ms(FORGET_SECS) && !is_future(checked_at_ms, now_ms)
}

/// Whether `at_ms` lies further ahead of `now_ms` than the clock's slack:
/// written while the clock ran ahead, so never trusted to order anything.
fn is_future(at_ms: u64, now_ms: u64) -> bool {
    at_ms > now_ms.saturating_add(ms(CLOCK_SLACK_SECS))
}

fn stored_failure(failure: &socket::Failure, at_ms: u64) -> StoredFailure {
    let wait = failure.retry_after.map_or(FAILED_SECS, |wait| {
        wait.as_secs().clamp(MIN_RETRY_SECS, MAX_RETRY_SECS)
    });
    StoredFailure {
        reason: failure.reason.clone(),
        retry_at_ms: at_ms.saturating_add(ms(wait)),
        at_ms,
        local: failure.local,
        transient: failure.transient,
    }
}

/// When asking Socket again is worth it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asking {
    /// For an install: about versions without a verdict or whose verdict
    /// aged, unless Socket failed lately.
    WhenDue,
    /// For a command the user runs to check now: also about versions
    /// Socket hadn't decided, and despite a recent failure.
    Now,
}

/// The versions of `relied` to ask Socket about now.
pub(crate) fn to_ask(
    book: &Book,
    relied: &BTreeSet<(String, String)>,
    asking: Asking,
) -> Vec<(String, String)> {
    if asking == Asking::WhenDue && book.active_failure().is_some() {
        return Vec::new();
    }
    relied
        .iter()
        .filter(|(name, version)| book.wants(name, version, asking))
        .cloned()
        .collect()
}

/// Asks Socket about `packages`, and says why its answers couldn't be
/// saved, if they couldn't. What Socket answered, and why it stopped
/// answering, is recorded for every project; a reason found before asking,
/// such as a missing token, is only returned, so fixing it takes effect at
/// once.
pub(crate) fn ask(packages: &[(String, String)]) -> (socket::Answers, Option<String>) {
    let _span = tracing::info_span!("install.dependency_skills.socket").entered();
    let endpoint = match socket::Endpoint::resolve() {
        Ok(endpoint) => endpoint,
        Err(failure) => return (socket::Answers::failed(failure), None),
    };
    let answers = socket::lookup(&endpoint, packages);
    let unsaved = socket::cache_scope()
        .and_then(|scope| record(&scope, &answers).err())
        .map(|error| error.to_string());
    (answers, unsaved)
}

/// Merges `answers` into the cache for `scope` under its lock: an answer
/// replaces only one it supersedes, and the round's outcome, failed or
/// not, replaces only an earlier round's.
fn record(scope: &str, answers: &socket::Answers) -> Result<(), lpm_common::LpmError> {
    with_cache(scope, |file| {
        let now_ms = now_ms();
        file.verdicts
            .retain(|_, entry| is_current(entry.checked_at_ms, now_ms));
        if is_future(file.last_round_at_ms, now_ms) {
            file.last_round_at_ms = 0;
        }
        if file
            .failure
            .as_ref()
            .is_some_and(|failure| is_future(failure.at_ms, now_ms))
        {
            file.failure = None;
        }
        for ((name, version), observed) in &answers.verdicts {
            let purl = lpm_common::npm_package_purl(name, version);
            let entry = Entry {
                verdict: observed.verdict.clone(),
                checked_at_ms: observed.at_ms,
            };
            if file
                .verdicts
                .get(&purl)
                .is_none_or(|current| entry.supersedes(current))
            {
                file.verdicts.insert(purl, entry);
            }
        }
        let found_here = answers
            .failure
            .as_ref()
            .is_some_and(|failure| failure.local);
        if !found_here && answers.at_ms >= file.last_round_at_ms {
            file.failure = answers
                .failure
                .as_ref()
                .map(|failure| stored_failure(failure, answers.at_ms));
            file.last_round_at_ms = answers.at_ms;
        }
    })
}

/// Notes that the user stored or removed a Socket token: the recorded
/// failure is forgotten, so the next install asks again at once, and the
/// credentials stamp changes, so links that waited on a token are
/// reconciled.
pub(crate) fn credentials_changed() {
    if let Some(scope) = socket::cache_scope() {
        let _ = with_cache(&scope, |file| {
            let now_ms = now_ms();
            file.failure = None;
            file.last_round_at_ms = if is_future(file.last_round_at_ms, now_ms) {
                now_ms
            } else {
                file.last_round_at_ms.max(now_ms)
            };
        });
    }
    if let Some(path) = credentials_stamp_path() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let _ = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| lpm_common::write_file_atomic(&path, nanos.to_string()));
    }
}

/// What the links' fingerprint keeps of the Socket credentials, without
/// the token: which token variables are set, and the stamp `lpm login
/// --socket` and `lpm logout --socket` leave.
pub(crate) fn credential_key() -> String {
    let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    let stamp = credentials_stamp_path()
        .and_then(|path| lpm_common::read_text_file_capped(&path, 64).ok())
        .unwrap_or_default();
    format!(
        "{}{}:{}",
        u8::from(set("SOCKET_CLI_API_TOKEN")),
        u8::from(set("SOCKET_SECURITY_API_TOKEN")),
        stamp.trim()
    )
}

fn credentials_stamp_path() -> Option<PathBuf> {
    let mut path = LpmRoot::from_env().ok()?.cache_root();
    path.push("skill-checks");
    path.push("credentials");
    Some(path)
}

/// When the links are next due a check, and when the earliest verdict they
/// rest on expires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Recheck {
    /// In seconds since the Unix epoch.
    pub(crate) at: Option<u64>,
    /// When the earliest verdict the links rest on expires from the cache,
    /// in seconds since the Unix epoch: then its copies stop being kept,
    /// even offline.
    pub(crate) expires_at: Option<u64>,
}

/// When the verdicts behind `relied` next need asking for, as `book` has
/// them: the earliest verdict to age, or, for a version without a verdict,
/// once LPM may ask again. While a failure found on this machine stands, a
/// version due is looked at again when its verdict expires, or sooner
/// without waiting on Socket: after the usual wait when the failure is
/// likely to pass, else a day on, since a token the keychain couldn't give
/// may come back.
pub(crate) fn recheck(book: &Book, relied: &BTreeSet<(String, String)>) -> Recheck {
    let failure = book.active_failure();
    let mut earliest_ms: Option<u64> = None;
    let mut expires_ms: Option<u64> = None;
    for (name, version) in relied {
        let entry = book.entry(name, version);
        let expiry_ms = entry.map(|entry| entry.checked_at_ms.saturating_add(ms(FORGET_SECS)));
        if let Some(expiry_ms) = expiry_ms {
            expires_ms = Some(expires_ms.map_or(expiry_ms, |earliest| earliest.min(expiry_ms)));
        }
        let due_ms = entry.map_or(book.now_ms, Entry::due_at_ms);
        let at_ms = match failure {
            Some(failure) if due_ms <= book.now_ms && failure.local => {
                let wait = if failure.transient {
                    FAILED_SECS
                } else {
                    MAX_RETRY_SECS
                };
                let next_ms = book.now_ms.saturating_add(ms(wait));
                expiry_ms.map_or(next_ms, |expiry_ms| expiry_ms.min(next_ms))
            }
            Some(failure) if due_ms <= book.now_ms => due_ms.max(failure.retry_at_ms),
            _ => due_ms,
        };
        earliest_ms = Some(earliest_ms.map_or(at_ms, |earliest| earliest.min(at_ms)));
    }
    Recheck {
        at: earliest_ms.map(|at_ms| {
            if at_ms > book.now_ms {
                at_ms.div_ceil(1000)
            } else {
                at_ms / 1000
            }
        }),
        expires_at: expires_ms.map(|expiry_ms| expiry_ms.div_ceil(1000)),
    }
}

/// How many of `relied` rest on a clean or malware verdict that came due
/// and couldn't be asked for again.
pub(crate) fn stale(book: &Book, relied: &BTreeSet<(String, String)>) -> usize {
    relied
        .iter()
        .filter(|(name, version)| {
            book.entry(name, version)
                .is_some_and(|entry| entry.is_settled() && book.is_due(entry))
        })
        .count()
}

/// The public npm release `package` is a copy of, as a name and version,
/// or why no verdict about a release covers its files. `locked` holds the
/// `lpm.lock` entries that may be its own: the one its instance names, or
/// the ones with its name, version and integrity. Every one of them must
/// come from an npm registry, under the name and version it records, and a
/// recorded tarball must be that release's own on the public registry or
/// the named mirror.
pub(crate) fn npm_release(
    package: &DiscoveredPackage,
    locked: &[&lpm_lockfile::LockedPackage],
) -> Result<(String, String), String> {
    if package.local_source_dir.is_some() {
        return Err("it was installed from a local directory".into());
    }
    if package.patch_sha256.is_some() {
        return Err("the project patches it, so its files aren't the release as published".into());
    }
    let Some(first) = locked.first() else {
        return Err(
            "LPM didn't install it from its own lockfile, so it can't tell the files on disk are the release's"
                .into(),
        );
    };
    for row in locked {
        let registry = match row
            .source
            .as_deref()
            .and_then(|source| lpm_lockfile::Source::parse(source).ok())
        {
            Some(lpm_lockfile::Source::Registry { url }) if is_npm_registry(&url) => url,
            Some(lpm_lockfile::Source::Registry { url }) => {
                return Err(format!(
                    "it was installed from {}, not the public npm registry; set {MIRROR_VARIABLE} to that registry if it mirrors npm unchanged",
                    origin(&url)
                ));
            }
            Some(lpm_lockfile::Source::Tarball { .. }) => {
                return Err("it was installed from a tarball URL".into());
            }
            Some(lpm_lockfile::Source::Git { .. }) => {
                return Err("it was installed from a Git repository".into());
            }
            Some(lpm_lockfile::Source::Directory { .. } | lpm_lockfile::Source::Link { .. }) => {
                return Err("it was installed from a local directory".into());
            }
            None => return Err("its lockfile entry doesn't say where it came from".into()),
        };
        if row.name != first.name || row.version != first.version {
            return Err("its lockfile entries name different releases".into());
        }
        if row.integrity.is_none() {
            return Err(
                "its lockfile entry records no integrity, so LPM can't tell the files on disk are the release's"
                    .into(),
            );
        }
        let release = (row.name.clone(), row.version.clone());
        if let Some(tarball) = row.tarball.as_deref()
            && !std::iter::once(registry)
                .chain(registries())
                .any(|registry| {
                    npm_tarball_release(tarball, &row.version, &registry).as_ref() == Some(&release)
                })
        {
            return Err(format!(
                "its lockfile fetches it from {}, which isn't that release's own tarball",
                origin(tarball)
            ));
        }
    }
    Ok((first.name.clone(), first.version.clone()))
}

/// The name of the release `url` downloads, when `url` is `registry`'s
/// tarball for `version`: `<registry>/<name>/-/<bare name>-<version>.tgz`,
/// or with the full name in the file, as some registries write scoped ones.
fn npm_tarball_release(url: &str, version: &str, registry: &str) -> Option<(String, String)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let base = reqwest::Url::parse(registry).ok()?;
    if parsed.scheme() != base.scheme()
        || parsed.host_str().map(str::to_ascii_lowercase)
            != base.host_str().map(str::to_ascii_lowercase)
        || parsed.port_or_known_default() != base.port_or_known_default()
        || parsed.query().is_some()
    {
        return None;
    }
    let relative = parsed
        .path()
        .strip_prefix(base.path().trim_end_matches('/'))?
        .strip_prefix('/')?;
    let decoded = urlencoding::decode(relative).ok()?;
    let (name, file) = decoded.split_once("/-/")?;
    let bare = match name.strip_prefix('@') {
        Some(scoped) => scoped.split_once('/')?.1,
        None => name,
    };
    let named = file == format!("{bare}-{version}.tgz") || file == format!("{name}-{version}.tgz");
    if bare.is_empty() || bare.contains('/') || !named {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Whether `url`, a registry's root, is the public npm registry or the
/// mirror the user named: the same scheme, host, port and path.
fn is_npm_registry(url: &str) -> bool {
    let Some(candidate) = registry_root(url) else {
        return false;
    };
    registries().any(|registry| registry_root(&registry).as_ref() == Some(&candidate))
}

/// `url` as a registry root to compare: scheme, host, port and path
/// without its trailing slash; `None` with credentials, a query or a
/// fragment.
fn registry_root(url: &str) -> Option<(String, String, Option<u16>, String)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some((
        parsed.scheme().to_string(),
        parsed.host_str()?.to_ascii_lowercase(),
        parsed.port_or_known_default(),
        parsed.path().trim_end_matches('/').to_string(),
    ))
}

/// The public npm registries, and the mirror the user named.
fn registries() -> impl Iterator<Item = String> {
    NPM_REGISTRIES
        .iter()
        .map(|url| (*url).to_string())
        .chain(mirror())
}

/// The release check copies linking now pass, named by the security
/// provider's API and the npm mirror LPM accepts besides the public
/// registry; `None` when the API can't be used.
pub(crate) fn release_check() -> Option<String> {
    socket::cache_scope().map(|scope| format!("{scope} {}", mirror().unwrap_or_default()))
}

/// The `LPM_SOCKET_NPM_MIRROR` mirror, when LPM accepts it: HTTPS, or HTTP
/// to a loopback address, without credentials, a query or a fragment.
pub(crate) fn mirror() -> Option<String> {
    std::env::var(MIRROR_VARIABLE)
        .ok()
        .filter(|url| crate::release_lookup::accept_override(url) && registry_root(url).is_some())
}

/// `url`'s scheme, host and port, for messages: no path or credentials.
fn origin(url: &str) -> String {
    reqwest::Url::parse(url).map_or_else(
        |_| "an unrecognized source".to_string(),
        |parsed| parsed.origin().ascii_serialization(),
    )
}

fn cache_path(scope: &str) -> Option<PathBuf> {
    let mut path = LpmRoot::from_env().ok()?.cache_root();
    path.push("skill-checks");
    path.push(format!("{scope}.json"));
    Some(path)
}

/// Why the verdict cache couldn't be read.
enum CacheReadError {
    /// Reading it failed, which may pass: what it holds is unknown.
    Unreadable(String),
    /// It holds something no LPM writes: too large, not UTF-8 or not JSON.
    Corrupt,
}

/// The cache for `scope`: `Ok(None)` when there is none or it holds another
/// schema.
fn read_cache_checked(scope: &str) -> Result<Option<CacheFile>, CacheReadError> {
    read_cache_stamped(scope).map(|read| read.and_then(|(file, _)| file))
}

/// The cache for `scope` with its stamp, `None` when there is no cache, and
/// no file in it when it holds another schema.
fn read_cache_stamped(
    scope: &str,
) -> Result<Option<(Option<CacheFile>, CacheStamp)>, CacheReadError> {
    let Some(path) = cache_path(scope) else {
        return Ok(None);
    };
    let unreadable = |error: lpm_common::BoundedReadError| match error {
        lpm_common::BoundedReadError::Io { .. } => CacheReadError::Unreadable(error.to_string()),
        _ => CacheReadError::Corrupt,
    };
    let Some((file, stamp)) = open_cache(&path).map_err(unreadable)? else {
        return Ok(None);
    };
    let content = lpm_common::read_text_file_capped_from_open_file_with_known_size(
        file,
        &path,
        MAX_CACHE_BYTES,
        stamp.size,
    )
    .map_err(unreadable)?;
    let file: CacheFile = serde_json::from_str(&content).map_err(|_| CacheReadError::Corrupt)?;
    Ok(Some((
        (file.schema_version == CACHE_VERSION).then_some(file),
        stamp,
    )))
}

/// `file` serialized within the size LPM reads back, the oldest verdicts
/// dropped first when it wouldn't fit.
fn fitted_cache(file: &mut CacheFile) -> Result<Vec<u8>, lpm_common::LpmError> {
    loop {
        let mut content = serde_json::to_vec_pretty(&*file).map_err(|error| {
            lpm_common::LpmError::Registry(format!("failed to serialize Socket verdicts: {error}"))
        })?;
        content.push(b'\n');
        if content.len() as u64 <= MAX_CACHE_BYTES || file.verdicts.is_empty() {
            return Ok(content);
        }
        let mut oldest: Vec<(u64, String)> = file
            .verdicts
            .iter()
            .map(|(purl, entry)| (entry.checked_at_ms, purl.clone()))
            .collect();
        oldest.sort_unstable();
        let drop = (oldest.len() / 8).max(1);
        for (_, purl) in oldest.into_iter().take(drop) {
            file.verdicts.remove(&purl);
        }
    }
}

/// Reads the cache for `scope`, lets `change` edit it, and writes it back,
/// all under the cache's lock, so two projects asking at once both keep
/// their answers. A cache that couldn't be read is left as it is, since
/// writing over it could drop verdicts another project recorded; a corrupt
/// one is started afresh.
fn with_cache(
    scope: &str,
    change: impl FnOnce(&mut CacheFile),
) -> Result<(), lpm_common::LpmError> {
    let Some(path) = cache_path(scope) else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    lpm_common::with_exclusive_lock(path.with_extension("lock"), || {
        let mut file = match read_cache_checked(scope) {
            Ok(file) => file.unwrap_or_default(),
            Err(CacheReadError::Corrupt) => CacheFile::default(),
            Err(CacheReadError::Unreadable(error)) => {
                return Err(lpm_common::LpmError::Registry(format!(
                    "the verdict cache couldn't be read, so LPM left it as it is: {error}"
                )));
            }
        };
        file.schema_version = CACHE_VERSION;
        change(&mut file);
        let content = fitted_cache(&mut file)?;
        lpm_common::write_file_atomic(&path, content)?;
        Ok(())
    })
}

pub(crate) fn now_secs() -> u64 {
    now_ms() / 1000
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: &str) -> DiscoveredPackage {
        DiscoveredPackage {
            name: name.into(),
            version: version.into(),
            instance_id: None,
            path: format!("node_modules/{name}"),
            integrity: None,
            patch_sha256: None,
            resolved_url: None,
            local_source_dir: None,
            scan_mode: crate::commands::audit::discovery::ScanMode::FullLocal,
            is_dev: false,
            is_optional: false,
            platform_skipped: false,
            installed: None,
            dependencies: Vec::new(),
        }
    }

    fn locked(name: &str, version: &str, source: Option<&str>) -> lpm_lockfile::LockedPackage {
        lpm_lockfile::LockedPackage {
            name: name.into(),
            version: version.into(),
            source: source.map(str::to_string),
            integrity: Some(format!("sha512-{name}-{version}")),
            ..lpm_lockfile::LockedPackage::default()
        }
    }

    const NPM: &str = "registry+https://registry.npmjs.org";

    #[test]
    fn only_a_copy_lpm_installed_from_the_npm_registry_is_an_npm_release() {
        let tool = package("tool", "1.0.0");
        assert_eq!(
            npm_release(&tool, &[&locked("tool", "1.0.0", Some(NPM))]),
            Ok(("tool".to_string(), "1.0.0".to_string()))
        );
        for source in [
            Some("registry+https://npm.corp.example"),
            Some("registry+https://registry.npmjs.org.evil.example"),
            Some("tarball+https://cdn.example/tool-1.0.0.tgz"),
            Some("git+https://github.com/acme/tool.git#0123456789012345678901234567890123456789"),
            Some("directory+vendor/tool"),
            None,
        ] {
            assert!(
                npm_release(&tool, &[&locked("tool", "1.0.0", source)]).is_err(),
                "{source:?}"
            );
        }

        let mut local = package("tool", "1.0.0");
        local.local_source_dir = Some(PathBuf::from("/vendor/tool"));
        assert!(npm_release(&local, &[&locked("tool", "1.0.0", Some(NPM))]).is_err());

        let mut foreign = package("tool", "1.0.0");
        foreign.resolved_url = Some("https://registry.npmjs.org/tool/-/tool-1.0.0.tgz".into());
        assert!(npm_release(&foreign, &[]).is_err());
    }

    #[test]
    fn a_copy_whose_lockfile_entry_records_no_integrity_or_that_the_project_patches_is_not_checkable()
     {
        let tool = package("tool", "1.0.0");
        let mut unpinned = locked("tool", "1.0.0", Some(NPM));
        unpinned.integrity = None;
        assert!(npm_release(&tool, &[&unpinned]).is_err());

        let mut patched = package("tool", "1.0.0");
        patched.patch_sha256 = Some("0".repeat(64));
        assert!(npm_release(&patched, &[&locked("tool", "1.0.0", Some(NPM))]).is_err());
    }

    #[test]
    fn every_lockfile_entry_that_may_be_the_copy_must_be_the_same_npm_release() {
        let tool = package("tool", "1.0.0");
        let npm = locked("tool", "1.0.0", Some(NPM));
        let tarball = locked(
            "tool",
            "1.0.0",
            Some("tarball+https://cdn.example/tool.tgz"),
        );
        assert!(npm_release(&tool, &[&npm, &tarball]).is_err());
        assert!(npm_release(&tool, &[&npm, &npm]).is_ok());
    }

    #[test]
    fn a_recorded_tarball_must_be_the_releases_own() {
        let tool = package("@acme/tool", "2.0.0");
        let mut own = locked("@acme/tool", "2.0.0", Some(NPM));
        own.tarball = Some("https://registry.npmjs.org/@acme/tool/-/tool-2.0.0.tgz".into());
        assert!(npm_release(&tool, &[&own]).is_ok());
        for tarball in [
            "https://registry.npmjs.org/evil/-/evil-2.0.0.tgz",
            "https://registry.npmjs.org/@acme/tool/-/tool-9.9.9.tgz",
            "https://cdn.example/@acme/tool/-/tool-2.0.0.tgz",
        ] {
            let mut other = own.clone();
            other.tarball = Some(tarball.into());
            assert!(npm_release(&tool, &[&other]).is_err(), "{tarball}");
        }
    }

    #[test]
    fn a_named_mirror_counts_as_the_npm_registry_only_at_its_own_root() {
        let package = package("tool", "1.0.0");
        let mirror = locked(
            "tool",
            "1.0.0",
            Some("registry+https://npm.corp.example/npm"),
        );
        let below = locked(
            "tool",
            "1.0.0",
            Some("registry+https://npm.corp.example/npm/private"),
        );
        assert!(npm_release(&package, &[&mirror]).is_err());

        let _env = crate::test_env::ScopedEnv::set([(
            MIRROR_VARIABLE,
            "https://npm.corp.example/npm/".into(),
        )]);
        assert!(npm_release(&package, &[&mirror]).is_ok());
        assert!(npm_release(&package, &[&below]).is_err());
    }

    fn entry(verdict: Verdict, checked_at_secs: u64) -> Entry {
        Entry {
            verdict,
            checked_at_ms: ms(checked_at_secs),
        }
    }

    fn book(now: u64, entries: &[(&str, Verdict, u64)]) -> Book {
        Book {
            verdicts: entries
                .iter()
                .map(|(name, verdict, checked_at)| {
                    (
                        lpm_common::npm_package_purl(name, "1.0.0"),
                        entry(verdict.clone(), *checked_at),
                    )
                })
                .collect(),
            failure: None,
            now_ms: ms(now),
            ..Book::default()
        }
    }

    #[test]
    fn verdicts_age_by_how_settled_they_are() {
        let now = 10_000_000;
        let malware = Verdict::Malware {
            alert: "malware".into(),
        };
        let book = book(
            now,
            &[
                ("clean", Verdict::Clean, now - SETTLED_SECS + 1),
                ("aged", Verdict::Clean, now - SETTLED_SECS),
                ("flagged", malware.clone(), now - SETTLED_SECS + 1),
                ("aged-flagged", malware, now - SETTLED_SECS),
                ("pending", Verdict::Pending, now - PENDING_SECS + 1),
                ("stale-pending", Verdict::Pending, now - PENDING_SECS),
                ("unknown", Verdict::Unknown, now - UNKNOWN_SECS + 1),
                ("stale-unknown", Verdict::Unknown, now - UNKNOWN_SECS),
            ],
        );

        for (name, wanted) in [
            ("clean", false),
            ("aged", true),
            ("flagged", false),
            ("aged-flagged", true),
            ("pending", false),
            ("stale-pending", true),
            ("unknown", false),
            ("stale-unknown", true),
            ("missing", true),
        ] {
            assert_eq!(book.wants(name, "1.0.0", Asking::WhenDue), wanted, "{name}");
        }
        assert!(book.wants("pending", "1.0.0", Asking::Now));
        assert!(book.wants("unknown", "1.0.0", Asking::Now));
        assert!(!book.wants("clean", "1.0.0", Asking::Now));
    }

    fn failure(retry_at_secs: u64, at_secs: u64, local: bool) -> StoredFailure {
        StoredFailure {
            reason: "down".into(),
            retry_at_ms: ms(retry_at_secs),
            at_ms: ms(at_secs),
            local,
            transient: false,
        }
    }

    fn relied(names: &[&str]) -> BTreeSet<(String, String)> {
        names
            .iter()
            .map(|name| (name.to_string(), "1.0.0".to_string()))
            .collect()
    }

    #[test]
    fn the_recheck_is_the_earliest_verdict_to_age_or_the_retry_after_a_failure() {
        let now = 10_000_000;
        let relied = relied(&["clean", "pending"]);
        let mut answered = book(
            now,
            &[
                ("clean", Verdict::Clean, now - 10),
                ("pending", Verdict::Pending, now - 10),
            ],
        );
        assert_eq!(
            recheck(&answered, &relied),
            Recheck {
                at: Some(now - 10 + PENDING_SECS),
                expires_at: Some(now - 10 + FORGET_SECS),
            }
        );

        answered.verdicts.clear();
        answered.failure = Some(failure(now + 120, now, false));
        assert_eq!(
            recheck(&answered, &relied),
            Recheck {
                at: Some(now + 120),
                expires_at: None,
            }
        );
        assert!(to_ask(&answered, &relied, Asking::WhenDue).is_empty());
        assert_eq!(to_ask(&answered, &relied, Asking::Now).len(), 2);
    }

    #[test]
    fn a_failure_found_on_this_machine_rechecks_later_without_waiting_on_socket() {
        let now = 10_000_000;
        let mut answered = book(now, &[("aged", Verdict::Clean, now - SETTLED_SECS - 10)]);
        answered.failure = Some(failure(now + FAILED_SECS, now, true));

        assert_eq!(
            recheck(&answered, &relied(&["aged", "missing"])),
            Recheck {
                at: Some(now + MAX_RETRY_SECS),
                expires_at: Some(now - SETTLED_SECS - 10 + FORGET_SECS),
            }
        );

        let nearly_expired = now - FORGET_SECS + 60;
        let mut answered = book(now, &[("old", Verdict::Clean, nearly_expired)]);
        answered.failure = Some(failure(now + FAILED_SECS, now, true));
        assert_eq!(
            recheck(&answered, &relied(&["old"])).at,
            Some(nearly_expired + FORGET_SECS),
            "a verdict that expires sooner is looked at when it does"
        );

        let mut passing = book(now, &[("aged", Verdict::Clean, now - SETTLED_SECS - 10)]);
        passing.failure = Some(StoredFailure {
            transient: true,
            ..failure(now + FAILED_SECS, now, true)
        });
        assert_eq!(
            recheck(&passing, &relied(&["aged"])).at,
            Some(now + FAILED_SECS),
            "a failure likely to pass is looked at again after the usual wait"
        );
    }

    #[test]
    fn a_recheck_already_due_is_never_put_off_to_the_next_second() {
        let mut answered = book(10_000_000, &[]);
        answered.now_ms = ms(10_000_000) + 400;

        assert_eq!(
            recheck(&answered, &relied(&["missing"])).at,
            Some(10_000_000)
        );
    }

    #[test]
    fn a_verdict_coming_due_between_two_reads_counts_as_a_difference() {
        let now = 10_000_000;
        let mine = book(now, &[("tool", Verdict::Clean, now - SETTLED_SECS + 1)]);
        let later = book(now + 2, &[("tool", Verdict::Clean, now - SETTLED_SECS + 1)]);
        let expired = book(now + FORGET_SECS, &[]);

        assert!(mine.differs_for(&later, &relied(&["tool"])));
        assert!(!mine.differs_for(&mine.clone(), &relied(&["tool"])));
        assert!(mine.differs_for(&expired, &relied(&["tool"])));
        assert!(
            mine.merged_with(expired).entry("tool", "1.0.0").is_none(),
            "a merge drops what expired at the merged clock"
        );

        let newer_than_cache = book(now, &[("tool", Verdict::Clean, now - SETTLED_SECS + 1)]);
        let stale_cache = book(now + 2, &[("tool", Verdict::Clean, now - SETTLED_SECS - 5)]);
        assert!(
            newer_than_cache.differs_for(&stale_cache, &relied(&["tool"])),
            "this book's own verdict came due by the second read"
        );

        let unreadable_later = book(now + 2, &[]);
        assert!(
            newer_than_cache.differs_for(&unreadable_later, &relied(&["tool"])),
            "a verdict coming due counts when the second read finds nothing"
        );
        let settled_mine = book(now, &[("tool", Verdict::Clean, now - 10)]);
        assert!(!settled_mine.differs_for(&book(now + 2, &[]), &relied(&["tool"])));
        let expired_theirs = book(now, &[("tool", Verdict::Clean, now - FORGET_SECS - 10)]);
        assert!(
            !book(now, &[]).differs_for(&expired_theirs, &relied(&["tool"])),
            "an entry the merge would drop says nothing new"
        );
    }

    #[test]
    fn a_cache_lpm_cant_read_never_vouches_for_what_it_may_hold() {
        with_lpm_home(|| {
            let now = now_secs();
            record(
                "socket",
                &observed(&[("tool", Verdict::Clean, now)], None, now),
            )
            .unwrap();
            let mut mine = Book::load();
            let read = mine.stamp();
            assert!(read.is_some());
            std::fs::write(cache_path("socket").unwrap(), "not json").unwrap();

            let later = Book::load();

            assert!(later.read_failed);
            assert_eq!(later.stamp(), None);
            mine.caught_up_with(&later);
            assert_eq!(mine.stamp(), read, "a failed read stands for no cache");
            assert_eq!(mine.merged_with(later).stamp(), read);
        });
    }

    #[test]
    fn a_cache_that_would_outgrow_what_lpm_reads_drops_its_oldest_verdicts() {
        let mut file = CacheFile {
            schema_version: CACHE_VERSION,
            ..CacheFile::default()
        };
        let padding = "x".repeat(200);
        let count = (MAX_CACHE_BYTES / 200) as usize + 1_000;
        for index in 0..count {
            file.verdicts.insert(
                format!("pkg:npm/{padding}-{index}@1.0.0"),
                Entry {
                    verdict: Verdict::Clean,
                    checked_at_ms: index as u64,
                },
            );
        }

        let content = fitted_cache(&mut file).unwrap();

        assert!(content.len() as u64 <= MAX_CACHE_BYTES);
        assert!(file.verdicts.len() < count);
        let newest = format!("pkg:npm/{padding}-{}@1.0.0", count - 1);
        assert!(
            file.verdicts.contains_key(&newest),
            "the newest verdicts stay"
        );
        assert!(
            !file
                .verdicts
                .contains_key(&format!("pkg:npm/{padding}-0@1.0.0"))
        );
    }

    #[test]
    fn rewriting_the_cache_gives_it_a_new_identity() {
        with_lpm_home(|| {
            let now = now_secs();
            record(
                "socket",
                &observed(&[("tool", Verdict::Clean, now)], None, now),
            )
            .unwrap();
            let before = cache_stamp().unwrap().unwrap();
            let path = cache_path("socket").unwrap();
            let content = std::fs::read(&path).unwrap();

            lpm_common::write_file_atomic(&path, content).unwrap();

            let after = cache_stamp().unwrap().unwrap();
            assert_eq!(after.size, before.size);
            assert_ne!(after.identity, before.identity);
        });
    }

    #[test]
    fn round_times_and_failures_dated_in_the_future_are_discarded() {
        with_lpm_home(|| {
            let now = now_secs();
            let ahead = now + 10 * CLOCK_SLACK_SECS;
            record("socket", &observed(&[], Some(down(None)), ahead)).unwrap();
            assert!(read_cache("socket").unwrap().failure.is_some());
            assert!(Book::load().failure().is_none());

            record("socket", &observed(&[], None, now)).unwrap();

            let file = read_cache("socket").unwrap();
            assert!(file.failure.is_none());
            assert!(file.last_round_at_ms <= ms(now + CLOCK_SLACK_SECS));
            assert!(Book::load().failure().is_none());
        });
    }

    fn read_cache(scope: &str) -> Option<CacheFile> {
        read_cache_checked(scope).ok().flatten()
    }

    fn with_lpm_home<T>(test: impl FnOnce() -> T) -> T {
        let _home = crate::test_env::isolated_lpm_home();
        test()
    }

    fn observed(
        verdicts: &[(&str, Verdict, u64)],
        failure: Option<socket::Failure>,
        at_secs: u64,
    ) -> socket::Answers {
        socket::Answers {
            verdicts: verdicts
                .iter()
                .map(|(name, verdict, at)| {
                    (
                        (name.to_string(), "1.0.0".to_string()),
                        socket::Observed {
                            verdict: verdict.clone(),
                            at_ms: ms(*at),
                        },
                    )
                })
                .collect(),
            failure,
            at_ms: ms(at_secs),
        }
    }

    fn down(retry_after: Option<u64>) -> socket::Failure {
        socket::Failure {
            reason: "down".into(),
            retry_after: retry_after.map(std::time::Duration::from_secs),
            local: false,
            transient: false,
        }
    }

    fn malware() -> Verdict {
        Verdict::Malware {
            alert: "malware".into(),
        }
    }

    #[test]
    fn a_recorded_failure_waits_as_long_as_socket_asks_within_bounds() {
        with_lpm_home(|| {
            let now = now_secs();
            for (retry_after, waits) in [
                (None, FAILED_SECS),
                (Some(5), MIN_RETRY_SECS),
                (Some(120), 120),
                (Some(10 * MAX_RETRY_SECS), MAX_RETRY_SECS),
            ] {
                record("socket", &observed(&[], Some(down(retry_after)), now)).unwrap();
                assert_eq!(
                    read_cache("socket").unwrap().failure.unwrap().retry_at_ms,
                    ms(now + waits),
                    "{retry_after:?}"
                );
            }
            assert!(Book::load().failure().is_some());
            credentials_changed();
            assert!(Book::load().failure().is_none());
        });
    }

    #[test]
    fn an_answer_from_a_slow_round_never_replaces_a_later_one_and_old_or_future_ones_are_dropped() {
        with_lpm_home(|| {
            let now = now_secs();
            record("socket", &observed(&[("tool", malware(), now)], None, now)).unwrap();
            record(
                "socket",
                &observed(&[("tool", Verdict::Clean, now - 60)], None, now + 1),
            )
            .unwrap();
            assert_eq!(
                Book::load().entry("tool", "1.0.0").unwrap().verdict,
                malware()
            );

            with_cache("socket", |file| {
                file.verdicts.insert(
                    lpm_common::npm_package_purl("old", "1.0.0"),
                    entry(Verdict::Clean, now - FORGET_SECS - 1),
                );
                file.verdicts.insert(
                    lpm_common::npm_package_purl("future", "1.0.0"),
                    entry(Verdict::Clean, now + 2 * CLOCK_SLACK_SECS),
                );
            })
            .unwrap();
            let loaded = Book::load();
            assert!(loaded.entry("old", "1.0.0").is_none());
            assert!(loaded.entry("future", "1.0.0").is_none());
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_verdict_cache_that_cant_be_read_is_left_as_it_is_and_a_corrupt_one_is_replaced() {
        with_lpm_home(|| {
            let now = now_secs();
            record("socket", &observed(&[("tool", malware(), now)], None, now)).unwrap();
            let path = cache_path("socket").unwrap();
            let before = std::fs::read(&path).unwrap();
            let mode = super::super::tests::ModeGuard::set(&path, 0o000);
            if std::fs::read(&path).is_ok() {
                return;
            }

            let recorded = record(
                "socket",
                &observed(&[("other", Verdict::Clean, now)], None, now),
            );
            drop(mode);

            assert!(recorded.is_err());
            assert_eq!(
                std::fs::read(&path).unwrap(),
                before,
                "the malware verdict another project recorded stays"
            );

            std::fs::write(&path, "{ not json").unwrap();
            record(
                "socket",
                &observed(&[("other", Verdict::Clean, now)], None, now),
            )
            .unwrap();
            assert_eq!(
                Book::load().entry("other", "1.0.0").unwrap().verdict,
                Verdict::Clean
            );
        });
    }

    #[test]
    fn answers_given_at_the_same_moment_keep_the_stricter_verdict() {
        with_lpm_home(|| {
            let now = now_secs();
            record("socket", &observed(&[("tool", malware(), now)], None, now)).unwrap();
            record(
                "socket",
                &observed(&[("tool", Verdict::Clean, now)], None, now),
            )
            .unwrap();
            assert_eq!(
                Book::load().entry("tool", "1.0.0").unwrap().verdict,
                malware()
            );
        });

        let mut mine = book(100, &[("tool", Verdict::Clean, 50)]);
        mine.absorb(&observed(&[("tool", Verdict::Pending, 50)], None, 60));
        assert_eq!(
            mine.entry("tool", "1.0.0").unwrap().verdict,
            Verdict::Pending
        );
        let theirs = book(100, &[("tool", malware(), 50)]);
        assert!(mine.differs_for(&theirs, &relied(&["tool"])));
        assert_eq!(
            mine.merged_with(theirs)
                .entry("tool", "1.0.0")
                .unwrap()
                .verdict,
            malware()
        );
    }

    #[test]
    fn a_fresh_copy_of_an_aged_verdict_counts_as_a_difference() {
        let now = 10_000_000;
        let mine = book(now, &[("tool", Verdict::Clean, now - SETTLED_SECS - 1)]);
        let theirs = book(now, &[("tool", Verdict::Clean, now - 5)]);
        let same_age = book(now, &[("tool", Verdict::Clean, now - SETTLED_SECS)]);

        assert!(mine.differs_for(&theirs, &relied(&["tool"])));
        assert!(!mine.differs_for(&same_age, &relied(&["tool"])));
    }

    #[test]
    fn merging_takes_the_caches_failure_unless_the_failure_was_found_on_this_machine() {
        let now = 10_000_000;
        let mut mine = book(now, &[]);
        mine.failure = Some(failure(now + 60, now, false));
        let recovered = book(now, &[]);
        assert!(mine.merged_with(recovered).failure.is_none());

        let mut local = book(now, &[]);
        local.failure = Some(failure(now + 60, now, true));
        assert!(local.merged_with(book(now, &[])).failure.is_some());
    }

    #[test]
    fn a_round_dates_its_failure_when_it_ends_and_never_replaces_a_newer_record() {
        let mut mine = book(100, &[]);
        mine.absorb(&observed(&[], Some(down(None)), 400));
        assert_eq!(mine.now_ms, ms(400));
        assert_eq!(
            mine.failure.as_ref().unwrap().retry_at_ms,
            ms(400 + FAILED_SECS)
        );

        with_lpm_home(|| {
            let now = now_secs();
            record("socket", &observed(&[], None, now)).unwrap();
            record("socket", &observed(&[], Some(down(None)), now - 30)).unwrap();
            assert!(read_cache("socket").unwrap().failure.is_none());

            record("socket", &observed(&[], Some(down(None)), now)).unwrap();
            record("socket", &observed(&[], None, now - 30)).unwrap();
            assert!(read_cache("socket").unwrap().failure.is_some());
        });
    }

    #[test]
    fn storing_or_removing_a_token_changes_the_credential_key() {
        let home = tempfile::tempdir().unwrap();
        let env = |token: Option<&str>| {
            crate::test_env::ScopedEnv::update([
                ("LPM_HOME", Some(home.path().as_os_str().to_owned())),
                ("SOCKET_CLI_API_TOKEN", token.map(Into::into)),
                ("SOCKET_SECURITY_API_TOKEN", None),
            ])
        };
        let without_token = env(None);
        let before = credential_key();
        credentials_changed();
        let after = credential_key();
        assert_ne!(before, after);
        drop(without_token);

        let _with_token = env(Some("token"));
        assert_ne!(credential_key(), after);
        assert!(!credential_key().contains("token"));
    }

    #[test]
    fn a_reason_found_before_asking_is_never_recorded_for_other_projects() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::ScopedEnv::update([
            ("LPM_HOME", Some(home.path().as_os_str().to_owned())),
            ("LPM_FORCE_FILE_AUTH", Some("1".into())),
            ("SOCKET_CLI_API_TOKEN", None),
            ("SOCKET_SECURITY_API_TOKEN", None),
            (socket::API_OVERRIDE_VARIABLE, None),
        ]);

        let (answers, unsaved) = ask(&[("tool".to_string(), "1.0.0".to_string())]);

        assert!(answers.failure.is_some_and(|failure| failure.local));
        assert!(unsaved.is_none());
        assert!(read_cache("socket").is_none());
    }
}
