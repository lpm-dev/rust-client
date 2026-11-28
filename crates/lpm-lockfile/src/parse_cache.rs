//! Reuse parsed lockfiles across reads of identical text.
//!
//! One install reads `lpm.lock` from several independent phases. Parsing and
//! validating is a pure function of the text, so a repeated read of the same
//! bytes shares the first result instead of parsing again. Entries are keyed
//! by exact length plus SHA-256 digest so raw multi-MB TOML text is not
//! retained in memory after parsing, while edited files always parse afresh.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use sha2::{Digest, Sha256};

use crate::{Lockfile, LockfileError};

/// Distinct lockfile texts kept per process; a command reads one or two.
const CAPACITY: usize = 4;

static GLOBAL: ParseCache = ParseCache::new();

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    len: usize,
    digest: [u8; 32],
}

impl CacheKey {
    fn from_text(text: &str) -> Self {
        let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        Self {
            len: text.len(),
            digest,
        }
    }
}

/// How many lockfile parses the process performed and avoided.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseCacheStats {
    /// Texts parsed and validated.
    pub parses: u64,
    /// Reads answered by an earlier parse of identical text.
    pub reuses: u64,
}

/// Parse counters for this process.
pub fn parse_cache_stats() -> ParseCacheStats {
    GLOBAL.stats()
}

pub(crate) fn parse_shared(text: &str) -> Result<Arc<Lockfile>, LockfileError> {
    GLOBAL.parse(text, Lockfile::parse_uncached)
}

struct Entry {
    key: CacheKey,
    lockfile: Arc<Lockfile>,
}

struct InFlightParse {
    state: Mutex<InFlightState>,
    ready: Condvar,
    #[cfg(test)]
    waiters: std::sync::atomic::AtomicUsize,
}

enum InFlightState {
    Pending,
    Done(Result<Arc<Lockfile>, LockfileError>),
    Aborted,
}

struct InFlightGuard<'a> {
    cache: &'a ParseCache,
    key: CacheKey,
    flight: Arc<InFlightParse>,
    result: Option<Result<Arc<Lockfile>, LockfileError>>,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        {
            let mut in_flight = self
                .cache
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(in_flight) = in_flight.as_mut() {
                in_flight.remove(&self.key);
            }
        }
        let mut state = self
            .flight
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *state = match self.result.take() {
            Some(result) => InFlightState::Done(result),
            None => InFlightState::Aborted,
        };
        self.flight.ready.notify_all();
    }
}

struct ParseCache {
    /// Most recently used first.
    entries: Mutex<Vec<Entry>>,
    in_flight: Mutex<Option<HashMap<CacheKey, Arc<InFlightParse>>>>,
    parses: AtomicU64,
    reuses: AtomicU64,
}

impl ParseCache {
    const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            in_flight: Mutex::new(None),
            parses: AtomicU64::new(0),
            reuses: AtomicU64::new(0),
        }
    }

    fn parse(
        &self,
        text: &str,
        parse: impl FnOnce(&str) -> Result<Lockfile, LockfileError>,
    ) -> Result<Arc<Lockfile>, LockfileError> {
        let key = CacheKey::from_text(text);
        loop {
            if let Some(lockfile) = self.lookup(key) {
                self.reuses.fetch_add(1, Ordering::Relaxed);
                return Ok(lockfile);
            }
            let existing_flight = {
                let mut map_slot = self
                    .in_flight
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let map = map_slot.get_or_insert_with(HashMap::new);
                if let Some(flight) = map.get(&key) {
                    Err(Arc::clone(flight))
                } else {
                    let flight = Arc::new(InFlightParse {
                        state: Mutex::new(InFlightState::Pending),
                        ready: Condvar::new(),
                        #[cfg(test)]
                        waiters: std::sync::atomic::AtomicUsize::new(0),
                    });
                    map.insert(key, Arc::clone(&flight));
                    Ok(flight)
                }
            };
            match existing_flight {
                Ok(flight) => {
                    let mut guard = InFlightGuard {
                        cache: self,
                        key,
                        flight,
                        result: None,
                    };
                    // Re-check LRU cache in case a peer finished between lookup and flight insert.
                    if let Some(lockfile) = self.lookup(key) {
                        guard.result = Some(Ok(Arc::clone(&lockfile)));
                        self.reuses.fetch_add(1, Ordering::Relaxed);
                        return Ok(lockfile);
                    }
                    match parse(text) {
                        Ok(parsed) => {
                            let lockfile = Arc::new(parsed);
                            self.parses.fetch_add(1, Ordering::Relaxed);
                            self.insert(key, &lockfile);
                            guard.result = Some(Ok(Arc::clone(&lockfile)));
                            return Ok(lockfile);
                        }
                        Err(error) => {
                            guard.result = Some(Err(error.clone()));
                            return Err(error);
                        }
                    }
                }
                Err(flight) => {
                    let mut state = flight.state.lock().unwrap_or_else(PoisonError::into_inner);
                    #[cfg(test)]
                    let mut counted_waiter = false;
                    loop {
                        match &*state {
                            InFlightState::Pending => {
                                #[cfg(test)]
                                if !counted_waiter {
                                    flight.waiters.fetch_add(1, Ordering::SeqCst);
                                    counted_waiter = true;
                                }
                                state = flight
                                    .ready
                                    .wait(state)
                                    .unwrap_or_else(PoisonError::into_inner);
                            }
                            InFlightState::Done(Ok(lockfile)) => {
                                self.reuses.fetch_add(1, Ordering::Relaxed);
                                return Ok(Arc::clone(lockfile));
                            }
                            InFlightState::Done(Err(error)) => {
                                return Err(error.clone());
                            }
                            InFlightState::Aborted => break,
                        }
                    }
                }
            }
        }
    }

    fn lookup(&self, key: CacheKey) -> Option<Arc<Lockfile>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let index = entries.iter().position(|entry| entry.key == key)?;
        let entry = entries.remove(index);
        let lockfile = Arc::clone(&entry.lockfile);
        entries.insert(0, entry);
        Some(lockfile)
    }

    fn insert(&self, key: CacheKey, lockfile: &Arc<Lockfile>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.iter().any(|entry| entry.key == key) {
            return;
        }
        entries.insert(
            0,
            Entry {
                key,
                lockfile: Arc::clone(lockfile),
            },
        );
        entries.truncate(CAPACITY);
    }

    fn stats(&self) -> ParseCacheStats {
        ParseCacheStats {
            parses: self.parses.load(Ordering::Relaxed),
            reuses: self.reuses.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn lockfile_text(version: &str) -> String {
        let mut lockfile = Lockfile::new();
        lockfile.metadata.lockfile_version = crate::LOCKFILE_VERSION_WITH_STRUCTURED_PEERS;
        lockfile.add_package(crate::LockedPackage {
            name: "left-pad".to_string(),
            version: version.to_string(),
            ..crate::LockedPackage::default()
        });
        lockfile.to_toml().unwrap()
    }

    fn counting_parse(
        calls: &Cell<usize>,
    ) -> impl Fn(&str) -> Result<Lockfile, LockfileError> + '_ {
        |text| {
            calls.set(calls.get() + 1);
            Lockfile::parse_uncached(text)
        }
    }

    #[test]
    fn identical_text_shares_the_first_parse() {
        let cache = ParseCache::new();
        let calls = Cell::new(0);
        let first = cache
            .parse(&lockfile_text("1.0.0"), counting_parse(&calls))
            .unwrap();
        let second = cache
            .parse(&lockfile_text("1.0.0"), counting_parse(&calls))
            .unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(calls.get(), 1);
        assert_eq!(
            cache.stats(),
            ParseCacheStats {
                parses: 1,
                reuses: 1
            }
        );
    }

    #[test]
    fn edited_text_is_parsed_again() {
        let cache = ParseCache::new();
        let calls = Cell::new(0);

        let first = cache
            .parse(&lockfile_text("1.0.0"), counting_parse(&calls))
            .unwrap();
        let edited = cache
            .parse(&lockfile_text("1.0.1"), counting_parse(&calls))
            .unwrap();

        assert_eq!(calls.get(), 2);
        assert_eq!(first.packages[0].version, "1.0.0");
        assert_eq!(edited.packages[0].version, "1.0.1");
    }

    #[test]
    fn failed_parses_are_not_kept() {
        let cache = ParseCache::new();
        let calls = Cell::new(0);

        for _ in 0..2 {
            assert!(cache.parse("packages = [", counting_parse(&calls)).is_err());
        }

        assert_eq!(calls.get(), 2);
        assert_eq!(cache.stats(), ParseCacheStats::default());
    }

    #[test]
    fn least_recently_used_text_is_evicted_beyond_capacity() {
        let cache = ParseCache::new();
        let calls = Cell::new(0);
        let texts: Vec<_> = (0..=CAPACITY)
            .map(|patch| lockfile_text(&format!("1.0.{patch}")))
            .collect();
        for text in &texts[..CAPACITY] {
            cache.parse(text, counting_parse(&calls)).unwrap();
        }
        cache.parse(&texts[0], counting_parse(&calls)).unwrap();
        cache
            .parse(&texts[CAPACITY], counting_parse(&calls))
            .unwrap();
        assert_eq!(calls.get(), CAPACITY + 1);

        cache.parse(&texts[0], counting_parse(&calls)).unwrap();
        assert_eq!(calls.get(), CAPACITY + 1, "recently used text was evicted");
        cache.parse(&texts[1], counting_parse(&calls)).unwrap();
        assert_eq!(calls.get(), CAPACITY + 2, "oldest text was kept");
    }

    #[test]
    fn concurrent_identical_misses_coalesce_into_a_single_parse() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        let cache = Arc::new(ParseCache::new());
        let text = Arc::new(lockfile_text("2.0.0"));
        let barrier = Arc::new(Barrier::new(4));
        let parse_calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(4);
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            let text = Arc::clone(&text);
            let barrier = Arc::clone(&barrier);
            let parse_calls = Arc::clone(&parse_calls);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                cache
                    .parse(&text, |input| {
                        parse_calls.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        Lockfile::parse_uncached(input)
                    })
                    .unwrap()
            }));
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(parse_calls.load(Ordering::SeqCst), 1);
        for result in &results[1..] {
            assert!(Arc::ptr_eq(&results[0], result));
        }
        assert_eq!(
            cache.stats(),
            ParseCacheStats {
                parses: 1,
                reuses: 3,
            }
        );
    }

    #[test]
    fn concurrent_corrupt_lockfile_reads_share_one_failure_and_do_not_cache_errors() {
        use std::sync::atomic::AtomicUsize;

        let cache = Arc::new(ParseCache::new());
        let corrupt = Arc::new("not valid toml === [[[".to_string());
        let key = CacheKey::from_text(&corrupt);
        let parse_calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);

        let leader = {
            let cache = Arc::clone(&cache);
            let corrupt = Arc::clone(&corrupt);
            let parse_calls = Arc::clone(&parse_calls);
            std::thread::spawn(move || {
                cache.parse(&corrupt, |input| {
                    parse_calls.fetch_add(1, Ordering::SeqCst);
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Lockfile::parse_uncached(input)
                })
            })
        };

        // Ensure the leader holds the `in_flight` slot before spawning followers.
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("leader must enter parse");

        let mut followers = Vec::with_capacity(3);
        for _ in 0..3 {
            let cache = Arc::clone(&cache);
            let corrupt = Arc::clone(&corrupt);
            let parse_calls = Arc::clone(&parse_calls);
            followers.push(std::thread::spawn(move || {
                cache.parse(&corrupt, |input| {
                    parse_calls.fetch_add(1, Ordering::SeqCst);
                    Lockfile::parse_uncached(input)
                })
            }));
        }

        // Deterministically wait until all 3 followers are parked on the leader's Condvar.
        let flight = {
            let map = cache.in_flight.lock().unwrap();
            Arc::clone(map.as_ref().unwrap().get(&key).unwrap())
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while flight.waiters.load(Ordering::SeqCst) < 3 {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for followers to park on in-flight parse"
            );
            std::thread::yield_now();
        }
        release_tx.send(()).unwrap();

        assert!(leader.join().unwrap().is_err());
        for handle in followers {
            assert!(
                handle.join().unwrap().is_err(),
                "every concurrent reader of corrupt text must receive the parse error"
            );
        }
        assert_eq!(
            parse_calls.load(Ordering::SeqCst),
            1,
            "concurrent waiters on the same corrupt text must share a single parse failure"
        );

        // Retrying the exact same corrupt text must re-parse (errors are never cached).
        let retry = cache.parse(&corrupt, |input| {
            parse_calls.fetch_add(1, Ordering::SeqCst);
            Lockfile::parse_uncached(input)
        });
        assert!(retry.is_err());
        assert_eq!(
            parse_calls.load(Ordering::SeqCst),
            2,
            "parse errors must not be cached for subsequent calls"
        );

        let valid = lockfile_text("3.0.0");
        assert!(cache.parse(&valid, Lockfile::parse_uncached).is_ok());
    }
}
