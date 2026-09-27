//! Reuse parsed lockfiles across reads of identical text.
//!
//! One install reads `lpm.lock` from several independent phases. Parsing and
//! validating is a pure function of the text, so a repeated read of the same
//! bytes shares the first result instead of parsing again. Entries are keyed
//! by the full text, never by a path or timestamp, so an edited file is always
//! parsed afresh.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Lockfile, LockfileError};

/// Distinct lockfile texts kept per process; a command reads one or two.
const CAPACITY: usize = 4;

static GLOBAL: ParseCache = ParseCache::new();

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
    text: Arc<str>,
    lockfile: Arc<Lockfile>,
}

struct ParseCache {
    /// Most recently used first.
    entries: Mutex<Vec<Entry>>,
    parses: AtomicU64,
    reuses: AtomicU64,
}

impl ParseCache {
    const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            parses: AtomicU64::new(0),
            reuses: AtomicU64::new(0),
        }
    }

    fn parse(
        &self,
        text: &str,
        parse: impl FnOnce(&str) -> Result<Lockfile, LockfileError>,
    ) -> Result<Arc<Lockfile>, LockfileError> {
        if let Some(lockfile) = self.lookup(text) {
            self.reuses.fetch_add(1, Ordering::Relaxed);
            return Ok(lockfile);
        }
        // Parse outside the lock; a concurrent parse of the same text only
        // duplicates work.
        let lockfile = Arc::new(parse(text)?);
        self.parses.fetch_add(1, Ordering::Relaxed);
        self.insert(text, &lockfile);
        Ok(lockfile)
    }

    fn lookup(&self, text: &str) -> Option<Arc<Lockfile>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let index = entries.iter().position(|entry| *entry.text == *text)?;
        let entry = entries.remove(index);
        let lockfile = Arc::clone(&entry.lockfile);
        entries.insert(0, entry);
        Some(lockfile)
    }

    fn insert(&self, text: &str, lockfile: &Arc<Lockfile>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.iter().any(|entry| *entry.text == *text) {
            return;
        }
        entries.insert(
            0,
            Entry {
                text: Arc::from(text),
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
}
