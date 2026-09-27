use super::*;
use std::sync::{Mutex, Weak};
use std::time::Instant;
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

const MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;
const MAX_HISTORY_ENTRY_BYTES: usize = 512 * 1024;
const MAX_HISTORY_ENTRIES: usize = 128;
const MAX_HISTORY_FLIGHTS: usize = 256;

pub(super) struct HistoryBody {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Default)]
struct HistoryBuffer(Vec<u8>);

impl std::io::Write for HistoryBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self.0.len().saturating_add(bytes.len());
        if length > MAX_HISTORY_ENTRY_BYTES {
            return Err(std::io::Error::other(
                "history entry exceeds retention limit",
            ));
        }
        if length > self.0.capacity() {
            let capacity = length
                .next_power_of_two()
                .clamp(1024, MAX_HISTORY_ENTRY_BYTES);
            self.0
                .try_reserve_exact(capacity - self.0.len())
                .map_err(std::io::Error::other)?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl HistoryBody {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) struct HistoryEntry {
    pub(super) body: Arc<HistoryBody>,
    pub(super) expires_at: Instant,
    pub(super) etag: Option<String>,
}

#[derive(Default)]
struct HistoryState {
    generation: u64,
    entries: HashMap<String, Arc<HistoryEntry>>,
    flights: HashMap<String, Weak<tokio::sync::Mutex<()>>>,
}

pub(super) struct HistoryCache {
    state: Mutex<HistoryState>,
    budget: Arc<Semaphore>,
}

impl Default for HistoryCache {
    fn default() -> Self {
        Self {
            state: Mutex::new(HistoryState::default()),
            budget: Arc::new(Semaphore::new(MAX_HISTORY_BYTES)),
        }
    }
}

pub(super) struct HistoryFlight {
    _guard: OwnedMutexGuard<()>,
    pub(super) first: bool,
}

impl HistoryCache {
    pub(super) async fn flight(&self, key: &str) -> Option<HistoryFlight> {
        let (flight, first) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.flights.retain(|_, flight| flight.strong_count() > 0);
            if let Some(flight) = state.flights.get(key).and_then(Weak::upgrade) {
                (flight, false)
            } else {
                if state.flights.len() >= MAX_HISTORY_FLIGHTS {
                    return None;
                }
                let flight = Arc::new(tokio::sync::Mutex::new(()));
                state
                    .flights
                    .insert(key.to_owned(), Arc::downgrade(&flight));
                (flight, true)
            }
        };
        Some(HistoryFlight {
            _guard: flight.lock_owned().await,
            first,
        })
    }

    pub(super) fn lookup(&self, key: &str) -> (u64, Option<Arc<HistoryEntry>>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        state.entries.retain(|_, entry| entry.expires_at > now);
        (state.generation, state.entries.get(key).map(Arc::clone))
    }

    pub(super) fn retain(&self, bytes: Vec<u8>) -> Option<Arc<HistoryBody>> {
        let capacity = bytes.capacity();
        if capacity > MAX_HISTORY_ENTRY_BYTES {
            return None;
        }
        let permit = Arc::clone(&self.budget)
            .try_acquire_many_owned(capacity as u32)
            .ok()?;
        Some(Arc::new(HistoryBody {
            bytes,
            _permit: permit,
        }))
    }

    pub(super) fn retain_json(&self, value: &impl serde::Serialize) -> Option<Arc<HistoryBody>> {
        let mut buffer = HistoryBuffer::default();
        serde_json::to_writer(&mut buffer, value).ok()?;
        self.retain(buffer.0)
    }

    pub(super) fn retain_compact(&self, bytes: Vec<u8>) -> Option<Arc<HistoryBody>> {
        let length = bytes.len();
        if length > MAX_HISTORY_ENTRY_BYTES {
            return None;
        }
        let permit = Arc::clone(&self.budget)
            .try_acquire_many_owned(length as u32)
            .ok()?;
        Some(Arc::new(HistoryBody {
            bytes: bytes.into_boxed_slice().into_vec(),
            _permit: permit,
        }))
    }

    pub(super) fn insert(&self, key: String, generation: u64, entry: HistoryEntry) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != generation || entry.expires_at <= Instant::now() {
            return;
        }
        if state.entries.len() >= MAX_HISTORY_ENTRIES
            && let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
        {
            state.entries.remove(&oldest);
        }
        state.entries.insert(key, Arc::new(entry));
    }

    pub(super) fn with_generation(&self, generation: u64, publish: impl FnOnce()) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation == generation {
            publish();
        }
    }

    pub(super) fn invalidate(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Invalidations are rare recovery operations. One epoch also prevents
        // detached reads from publishing histories fetched before recovery.
        state.generation = state.generation.wrapping_add(1);
        state.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_retention_charges_only_the_retained_allocation_and_releases_it() {
        let cache = HistoryCache::default();
        let mut bytes = Vec::with_capacity(64 * 1024);
        bytes.extend_from_slice(b"small document");
        let length = bytes.len();
        let body = cache.retain_compact(bytes).unwrap();
        assert_eq!(body.bytes(), b"small document");
        assert_eq!(body.bytes.capacity(), length);
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES - length);
        drop(body);
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES);
    }

    #[test]
    fn compact_retention_rejects_oversized_documents_without_taking_budget() {
        let cache = HistoryCache::default();
        assert!(
            cache
                .retain_compact(vec![0; MAX_HISTORY_ENTRY_BYTES + 1])
                .is_none()
        );
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES);
    }

    fn entry(body: Arc<HistoryBody>) -> HistoryEntry {
        HistoryEntry {
            body,
            expires_at: Instant::now() + Duration::from_secs(30),
            etag: None,
        }
    }

    #[test]
    fn invalidation_rejects_history_publication_from_an_earlier_generation() {
        let cache = HistoryCache::default();
        let (generation, _) = cache.lookup("pkg");
        let body = cache.retain(vec![0; 16]).unwrap();
        cache.invalidate();
        cache.insert("pkg".into(), generation, entry(body));
        assert!(cache.lookup("pkg").1.is_none());
    }

    #[test]
    fn invalidated_projection_cannot_dispatch_a_selected_cache_write() {
        let cache = HistoryCache::default();
        let (generation, _) = cache.lookup("pkg");
        cache.invalidate();
        cache.with_generation(generation, || panic!("stale projection was published"));
    }

    #[test]
    fn expired_histories_are_removed_before_reuse() {
        let cache = HistoryCache::default();
        let body = cache.retain(vec![0; 16]).unwrap();
        let expired = HistoryEntry {
            body,
            expires_at: Instant::now() - Duration::from_secs(1),
            etag: None,
        };
        cache
            .state
            .lock()
            .unwrap()
            .entries
            .insert("pkg".into(), Arc::new(expired));
        assert!(cache.lookup("pkg").1.is_none());
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES);
    }

    #[test]
    fn retained_readers_keep_their_budget_after_cache_invalidation() {
        let cache = HistoryCache::default();
        let body = cache.retain(vec![0; MAX_HISTORY_ENTRY_BYTES]).unwrap();
        cache.insert("pkg".into(), 0, entry(Arc::clone(&body)));
        cache.invalidate();
        assert_eq!(
            cache.budget.available_permits(),
            MAX_HISTORY_BYTES - MAX_HISTORY_ENTRY_BYTES
        );
        drop(body);
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES);
    }

    #[test]
    fn history_admission_bounds_capacity_and_never_waits_for_budget() {
        let cache = HistoryCache::default();
        assert!(
            cache
                .retain(Vec::with_capacity(MAX_HISTORY_ENTRY_BYTES + 1))
                .is_none()
        );
        let mut retained = Vec::new();
        for _ in 0..MAX_HISTORY_BYTES / MAX_HISTORY_ENTRY_BYTES {
            retained.push(cache.retain(vec![0; MAX_HISTORY_ENTRY_BYTES]).unwrap());
        }
        assert!(cache.retain(vec![0]).is_none());
        assert_eq!(cache.budget.available_permits(), 0);
        drop(retained);
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES);
    }

    #[test]
    fn serialized_history_retention_rejects_oversized_values() {
        let cache = HistoryCache::default();
        assert!(
            cache
                .retain_json(&"x".repeat(MAX_HISTORY_ENTRY_BYTES))
                .is_none()
        );
        assert_eq!(cache.budget.available_permits(), MAX_HISTORY_BYTES);
        let body = cache.retain_json(&"small").unwrap();
        assert_eq!(body.bytes(), br#""small""#);
        assert!(cache.budget.available_permits() < MAX_HISTORY_BYTES);
    }

    #[tokio::test]
    async fn inactive_history_flights_do_not_accumulate() {
        let cache = HistoryCache::default();
        for index in 0..MAX_HISTORY_FLIGHTS * 2 {
            drop(cache.flight(&index.to_string()).await.unwrap());
        }
        assert!(cache.state.lock().unwrap().flights.len() <= 1);
    }
}
