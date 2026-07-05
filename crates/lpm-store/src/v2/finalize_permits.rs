use std::sync::{Arc, Condvar, Mutex, OnceLock};

pub(crate) const ENV_V2_FINALIZE_PERMITS: &str = "LPM_V2_FINALIZE_PERMITS";

static V2_FINALIZE_LIMITER: OnceLock<Option<Arc<FinalizePermitLimiter>>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct FinalizePermitLimiter {
    state: Mutex<FinalizePermitState>,
    available: Condvar,
}

#[derive(Debug)]
struct FinalizePermitState {
    available: usize,
}

impl FinalizePermitLimiter {
    pub(crate) fn new(permits: usize) -> Self {
        debug_assert!(permits > 0);
        Self {
            state: Mutex::new(FinalizePermitState { available: permits }),
            available: Condvar::new(),
        }
    }

    pub(crate) fn acquire(&self) -> FinalizePermitGuard<'_> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state.available == 0 {
            state = self
                .available
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state.available -= 1;
        FinalizePermitGuard { limiter: self }
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.available += 1;
        self.available.notify_one();
    }
}

pub(crate) struct FinalizePermitGuard<'a> {
    limiter: &'a FinalizePermitLimiter,
}

impl Drop for FinalizePermitGuard<'_> {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

pub(crate) fn parse_v2_finalize_permits(value: &str) -> Option<usize> {
    value.trim().parse::<usize>().ok().filter(|&n| n > 0)
}

fn configured_v2_finalize_permits() -> Option<usize> {
    std::env::var(ENV_V2_FINALIZE_PERMITS)
        .ok()
        .and_then(|value| parse_v2_finalize_permits(&value))
}

pub(crate) fn v2_finalize_limiter() -> Option<&'static FinalizePermitLimiter> {
    V2_FINALIZE_LIMITER
        .get_or_init(|| {
            configured_v2_finalize_permits()
                .map(FinalizePermitLimiter::new)
                .map(Arc::new)
        })
        .as_deref()
}
