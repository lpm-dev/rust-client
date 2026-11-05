//! Counts of the work a reader or writer does, which tests assert on: a
//! slower algorithm shows up as more work, not as more time. Counting is
//! compiled into tests only.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Work {
    /// One keyed digest of a value.
    ValueDigest,
    /// One part decoded and checked.
    PartDecode,
    /// One tracked key a rebuild looked at to resolve or reconcile it.
    KeyVisit,
    /// One step through a removal review's rename groups.
    AliasStep,
}

#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::RefCell<std::collections::HashMap<&'static str, usize>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

#[cfg(test)]
fn name(work: Work) -> &'static str {
    match work {
        Work::ValueDigest => "value digest",
        Work::PartDecode => "part decode",
        Work::KeyVisit => "key visit",
        Work::AliasStep => "alias step",
    }
}

#[inline]
pub(crate) fn note(work: Work) {
    #[cfg(test)]
    COUNTS.with_borrow_mut(|counts| *counts.entry(name(work)).or_default() += 1);
    #[cfg(not(test))]
    let _ = work;
}

/// How much of `work` this thread has done since the last reset.
#[cfg(test)]
pub(crate) fn count(work: Work) -> usize {
    COUNTS.with_borrow(|counts| counts.get(name(work)).copied().unwrap_or_default())
}

#[cfg(test)]
pub(crate) fn reset() {
    COUNTS.with_borrow_mut(std::collections::HashMap::clear);
}
