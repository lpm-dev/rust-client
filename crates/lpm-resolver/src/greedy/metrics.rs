use super::prelude::*;

// Metrics helpers — wrap the `pub(crate)` increment methods on
// `StreamingBfsMetrics` so the call sites in `ensure_manifest` stay
// readable. Each is a one-line forwarder; kept private here.
pub(super) fn metrics_incr_cache_wait(_m: &StreamingBfsMetrics) {
    // The fields on `StreamingBfsMetrics` are private to `provider`;
    // greedy uses the public counter readback at install.rs JSON time
    // and doesn't need to bump them here. Left as a no-op stub so we
    // can wire telemetry symmetrically once the metrics surface is widened.
}
pub(super) fn metrics_incr_timeout(_m: &StreamingBfsMetrics) {}
pub(super) fn metrics_incr_escape_hatch(_m: &StreamingBfsMetrics) {}
