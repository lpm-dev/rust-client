/// Run `f` with `subscriber` as this thread's default dispatcher.
///
/// While only one dispatcher exists, tracing registers a callsite through the
/// registering thread's own dispatcher, so a callsite first reached by a
/// concurrent test without a subscriber stays disabled for this one. A second
/// live dispatcher makes registration consult every subscriber.
pub(crate) fn with_default<S, T>(subscriber: S, f: impl FnOnce() -> T) -> T
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    let _registration = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tracing::subscriber::with_default(subscriber, f)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing_subscriber::layer::SubscriberExt as _;

    struct CountEvents(Arc<AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountEvents {
        fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn shared_event() {
        tracing::info!(target: "lpm_test_tracing", "shared");
    }

    #[test]
    fn subscriber_sees_callsites_first_reached_on_another_thread() {
        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(CountEvents(Arc::clone(&events)));
        super::with_default(subscriber, || {
            std::thread::spawn(shared_event).join().unwrap();
            shared_event();
        });
        assert_eq!(events.load(Ordering::Relaxed), 1);
    }
}
