use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

tokio::task_local! {
    static CANCELLED: Arc<AtomicBool>;
}

pub(crate) fn cancellation_flag() -> Arc<AtomicBool> {
    CANCELLED.try_with(Arc::clone).unwrap_or_default()
}

pub(super) struct SignalCancellation {
    flag: Arc<AtomicBool>,
    #[cfg(unix)]
    registrations: Vec<signal_hook::SigId>,
    #[cfg(not(unix))]
    listener: tokio::task::JoinHandle<()>,
}

impl SignalCancellation {
    pub(super) fn new() -> std::io::Result<Self> {
        let flag = Arc::new(AtomicBool::new(false));
        #[cfg(unix)]
        {
            let mut guard = Self {
                flag,
                registrations: Vec::with_capacity(2),
            };
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                guard.registrations.push(signal_hook::flag::register(
                    signal,
                    Arc::clone(&guard.flag),
                )?);
            }
            Ok(guard)
        }
        #[cfg(not(unix))]
        {
            let listener_flag = Arc::clone(&flag);
            let listener = tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    listener_flag.store(true, std::sync::atomic::Ordering::Release);
                }
            });
            Ok(Self { flag, listener })
        }
    }

    pub(super) async fn scope<F: Future>(&self, future: F) -> F::Output {
        CANCELLED.scope(Arc::clone(&self.flag), future).await
    }
}

impl Drop for SignalCancellation {
    fn drop(&mut self) {
        #[cfg(unix)]
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
        #[cfg(not(unix))]
        self.listener.abort();
    }
}
