use super::dev_ui;
use crate::install_ui;
use lpm_common::color::Painted;
use lpm_common::{LocalScheme, LocalTarget, LpmError};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

struct LocalProxyRuntime {
    lease: lpm_proxy::RouteLease,
    bridges: Vec<lpm_proxy::HttpProxyHandle>,
    routes: Vec<lpm_proxy::Route>,
}

struct TunnelReadyPublication {
    session: lpm_tunnel::TunnelSession,
    local_target_url: String,
    tunnel_auth: Option<String>,
    usage: Option<lpm_tunnel::TunnelUsageMetadata>,
}

#[derive(Clone)]
struct TunnelShutdownBoundary {
    state: Arc<Mutex<TunnelShutdownState>>,
}

struct TunnelShutdownState {
    request: Option<tokio::sync::oneshot::Sender<()>>,
    completion: Option<std::sync::mpsc::Receiver<()>>,
}

struct TunnelTaskCompletion(Option<std::sync::mpsc::Sender<()>>);

impl TunnelShutdownBoundary {
    fn new() -> (
        Self,
        tokio::sync::oneshot::Receiver<()>,
        TunnelTaskCompletion,
    ) {
        let (request, request_rx) = tokio::sync::oneshot::channel();
        let (completion, completion_rx) = std::sync::mpsc::channel();
        (
            Self {
                state: Arc::new(Mutex::new(TunnelShutdownState {
                    request: Some(request),
                    completion: Some(completion_rx),
                })),
            },
            request_rx,
            TunnelTaskCompletion(Some(completion)),
        )
    }

    fn request(&self) -> Result<(), LpmError> {
        let request = self
            .state
            .lock()
            .map_err(|_| LpmError::Tunnel("tunnel shutdown state is poisoned".into()))?
            .request
            .take();
        if let Some(request) = request {
            let _ = request.send(());
        }
        Ok(())
    }

    fn request_and_wait(&self) -> Result<(), LpmError> {
        let completion = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LpmError::Tunnel("tunnel shutdown state is poisoned".into()))?;
            if let Some(request) = state.request.take() {
                let _ = request.send(());
            }
            state.completion.take()
        };
        let Some(completion) = completion else {
            return Ok(());
        };
        completion
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    LpmError::Tunnel("tunnel did not acknowledge shutdown within 5 seconds".into())
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    LpmError::Tunnel("tunnel shutdown acknowledgement channel closed".into())
                }
            })
    }
}

impl Drop for TunnelTaskCompletion {
    fn drop(&mut self) {
        if let Some(completion) = self.0.take() {
            let _ = completion.send(());
        }
    }
}

struct ProxyRoutePublisher {
    command_tx: tokio::sync::mpsc::UnboundedSender<ProxyPublisherCommand>,
    worker: tokio::task::JoinHandle<()>,
}

enum ProxyPublisherCommand {
    Prepare {
        routes: Vec<lpm_proxy::Route>,
        bridges: Vec<lpm_proxy::HttpProxyHandle>,
        reply: tokio::sync::oneshot::Sender<Result<u64, LpmError>>,
    },
    Finalize {
        publication_id: u64,
        reply: tokio::sync::oneshot::Sender<Result<(), LpmError>>,
    },
    Accept {
        publication_id: u64,
    },
    Restore {
        publication_id: u64,
        reply: Option<tokio::sync::oneshot::Sender<Result<(), LpmError>>>,
    },
    Rollback {
        publication_id: u64,
        reply: Option<tokio::sync::oneshot::Sender<Result<(), LpmError>>>,
    },
    Release {
        reply: tokio::sync::oneshot::Sender<Result<(), LpmError>>,
    },
    #[cfg(test)]
    Snapshot {
        reply: tokio::sync::oneshot::Sender<Vec<lpm_proxy::Route>>,
    },
}

struct PendingProxyPublication {
    publication_id: u64,
    routes: Vec<lpm_proxy::Route>,
    bridges: Vec<lpm_proxy::HttpProxyHandle>,
}

struct CommittedProxyPublication {
    publication_id: u64,
    previous_routes: Vec<lpm_proxy::Route>,
    previous_bridges: Vec<lpm_proxy::HttpProxyHandle>,
}

impl ProxyRoutePublisher {
    fn start(runtime: LocalProxyRuntime) -> Self {
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
        let worker = tokio::spawn(run_proxy_route_publisher(runtime, command_rx));
        Self { command_tx, worker }
    }

    async fn release(self) -> Result<(), LpmError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let send_result = self
            .command_tx
            .send(ProxyPublisherCommand::Release { reply });
        drop(self.command_tx);
        let release_result = if send_result.is_ok() {
            response.await.map_err(|_| {
                LpmError::Script("local proxy route publisher stopped during release".into())
            })?
        } else {
            Err(LpmError::Script(
                "local proxy route publisher stopped before release".into(),
            ))
        };
        self.worker.await.map_err(|error| {
            LpmError::Script(format!("local proxy route publisher task failed: {error}"))
        })?;
        release_result
    }
}

type ProxyLeaseSlot = Arc<tokio::sync::Mutex<Option<ProxyRoutePublisher>>>;

struct PreparedProxyRoutePlan {
    command_tx: tokio::sync::mpsc::UnboundedSender<ProxyPublisherCommand>,
    publication_id: u64,
    finalized: bool,
}

struct PublishedProxyRoutePlan {
    command_tx: tokio::sync::mpsc::UnboundedSender<ProxyPublisherCommand>,
    publication_id: u64,
    finalized: bool,
}

impl PreparedProxyRoutePlan {
    async fn finalize(self) -> Result<(), LpmError> {
        self.commit_reversible().await?.finalize();
        Ok(())
    }

    async fn commit_reversible(mut self) -> Result<PublishedProxyRoutePlan, LpmError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(ProxyPublisherCommand::Finalize {
                publication_id: self.publication_id,
                reply,
            })
            .map_err(|_| {
                LpmError::Script("local proxy route publisher stopped before finalization".into())
            })?;
        let result = response.await.map_err(|_| {
            LpmError::Script("local proxy route publisher stopped during finalization".into())
        })?;
        self.finalized = true;
        result?;
        Ok(PublishedProxyRoutePlan {
            command_tx: self.command_tx.clone(),
            publication_id: self.publication_id,
            finalized: false,
        })
    }

    async fn rollback(mut self) -> Result<(), LpmError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(ProxyPublisherCommand::Rollback {
                publication_id: self.publication_id,
                reply: Some(reply),
            })
            .map_err(|_| {
                LpmError::Script("local proxy route publisher stopped before rollback".into())
            })?;
        let result = response.await.map_err(|_| {
            LpmError::Script("local proxy route publisher stopped during rollback".into())
        })?;
        if result.is_ok() {
            self.finalized = true;
        }
        result
    }
}

impl PublishedProxyRoutePlan {
    fn finalize(mut self) {
        if self
            .command_tx
            .send(ProxyPublisherCommand::Accept {
                publication_id: self.publication_id,
            })
            .is_err()
        {
            tracing::error!("local proxy route publisher stopped before acceptance");
        }
        self.finalized = true;
    }

    async fn rollback(mut self) -> Result<(), LpmError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(ProxyPublisherCommand::Restore {
                publication_id: self.publication_id,
                reply: Some(reply),
            })
            .map_err(|_| {
                LpmError::Script("local proxy route publisher stopped before restoration".into())
            })?;
        let result = response.await.map_err(|_| {
            LpmError::Script("local proxy route publisher stopped during restoration".into())
        })?;
        if result.is_ok() {
            self.finalized = true;
        }
        result
    }
}

impl Drop for PreparedProxyRoutePlan {
    fn drop(&mut self) {
        if !self.finalized
            && self
                .command_tx
                .send(ProxyPublisherCommand::Rollback {
                    publication_id: self.publication_id,
                    reply: None,
                })
                .is_err()
        {
            tracing::error!("local proxy route publisher stopped before automatic rollback");
        }
    }
}

impl Drop for PublishedProxyRoutePlan {
    fn drop(&mut self) {
        if !self.finalized
            && self
                .command_tx
                .send(ProxyPublisherCommand::Restore {
                    publication_id: self.publication_id,
                    reply: None,
                })
                .is_err()
        {
            tracing::error!("local proxy route publisher stopped before automatic restoration");
        }
    }
}

async fn run_proxy_route_publisher(
    mut runtime: LocalProxyRuntime,
    mut command_rx: tokio::sync::mpsc::UnboundedReceiver<ProxyPublisherCommand>,
) {
    let mut pending = None::<PendingProxyPublication>;
    let mut committed = None::<CommittedProxyPublication>;
    let mut next_publication_id = 1u64;
    let mut failed_closed = None::<String>;

    while let Some(command) = command_rx.recv().await {
        match command {
            ProxyPublisherCommand::Prepare {
                routes,
                bridges,
                reply,
            } => {
                if let Some(error) = failed_closed.as_ref() {
                    let _ = reply.send(Err(LpmError::Script(error.clone())));
                    continue;
                }
                if pending.is_some() || committed.is_some() {
                    let _ = reply.send(Err(LpmError::Script(
                        "local proxy route publication is already pending acceptance".into(),
                    )));
                    continue;
                }
                let publication_id = next_publication_id;
                next_publication_id = next_publication_id.wrapping_add(1).max(1);
                match runtime
                    .lease
                    .stage_routes(publication_id, routes.clone())
                    .await
                {
                    Ok(()) => {
                        pending = Some(PendingProxyPublication {
                            publication_id,
                            routes,
                            bridges,
                        });
                        if reply.send(Ok(publication_id)).is_err()
                            && let Err(error) = rollback_proxy_publication(
                                &mut runtime,
                                &mut pending,
                                &mut failed_closed,
                                publication_id,
                            )
                            .await
                        {
                            tracing::error!(
                                "cancelled local proxy route publication could not roll back: {error}"
                            );
                        }
                    }
                    Err(error) => {
                        let error = map_proxy_register_error(error);
                        if runtime.lease.lease_id().is_none() {
                            fail_proxy_publisher_closed(
                                &mut runtime,
                                &mut pending,
                                &mut failed_closed,
                                &error,
                            );
                        }
                        let _ = reply.send(Err(error));
                    }
                }
            }
            ProxyPublisherCommand::Finalize {
                publication_id,
                reply,
            } => {
                let result = commit_proxy_publication(
                    &mut runtime,
                    &mut pending,
                    &mut failed_closed,
                    publication_id,
                )
                .await;
                match result {
                    Ok(publication) => {
                        committed = Some(publication);
                        if reply.send(Ok(())).is_err()
                            && let Err(error) = restore_proxy_publication(
                                &mut runtime,
                                &mut committed,
                                publication_id,
                            )
                            .await
                        {
                            tracing::error!(
                                "cancelled local proxy route finalization could not restore the previous generation: {error}"
                            );
                        }
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            ProxyPublisherCommand::Accept { publication_id } => {
                if let Err(error) = accept_proxy_publication(&mut committed, publication_id) {
                    tracing::error!("local proxy route acceptance failed: {error}");
                }
            }
            ProxyPublisherCommand::Restore {
                publication_id,
                reply,
            } => {
                let result =
                    restore_proxy_publication(&mut runtime, &mut committed, publication_id).await;
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                } else if let Err(error) = result {
                    tracing::error!("automatic local proxy route restoration failed: {error}");
                }
            }
            ProxyPublisherCommand::Rollback {
                publication_id,
                reply,
            } => {
                let result = if let Some(error) = failed_closed.as_ref() {
                    Err(LpmError::Script(error.clone()))
                } else {
                    rollback_proxy_publication(
                        &mut runtime,
                        &mut pending,
                        &mut failed_closed,
                        publication_id,
                    )
                    .await
                };
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                } else if let Err(error) = result {
                    tracing::error!("automatic local proxy route rollback failed: {error}");
                }
            }
            ProxyPublisherCommand::Release { reply } => {
                let result = runtime.lease.release().await.map(|_| ()).map_err(|error| {
                    LpmError::Script(format!("local proxy route release failed: {error}"))
                });
                let _ = reply.send(result);
                return;
            }
            #[cfg(test)]
            ProxyPublisherCommand::Snapshot { reply } => {
                let _ = reply.send(runtime.routes.clone());
            }
        }
    }

    if let Err(error) = runtime.lease.release().await {
        tracing::error!("local proxy route publisher shutdown failed: {error}");
    }
}

async fn rollback_proxy_publication(
    runtime: &mut LocalProxyRuntime,
    pending: &mut Option<PendingProxyPublication>,
    failed_closed: &mut Option<String>,
    publication_id: u64,
) -> Result<(), LpmError> {
    let candidate = pending.as_ref().ok_or_else(|| {
        LpmError::Script(format!(
            "local proxy route publication {publication_id} is not pending"
        ))
    })?;
    if candidate.publication_id != publication_id {
        return Err(LpmError::Script(format!(
            "local proxy route publication {publication_id} cannot roll back pending publication {}",
            candidate.publication_id,
        )));
    }
    match runtime.lease.rollback_routes(publication_id).await {
        Ok(()) => {
            pending.take();
            Ok(())
        }
        Err(error) => {
            let error = map_proxy_register_error(error);
            if runtime.lease.lease_id().is_none() {
                fail_proxy_publisher_closed(runtime, pending, failed_closed, &error);
            }
            Err(error)
        }
    }
}

async fn commit_proxy_publication(
    runtime: &mut LocalProxyRuntime,
    pending: &mut Option<PendingProxyPublication>,
    failed_closed: &mut Option<String>,
    publication_id: u64,
) -> Result<CommittedProxyPublication, LpmError> {
    if let Some(error) = failed_closed.as_ref() {
        return Err(LpmError::Script(error.clone()));
    }
    let candidate = pending.as_ref().ok_or_else(|| {
        LpmError::Script(format!(
            "local proxy route publication {publication_id} is not pending"
        ))
    })?;
    if candidate.publication_id != publication_id {
        return Err(LpmError::Script(format!(
            "local proxy route publication {publication_id} cannot commit pending publication {}",
            candidate.publication_id,
        )));
    }

    match runtime.lease.commit_routes(publication_id).await {
        Ok(()) => {
            let candidate = pending
                .take()
                .expect("validated proxy publication must remain pending");
            Ok(CommittedProxyPublication {
                publication_id,
                previous_routes: std::mem::replace(&mut runtime.routes, candidate.routes),
                previous_bridges: std::mem::replace(&mut runtime.bridges, candidate.bridges),
            })
        }
        Err(commit_error) => {
            let commit_error = map_proxy_register_error(commit_error);
            if runtime.lease.lease_id().is_none() {
                fail_proxy_publisher_closed(runtime, pending, failed_closed, &commit_error);
                return Err(commit_error);
            }
            match runtime.lease.rollback_routes(publication_id).await {
                Ok(()) => {
                    pending.take();
                    Err(commit_error)
                }
                Err(rollback_error) => {
                    let rollback_error = map_proxy_register_error(rollback_error);
                    if runtime.lease.lease_id().is_none() {
                        fail_proxy_publisher_closed(
                            runtime,
                            pending,
                            failed_closed,
                            &rollback_error,
                        );
                    }
                    Err(LpmError::Script(format!(
                        "{commit_error}; discarding the staged proxy routes also failed: {rollback_error}"
                    )))
                }
            }
        }
    }
}

fn accept_proxy_publication(
    committed: &mut Option<CommittedProxyPublication>,
    publication_id: u64,
) -> Result<(), LpmError> {
    let publication = committed.as_ref().ok_or_else(|| {
        LpmError::Script(format!(
            "local proxy route publication {publication_id} is not awaiting acceptance"
        ))
    })?;
    if publication.publication_id != publication_id {
        return Err(LpmError::Script(format!(
            "local proxy route publication {publication_id} cannot accept publication {}",
            publication.publication_id,
        )));
    }
    committed.take();
    Ok(())
}

async fn restore_proxy_publication(
    runtime: &mut LocalProxyRuntime,
    committed: &mut Option<CommittedProxyPublication>,
    publication_id: u64,
) -> Result<(), LpmError> {
    let publication = committed.as_ref().ok_or_else(|| {
        LpmError::Script(format!(
            "local proxy route publication {publication_id} is not awaiting restoration"
        ))
    })?;
    if publication.publication_id != publication_id {
        return Err(LpmError::Script(format!(
            "local proxy route publication {publication_id} cannot restore publication {}",
            publication.publication_id,
        )));
    }
    let previous_routes = publication.previous_routes.clone();
    if let Err(error) = runtime.lease.replace_routes(previous_routes).await {
        let error = map_proxy_register_error(error);
        if runtime.lease.lease_id().is_none() {
            runtime.routes.clear();
            runtime.bridges.clear();
            committed.take();
        }
        return Err(error);
    }
    let publication = committed
        .take()
        .expect("validated proxy publication must remain reversible");
    runtime.routes = publication.previous_routes;
    runtime.bridges = publication.previous_bridges;
    Ok(())
}

fn fail_proxy_publisher_closed(
    runtime: &mut LocalProxyRuntime,
    pending: &mut Option<PendingProxyPublication>,
    failed_closed: &mut Option<String>,
    error: &LpmError,
) {
    pending.take();
    runtime.routes.clear();
    runtime.bridges.clear();
    *failed_closed = Some(format!(
        "local proxy route publisher failed closed after an ambiguous control operation: {error}"
    ));
}

#[allow(clippy::too_many_arguments)]
fn publish_initial_runtime(
    runtime_handle: &tokio::runtime::Handle,
    endpoint: &lpm_runner::dev_endpoint::DevEndpoint,
    endpoints: lpm_runner::orchestrator::ServiceEndpointMap,
    active_frontends: DevFrontends,
    prepared_session: lpm_runner::dev_session::PreparedDevSession,
    frontend_slot: &Arc<Mutex<Option<DevFrontends>>>,
    dev_session_slot: &Arc<Mutex<Option<lpm_runner::dev_session::DevSessionLease>>>,
    service_endpoint_slot: &Arc<Mutex<lpm_runner::orchestrator::ServiceEndpointMap>>,
    inspector_state: Option<&lpm_inspect::state::InspectorState>,
    tunnel_live_target: Option<&Arc<RwLock<LocalTarget>>>,
    tunnel_publication: Option<&TunnelReadyPublication>,
    tunnel_published: Option<&Arc<AtomicBool>>,
    prepared_proxy_plan: Option<PreparedProxyRoutePlan>,
    before_visible_commit: impl FnOnce() -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    before_visible_commit()?;
    let mut frontends = frontend_slot
        .lock()
        .map_err(|_| LpmError::Script("dev frontend state is poisoned".into()))?;
    let mut session = dev_session_slot
        .lock()
        .map_err(|_| LpmError::Script("dev session state is poisoned".into()))?;
    let mut published_endpoints = service_endpoint_slot
        .lock()
        .map_err(|_| LpmError::Script("service endpoint state is poisoned".into()))?;
    let mut tunnel_target = tunnel_live_target
        .map(|target| {
            target
                .write()
                .map_err(|_| LpmError::Tunnel("tunnel endpoint state is poisoned".into()))
        })
        .transpose()?;
    let published_proxy = match prepared_proxy_plan {
        Some(proxy_plan) => Some(runtime_handle.block_on(proxy_plan.commit_reversible())?),
        None => None,
    };
    let mut published_inspector_session = if let Some(publication) = tunnel_publication {
        let inspector_state = inspector_state
            .ok_or_else(|| LpmError::Tunnel("tunnel inspector state is not initialized".into()));
        let inspector_state = match inspector_state {
            Ok(state) => state,
            Err(error) => {
                return Err(rollback_published_proxy_after(
                    runtime_handle,
                    error,
                    published_proxy,
                ));
            }
        };
        let publication = match prepare_tunnel_connection(inspector_state, publication) {
            Ok(publication) => publication,
            Err(error) => {
                return Err(rollback_published_proxy_after(
                    runtime_handle,
                    error,
                    published_proxy,
                ));
            }
        };
        Some(publication)
    } else {
        None
    };

    let published_session = match prepared_session.commit() {
        Ok(session) => session,
        Err(error) => {
            let error = rollback_inspector_session_after(error, published_inspector_session);
            return Err(rollback_published_proxy_after(
                runtime_handle,
                error,
                published_proxy,
            ));
        }
    };
    if let Some(publication) = published_inspector_session.as_mut()
        && let Err(finalize_error) = publication.finalize()
    {
        let error = rollback_inspector_session_after(
            LpmError::Tunnel(format!(
                "failed to publish the inspector session: {finalize_error}"
            )),
            published_inspector_session,
        );
        return Err(rollback_published_proxy_after(
            runtime_handle,
            error,
            published_proxy,
        ));
    }
    if let Some(state) = inspector_state {
        state.set_local_target(endpoint.target.clone());
    }
    if let Some(target) = tunnel_target.as_mut() {
        **target = endpoint.target.clone();
    }
    if let Some(proxy) = published_proxy {
        proxy.finalize();
    }
    *frontends = Some(active_frontends);
    *session = Some(published_session);
    *published_endpoints = endpoints;
    if let Some(published) = tunnel_published {
        published.store(true, Ordering::Release);
    }
    if let Some(publication) = tunnel_publication {
        render_tunnel_connection(publication);
    }
    Ok(())
}

fn rollback_inspector_session_after(
    error: LpmError,
    publication: Option<lpm_inspect::state::PublishedInspectorSession>,
) -> LpmError {
    let Some(publication) = publication else {
        return error;
    };
    match publication.rollback() {
        Ok(()) => error,
        Err(rollback_error) => LpmError::Tunnel(format!(
            "{error}; restoring the inspector session also failed: {rollback_error}"
        )),
    }
}

fn rollback_published_proxy_after(
    runtime_handle: &tokio::runtime::Handle,
    error: LpmError,
    published_proxy: Option<PublishedProxyRoutePlan>,
) -> LpmError {
    let Some(published_proxy) = published_proxy else {
        return error;
    };
    match runtime_handle.block_on(published_proxy.rollback()) {
        Ok(()) => error,
        Err(rollback_error) => LpmError::Script(format!(
            "{error}; restoring local proxy routes also failed: {rollback_error}"
        )),
    }
}

fn rollback_prepared_proxy_after(
    runtime_handle: &tokio::runtime::Handle,
    error: LpmError,
    prepared_proxy: Option<PreparedProxyRoutePlan>,
) -> LpmError {
    let Some(prepared_proxy) = prepared_proxy else {
        return error;
    };
    match runtime_handle.block_on(prepared_proxy.rollback()) {
        Ok(()) => error,
        Err(rollback_error) => LpmError::Script(format!(
            "{error}; restoring local proxy routes also failed: {rollback_error}"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn publish_primary_endpoint(
    runtime_handle: &tokio::runtime::Handle,
    service: String,
    endpoint: lpm_runner::dev_endpoint::DevEndpoint,
    frontend_slot: &Arc<Mutex<Option<DevFrontends>>>,
    dev_session_slot: &Arc<Mutex<Option<lpm_runner::dev_session::DevSessionLease>>>,
    service_endpoint_slot: &Arc<Mutex<lpm_runner::orchestrator::ServiceEndpointMap>>,
    inspector_state: Option<&lpm_inspect::state::InspectorState>,
    tunnel_live_target: Option<&Arc<RwLock<LocalTarget>>>,
    prepared_session: lpm_runner::dev_session::PreparedDevSession,
    prepared_proxy_plan: Option<PreparedProxyRoutePlan>,
    before_visible_commit: impl FnOnce() -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    if let Err(error) = before_visible_commit() {
        return Err(rollback_prepared_proxy_after(
            runtime_handle,
            error,
            prepared_proxy_plan,
        ));
    }

    let mut frontends = match frontend_slot.lock() {
        Ok(frontends) => frontends,
        Err(_) => {
            return Err(rollback_prepared_proxy_after(
                runtime_handle,
                LpmError::Script("dev frontend state is poisoned".to_string()),
                prepared_proxy_plan,
            ));
        }
    };
    let frontends = match frontends.as_mut() {
        Some(frontends) => frontends,
        None => {
            return Err(rollback_prepared_proxy_after(
                runtime_handle,
                LpmError::Script("dev frontend state is not initialized".to_string()),
                prepared_proxy_plan,
            ));
        }
    };
    let mut session_slot = match dev_session_slot.lock() {
        Ok(session) => session,
        Err(_) => {
            return Err(rollback_prepared_proxy_after(
                runtime_handle,
                LpmError::Script("dev session state is poisoned".to_string()),
                prepared_proxy_plan,
            ));
        }
    };
    let mut endpoints = match service_endpoint_slot.lock() {
        Ok(endpoints) => endpoints,
        Err(_) => {
            return Err(rollback_prepared_proxy_after(
                runtime_handle,
                LpmError::Script("service endpoint state is poisoned".to_string()),
                prepared_proxy_plan,
            ));
        }
    };
    let mut tunnel_target = match tunnel_live_target {
        Some(target) => match target.write() {
            Ok(target) => Some(target),
            Err(_) => {
                return Err(rollback_prepared_proxy_after(
                    runtime_handle,
                    LpmError::Tunnel("tunnel endpoint state is poisoned".to_string()),
                    prepared_proxy_plan,
                ));
            }
        },
        None => None,
    };
    let previous_target = frontends.child_target.clone();
    if let Err(error) = frontends.update_child_target(endpoint.target.clone()) {
        return Err(rollback_prepared_proxy_after(
            runtime_handle,
            error,
            prepared_proxy_plan,
        ));
    }

    let published_proxy = match prepared_proxy_plan {
        Some(proxy_plan) => match runtime_handle.block_on(proxy_plan.commit_reversible()) {
            Ok(proxy) => Some(proxy),
            Err(error) => {
                let restore_error = frontends.update_child_target(previous_target).err();
                return match restore_error {
                    None => Err(error),
                    Some(restore_error) => Err(LpmError::Script(format!(
                        "{error}; restoring the local frontend also failed: {restore_error}"
                    ))),
                };
            }
        },
        None => None,
    };

    let session_lease = match prepared_session.commit() {
        Ok(session) => session,
        Err(error) => {
            let mut rollback_errors = Vec::new();
            if let Err(restore_error) = frontends.update_child_target(previous_target) {
                rollback_errors.push(format!("restore local frontend: {restore_error}"));
            }
            let error = if rollback_errors.is_empty() {
                error
            } else {
                LpmError::Script(format!(
                    "{error}; endpoint publication rollback also failed: {}",
                    rollback_errors.join("; ")
                ))
            };
            return Err(rollback_published_proxy_after(
                runtime_handle,
                error,
                published_proxy,
            ));
        }
    };
    if let Some(state) = inspector_state {
        state.set_local_target(endpoint.target.clone());
    }
    if let Some(target) = tunnel_target.as_mut() {
        **target = endpoint.target.clone();
    }
    endpoints.insert(service, endpoint);
    *session_slot = Some(session_lease);
    if let Some(proxy) = published_proxy {
        proxy.finalize();
    }
    Ok(())
}

fn show_tunnel_notice(message: &str) {
    dev_ui::warn(message);
    if message.contains("not claimed") {
        dev_ui::hint_line("Run: lpm tunnel claim <domain>");
    } else if message.contains("Pro plan") || message.contains("plan_required") {
        dev_ui::hint_line("Upgrade at: https://lpm.dev/pricing");
    } else if message.contains("concurrent") {
        dev_ui::hint_line("Close other tunnels first, or upgrade your plan");
    }
}

fn publish_tunnel_connection(
    inspector_state: &lpm_inspect::state::InspectorState,
    publication: &TunnelReadyPublication,
) -> Result<(), LpmError> {
    prepare_tunnel_connection(inspector_state, publication)?
        .finalize()
        .map_err(|error| {
            LpmError::Tunnel(format!("failed to publish the inspector session: {error}"))
        })?;
    render_tunnel_connection(publication);
    Ok(())
}

fn prepare_tunnel_connection(
    inspector_state: &lpm_inspect::state::InspectorState,
    publication: &TunnelReadyPublication,
) -> Result<lpm_inspect::state::PublishedInspectorSession, LpmError> {
    inspector_state
        .start_session_reversible(
            publication.session.session_id.clone(),
            Some(publication.session.domain.clone()),
            publication.session.local_port,
            None,
            publication.session.tunnel_url.clone(),
        )
        .map_err(|error| {
            LpmError::Tunnel(format!(
                "failed to persist inspector session start: {error}"
            ))
        })
}

fn render_tunnel_connection(publication: &TunnelReadyPublication) {
    dev_ui::trusted_detail_line(
        "Tunnel",
        install_ui::terminal_line!(
            "{} → {}",
            install_ui::url(&publication.session.tunnel_url),
            publication.local_target_url,
        ),
    );
    if let Some(expiry) =
        crate::commands::tunnel::tunnel_session_expiry_summary(&publication.session)
    {
        dev_ui::hint_line(&format!("Tunnel expires {expiry}"));
    }
    if let Some(limits) =
        crate::commands::tunnel::tunnel_limit_summary(publication.session.limits.as_ref())
    {
        dev_ui::hint_line(&format!("Tunnel limits: {limits}"));
    }
    if let Some(usage) = crate::commands::tunnel::tunnel_usage_summary(publication.usage.as_ref()) {
        dev_ui::hint_line(&format!("Tunnel usage: {usage}"));
    }
    if let Some(auth) = publication.tunnel_auth.as_deref() {
        dev_ui::hint_line(&format!(
            "Auth required: {}",
            crate::commands::tunnel::tunnel_auth_header_summary(
                auth,
                std::io::stderr().is_terminal(),
            )
        ));
    }
}

async fn prepare_service_runtime_hints(
    project_dir: &Path,
    services: &HashMap<String, lpm_runner::lpm_json::ServiceConfig>,
    root_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
) -> Result<HashMap<String, lpm_runner::bin_path::ManagedRuntimeHint>, LpmError> {
    let mut hints = HashMap::with_capacity(services.len());
    let mut hints_by_directory = HashMap::with_capacity(services.len());
    let mut node_versions = lpm_runtime::effective::PathNodeVersionCache::default();
    let project_root = project_dir.canonicalize().map_err(|error| {
        LpmError::Script(format!(
            "resolve dev project directory {}: {error}",
            project_dir.display()
        ))
    })?;
    hints_by_directory.insert(project_root.clone(), root_hint.clone());
    let mut ordered_names: Vec<_> = services.keys().cloned().collect();
    ordered_names.sort_unstable();
    for name in ordered_names {
        let config = &services[&name];
        let service_dir = config
            .cwd
            .as_deref()
            .map(|cwd| lpm_runner::orchestrator::safe_resolve_cwd(project_dir, cwd))
            .transpose()
            .map_err(|error| LpmError::Script(format!("service '{name}': {error}")))?
            .unwrap_or_else(|| project_root.clone());
        let hint = if let Some(hint) = hints_by_directory.get(&service_dir) {
            hint.clone()
        } else {
            let selectors = lpm_runtime::detect::detect_runtime_versions(&service_dir)?;
            let hint = if selectors.is_empty() {
                root_hint.clone()
            } else {
                let selected_runtimes: Vec<_> =
                    selectors.iter().map(|selector| selector.runtime).collect();
                super::run::ensure_detected_runtimes(selectors)
                    .await
                    .inherit_unselected_from(root_hint, &selected_runtimes)
            };
            super::run::validate_runtime_with_cache(
                &service_dir,
                &hint,
                false,
                &mut node_versions,
            )?;
            hints_by_directory.insert(service_dir, hint.clone());
            hint
        };
        hints.insert(name, hint);
    }
    Ok(hints)
}

struct DevCertSetup {
    setup: lpm_cert::HttpsSetup,
    inject_env: bool,
}

#[derive(Clone)]
struct DevTlsMaterial {
    cert_pem: Arc<[u8]>,
    key_pem: Arc<[u8]>,
    _runtime_lease: lpm_cert::RuntimeCertificateLease,
}

struct DevFrontends {
    child_target: LocalTarget,
    local_target: LocalTarget,
    network_port: Option<u16>,
    upstream: Option<lpm_proxy::FrontendUpstream>,
    handles: Vec<lpm_proxy::HttpProxyHandle>,
}

impl DevFrontends {
    fn validate_child_target(&self, child_target: &LocalTarget) -> Result<(), LpmError> {
        for handle in &self.handles {
            handle
                .validate_upstream_update(child_target)
                .map_err(|error| {
                    LpmError::Script(format!("update LPM dev frontend upstream: {error}"))
                })?;
        }
        Ok(())
    }

    fn update_child_target(&mut self, child_target: LocalTarget) -> Result<(), LpmError> {
        self.validate_child_target(&child_target)?;
        if let Some(upstream) = &self.upstream {
            upstream.update(child_target.clone()).map_err(|error| {
                LpmError::Script(format!("update LPM dev frontend upstream: {error}"))
            })?;
        }
        if self.handles.is_empty() {
            self.local_target = child_target.clone();
        } else {
            self.local_target.base_path = child_target.base_path.clone();
        }
        self.child_target = child_target;
        Ok(())
    }
}

/// Build the consent value for `ensure_https_with_consent` based on the dev flags.
///
/// - `--yes` → PreApproved.
/// - Otherwise → Prompt(callback). The callback enforces the TTY requirement
///   only when consent is actually needed; if the CA is already trusted, the
///   callback is never invoked and non-TTY contexts proceed cleanly.
/// - The callback errors on decline so `lpm dev --https` aborts cleanly instead
///   of silently continuing with an untrusted cert (which would make the dev
///   server's HTTPS effectively useless).
fn build_consent(yes: bool) -> lpm_cert::TrustStoreConsent<'static> {
    if yes {
        return lpm_cert::TrustStoreConsent::PreApproved;
    }
    lpm_cert::TrustStoreConsent::Prompt(Box::new(|req| {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Cert(
                "non-interactive shell: pass `--yes` to consent to the trust-store install, or run `lpm cert trust` first".into(),
            ));
        }
        println!();
        println!(
            "  {}",
            "LPM needs to install a local Certificate Authority into your".bold()
        );
        println!(
            "  {}",
            "system trust store to serve trusted HTTPS for development.".bold()
        );
        println!();
        print_cert_prompt_field("Subject:", "LPM Local Development CA");
        print_cert_prompt_field("Fingerprint:", &req.fingerprint);
        print_cert_prompt_field("Expires:", &req.expires);
        print_cert_prompt_field("Permitted:", &req.permitted_names.join(", "));
        if !req.name_constraints_enabled {
            println!(
                "    {}",
                "Note: NameConstraints disabled — set LPM_CERT_NAME_CONSTRAINTS=1 to scope the CA"
                    .dimmed()
            );
        }
        println!();
        println!("  You can remove it at any time with `lpm cert uninstall`.");
        println!();
        let answer = cliclack::confirm("Install now?")
            .initial_value(false)
            .interact()
            .map_err(crate::prompt::prompt_err)?;
        if !answer {
            return Err(LpmError::Cert(
                "trust-store install declined; aborting `lpm dev --https`. Run `lpm cert trust` when you're ready, or pass `--yes` to skip the prompt.".into(),
            ));
        }
        Ok(true)
    }))
}

fn print_cert_prompt_field(label: &'static str, value: &str) {
    println!("{}", format_cert_prompt_field(label, value));
}

fn format_cert_prompt_field(label: &'static str, value: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!("    {} {}", install_ui::dim(&format!("{label:<12}")), value,)
}

/// Run the `lpm dev` command with zero-config detection.
///
/// Auto-detects features from lpm.json: tunnel.domain, services.
/// Auto-installs dependencies if stale. Auto-copies .env.example.
/// Opens browser after services are ready.
///
/// `inspect_port`: `Some(n)` binds the inspector to that exact port and
/// fails loudly on `AddrInUse`. `None` auto-picks a free ephemeral port.
/// `no_inspect` skips the inspector entirely. All three are no-ops when
/// `tunnel` is false.
fn single_service_managed_port_args(
    project_dir: &Path,
    command: &str,
    port: u16,
) -> Result<Vec<String>, LpmError> {
    single_service_managed_port_args_with(
        project_dir,
        command,
        port,
        lpm_cert::framework::CommandPortPlanner::load,
    )
}

fn single_service_managed_port_args_with(
    project_dir: &Path,
    command: &str,
    port: u16,
    load_planner: impl FnOnce(&Path) -> lpm_cert::framework::CommandPortPlanner,
) -> Result<Vec<String>, LpmError> {
    load_planner(project_dir)
        .managed_port_args(command, port)
        .map_err(LpmError::Script)
}

#[expect(clippy::too_many_arguments)]
pub async fn run(
    client: &lpm_registry::RegistryClient,
    project_dir: &Path,
    detected_runtimes: Vec<lpm_runtime::detect::DetectedRuntimeVersion>,
    https: bool,
    tunnel: bool,
    network: bool,
    port: Option<u16>,
    host: Option<&str>,
    token: Option<&str>,
    tunnel_relay_url: Option<&str>,
    tunnel_domain: Option<&str>,
    tunnel_source: Option<&str>,
    extra_args: &[String],
    env_mode: Option<&str>,
    no_open: bool,
    no_install: bool,
    quiet: bool,
    dashboard: bool,
    pre_parsed_config: Option<lpm_runner::lpm_json::LpmJsonConfig>,
    tunnel_auth: bool,
    no_inspect: bool,
    inspect_port: Option<u16>,
    yes: bool,
    allow_ca_bootstrap: bool,
) -> Result<(), LpmError> {
    let mut extra_env: Vec<(String, String)> = Vec::new();

    let lpm_config = if let Some(cfg) = pre_parsed_config {
        Some(cfg)
    } else {
        lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?
    };
    let lpm_config = lpm_config
        .map(|mut config| {
            if config.services.is_empty() {
                return Ok(config);
            }
            let configured_primary =
                lpm_runner::service_graph::primary_service_name(&config.services)
                    .map_err(LpmError::Script)?
                    .map(str::to_string);
            let active_services = lpm_runner::service_graph::select_active_services_ref(
                &config.services,
                extra_args,
            )
            .map_err(LpmError::Script)?;
            let active_primary = lpm_runner::service_graph::primary_service_name(&active_services)
                .map_err(LpmError::Script)?
                .map(str::to_string);
            let primary_endpoint_requested = port.is_some()
                || https
                || network
                || tunnel
                || config
                    .proxy
                    .as_ref()
                    .and_then(|proxy| proxy.host.as_ref())
                    .is_some();
            if primary_endpoint_requested && active_primary != configured_primary {
                let configured_primary = configured_primary.as_deref().unwrap_or("<none>");
                return Err(LpmError::Script(format!(
                    "filtered services exclude the configured primary service `{configured_primary}`; include it when using a primary port, HTTPS, network access, a tunnel, or a proxy host"
                )));
            }
            if primary_endpoint_requested && active_primary.is_none() {
                return Err(LpmError::Script(
                    "multi-service dev features require exactly one active service marked `primary`"
                        .to_string(),
                ));
            }
            if let std::borrow::Cow::Owned(active_services) = active_services {
                config.services = active_services;
            }
            Ok(config)
        })
        .transpose()?
        .map(Arc::new);
    if let Some(config) = lpm_config.as_ref() {
        preflight_service_directories(project_dir, &config.services)?;
    }
    let has_services = lpm_config.as_ref().is_some_and(|c| !c.services.is_empty());
    let orchestrator_command_controller = lpm_config.as_ref().and_then(|config| {
        (has_services && (dashboard || tunnel)).then(|| {
            lpm_runner::orchestrator::OrchestratorCommandController::new(config.services.len())
        })
    });
    let single_dev_command = if has_services {
        None
    } else {
        Some(lpm_runner::script::script_command_with_config(
            project_dir,
            "dev",
            lpm_config.as_deref(),
        )?)
    };
    let requested_port = port;
    let port = resolve_dev_port(port, has_services);
    if tunnel
        && !no_inspect
        && let Some(inspect_port) = inspect_port
    {
        preflight_explicit_inspector_port(inspect_port, port, lpm_config.as_deref())?;
    }

    // Warn about privileged ports that may require elevated permissions
    if is_privileged_port(port) {
        dev_ui::warn(&format!(
            "Port {} is privileged. You may need elevated permissions (sudo) on Linux.",
            port
        ));
    }

    let local_domain_hostnames = lpm_config
        .as_ref()
        .map(|config| lpm_runner::local_domains::configured_hostnames(config))
        .unwrap_or_default();
    let cert_extra_permitted_dns = lpm_config
        .as_ref()
        .map(|config| lpm_runner::lpm_json::validated_cert_extra_permitted_dns(config))
        .transpose()
        .map_err(LpmError::Script)?
        .map(|entries| lpm_cert::name_constraints::dns_subtrees_from_entries(&entries))
        .unwrap_or_default();
    let startup_proxy_lines = lpm_config
        .as_ref()
        .map(|config| startup_proxy_lines_from_config(config))
        .unwrap_or_default();
    if !local_domain_hostnames.is_empty() {
        let config = lpm_config.as_ref().ok_or_else(|| {
            LpmError::Script("local domains require an lpm.json configuration".to_string())
        })?;
        ensure_local_proxy_running(project_dir, config).await?;
    }

    // ── Collect startup info for banner ─────────────────────────────
    let mut startup = StartupInfo {
        deps_status: String::new(),
        env_status: None,
        https_active: false,
        tunnel_url: None,
        tunnel_source: None,
        network_addr: None,
        node_version: None,
        node_source: None,
        inspector_url: None,
        proxy_lines: startup_proxy_lines,
    };

    // ── Run independent detection steps in parallel ──────────────────
    // Steps that can run concurrently:
    //   - auto_install_if_stale (async, potentially slow — runs `lpm install`)
    //   - auto_copy_env_example (sync file I/O — wrap in spawn_blocking)
    //   - HTTPS cert setup (sync, may generate certs — wrap in spawn_blocking)
    //   - ensure_detected_runtimes (async, may download node — potentially slow)
    //
    // Network display and tunnel setup depend on HTTPS result (cert env vars),
    // so they run after the parallel batch.

    let install_dir = project_dir.to_path_buf();
    let env_dir = project_dir.to_path_buf();
    let https_dir = project_dir.to_path_buf();
    let host_owned = host.map(|h| h.to_string());
    let local_display_host = host.unwrap_or("localhost").to_string();

    // Pre-compute network info once (used for both cert SANs and display)
    let network_info = if network {
        Some(lpm_network::get_network_info(port, https)?)
    } else {
        None
    };

    // Clone for the spawn_blocking closure (cert SANs need the IP list)
    let network_info_for_cert = network_info.clone();
    let local_domain_hostnames_for_cert = local_domain_hostnames.clone();
    let cert_extra_permitted_dns_for_cert = cert_extra_permitted_dns.clone();

    let selected_node_source = detected_runtimes
        .iter()
        .find(|detected| detected.runtime == lpm_runtime::detect::RuntimeKind::Node)
        .map(lpm_runtime::detect::DetectedRuntimeVersion::source_label);
    let dev_entrypoint_compatibility_bins = dev_entrypoint_compatibility_bins(project_dir);

    let (install_result, env_result, https_result, runtime_hint) = tokio::join!(
        async {
            if !no_install {
                auto_install_if_stale(client, &install_dir, &dev_entrypoint_compatibility_bins)
                    .await
            } else {
                Ok("skipped (--no-install)".to_string())
            }
        },
        async {
            let dir = env_dir.clone();
            tokio::task::spawn_blocking(move || auto_copy_env_example(&dir))
                .await
                .map_err(|error| LpmError::Script(format!(".env setup task panicked: {error}")))?
        },
        async {
            if https || !local_domain_hostnames_for_cert.is_empty() {
                let dir = https_dir.clone();
                let host_clone = host_owned.clone();
                let net_info = network_info_for_cert;
                let yes_local = yes;
                let inject_env = false;
                let setup = tokio::task::spawn_blocking(move || {
                    let mut extra_hostnames: Vec<String> = Vec::new();
                    if let Some(h) = host_clone {
                        push_unique_hostname(&mut extra_hostnames, h);
                    }
                    extend_unique_hostnames(&mut extra_hostnames, local_domain_hostnames_for_cert);
                    if let Some(ref info) = net_info {
                        for addr in &info.addresses {
                            if !addr.is_ipv6 {
                                push_unique_hostname(&mut extra_hostnames, addr.ip.clone());
                            }
                        }
                    }
                    let consent = build_consent(yes_local);
                    lpm_cert::ensure_https_with_consent_and_permitted_dns(
                        &dir,
                        &extra_hostnames,
                        &cert_extra_permitted_dns_for_cert,
                        consent,
                    )
                })
                .await
                .map_err(|e| LpmError::Script(format!("HTTPS setup panicked: {e}")))?;
                Ok::<_, LpmError>(Some(DevCertSetup {
                    setup: setup?,
                    inject_env,
                }))
            } else {
                Ok::<_, LpmError>(None)
            }
        },
        async { super::run::ensure_detected_runtimes(detected_runtimes).await },
    );

    // Process parallel results
    startup.deps_status = install_result?;
    startup.env_status = env_result?;
    let script_path =
        lpm_runner::bin_path::build_path_with_bins_pre_resolved(project_dir, &runtime_hint)?;
    let effective_node = lpm_runtime::effective::resolve_node_on_path_with_fingerprint(
        project_dir,
        std::ffi::OsStr::new(&script_path),
    );
    if let Some(requirement) =
        crate::engine_check::resolve_root_node_engine_requirement(project_dir)?
    {
        crate::engine_check::enforce_resolved_node_for_run(
            requirement,
            effective_node.clone(),
            false,
        )?;
    }
    if let Some(version) = effective_node.version() {
        startup.node_version = Some(format!("v{version}"));
        startup.node_source = Some(node_source_for_resolution(
            project_dir,
            &runtime_hint,
            &effective_node,
            selected_node_source.as_deref(),
        ));
    }

    let https_setup: Option<DevCertSetup> = https_result?;
    let tls_material = if let Some(cert_setup) = https_setup {
        let setup = cert_setup.setup;
        if setup.ca_freshly_installed {
            dev_ui::done("root CA generated and installed to trust store");
        }
        if setup.cert_freshly_generated {
            dev_ui::done("project certificate generated");
        }
        if cert_setup.inject_env {
            extra_env.extend(setup.env_vars.clone());
        }
        Some(DevTlsMaterial {
            cert_pem: setup.cert_pem.into(),
            key_pem: setup.key_pem.into(),
            _runtime_lease: setup.runtime_lease,
        })
    } else {
        None
    };
    startup.https_active = https;

    // The public HMR hostname can differ from the loopback child endpoint.
    if let Some(ref net_info) = network_info
        && let Some(ref primary) = net_info.primary
    {
        let framework = lpm_cert::framework::detect_framework(project_dir);
        if framework == lpm_cert::framework::Framework::Vite {
            extra_env.push(("VITE_HMR_HOST".to_string(), primary.ip.clone()));
        }
    }

    // ── Dashboard event channel ─────────────────────────────────────
    // When --dashboard is active, orchestrator events and webhook events
    // are forwarded through this channel to the TUI.
    let (dashboard_event_tx, dashboard_event_rx) = if dashboard {
        let (tx, rx) = std::sync::mpsc::sync_channel::<lpm_dashboard::DashboardEvent>(256);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // ── Tunnel setup ───────────────────────────────────────────────────
    let mut tunnel_handle: Option<tokio::task::JoinHandle<Result<(), LpmError>>> = None;
    let mut tunnel_shutdown_boundary: Option<TunnelShutdownBoundary> = None;
    let single_tunnel_shutdown_slot = Arc::new(Mutex::new(None::<TunnelShutdownBoundary>));
    let mut capture_consumer_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut inspector_handle: Option<lpm_inspect::InspectorHandle> = None;
    let mut multi_inspector_state = None;
    let mut multi_tunnel_ready_rx = None;
    let mut multi_tunnel_target_tx = None;
    let mut multi_tunnel_live_target = None;
    let mut multi_tunnel_published = None;
    let mut multi_tunnel_forwarding_controller = None;
    if tunnel && has_services {
        let (tunnel_target_tx, target_rx) = tokio::sync::oneshot::channel::<LocalTarget>();
        multi_tunnel_target_tx = Some(tunnel_target_tx);
        let live_local_target =
            Arc::new(RwLock::new(LocalTarget::loopback(LocalScheme::Http, port)));
        multi_tunnel_live_target = Some(Arc::clone(&live_local_target));
        let published_for_connect = Arc::new(AtomicBool::new(false));
        multi_tunnel_published = Some(Arc::clone(&published_for_connect));
        let token = token.ok_or_else(|| {
            LpmError::Tunnel("authentication required for tunnel. Run `lpm login` first.".into())
        })?;

        // Tunnel source for banner (resolved in main.rs: "lpm.json", "--domain", "--tunnel")
        startup.tunnel_source = tunnel_source.map(|s| s.to_string());

        // Proactive guidance for configured domains
        if let Some(domain) = tunnel_domain
            && !quiet
        {
            dev_ui::trusted_detail("Tunnel domain", &install_ui::cyan(domain));
        }

        // ── Inspector startup (paired with tunnel) ──────────────────
        // The browser inspector is the same surface as `lpm tunnel
        // inspect --ui` — real-time webhook capture, replay, snapshots.
        // It runs alongside the dashboard's webhook tab (which is
        // text-only) so the user can pick whichever fits the moment.
        // Quiet by default — we never auto-open a browser tab here.
        let inspector_db = lpm_inspect::db::InspectorDb::open(project_dir).map_err(|error| {
            LpmError::Tunnel(format!(
                "failed to open this project's .lpm/inspector.db: {error}. \
                 Repair or move the corrupt database and retry"
            ))
        })?;
        let inspector_state = lpm_inspect::state::InspectorState::with_db_pending(inspector_db);
        multi_inspector_state = Some(inspector_state.clone());
        if !no_inspect {
            // `Some(n)` → strict bind, fatal on AddrInUse (matches the
            // `--inspect-port N` user contract). `None` → auto-pick a
            // free ephemeral port; failure is best-effort.
            let (port_to_bind, strict) = match inspect_port {
                Some(n) => (n, true),
                None => (0, false),
            };
            match lpm_inspect::start(inspector_state.clone(), port_to_bind).await {
                Ok(handle) => {
                    startup.inspector_url = Some(handle.url.clone());
                    inspector_handle = Some(handle);
                }
                Err(e) if strict => return Err(e),
                Err(e) => {
                    if !quiet {
                        dev_ui::warn(&format!("inspector failed to start: {e}"));
                    }
                }
            }
        }

        // Create webhook capture channel.
        let (webhook_tx, mut webhook_rx) =
            tokio::sync::mpsc::channel::<lpm_tunnel::client::CapturedWebhookEvent>(64);

        crate::commands::tunnel::warn_capture_persistence(!quiet);

        // Dashboard webhook channel: when --dashboard is active, webhooks are
        // forwarded to the dashboard TUI via a std::sync channel.
        let dashboard_webhook_tx: Option<
            std::sync::mpsc::SyncSender<lpm_dashboard::DashboardEvent>,
        > = dashboard_event_tx.clone();

        // Generate tunnel auth token if requested (random 32-byte hex, one per session)
        let tunnel_auth_token = if tunnel_auth {
            use rand::Rng;
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill(&mut bytes);
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Some(hex)
        } else {
            None
        };

        let (forwarding_controller, forwarding_admission) =
            lpm_tunnel::client::forwarding_admission_barrier();
        multi_tunnel_forwarding_controller = Some(forwarding_controller);
        let relay_url = tunnel_relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned);
        let token_provider =
            crate::tunnel_session_auth::refresh_backed_provider(client, &relay_url)?;
        let options = lpm_tunnel::client::TunnelOptions {
            relay_url,
            token: token.to_string(),
            token_provider,
            local_target: LocalTarget::loopback(LocalScheme::Http, port),
            live_local_target: None,
            domain: tunnel_domain.map(|s| s.to_string()),
            tunnel_auth: tunnel_auth_token.clone(),
            webhook_tx: Some(webhook_tx),
            no_pin: false,
            auto_ack: false,
            ws_tx: None,
            forwarding_admission: Some(forwarding_admission),
            shutdown: None,
        };

        let inspector_state_for_consumer = inspector_state.clone();
        capture_consumer_handle = Some(tokio::spawn(async move {
            while let Some(captured) = webhook_rx.recv().await {
                let webhook = Arc::clone(&captured.webhook);
                inspector_state_for_consumer
                    .push_shared(Arc::clone(&webhook))
                    .await;

                // Forward to dashboard if active
                if let Some(ref tx) = dashboard_webhook_tx {
                    let _ = tx.try_send(lpm_dashboard::DashboardEvent::WebhookCaptured(
                        Arc::clone(&webhook),
                    ));
                }

                // Inline display: skip when dashboard is active (dashboard shows its own view),
                // skip GET/HEAD/OPTIONS (health checks, browsers), and respect --quiet flag
                if dashboard || quiet {
                    continue;
                }
                let method_upper = webhook.method.to_uppercase();
                if method_upper == "GET" || method_upper == "HEAD" || method_upper == "OPTIONS" {
                    continue;
                }

                install_ui::detail_line(format_dev_webhook_line(
                    &webhook.method,
                    &webhook.path,
                    webhook.response_status,
                    webhook.duration_ms,
                    &webhook.summary,
                ));

                // Show signature diagnostic if present
                if let Some(ref diag) = webhook.signature_diagnostic {
                    install_ui::detail_line(crate::install_ui::terminal_line!(
                        "           {} {}",
                        install_ui::yellow("!"),
                        lpm_common::sanitize_for_terminal(diag)
                    ));
                }
            }
        }));

        // Start tunnel in background task, storing the handle for clean shutdown
        let mut options_clone = options;
        let tunnel_cancel = tokio_util::sync::CancellationToken::new();
        options_clone.shutdown = Some(tunnel_cancel.clone());
        let tunnel_auth_display = tunnel_auth_token;
        let (tunnel_ready_tx, tunnel_ready_rx) = tokio::sync::oneshot::channel();
        multi_tunnel_ready_rx = Some(tunnel_ready_rx);
        let tunnel_ready_tx = Arc::new(Mutex::new(Some(tunnel_ready_tx)));
        let ready_for_connect = Arc::clone(&tunnel_ready_tx);
        let inspector_state_for_connect = inspector_state.clone();
        let latest_usage = Arc::new(Mutex::new(None::<lpm_tunnel::TunnelUsageMetadata>));
        let usage_for_connect = latest_usage.clone();
        let usage_for_notices = latest_usage;
        let (shutdown_boundary, mut shutdown_rx, tunnel_completion) = TunnelShutdownBoundary::new();
        let tunnel_failure_controller = orchestrator_command_controller.clone();
        tunnel_shutdown_boundary = Some(shutdown_boundary);
        tunnel_handle = Some(tokio::spawn(async move {
            let _tunnel_completion = tunnel_completion;
            let local_target = tokio::select! {
                target = target_rx => {
                    let Ok(target) = target else {
                        return Ok(());
                    };
                    target
                }
                _ = &mut shutdown_rx => return Ok(()),
            };
            let local_target_url = local_target.url();
            options_clone.local_target = local_target.clone();
            *live_local_target
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = local_target;
            options_clone.live_local_target = Some(live_local_target);
            let connect = lpm_tunnel::client::connect_with_usage_fallible(
                &options_clone,
                move |session| {
                    let usage = usage_for_connect
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    let publication = TunnelReadyPublication {
                        session: session.clone(),
                        local_target_url: local_target_url.clone(),
                        tunnel_auth: tunnel_auth_display.clone(),
                        usage,
                    };
                    if let Some(sender) = ready_for_connect
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                    {
                        sender.send(Ok(publication)).map_err(|_| {
                            LpmError::Tunnel(
                                "runtime stopped before tunnel publication completed".into(),
                            )
                        })?;
                    } else if published_for_connect.load(Ordering::Acquire) {
                        publish_tunnel_connection(&inspector_state_for_connect, &publication)?;
                    }
                    Ok(())
                },
                show_tunnel_notice,
                move |usage, initial| {
                    *usage_for_notices
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(usage.clone());
                    if !initial
                        && let Some(summary) =
                            crate::commands::tunnel::tunnel_usage_summary(Some(usage))
                    {
                        show_tunnel_notice(&format!("Tunnel usage: {summary}"));
                    }
                },
            );
            tokio::pin!(connect);
            let result = tokio::select! {
                result = &mut connect => result,
                _ = &mut shutdown_rx => {
                    tunnel_cancel.cancel();
                    connect.await
                },
            };
            if let Err(error) = &result {
                if let Some(sender) = tunnel_ready_tx
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    let _ = sender.send(Err::<TunnelReadyPublication, String>(error.to_string()));
                }
                show_tunnel_notice(&format!("Tunnel failed: {error}"));
                if let Some(controller) = tunnel_failure_controller.as_ref() {
                    controller.send(lpm_runner::orchestrator::OrchestratorCommand::StopAll);
                }
            }
            result
        }));
    }

    let multi_tunnel_abort_handle = tunnel_handle.as_ref().map(|handle| handle.abort_handle());

    // ── Check for multi-service orchestration ──────────────────────────
    if has_services {
        let preparation = async {
            let config = lpm_config.as_ref().ok_or_else(|| {
                LpmError::Script(
                    "multi-service configuration disappeared before startup".to_string(),
                )
            })?;
            let primary_service = lpm_runner::service_graph::primary_service_name(&config.services)
                .map_err(LpmError::Script)?
                .map(str::to_string);
            let service_runtime_hints =
                prepare_service_runtime_hints(project_dir, &config.services, &runtime_hint).await?;
            let dashboard_services = if dashboard {
                build_dashboard_services(config)?
            } else {
                Vec::new()
            };
            let hosts_file_lease =
                prepare_local_hosts_file(project_dir, &local_domain_hostnames, yes)?;
            Ok::<_, LpmError>((
                config,
                primary_service,
                service_runtime_hints,
                dashboard_services,
                hosts_file_lease,
            ))
        }
        .await;
        let (config, primary_service, service_runtime_hints, dashboard_services, hosts_file_lease) =
            match preparation {
                Ok(preparation) => preparation,
                Err(error) => {
                    return cleanup_failed_multi_service_preparation(
                        error,
                        tunnel_handle,
                        tunnel_shutdown_boundary.as_ref(),
                        capture_consumer_handle,
                        multi_inspector_state,
                        inspector_handle,
                    )
                    .await;
                }
            };
        let services = &config.services;
        print_startup_banner(&startup, project_dir);
        let open_browser = primary_service.is_some() && should_open_browser(true, no_open, is_ci());
        let frontend_slot = Arc::new(Mutex::new(None::<DevFrontends>));
        let dev_session_slot =
            Arc::new(Mutex::new(None::<lpm_runner::dev_session::DevSessionLease>));
        let service_endpoint_slot = Arc::new(Mutex::new(
            lpm_runner::orchestrator::ServiceEndpointMap::new(),
        ));
        let multi_started = std::time::Instant::now();

        // Bridge orchestrator events to the dashboard when --dashboard is active.
        // The orchestrator sends OrchestratorEvent, the dashboard receives DashboardEvent.
        let orchestrator_event_tx = dashboard_event_tx.as_ref().map(|dash_tx| {
            let (orch_tx, orch_rx) =
                std::sync::mpsc::sync_channel::<lpm_runner::orchestrator::OrchestratorEvent>(256);
            let dash_tx = dash_tx.clone();
            std::thread::spawn(move || {
                while let Ok(event) = orch_rx.recv() {
                    let dash_event = match event {
                        lpm_runner::orchestrator::OrchestratorEvent::ServiceLog {
                            service_index,
                            line,
                            ..
                        } => lpm_dashboard::DashboardEvent::ServiceLog {
                            index: service_index,
                            line,
                        },
                        lpm_runner::orchestrator::OrchestratorEvent::StatusChange {
                            service_index,
                            status,
                        } => lpm_dashboard::DashboardEvent::StatusChange {
                            index: service_index,
                            status: convert_service_status(&status),
                        },
                    };
                    match dash_event {
                        event @ lpm_dashboard::DashboardEvent::ServiceLog { .. } => {
                            if matches!(
                                dash_tx.try_send(event),
                                Err(std::sync::mpsc::TrySendError::Disconnected(_))
                            ) {
                                break;
                            }
                        }
                        event => {
                            if dash_tx.send(event).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            orch_tx
        });

        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        let dashboard_ports_tx = dashboard_event_tx.clone();
        let on_ports_assigned = dashboard_ports_tx.map(|tx| {
            Box::new(move |ports: &lpm_runner::orchestrator::ServicePortMap| {
                for (service, port) in ports {
                    let _ = tx.send(lpm_dashboard::DashboardEvent::PortAssigned {
                        service: service.clone(),
                        port: *port,
                    });
                }
                Ok(())
            }) as lpm_runner::orchestrator::PortsAssignedCallback
        });

        let manage_primary_endpoint = primary_service.is_some();
        let register_local_proxy = !local_domain_hostnames.is_empty();
        let on_all_ready = (manage_primary_endpoint || register_local_proxy).then(|| {
            let primary_service = primary_service.clone();
            let project_dir = project_dir.to_path_buf();
            let proxy_config = config.clone();
            let proxy_lease = Arc::clone(&proxy_lease);
            let runtime_handle = tokio::runtime::Handle::current();
            let frontend_slot = Arc::clone(&frontend_slot);
            let dev_session_slot = Arc::clone(&dev_session_slot);
            let inspector_state = multi_inspector_state.clone();
            let tunnel_target_tx = multi_tunnel_target_tx.take();
            let tunnel_ready_rx = multi_tunnel_ready_rx.take();
            let tunnel_live_target = multi_tunnel_live_target.clone();
            let tunnel_published = multi_tunnel_published.clone();
            let tunnel_forwarding_controller = multi_tunnel_forwarding_controller.clone();
            let tunnel_abort_handle = multi_tunnel_abort_handle.clone();
            let local_display_host = local_display_host.clone();
            let service_endpoint_slot = Arc::clone(&service_endpoint_slot);
            let tls_material = tls_material.clone();
            Box::new(
                move |endpoints: lpm_runner::orchestrator::ServiceEndpointMap| {
                    let publication_result = (|| -> Result<(), LpmError> {
                    let (prepared_proxy_plan, registered_proxy_routes) = if register_local_proxy {
                        let final_targets = endpoints
                            .iter()
                            .map(|(service, endpoint)| {
                                (service.clone(), endpoint.target.clone())
                            })
                            .collect();
                        let plan = lpm_runner::local_domains::plan_multi_service_routes(
                            &proxy_config,
                            &final_targets,
                        )
                        .map_err(LpmError::Script)?;
                        let routes = plan.routes;
                        let prepared = runtime_handle.block_on(prepare_initial_proxy_route_plan(
                            &project_dir,
                            routes.clone(),
                            Arc::clone(&proxy_lease),
                        ))?;
                        (Some(prepared), Some(routes))
                    } else {
                        (None, None)
                    };

                    let Some(primary_service) = primary_service else {
                        if let Some(proxy_plan) = prepared_proxy_plan {
                            runtime_handle.block_on(proxy_plan.finalize())?;
                        }
                        *service_endpoint_slot
                            .lock()
                            .map_err(|_| {
                                LpmError::Script("service endpoint state is poisoned".into())
                            })? = endpoints;
                        if let Some(routes) = registered_proxy_routes.as_deref() {
                            print_registered_proxy_routes(routes);
                        }
                        return Ok(());
                    };
                    let endpoint = endpoints.get(&primary_service).cloned().ok_or_else(|| {
                        LpmError::Script(format!(
                            "primary service `{primary_service}` did not open its assigned local endpoint"
                        ))
                    })?;
                    let child_target = endpoint.target.clone();
                    let active_frontends = runtime_handle.block_on(
                        start_single_service_frontends(
                            &project_dir,
                            child_target.clone(),
                            endpoint.owner_pid,
                            https,
                            network,
                            requested_port,
                            tls_material.as_ref(),
                        ),
                    )?;
                    let local_target = active_frontends.local_target.clone();

                    if let Some(network_port) = active_frontends.network_port {
                        let network_info =
                            lpm_network::get_network_info(network_port, local_target.scheme == LocalScheme::Https)?;
                        runtime_handle.block_on(display_network_access(
                            &network_info,
                            network_port,
                            local_target.scheme == LocalScheme::Https,
                            &local_target.base_path,
                            allow_ca_bootstrap,
                        ))?;
                    }

                    let local_url = format!(
                        "{}://{}:{}{}",
                        local_target.scheme,
                        local_display_host,
                        local_target.port,
                        local_target.base_path
                    );
                    let prepared_session = lpm_runner::dev_session::PreparedDevSession::prepare(
                        &project_dir,
                        child_target.clone(),
                        endpoint.owner_pid,
                        endpoint.owner_identity.clone(),
                        Some(primary_service),
                        https,
                    )?;

                    if let Some(sender) = tunnel_target_tx
                        && let Err(_target) = sender.send(child_target)
                    {
                        return Err(LpmError::Tunnel(
                                "tunnel stopped before the primary service became ready".to_string(),
                            ));
                    }
                    let tunnel_publication = tunnel_ready_rx
                        .map(|receiver| {
                            runtime_handle.block_on(wait_for_tunnel_readiness(
                                receiver,
                                std::time::Duration::from_secs(20),
                            ))
                        })
                        .transpose()?;
                    publish_initial_runtime(
                        &runtime_handle,
                        &endpoint,
                        endpoints,
                        active_frontends,
                        prepared_session,
                        &frontend_slot,
                        &dev_session_slot,
                        &service_endpoint_slot,
                        inspector_state.as_ref(),
                        tunnel_live_target.as_ref(),
                        tunnel_publication.as_ref(),
                        tunnel_published.as_ref(),
                        prepared_proxy_plan,
                        || Ok(()),
                    )?;
                    if let Some(routes) = registered_proxy_routes.as_deref() {
                        print_registered_proxy_routes(routes);
                    }
                    if let Some(controller) = tunnel_forwarding_controller.as_ref() {
                        controller.open();
                    }
                    dev_ui::trusted_detail("Local", &install_ui::url(&local_url));
                    dev_ui::blank_line();
                    dev_ui::done_ready("Local server", multi_started.elapsed());
                    if open_browser {
                        let _ = open::that(local_url);
                    }
                    Ok(())
                    })();
                    if let Err(error) = publication_result {
                        if let Some(controller) = tunnel_forwarding_controller.as_ref() {
                            controller.reject();
                        }
                        if let Some(handle) = tunnel_abort_handle.as_ref() {
                            handle.abort();
                        }
                        if register_local_proxy
                            && let Err(cleanup_error) =
                                runtime_handle.block_on(release_proxy_lease(&proxy_lease))
                        {
                            return Err(LpmError::Script(format!(
                                "{error}; local proxy route cleanup also failed: {cleanup_error}"
                            )));
                        }
                        return Err(error);
                    }
                    Ok(())
                },
            ) as lpm_runner::orchestrator::AllReadyCallback
        });

        let on_endpoint_changed = (manage_primary_endpoint || register_local_proxy).then(|| {
            let primary_service = primary_service.clone();
            let project_dir = project_dir.to_path_buf();
            let proxy_config = config.clone();
            let proxy_lease = Arc::clone(&proxy_lease);
            let runtime_handle = tokio::runtime::Handle::current();
            let frontend_slot = Arc::clone(&frontend_slot);
            let dev_session_slot = Arc::clone(&dev_session_slot);
            let service_endpoint_slot = Arc::clone(&service_endpoint_slot);
            let inspector_state = multi_inspector_state.clone();
            let tunnel_live_target = multi_tunnel_live_target.clone();
            Box::new(move |endpoint: lpm_runner::dev_endpoint::DevEndpoint| {
                let service = endpoint.service.clone().ok_or_else(|| {
                    LpmError::Script(
                        "restarted service endpoint is missing its service name".to_string(),
                    )
                })?;
                let final_targets = {
                    let endpoints = service_endpoint_slot.lock().map_err(|_| {
                        LpmError::Script("service endpoint state is poisoned".to_string())
                    })?;
                    let mut candidate = endpoints.clone();
                    candidate.insert(service.clone(), endpoint.clone());
                    candidate
                        .iter()
                        .map(|(name, endpoint)| (name.clone(), endpoint.target.clone()))
                        .collect()
                };

                let primary_changed = primary_service.as_deref() == Some(service.as_str());
                if primary_changed {
                    frontend_slot
                        .lock()
                        .map_err(|_| {
                            LpmError::Script("dev frontend state is poisoned".to_string())
                        })?
                        .as_ref()
                        .ok_or_else(|| {
                            LpmError::Script("dev frontend state is not initialized".to_string())
                        })?
                        .validate_child_target(&endpoint.target)?;
                }
                let prepared_session = primary_changed
                    .then(|| {
                        lpm_runner::dev_session::PreparedDevSession::prepare(
                            &project_dir,
                            endpoint.target.clone(),
                            endpoint.owner_pid,
                            endpoint.owner_identity.clone(),
                            Some(service.clone()),
                            https,
                        )
                    })
                    .transpose()?;

                let prepared_proxy_plan = if register_local_proxy {
                    let plan = lpm_runner::local_domains::plan_multi_service_routes(
                        &proxy_config,
                        &final_targets,
                    )
                    .map_err(LpmError::Script)?;
                    Some(runtime_handle.block_on(prepare_proxy_route_plan(
                        &project_dir,
                        plan.routes,
                        Arc::clone(&proxy_lease),
                    ))?)
                } else {
                    None
                };

                if !primary_changed {
                    let mut published_endpoints = service_endpoint_slot.lock().map_err(|_| {
                        LpmError::Script("service endpoint state is poisoned".to_string())
                    })?;
                    if let Some(proxy_plan) = prepared_proxy_plan {
                        runtime_handle.block_on(proxy_plan.finalize())?;
                    }
                    published_endpoints.insert(service, endpoint);
                    return Ok(());
                }

                let prepared_session = prepared_session.ok_or_else(|| {
                    LpmError::Script("primary endpoint publication is missing its session".into())
                })?;

                publish_primary_endpoint(
                    &runtime_handle,
                    service,
                    endpoint,
                    &frontend_slot,
                    &dev_session_slot,
                    &service_endpoint_slot,
                    inspector_state.as_ref(),
                    tunnel_live_target.as_ref(),
                    prepared_session,
                    prepared_proxy_plan,
                    || Ok(()),
                )
            }) as lpm_runner::orchestrator::EndpointChangedCallback
        });

        let on_shutdown_started = tunnel_shutdown_boundary.clone().map(|boundary| {
            Box::new(move || boundary.request_and_wait()) as lpm_runner::ShutdownStartedCallback
        });
        let options = lpm_runner::orchestrator::OrchestratorOptions {
            https: false,
            filter: Vec::new(),
            extra_envs: extra_env.clone(),
            env_mode: env_mode.map(str::to_string),
            service_runtime_hints,
            event_tx: orchestrator_event_tx,
            command_rx: None,
            command_controller: orchestrator_command_controller.clone(),
            on_ports_assigned,
            on_shutdown_started,
            on_all_ready,
            on_endpoint_changed,
            primary_port: requested_port.filter(|_| !https),
            manage_primary_endpoint,
            reserved_frontend_port: requested_port.filter(|_| https),
        };

        if dashboard {
            // Dashboard mode: run orchestrator in a background thread,
            // launch the TUI dashboard on the current thread (it blocks until quit).
            //
            // The dashboard sends service intents directly to the bounded
            // orchestrator controller and stays in the TUI until shutdown.
            let command_controller = orchestrator_command_controller.ok_or_else(|| {
                LpmError::Script("dashboard command controller was not initialized".to_string())
            })?;
            let project_dir_owned = project_dir.to_path_buf();
            let orchestrator_config = Arc::clone(config);
            let dashboard_terminal_tx = dashboard_event_tx.clone();
            let orch_handle = std::thread::spawn(move || {
                run_dashboard_orchestrator(dashboard_terminal_tx, || {
                    lpm_runner::orchestrator::run_services_with_config(
                        &project_dir_owned,
                        &orchestrator_config.services,
                        Some(&orchestrator_config),
                        options,
                    )
                })
            });

            let shutdown_controller = command_controller.clone();
            let dashboard_controller = command_controller.clone();
            let dashboard_command_sink: lpm_dashboard::DashboardCommandSink =
                Arc::new(move |command| {
                    dashboard_controller.send(dashboard_orchestrator_command(command));
                });

            let inspector_url_for_dashboard = inspector_handle.as_ref().map(|h| h.url.clone());

            let dashboard_result = if let Some(rx) = dashboard_event_rx {
                lpm_dashboard::run_dashboard(
                    dashboard_services,
                    rx,
                    Some(dashboard_command_sink),
                    inspector_url_for_dashboard,
                )
                .map(|_| ())
                .map_err(|error| LpmError::Script(error.to_string()))
            } else {
                Ok(())
            };
            let tunnel_shutdown_result =
                stop_multi_service_tunnel(tunnel_handle, tunnel_shutdown_boundary.as_ref()).await;
            shutdown_controller.send(lpm_runner::orchestrator::OrchestratorCommand::StopAll);
            let orchestrator_result = orch_handle.join().unwrap_or_else(|_| {
                Err(LpmError::Script(
                    "service orchestrator panicked".to_string(),
                ))
            });
            let result = orchestrator_result.and(dashboard_result);
            let result = combine_tunnel_cleanup_results(result, tunnel_shutdown_result);

            let result = release_multi_service_runtime(result, &frontend_slot, &dev_session_slot);
            let result = release_proxy_lease_after(result, &proxy_lease).await;
            let result = release_hosts_file_after(result, hosts_file_lease);

            return finalize_multi_service_tunnel_after(
                result,
                capture_consumer_handle,
                multi_inspector_state,
                inspector_handle,
            )
            .await;
        }

        let result = lpm_runner::orchestrator::run_services_with_config(
            project_dir,
            services,
            Some(config.as_ref()),
            options,
        );
        let tunnel_shutdown_result =
            stop_multi_service_tunnel(tunnel_handle, tunnel_shutdown_boundary.as_ref()).await;
        let result = combine_tunnel_cleanup_results(result, tunnel_shutdown_result);
        let result = release_multi_service_runtime(result, &frontend_slot, &dev_session_slot);
        let result = release_proxy_lease_after(result, &proxy_lease).await;
        let result = release_hosts_file_after(result, hosts_file_lease);
        return finalize_multi_service_tunnel_after(
            result,
            capture_consumer_handle,
            multi_inspector_state,
            inspector_handle,
        )
        .await;
    }

    // ── Single service: start dev server ────────────────────────────
    let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
    let dev_command = single_dev_command.ok_or_else(|| {
        LpmError::Script("single-service dev command was not prepared".to_string())
    })?;
    let hosts_file_lease = prepare_local_hosts_file(project_dir, &local_domain_hostnames, yes)?;
    let mut script_env = extra_env.clone();
    let child_requested_port = requested_port.filter(|_| !https);
    let explicit_inspector_port = if tunnel && !no_inspect {
        inspect_port
    } else {
        None
    };
    let child_port_hint = if https {
        find_internal_dev_port_excluding(port, explicit_inspector_port)?
    } else {
        port
    };
    upsert_extra_env(&mut script_env, "PORT", child_port_hint.to_string());
    let mut script_args = extra_args.to_vec();
    if let Some(requested_port) = child_requested_port {
        script_args.extend(single_service_managed_port_args(
            project_dir,
            &dev_command,
            requested_port,
        )?);
    }

    let (endpoint_tx, endpoint_rx) = tokio::sync::oneshot::channel();
    let script_project_dir = project_dir.to_path_buf();
    let script_env_mode = env_mode.map(str::to_string);
    let script_runtime_hint = runtime_hint.clone();
    let script_config = lpm_config.clone();
    let startup_started = std::time::Instant::now();
    let script_stop_requested = Arc::new(AtomicBool::new(false));
    let script_stop_for_runner = Arc::clone(&script_stop_requested);
    let script_tunnel_shutdown_slot = Arc::clone(&single_tunnel_shutdown_slot);
    let mut script_handle = tokio::task::spawn_blocking(move || {
        lpm_runner::script::run_dev_script_with_envs_and_config(
            &script_project_dir,
            &script_args,
            script_env_mode.as_deref(),
            &script_env,
            &script_runtime_hint,
            script_config.as_deref(),
            lpm_runner::script::DevScriptEndpointOptions {
                requested_port: child_requested_port,
                stop_requested: script_stop_for_runner,
                on_endpoint: Box::new(move |result| {
                    let _ = endpoint_tx.send(result);
                }),
                on_shutdown_started: Some(Box::new(move || {
                    let boundary = script_tunnel_shutdown_slot
                        .lock()
                        .map_err(|_| {
                            LpmError::Tunnel(
                                "single-service tunnel shutdown state is poisoned".into(),
                            )
                        })?
                        .clone();
                    boundary.map_or(Ok(()), |boundary| boundary.request_and_wait())
                })),
            },
        )
    });

    let endpoint_result = tokio::select! {
        endpoint = endpoint_rx => endpoint.ok(),
        script_result = &mut script_handle => {
            let script_result = script_result
                .map_err(|error| LpmError::Script(format!("dev script task panicked: {error}")))?;
            let result = release_proxy_lease_after(script_result, &proxy_lease).await;
            return release_hosts_file_after(result, hosts_file_lease);
        }
    };

    let endpoint = match endpoint_result {
        Some(Ok(Some(endpoint))) => Some(endpoint),
        Some(Ok(None)) | None => None,
        Some(Err(error)) => {
            let _ = script_handle.await;
            let result =
                release_proxy_lease_after(Err(LpmError::Script(error)), &proxy_lease).await;
            return release_hosts_file_after(result, hosts_file_lease);
        }
    };

    let setup_result = async {
        let mut frontends = None;
        let mut dev_session_lease = None;
        if let Some(endpoint) = endpoint {
            let endpoint_owner_pid = endpoint.owner_pid;
            let endpoint_owner_identity = endpoint.owner_identity;
            let child_target = endpoint.target;
            let active_frontends = start_single_service_frontends(
                project_dir,
                child_target.clone(),
                endpoint_owner_pid,
                https,
                network,
                requested_port,
                tls_material.as_ref(),
            )
            .await?;
            let target = active_frontends.local_target.clone();
            if tunnel {
                let tunnel_token = token
                    .ok_or_else(|| {
                        LpmError::Tunnel(
                            "authentication required for tunnel. Run `lpm login` first.".into(),
                        )
                    })?
                    .to_string();
                let tunnel_project_dir = project_dir.to_path_buf();
                let tunnel_domain = tunnel_domain.map(str::to_string);
                let tunnel_relay_url =
                    tunnel_relay_url.map_or_else(lpm_tunnel::resolve_relay_url, str::to_owned);
                let tunnel_token_provider =
                    crate::tunnel_session_auth::refresh_backed_provider(client, &tunnel_relay_url)?;
                let tunnel_target = child_target.clone();
                let (shutdown_boundary, shutdown_rx, tunnel_completion) =
                    TunnelShutdownBoundary::new();
                *single_tunnel_shutdown_slot.lock().map_err(|_| {
                    LpmError::Tunnel("single-service tunnel shutdown state is poisoned".into())
                })? = Some(shutdown_boundary.clone());
                tunnel_shutdown_boundary = Some(shutdown_boundary);
                startup.tunnel_source = tunnel_source.map(str::to_string);
                if let Some(domain) = tunnel_domain.as_deref()
                    && !quiet
                {
                    dev_ui::trusted_detail("Tunnel domain", &install_ui::cyan(domain));
                }
                tunnel_handle = Some(tokio::spawn(async move {
                    let _tunnel_completion = tunnel_completion;
                    let result = crate::commands::tunnel::run_start(
                        Some(&tunnel_token),
                        tunnel_target,
                        tunnel_domain.as_deref(),
                        false,
                        &tunnel_project_dir,
                        tunnel_auth,
                        no_inspect,
                        inspect_port,
                        false,
                        None,
                        Some(&tunnel_relay_url),
                        tunnel_token_provider,
                        !quiet,
                        Some(shutdown_rx),
                    )
                    .await;
                    if let Err(error) = &result {
                        show_tunnel_notice(&format!("Tunnel failed: {error}"));
                    }
                    result
                }));
            }
            if let Some(network_port) = active_frontends.network_port {
                let current_network_info = lpm_network::get_network_info(network_port, https)?;
                startup.network_addr = display_network_access(
                    &current_network_info,
                    network_port,
                    https,
                    &target.base_path,
                    allow_ca_bootstrap,
                )
                .await?;
            }
            print_startup_banner(&startup, project_dir);
            let url = format!(
                "{}://{}:{}{}",
                target.scheme, local_display_host, target.port, target.base_path
            );
            dev_ui::trusted_detail("Local", &install_ui::url(&url));
            dev_ui::blank_line();
            dev_ui::done_ready("Local server", startup_started.elapsed());

            if let Some(config) = lpm_config.as_ref()
                && let Some(plan) = lpm_runner::local_domains::plan_single_service_route(
                    config,
                    child_target.clone(),
                )
            {
                register_proxy_route_plan(project_dir, plan.routes, Arc::clone(&proxy_lease))
                    .await?;
            }

            dev_session_lease = Some(lpm_runner::dev_session::DevSessionLease::register(
                project_dir,
                child_target,
                endpoint_owner_pid,
                endpoint_owner_identity,
                None,
                https,
            )?);
            if should_open_browser(true, no_open, is_ci()) {
                let _ = open::that(&url);
            }
            frontends = Some(active_frontends);
        } else {
            print_startup_banner(&startup, project_dir);
        }
        Ok::<_, LpmError>((frontends, dev_session_lease))
    }
    .await;

    let (frontends, dev_session_lease) = match setup_result {
        Ok(runtime) => runtime,
        Err(error) => {
            let tunnel_shutdown_result =
                shutdown_spawned_tunnel(tunnel_handle.take(), tunnel_shutdown_boundary.as_ref())
                    .await;
            script_stop_requested.store(true, Ordering::Release);
            let _ = script_handle.await;
            let result = release_proxy_lease_after(Err(error), &proxy_lease).await;
            let result = release_hosts_file_after(result, hosts_file_lease);
            let result = combine_tunnel_cleanup_results(result, tunnel_shutdown_result);
            let inspector_result = match inspector_handle.take() {
                Some(handle) => handle.shutdown().await,
                None => Ok(()),
            };
            return combine_tunnel_cleanup_results(result, inspector_result);
        }
    };

    let (script_result, tunnel_shutdown_result) =
        if let Some(mut active_tunnel_handle) = tunnel_handle.take() {
            tokio::select! {
                script_join = &mut script_handle => {
                    let script_result = script_join.map_err(|error| {
                        LpmError::Script(format!("dev script task panicked: {error}"))
                    })?;
                    let tunnel_result = shutdown_spawned_tunnel(
                        Some(active_tunnel_handle),
                        tunnel_shutdown_boundary.as_ref(),
                    )
                    .await;
                    (script_result, tunnel_result)
                }
                tunnel_join = &mut active_tunnel_handle => {
                    let tunnel_result = match tunnel_join {
                        Ok(result) => result,
                        Err(error) if error.is_cancelled() => Ok(()),
                        Err(error) => Err(LpmError::Tunnel(format!(
                            "tunnel task failed: {error}"
                        ))),
                    };
                    script_stop_requested.store(true, Ordering::Release);
                    let script_result = script_handle.await.map_err(|error| {
                        LpmError::Script(format!("dev script task panicked: {error}"))
                    })?;
                    (script_result, tunnel_result)
                }
            }
        } else {
            let script_result = script_handle
                .await
                .map_err(|error| LpmError::Script(format!("dev script task panicked: {error}")))?;
            (script_result, Ok(()))
        };
    drop(frontends);
    drop(dev_session_lease);
    let result = release_proxy_lease_after(script_result, &proxy_lease).await;
    let result = release_hosts_file_after(result, hosts_file_lease);
    let result = combine_tunnel_cleanup_results(result, tunnel_shutdown_result);
    let inspector_result = match inspector_handle {
        Some(handle) => handle.shutdown().await,
        None => Ok(()),
    };
    combine_tunnel_cleanup_results(result, inspector_result)
}

fn preflight_service_directories(
    project_dir: &Path,
    services: &HashMap<String, lpm_runner::lpm_json::ServiceConfig>,
) -> Result<(), LpmError> {
    let mut names: Vec<&String> = services.keys().collect();
    names.sort_unstable();
    for name in names {
        let Some(cwd) = services[name].cwd.as_deref() else {
            continue;
        };
        let resolved = lpm_runner::orchestrator::safe_resolve_cwd(project_dir, cwd)
            .map_err(|error| LpmError::Script(format!("service '{name}': {error}")))?;
        if !resolved.is_dir() {
            return Err(LpmError::Script(format!(
                "service '{name}' cwd '{}' is not an existing directory",
                resolved.display()
            )));
        }
    }
    Ok(())
}

fn preflight_explicit_inspector_port(
    port: u16,
    dev_port: u16,
    config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Result<(), LpmError> {
    if port == dev_port {
        return Err(LpmError::Tunnel(format!(
            "inspector port {port} conflicts with the dev port. Pass `--inspect-port <N>` to choose another."
        )));
    }
    if let Some(config) = config {
        let mut service_names: Vec<_> = config.services.keys().collect();
        service_names.sort_unstable();
        for name in service_names {
            let service = &config.services[name];
            if service.port == Some(port) {
                return Err(LpmError::Tunnel(format!(
                    "inspector port {port} conflicts with configured service '{name}'. Pass `--inspect-port <N>` to choose another."
                )));
            }
            if service.ready_port == Some(port) {
                return Err(LpmError::Tunnel(format!(
                    "inspector port {port} conflicts with the readiness port for configured service '{name}'. Pass `--inspect-port <N>` to choose another."
                )));
            }
        }
        if let Some(proxy) = config.proxy.as_ref() {
            let proxy_port = proxy.port.unwrap_or(443);
            if port == proxy_port {
                return Err(LpmError::Tunnel(format!(
                    "inspector port {port} conflicts with the configured HTTPS proxy. Pass `--inspect-port <N>` to choose another."
                )));
            }
            if proxy.http_redirect.unwrap_or(true) && port == 80 {
                return Err(LpmError::Tunnel(
                    "inspector port 80 conflicts with the configured HTTP redirect listener. Pass `--inspect-port <N>` to choose another."
                        .to_string(),
                ));
            }
        }
    }
    match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            Err(LpmError::Tunnel(format!(
                "inspector port {port} is already in use. Pass `--inspect-port <N>` to choose another, or omit the flag to auto-pick a free port."
            )))
        }
        Err(error) => Err(LpmError::Tunnel(format!(
            "failed to preflight inspector port {port}: {error}"
        ))),
    }
}

fn startup_proxy_lines_from_config(
    config: &lpm_runner::lpm_json::LpmJsonConfig,
) -> Vec<StartupProxyLine> {
    let mut lines = Vec::new();

    if config.services.is_empty() {
        if let Some(host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref()) {
            push_startup_proxy_line(&mut lines, host, None);
        }
        return lines;
    }

    let mut service_names: Vec<&String> = config.services.keys().collect();
    service_names.sort();
    for service_name in service_names {
        let service = &config.services[service_name];
        if let Some(host) = service.host.as_ref() {
            push_startup_proxy_line(&mut lines, host, Some(service_name.clone()));
        }
    }

    if let Some(host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref()) {
        match primary_proxy_service_for_display(config) {
            Some(service_name) => {
                if config.services.contains_key(service_name) {
                    push_startup_proxy_line(&mut lines, host, Some(service_name.to_string()));
                }
            }
            None => lines.push(StartupProxyLine {
                host: host.clone(),
                target: "primary service required".to_string(),
                service: None,
            }),
        }
    }

    lines
}

fn run_dashboard_orchestrator(
    terminal_tx: Option<std::sync::mpsc::SyncSender<lpm_dashboard::DashboardEvent>>,
    run: impl FnOnce() -> Result<(), LpmError>,
) -> Result<(), LpmError> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
        Err(LpmError::Script(
            "service orchestrator panicked while the dashboard was active".to_string(),
        ))
    });
    if let Some(tx) = terminal_tx {
        let event = match &result {
            Ok(()) => lpm_dashboard::DashboardEvent::Shutdown,
            Err(error) => lpm_dashboard::DashboardEvent::FatalError(error.to_string()),
        };
        let _ = tx.send(event);
    }
    result
}

fn dashboard_orchestrator_command(
    command: lpm_dashboard::DashboardCommand,
) -> lpm_runner::orchestrator::OrchestratorCommand {
    match command {
        lpm_dashboard::DashboardCommand::RestartService(index) => {
            lpm_runner::orchestrator::OrchestratorCommand::RestartService(index)
        }
        lpm_dashboard::DashboardCommand::StopService(index) => {
            lpm_runner::orchestrator::OrchestratorCommand::StopService(index)
        }
        lpm_dashboard::DashboardCommand::StopAll => {
            lpm_runner::orchestrator::OrchestratorCommand::StopAll
        }
    }
}

fn dashboard_service_hosts(
    config: &lpm_runner::lpm_json::LpmJsonConfig,
    service_name: &str,
) -> Vec<String> {
    let mut hosts = Vec::new();
    if let Some(service) = config.services.get(service_name)
        && let Some(host) = service.host.as_ref()
    {
        push_unique_hostname(&mut hosts, host.clone());
    }
    if let Some(proxy_host) = config.proxy.as_ref().and_then(|proxy| proxy.host.as_ref())
        && primary_proxy_service_for_display(config) == Some(service_name)
    {
        push_unique_hostname(&mut hosts, proxy_host.clone());
    }
    hosts
}

fn dashboard_service_names(
    services: &HashMap<String, lpm_runner::lpm_json::ServiceConfig>,
) -> Result<Vec<String>, LpmError> {
    lpm_runner::service_graph::topological_sort(services)
        .map(|groups| groups.into_iter().flatten().collect())
        .map_err(LpmError::Script)
}

fn build_dashboard_services(
    config: &lpm_runner::lpm_json::LpmJsonConfig,
) -> Result<Vec<lpm_dashboard::ServiceState>, LpmError> {
    dashboard_service_names(&config.services).map(|service_names| {
        let per_service_log_bytes = (16 * 1024 * 1024) / service_names.len().max(1);
        service_names
            .into_iter()
            .map(|name| {
                let service = &config.services[&name];
                lpm_dashboard::ServiceState {
                    hosts: dashboard_service_hosts(config, &name),
                    name,
                    port: service.port,
                    status: lpm_dashboard::ServiceStatus::Starting,
                    logs: lpm_dashboard::LogBuffer::with_limits(5000, per_service_log_bytes),
                }
            })
            .collect()
    })
}

fn primary_proxy_service_for_display(config: &lpm_runner::lpm_json::LpmJsonConfig) -> Option<&str> {
    let mut primary = config
        .services
        .iter()
        .filter(|(_, service)| service.primary)
        .map(|(name, _)| name.as_str());
    if let Some(name) = primary.next() {
        return primary.next().is_none().then_some(name);
    }

    if config.services.len() == 1 {
        return config.services.keys().next().map(String::as_str);
    }

    None
}

fn push_startup_proxy_line(lines: &mut Vec<StartupProxyLine>, host: &str, service: Option<String>) {
    if lines
        .iter()
        .any(|line| line.host.eq_ignore_ascii_case(host))
    {
        return;
    }
    lines.push(StartupProxyLine {
        host: host.to_string(),
        target: "resolving endpoint".to_string(),
        service,
    });
}

async fn ensure_local_proxy_running(
    project_dir: &Path,
    config: &lpm_runner::lpm_json::LpmJsonConfig,
) -> Result<(), LpmError> {
    let status = match lpm_proxy::status().await {
        Ok(status) if status.running => status,
        Ok(_) => {
            let start =
                crate::commands::proxy::ensure_detached_started_for_config(project_dir, config)
                    .await
                    .map_err(|err| {
                    LpmError::Script(format!(
                        "local proxy auto-start failed: {err}. Start it with `{}` before using `host` in lpm.json.",
                        local_proxy_https_start_command()
                    ))
                })?;
            if start.started {
                dev_ui::done("local proxy control daemon started in the background");
            }
            start.status
        }
        Err(err) => {
            return Err(LpmError::Script(format!(
                "local proxy status check failed: {err}"
            )));
        }
    };

    validate_local_proxy_listener_contract(config, &status).map_err(|error| {
        LpmError::Script(format!(
            "local proxy listener contract does not match lpm.json: {error}. Restart it with `{}` before using `host` in lpm.json.",
            local_proxy_https_start_command()
        ))
    })
}

fn validate_local_proxy_listener_contract(
    config: &lpm_runner::lpm_json::LpmJsonConfig,
    status: &lpm_proxy::ProxyStatus,
) -> Result<(), String> {
    if !status.running {
        return Err("local proxy is not running".to_string());
    }
    let tls_addr = status
        .tls_addr
        .as_deref()
        .ok_or_else(|| "local proxy is running without an HTTPS listener".to_string())?;
    let socket_addr = tls_addr.strip_prefix("https://").unwrap_or(tls_addr);
    let actual_tls_port = socket_addr
        .parse::<std::net::SocketAddr>()
        .map_err(|_| format!("local proxy reported an invalid HTTPS listener `{tls_addr}`"))?
        .port();
    let proxy = config.proxy.as_ref();
    if let Some(expected_tls_port) = proxy.and_then(|proxy| proxy.port)
        && expected_tls_port != 0
        && expected_tls_port != 443
        && actual_tls_port != expected_tls_port
    {
        return Err(format!(
            "expected HTTPS port {expected_tls_port}, but the running proxy listens on {actual_tls_port}"
        ));
    }

    if let Some(redirect_expected) = proxy.and_then(|proxy| proxy.http_redirect) {
        let redirect_active = status.http_redirect_addr.is_some();
        if redirect_expected != redirect_active {
            let expected = if redirect_expected {
                "enabled"
            } else {
                "disabled"
            };
            let actual = if redirect_active {
                "enabled"
            } else {
                "disabled"
            };
            return Err(format!(
                "expected the HTTP redirect listener to be {expected}, but it is {actual}"
            ));
        }
    }

    Ok(())
}

fn prepare_local_hosts_file(
    project_dir: &Path,
    hostnames: &[String],
    yes: bool,
) -> Result<Option<lpm_runner::local_domains::ManagedHostsFile>, LpmError> {
    let Some(plan) = lpm_runner::local_domains::plan_hosts_file_update(project_dir, hostnames)
        .map_err(|err| LpmError::Script(format!("local hosts file planning failed: {err}")))?
    else {
        return Ok(None);
    };

    confirm_hosts_file_update(&plan, yes)?;
    let lease = crate::commands::hosts::apply_hosts_file_plan_with_permission(&plan).map_err(|err| {
        LpmError::Script(format!(
            "local hosts file update failed for {}: {err}. Run `lpm dev` with permission to edit the hosts file (sudo on Unix, Administrator on Windows), or use `.localhost` hosts that do not need a hosts-file entry.",
            plan.path.display()
        ))
    })?;
    if lease.changed() {
        dev_ui::done("hosts file updated for local domains");
    }
    Ok(Some(lease))
}

fn confirm_hosts_file_update(
    plan: &lpm_runner::local_domains::HostsFilePlan,
    yes: bool,
) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Script(format!(
            "non-interactive shell: pass `--yes` to consent to updating the hosts file for local domains ({})",
            plan.hosts.join(", ")
        )));
    }

    println!();
    println!(
        "  {}",
        "LPM needs to update your hosts file for local domains.".bold()
    );
    println!();
    print_cert_prompt_field("Hosts file:", &plan.path.display().to_string());
    print_cert_prompt_field("Backup:", &plan.backup_path.display().to_string());
    print_cert_prompt_field("Hosts:", &plan.hosts.join(", "));
    println!();
    let answer = cliclack::confirm("Update hosts file now?")
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if !answer {
        return Err(LpmError::Script(
            "hosts file update declined; aborting `lpm dev`. Use `.localhost` hosts, or pass `--yes` when you're ready.".into(),
        ));
    }
    Ok(())
}

async fn register_proxy_route_plan(
    project_dir: &Path,
    routes: Vec<lpm_runner::local_domains::LocalDomainRoute>,
    proxy_lease: ProxyLeaseSlot,
) -> Result<(), LpmError> {
    if routes.is_empty() {
        return Ok(());
    }

    let prepared =
        prepare_initial_proxy_route_plan(project_dir, routes.clone(), proxy_lease).await?;
    prepared.finalize().await?;
    print_registered_proxy_routes(&routes);
    Ok(())
}

async fn prepare_initial_proxy_route_plan(
    project_dir: &Path,
    routes: Vec<lpm_runner::local_domains::LocalDomainRoute>,
    proxy_lease: ProxyLeaseSlot,
) -> Result<PreparedProxyRoutePlan, LpmError> {
    if routes.is_empty() {
        return Err(LpmError::Script(
            "cannot initialize a local proxy route lease with no routes".into(),
        ));
    }

    let (proxy_routes, bridges) = prepare_proxy_routes(project_dir, &routes).await?;
    let lease = register_staged_proxy_routes().await?;
    store_proxy_lease(
        Arc::clone(&proxy_lease),
        LocalProxyRuntime {
            lease,
            bridges: Vec::new(),
            routes: Vec::new(),
        },
    )
    .await?;
    match stage_proxy_route_plan(proxy_routes, bridges, Arc::clone(&proxy_lease)).await {
        Ok(plan) => Ok(plan),
        Err(error) => {
            let cleanup = release_proxy_lease(&proxy_lease).await;
            match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(LpmError::Script(format!(
                    "{error}; releasing the uninitialized local proxy lease also failed: {cleanup_error}"
                ))),
            }
        }
    }
}

async fn prepare_proxy_route_plan(
    project_dir: &Path,
    routes: Vec<lpm_runner::local_domains::LocalDomainRoute>,
    proxy_lease: ProxyLeaseSlot,
) -> Result<PreparedProxyRoutePlan, LpmError> {
    if routes.is_empty() {
        return Err(LpmError::Script(
            "cannot replace a local proxy route lease with no routes".into(),
        ));
    }

    let (proxy_routes, bridges) = prepare_proxy_routes(project_dir, &routes).await?;
    stage_proxy_route_plan(proxy_routes, bridges, proxy_lease).await
}

async fn stage_proxy_route_plan(
    proxy_routes: Vec<lpm_proxy::Route>,
    bridges: Vec<lpm_proxy::HttpProxyHandle>,
    proxy_lease: ProxyLeaseSlot,
) -> Result<PreparedProxyRoutePlan, LpmError> {
    let command_tx = proxy_lease
        .lock()
        .await
        .as_ref()
        .map(|publisher| publisher.command_tx.clone())
        .ok_or_else(|| LpmError::Script("local proxy route lease is not initialized".into()))?;
    let (reply, response) = tokio::sync::oneshot::channel();
    command_tx
        .send(ProxyPublisherCommand::Prepare {
            routes: proxy_routes,
            bridges,
            reply,
        })
        .map_err(|_| LpmError::Script("local proxy route publisher stopped".into()))?;
    let publication_id = response.await.map_err(|_| {
        LpmError::Script("local proxy route publisher stopped during replacement".into())
    })??;
    Ok(PreparedProxyRoutePlan {
        command_tx,
        publication_id,
        finalized: false,
    })
}

async fn prepare_proxy_routes(
    project_dir: &Path,
    routes: &[lpm_runner::local_domains::LocalDomainRoute],
) -> Result<(Vec<lpm_proxy::Route>, Vec<lpm_proxy::HttpProxyHandle>), LpmError> {
    let mut proxy_routes = Vec::with_capacity(routes.len());
    let mut bridges = Vec::with_capacity(routes.len());
    for route in routes {
        if route.upstream.scheme != LocalScheme::Http {
            return Err(LpmError::Script(format!(
                "local-domain proxy host `{}` requires a plain HTTP child, but service {} reported {}; disable framework HTTPS and let the LPM proxy terminate TLS",
                route.host,
                route.service.as_deref().unwrap_or("dev"),
                route.upstream.url(),
            )));
        }
        let upstream_port = if proxy_can_reach_target_directly(&route.upstream) {
            route.upstream.port
        } else {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|error| {
                    LpmError::Script(format!(
                        "bind local proxy bridge for `{}`: {error}",
                        route.host
                    ))
                })?;
            let bridge =
                lpm_proxy::start_http_frontend_on_listener(listener, route.upstream.clone())
                    .map_err(|error| {
                        LpmError::Script(format!(
                            "start local proxy bridge for `{}`: {error}",
                            route.host
                        ))
                    })?;
            let port = bridge.port();
            bridges.push(bridge);
            port
        };
        proxy_routes.push(lpm_proxy::Route {
            host: route.host.clone(),
            upstream_port,
            project_dir: project_dir.to_path_buf(),
            service: route.service.clone(),
        });
    }
    Ok((proxy_routes, bridges))
}

fn proxy_can_reach_target_directly(target: &LocalTarget) -> bool {
    target.scheme == LocalScheme::Http
        && target.address == IpAddr::V4(Ipv4Addr::LOCALHOST)
        && target.base_path == "/"
}

async fn store_proxy_lease(
    proxy_lease: ProxyLeaseSlot,
    runtime: LocalProxyRuntime,
) -> Result<(), LpmError> {
    let mut guard = proxy_lease.lock().await;
    if guard.is_some() {
        return Err(LpmError::Script(
            "local proxy route lease is already initialized".into(),
        ));
    }
    *guard = Some(ProxyRoutePublisher::start(runtime));
    Ok(())
}

async fn register_staged_proxy_routes() -> Result<lpm_proxy::RouteLease, LpmError> {
    lpm_proxy::register_staged()
        .await
        .map_err(map_proxy_register_error)
}

fn map_proxy_register_error(err: lpm_proxy::ProxyError) -> LpmError {
    match err {
        lpm_proxy::ProxyError::IpcUnavailable(_) | lpm_proxy::ProxyError::IpcUnsupported => {
            LpmError::Script(format!(
                "local proxy is not running. Start it with `{}` before using `host` in lpm.json.",
                local_proxy_https_start_command()
            ))
        }
        other => LpmError::Script(format!("local proxy route registration failed: {other}")),
    }
}

fn local_proxy_https_start_command() -> String {
    install_ui::yellow("lpm proxy start --tls-port 9443").to_string()
}

async fn release_proxy_lease_after(
    result: Result<(), LpmError>,
    proxy_lease: &ProxyLeaseSlot,
) -> Result<(), LpmError> {
    let release_result = release_proxy_lease(proxy_lease).await;
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(release_err)) => {
            dev_ui::warn(&format!("local proxy route cleanup failed: {release_err}"));
            Err(primary)
        }
    }
}

async fn shutdown_spawned_tunnel(
    tunnel_handle: Option<tokio::task::JoinHandle<Result<(), LpmError>>>,
    shutdown_boundary: Option<&TunnelShutdownBoundary>,
) -> Result<(), LpmError> {
    stop_multi_service_tunnel(tunnel_handle, shutdown_boundary).await
}

async fn wait_for_tunnel_readiness<T>(
    receiver: tokio::sync::oneshot::Receiver<Result<T, String>>,
    timeout: std::time::Duration,
) -> Result<T, LpmError> {
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(Ok(publication))) => Ok(publication),
        Ok(Ok(Err(error))) => Err(LpmError::Tunnel(format!(
            "tunnel failed before runtime publication: {error}"
        ))),
        Ok(Err(_)) => Err(LpmError::Tunnel(
            "tunnel stopped before confirming readiness".to_string(),
        )),
        Err(_) => Err(LpmError::Tunnel(
            "timed out waiting for the tunnel to become ready".to_string(),
        )),
    }
}

async fn stop_multi_service_tunnel(
    tunnel_handle: Option<tokio::task::JoinHandle<Result<(), LpmError>>>,
    shutdown_boundary: Option<&TunnelShutdownBoundary>,
) -> Result<(), LpmError> {
    let request_result = match shutdown_boundary {
        Some(boundary) => boundary.request(),
        None => Ok(()),
    };
    let task_result = match tunnel_handle {
        Some(mut handle) => {
            match tokio::time::timeout(std::time::Duration::from_secs(5), &mut handle).await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(error))) => Err(error),
                Ok(Err(error)) if error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(LpmError::Tunnel(format!(
                    "tunnel task failed during shutdown: {error}"
                ))),
                Err(_) => {
                    handle.abort();
                    let join_result = handle.await;
                    let timeout_error =
                        LpmError::Tunnel("tunnel did not stop within 5 seconds".to_string());
                    match join_result {
                        Ok(Ok(())) => Err(timeout_error),
                        Ok(Err(error)) => Err(LpmError::Tunnel(format!(
                            "{timeout_error}; tunnel task also failed: {error}"
                        ))),
                        Err(error) if error.is_cancelled() => Err(timeout_error),
                        Err(error) => Err(LpmError::Tunnel(format!(
                            "{timeout_error}; aborting the tunnel task also failed: {error}"
                        ))),
                    }
                }
            }
        }
        None => Ok(()),
    };
    combine_tunnel_cleanup_results(request_result, task_result)
}

async fn cleanup_failed_multi_service_preparation(
    error: LpmError,
    tunnel_handle: Option<tokio::task::JoinHandle<Result<(), LpmError>>>,
    shutdown_boundary: Option<&TunnelShutdownBoundary>,
    capture_consumer_handle: Option<tokio::task::JoinHandle<()>>,
    inspector_state: Option<lpm_inspect::state::InspectorState>,
    inspector_handle: Option<lpm_inspect::InspectorHandle>,
) -> Result<(), LpmError> {
    let tunnel_result = stop_multi_service_tunnel(tunnel_handle, shutdown_boundary).await;
    let result = combine_tunnel_cleanup_results(Err(error), tunnel_result);
    finalize_multi_service_tunnel_after(
        result,
        capture_consumer_handle,
        inspector_state,
        inspector_handle,
    )
    .await
}

async fn finalize_multi_service_tunnel_after(
    result: Result<(), LpmError>,
    capture_consumer_handle: Option<tokio::task::JoinHandle<()>>,
    inspector_state: Option<lpm_inspect::state::InspectorState>,
    inspector_handle: Option<lpm_inspect::InspectorHandle>,
) -> Result<(), LpmError> {
    let capture_result = match capture_consumer_handle {
        Some(handle) => handle
            .await
            .map_err(|error| LpmError::Tunnel(format!("capture task failed: {error}"))),
        None => Ok(()),
    };
    let persistence_result = if let Some(state) = inspector_state {
        let end_result = state.end_session().await.map_err(|error| {
            LpmError::Tunnel(format!("failed to persist inspector session end: {error}"))
        });
        let flush_result = state.flush().await.map_err(|error| {
            LpmError::Tunnel(format!(
                "failed to commit captures to .lpm/inspector.db: {error}"
            ))
        });
        combine_tunnel_cleanup_results(end_result, flush_result)
    } else {
        Ok(())
    };
    let inspector_result = match inspector_handle {
        Some(handle) => handle.shutdown().await,
        None => Ok(()),
    };

    let cleanup_result = combine_tunnel_cleanup_results(capture_result, persistence_result);
    let cleanup_result = combine_tunnel_cleanup_results(cleanup_result, inspector_result);
    compose_tunnel_runtime_and_cleanup(result, cleanup_result)
}

fn combine_tunnel_cleanup_results(
    first: Result<(), LpmError>,
    second: Result<(), LpmError>,
) -> Result<(), LpmError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(LpmError::Tunnel(format!("{first}; {second}"))),
    }
}

fn compose_tunnel_runtime_and_cleanup(
    result: Result<(), LpmError>,
    cleanup_result: Result<(), LpmError>,
) -> Result<(), LpmError> {
    match (result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup_error)) => {
            dev_ui::warn(&format!("tunnel capture cleanup failed: {cleanup_error}"));
            Err(LpmError::Tunnel(format!(
                "{primary}; tunnel capture cleanup also failed: {cleanup_error}"
            )))
        }
    }
}

fn release_multi_service_runtime(
    result: Result<(), LpmError>,
    frontend_slot: &Arc<Mutex<Option<DevFrontends>>>,
    dev_session_slot: &Arc<Mutex<Option<lpm_runner::dev_session::DevSessionLease>>>,
) -> Result<(), LpmError> {
    let release_result = (|| {
        let frontends = frontend_slot
            .lock()
            .map_err(|_| LpmError::Script("dev frontend state is poisoned".to_string()))?
            .take();
        let session = dev_session_slot
            .lock()
            .map_err(|_| LpmError::Script("dev session state is poisoned".to_string()))?
            .take();
        drop(frontends);
        drop(session);
        Ok(())
    })();
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(release_err)) => {
            dev_ui::warn(&format!("dev runtime cleanup failed: {release_err}"));
            Err(primary)
        }
    }
}

fn release_hosts_file_after(
    result: Result<(), LpmError>,
    hosts_file: Option<lpm_runner::local_domains::ManagedHostsFile>,
) -> Result<(), LpmError> {
    let release_result = release_hosts_file(hosts_file);
    match (result, release_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(release_err)) => Err(release_err),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(release_err)) => {
            dev_ui::warn(&format!("local hosts file cleanup failed: {release_err}"));
            Err(primary)
        }
    }
}

fn release_hosts_file(
    hosts_file: Option<lpm_runner::local_domains::ManagedHostsFile>,
) -> Result<(), LpmError> {
    if let Some(hosts_file) = hosts_file {
        crate::commands::hosts::release_hosts_file_with_permission(hosts_file)
            .map_err(|err| LpmError::Script(format!("local hosts file cleanup failed: {err}")))?;
    }
    Ok(())
}

async fn release_proxy_lease(proxy_lease: &ProxyLeaseSlot) -> Result<(), LpmError> {
    let publisher = {
        let mut guard = proxy_lease.lock().await;
        guard.take()
    };
    if let Some(publisher) = publisher {
        publisher.release().await?;
    }
    Ok(())
}

#[cfg(test)]
async fn proxy_route_snapshot(proxy_lease: &ProxyLeaseSlot) -> Vec<lpm_proxy::Route> {
    let command_tx = proxy_lease
        .lock()
        .await
        .as_ref()
        .unwrap()
        .command_tx
        .clone();
    let (reply, response) = tokio::sync::oneshot::channel();
    command_tx
        .send(ProxyPublisherCommand::Snapshot { reply })
        .unwrap();
    response.await.unwrap()
}

fn print_registered_proxy_routes(routes: &[lpm_runner::local_domains::LocalDomainRoute]) {
    for route in routes {
        let upstream = if proxy_can_reach_target_directly(&route.upstream) {
            format!("localhost:{}", route.upstream.port)
        } else {
            route.upstream.url()
        };
        let target = format!("{} -> {upstream}", route.host);
        if let Some(ref service) = route.service {
            dev_ui::trusted_detail_with_hint("Proxy", &install_ui::yellow(&target), service);
        } else {
            dev_ui::trusted_detail("Proxy", &install_ui::yellow(&target));
        }
    }
    dev_ui::blank_line();
}

fn extend_unique_hostnames(hostnames: &mut Vec<String>, extra: impl IntoIterator<Item = String>) {
    for hostname in extra {
        push_unique_hostname(hostnames, hostname);
    }
}

fn push_unique_hostname(hostnames: &mut Vec<String>, hostname: String) {
    if !hostnames
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&hostname))
    {
        hostnames.push(hostname);
    }
}

// ── Startup info ────────────────────────────────────────────────────

struct StartupInfo {
    /// "up to date (2ms)" or "installed 847 packages in 3.2s" or "skipped (--no-install)"
    deps_status: String,
    /// "loaded" or "created from .env.example" or None (no .env.example)
    env_status: Option<String>,
    /// Whether HTTPS certificate was set up
    https_active: bool,
    /// Tunnel URL once connected (may not be known yet at banner time)
    tunnel_url: Option<String>,
    /// Where the tunnel config came from: "lpm.json", "--domain", "--tunnel"
    tunnel_source: Option<String>,
    /// Network address (e.g. "192.168.1.42:3000")
    network_addr: Option<String>,
    /// Node.js version string (e.g. "v20.11.0"), pre-fetched in parallel
    node_version: Option<String>,
    /// Source of the executable reported by `node_version`.
    node_source: Option<String>,
    /// Live browser-inspector URL (e.g. `http://127.0.0.1:53412`) when
    /// `--tunnel` started one. Printed in the banner so the user can
    /// copy-paste it; the dashboard's `o` key opens the same URL.
    inspector_url: Option<String>,
    proxy_lines: Vec<StartupProxyLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupProxyLine {
    host: String,
    target: String,
    service: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct StartupBannerLine {
    label: &'static str,
    value: String,
    hint: Option<String>,
}

fn node_source_for_resolution(
    project_dir: &Path,
    runtime_hint: &lpm_runner::bin_path::ManagedRuntimeHint,
    resolution: &lpm_runtime::effective::PathNodeResolution,
    selected_source: Option<&str>,
) -> String {
    let Some(executable) = resolution.executable() else {
        return "system PATH".to_string();
    };
    if runtime_hint
        .bin_dir(lpm_runtime::detect::RuntimeKind::Node)
        .is_some_and(|bin_dir| executable.starts_with(bin_dir))
    {
        return selected_source.unwrap_or("managed runtime").to_string();
    }
    if lpm_runner::bin_path::find_bin_dirs(project_dir)
        .iter()
        .any(|bin_dir| executable.starts_with(bin_dir))
    {
        return "project PATH".to_string();
    }
    "system PATH".to_string()
}

fn normalize_env_banner_status(status: &str) -> (String, Option<String>) {
    match status {
        ".env loaded" => ("loaded".to_string(), Some("(.env)".to_string())),
        "created from .env.example" => ("created".to_string(), Some("(.env.example)".to_string())),
        _ => (status.to_string(), None),
    }
}

fn split_trailing_parenthetical(status: &str) -> (String, Option<String>) {
    let Some(open_index) = status.rfind(" (") else {
        return (status.to_string(), None);
    };
    if !status.ends_with(')') {
        return (status.to_string(), None);
    }
    (
        status[..open_index].to_string(),
        Some(status[open_index + 1..].to_string()),
    )
}

fn startup_banner_lines(info: &StartupInfo, _project_dir: &Path) -> Vec<StartupBannerLine> {
    let mut lines = Vec::new();

    if let Some(ref version) = info.node_version {
        lines.push(StartupBannerLine {
            label: "Node",
            value: version.clone(),
            hint: info
                .node_source
                .as_ref()
                .map(|source| format!("({source})")),
        });
    }

    if !info.deps_status.is_empty() {
        let (value, hint) = split_trailing_parenthetical(&info.deps_status);
        lines.push(StartupBannerLine {
            label: "Deps",
            value,
            hint,
        });
    }

    if let Some(ref status) = info.env_status {
        let (value, hint) = normalize_env_banner_status(status);
        lines.push(StartupBannerLine {
            label: "Env",
            value,
            hint,
        });
    }

    if info.https_active {
        lines.push(StartupBannerLine {
            label: "HTTPS",
            value: "enabled".to_string(),
            hint: Some("(trusted local certificate)".to_string()),
        });
    }

    for proxy in &info.proxy_lines {
        lines.push(StartupBannerLine {
            label: "Proxy",
            value: format!("https://{} -> {}", proxy.host, proxy.target),
            hint: proxy.service.as_ref().map(|service| format!("({service})")),
        });
    }

    if let Some(ref source) = info.tunnel_source {
        lines.push(StartupBannerLine {
            label: "Tunnel",
            value: info
                .tunnel_url
                .clone()
                .unwrap_or_else(|| "connecting...".to_string()),
            hint: Some(format!("({source})")),
        });
    }

    if let Some(ref url) = info.inspector_url {
        lines.push(StartupBannerLine {
            label: "Inspect",
            value: url.clone(),
            hint: None,
        });
    }

    if let Some(ref addr) = info.network_addr {
        lines.push(StartupBannerLine {
            label: "Network",
            value: addr.clone(),
            hint: None,
        });
    }

    lines
}

fn print_startup_banner(info: &StartupInfo, project_dir: &Path) {
    dev_ui::blank_line();

    for line in startup_banner_lines(info, project_dir) {
        if let Some(hint) = line.hint {
            dev_ui::readiness_with_hint(line.label, &line.value, &hint);
        } else {
            dev_ui::readiness(line.label, &line.value);
        }
    }

    dev_ui::blank_line();
}

// ── Zero-config helpers ──────────────────────────────────────────────

/// Check if dependencies are up to date by comparing install hash.
///
/// delegates to the shared `install_state::check_install_state()`
/// which has the stronger semantics (lockfile required, mtime check).
///
/// Returns `(needs_install, computed_hash)`. The hash is `None` only when
/// there is no `package.json` (nothing to install). Returning the hash
/// avoids re-reading package.json and lockfile when install is needed.
fn needs_install(project_dir: &std::path::Path) -> (bool, Option<String>) {
    let state = crate::install_state::check_install_state(project_dir);
    match state.hash {
        // No package.json → nothing to install (not stale, just absent)
        None => (false, None),
        Some(hash) => (!state.up_to_date, Some(hash)),
    }
}

/// Auto-install dependencies if the install hash doesn't match.
///
/// Compares sha256(package.json + lockfile) against `.lpm/install-hash`.
/// If different or missing, runs `lpm install`. ~2ms when up-to-date.
///
/// Returns a status string for the startup banner.
async fn auto_install_if_stale(
    client: &lpm_registry::RegistryClient,
    project_dir: &std::path::Path,
    compatibility_bin_names: &[String],
) -> Result<String, LpmError> {
    let pkg_json = project_dir.join("package.json");
    if !pkg_json.exists() {
        return Ok("no package.json".to_string());
    }

    let start = std::time::Instant::now();

    let (stale, _) = needs_install(project_dir);
    let compatibility_missing =
        dev_entrypoint_compatibility_missing(project_dir, compatibility_bin_names);
    if !stale && !compatibility_missing {
        let elapsed = start.elapsed();
        return Ok(format!("up to date ({})", format_duration(elapsed)));
    }

    if stale {
        dev_ui::phase("Dependencies out of date, installing...");
    } else {
        dev_ui::phase("Preparing dev tool compatibility...");
    }

    // Single-writer ownership: `run_with_options` is the only writer
    // of `.lpm/install-hash`. This branch must not write a stale,
    // pre-install single-line hash AFTER the install returned,
    // clobbering the v6 mtime / linker metadata the install pipeline
    // had just written and (worse) using the pre-install hash even
    // though save policy may have rewritten ranges during install.
    // The install pipeline now writes the correct v6 hash on every
    // successful exit path; this branch just propagates success.
    //
    // Use the injected client so nested installs preserve the caller's
    // registry, authentication, and test configuration.
    let nested_install_result = {
        let _stdout_suppressed = crate::output::suppress_stdout(true).map_err(LpmError::Script)?;
        let _stderr_suppressed = crate::output::suppress_stderr(true).map_err(LpmError::Script)?;

        crate::commands::install::run_with_options(
            client,
            project_dir,
            false, // json_output
            false, // offline
            crate::commands::install::FrozenLockfileMode::Never,
            false, // force
            false, // allow_new
            false, // strict_integrity
            false, // no_engine_strict
            None,  // strict_peer_dependencies_override
            None,  // linker_override
            crate::lpm_skills_config::LpmSkillsPreference::Config,
            false, // no_editor_setup
            true,  // no_security_summary
            false, // auto_build
            None,  // target_set: dev is single-project
            None,  // direct_versions_out: dev does not finalize placeholders
            None,  // requested_add_count: dev auto-install is not an add-path install
            None,  // script_policy_override: `lpm dev` does not expose policy flags
            None,  // advisor_override: `lpm dev` does not expose `--advisor`
            None,  // min_release_age_override: `lpm dev` uses the chain
            &[],
            crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm dev` enforces drift
            crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify-policy: `lpm dev` honors env + config posture chain
            crate::commands::install::InstallOmitPolicy::default(),
            // `lpm dev` does not surface its own
            // sandbox-mode flags. The env / config / default chain
            // inside `rebuild::run` still applies.
            false, // strict_sandbox
            false, // no_sandbox
            false, // verbose: internal pipeline, no user-facing Done footer
            false, // audit_after_install: internal pipeline never runs audit
            false, // timing: dev auto-install does not expose install's --timing flag
            compatibility_bin_names,
        )
        .await
    };

    match nested_install_result {
        Ok(()) => {
            let elapsed = start.elapsed();
            Ok(format!("installed in {}", format_duration(elapsed)))
        }
        Err(e) => Err(LpmError::Script(format!(
            "auto-install failed: {e}\n    Use --no-install to skip dependency installation."
        ))),
    }
}

fn dev_entrypoint_compatibility_bins(project_dir: &Path) -> Vec<String> {
    let Ok(script_cmd) = lpm_runner::script::script_command(project_dir, "dev") else {
        return Vec::new();
    };
    first_script_binary_name(&script_cmd)
        .map(|bin| vec![bin])
        .unwrap_or_default()
}

fn dev_entrypoint_compatibility_missing(project_dir: &Path, bin_names: &[String]) -> bool {
    !bin_names.is_empty()
        && lpm_store::StoreVersion::from_env().uses_virtual_store()
        && !lpm_linker::v2::project_compatibility_bins_ready(project_dir, bin_names)
}

fn first_script_binary_name(script_cmd: &str) -> Option<String> {
    let words = shlex::split(script_cmd)?;
    let mut index = 0usize;
    while index < words.len() {
        let word = words[index].as_str();
        if is_shell_assignment(word) {
            index += 1;
            continue;
        }
        match word {
            "env" | "command" => {
                index += 1;
                continue;
            }
            "cross-env" | "cross-env-shell" => {
                index += 1;
                while index < words.len() && is_shell_assignment(&words[index]) {
                    index += 1;
                }
                continue;
            }
            _ => return normalize_script_binary_name(word),
        }
    }
    None
}

fn is_shell_assignment(word: &str) -> bool {
    let Some((key, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn normalize_script_binary_name(word: &str) -> Option<String> {
    if word.is_empty()
        || word.starts_with('-')
        || word.contains('/')
        || word.contains('\\')
        || word.contains('\0')
        || matches!(
            word,
            "node"
                | "npm"
                | "npx"
                | "pnpm"
                | "yarn"
                | "bun"
                | "lpm"
                | "cd"
                | "echo"
                | "export"
                | "set"
                | "source"
                | "."
                | "&&"
                | "||"
                | ";"
                | "|"
        )
    {
        return None;
    }
    Some(word.to_string())
}

/// Auto-copy .env.example → .env if .env doesn't exist.
///
/// Uses `create_new(true)` for atomic file creation to avoid TOCTOU races
/// where a concurrent process could create .env between the exists() check
/// and the copy, potentially clobbering the other process's file.
///
/// Returns a status string for the startup banner, or None if no .env.example.
fn auto_copy_env_example(project_dir: &std::path::Path) -> Result<Option<String>, LpmError> {
    use std::io::{ErrorKind, Write};

    let env_file = project_dir.join(".env");
    let example_file = project_dir.join(".env.example");

    let source_metadata = match std::fs::symlink_metadata(&example_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "inspect {}: {error}",
                example_file.display()
            )));
        }
    };
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(LpmError::Script(format!(
            "refusing to copy {} because it is not a regular file",
            example_file.display()
        )));
    }

    let (contents, _opened_metadata) = lpm_common::read_regular_file_capped_with_metadata(
        &example_file,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )
    .map_err(|error| LpmError::Script(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if _opened_metadata.dev() != source_metadata.dev()
            || _opened_metadata.ino() != source_metadata.ino()
        {
            return Err(LpmError::Script(format!(
                "{} changed while it was being opened; retry lpm dev",
                example_file.display()
            )));
        }
    }

    let mut temporary = tempfile::NamedTempFile::new_in(project_dir).map_err(LpmError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(LpmError::Io)?;
    }
    temporary.write_all(&contents).map_err(LpmError::Io)?;
    temporary.as_file().sync_all().map_err(LpmError::Io)?;
    match temporary.persist_noclobber(&env_file) {
        Ok(_) => {
            dev_ui::warn("No .env file found. Created from .env.example");
            dev_ui::hint_line("Review .env and fill in missing values");
            dev_ui::trusted_hint_line(install_ui::terminal_line!(
                "Or use {} to store secrets in the vault",
                install_ui::yellow("lpm env vars set"),
            ));
            Ok(Some("created from .env.example".to_string()))
        }
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => {
            Ok(Some(".env loaded".to_string()))
        }
        Err(error) => Err(LpmError::Script(format!(
            "create {}: {}",
            env_file.display(),
            error.error
        ))),
    }
}

/// Format a Duration as human-readable (e.g. "42ms" or "3.2s").
fn format_duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

fn format_dev_webhook_status(status: u16) -> install_ui::TerminalFragment {
    let status_label = status.to_string();
    if status >= 500 {
        install_ui::red(&status_label)
    } else if status >= 400 {
        install_ui::yellow(&status_label)
    } else {
        install_ui::status_ok(&status_label)
    }
}

fn format_dev_webhook_line(
    method: &str,
    path: &str,
    response_status: u16,
    duration_ms: u64,
    summary: &str,
) -> install_ui::TerminalLine {
    let method = method.to_uppercase();
    let warning = if response_status >= 400 {
        crate::install_ui::terminal_line!(" {}", install_ui::yellow("!"))
    } else {
        install_ui::TerminalLine::new("")
    };
    crate::install_ui::terminal_line!(
        "  {} {} {} -> {} {} — {}{}",
        install_ui::dim("tunnel"),
        install_ui::yellow(&method),
        install_ui::cyan(path),
        format_dev_webhook_status(response_status),
        install_ui::dim(&format!("({duration_ms}ms)")),
        summary,
        warning
    )
}

/// Check if a port number is in the privileged range (< 1024).
///
/// On Linux, binding to ports below 1024 requires root or `CAP_NET_BIND_SERVICE`.
/// macOS is more lenient but we still warn to avoid confusion.
fn is_privileged_port(port: u16) -> bool {
    port < 1024
}

fn resolve_dev_port(requested: Option<u16>, has_services: bool) -> u16 {
    if let Some(port) = requested {
        return port;
    }
    if has_services {
        return 3000;
    }
    lpm_runner::ports::find_available_port(3000).unwrap_or(3000)
}

fn find_internal_dev_port_excluding(
    public_port: u16,
    excluded_port: Option<u16>,
) -> Result<u16, LpmError> {
    let find_candidate = |start| {
        let mut start = start;
        loop {
            let port = lpm_runner::ports::find_available_port(start)?;
            if port != public_port && Some(port) != excluded_port {
                return Some(port);
            }
            start = port.checked_add(1)?;
        }
    };
    public_port
        .checked_add(1)
        .and_then(find_candidate)
        .or_else(|| find_candidate(3000))
        .ok_or_else(|| LpmError::Script("no available internal dev-server port found".to_string()))
}

async fn start_single_service_frontends(
    _project_dir: &Path,
    child_target: LocalTarget,
    child_owner_pid: Option<u32>,
    https: bool,
    network: bool,
    requested_port: Option<u16>,
    tls_material: Option<&DevTlsMaterial>,
) -> Result<DevFrontends, LpmError> {
    if child_target.scheme == LocalScheme::Https {
        if https {
            let port_context = requested_port
                .filter(|port| *port != child_target.port)
                .map_or_else(String::new, |public_port| {
                    format!(" or remap it to requested public port {public_port}")
                });
            return Err(LpmError::Script(format!(
                "the child already serves HTTPS on port {}, so LPM CLI cannot terminate TLS{port_context}; configure the child to serve plain HTTP",
                child_target.port
            )));
        }
        if network {
            return Err(LpmError::Network(
                "the HTTPS child is loopback-only, so `--network` cannot publish it without a TLS-aware frontend; configure the child to serve plain HTTP and let LPM CLI terminate HTTPS"
                    .to_string(),
            ));
        }
        return Ok(DevFrontends {
            child_target: child_target.clone(),
            local_target: child_target.clone(),
            network_port: network.then_some(child_target.port),
            upstream: None,
            handles: Vec::new(),
        });
    }

    if https {
        let tls_material = tls_material.ok_or_else(|| {
            LpmError::Script("HTTPS certificate material was not retained after setup".to_string())
        })?;
        let public_port = requested_port.unwrap_or(0);
        let bind_address = if network {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let listener = tokio::net::TcpListener::bind((bind_address, public_port))
            .await
            .map_err(|error| {
                LpmError::Script(format!(
                    "bind LPM HTTPS frontend on {bind_address}:{public_port}: {error}"
                ))
            })?;
        let upstream = lpm_proxy::FrontendUpstream::new(child_target.clone())
            .map_err(|error| LpmError::Script(format!("prepare LPM HTTPS frontend: {error}")))?;
        let handle = lpm_proxy::start_tls_frontend_on_listener_with_pem_and_upstream(
            listener,
            &tls_material.cert_pem,
            &tls_material.key_pem,
            upstream.clone(),
        )
        .await
        .map_err(|error| LpmError::Script(format!("start LPM HTTPS frontend: {error}")))?;
        return Ok(DevFrontends {
            child_target: child_target.clone(),
            local_target: LocalTarget::loopback(LocalScheme::Https, handle.port())
                .with_base_path(child_target.base_path.clone()),
            network_port: network.then_some(handle.port()),
            upstream: Some(upstream),
            handles: vec![handle],
        });
    }

    let upstream = network
        .then(|| lpm_proxy::FrontendUpstream::new(child_target.clone()))
        .transpose()
        .map_err(|error| LpmError::Network(format!("prepare LPM network frontend: {error}")))?;
    let mut handles = Vec::new();
    if network {
        let network_info = lpm_network::get_network_info(child_target.port, false)?;
        for address in network_info
            .addresses
            .iter()
            .filter(|address| !address.is_ipv6)
        {
            let Ok(ip) = address.ip.parse::<IpAddr>() else {
                continue;
            };
            match tokio::net::TcpListener::bind((ip, child_target.port)).await {
                Ok(listener) => {
                    let handle = lpm_proxy::start_http_frontend_on_listener_with_upstream(
                        listener,
                        upstream
                            .as_ref()
                            .expect("network frontends must share an upstream")
                            .clone(),
                    )
                    .map_err(|error| {
                        LpmError::Network(format!(
                            "start LPM network frontend on {ip}:{}: {error}",
                            child_target.port
                        ))
                    })?;
                    handles.push(handle);
                }
                Err(error) => {
                    let listeners = lpm_runner::ports::list_listening_ports();
                    let owned = lan_listener_is_owned_by_child(
                        &listeners,
                        ip,
                        child_target.port,
                        child_owner_pid,
                    );
                    let reachable = tokio::time::timeout(
                        std::time::Duration::from_millis(300),
                        tokio::net::TcpStream::connect((ip, child_target.port)),
                    )
                    .await
                    .is_ok_and(|result| result.is_ok());
                    if !owned || !reachable {
                        return Err(LpmError::Network(format!(
                            "bind LPM network frontend on {ip}:{}: {error}; the existing listener is not owned by the verified child endpoint",
                            child_target.port,
                        )));
                    }
                }
            }
        }
    }

    Ok(DevFrontends {
        network_port: network.then_some(child_target.port),
        local_target: child_target.clone(),
        child_target,
        upstream,
        handles,
    })
}

fn lan_listener_is_owned_by_child(
    listeners: &[lpm_runner::ports::ListeningPort],
    address: IpAddr,
    port: u16,
    child_owner_pid: Option<u32>,
) -> bool {
    let Some(child_owner_pid) = child_owner_pid else {
        return false;
    };
    listeners
        .iter()
        .any(|listener| listener.pid == Some(child_owner_pid) && listener.listens_on(address, port))
}

async fn display_network_access(
    network_info: &lpm_network::NetworkInfo,
    port: u16,
    https: bool,
    base_path: &str,
    allow_ca_bootstrap: bool,
) -> Result<Option<String>, LpmError> {
    let scheme = if https { "https" } else { "http" };
    let mut network_addr = None;
    let primary = network_info
        .primary
        .as_ref()
        .filter(|address| !address.is_ipv6)
        .or_else(|| {
            network_info
                .addresses
                .iter()
                .find(|address| !address.is_ipv6)
        });
    if let Some(primary) = primary {
        network_addr = Some(format!("{}:{port}", primary.ip));
        let url = format_network_url(scheme, &primary.ip, primary.is_ipv6, port, base_path);
        dev_ui::blank_line();
        dev_ui::trusted_detail_with_hint(
            "Network",
            &install_ui::url(&url),
            &format!("({})", primary.interface_type),
        );
        for address in network_info
            .addresses
            .iter()
            .filter(|address| !address.is_preferred && !address.is_ipv6)
        {
            let url = format_network_url(scheme, &address.ip, address.is_ipv6, port, base_path);
            dev_ui::trusted_hint_line(install_ui::terminal_line!(
                "{} {}",
                install_ui::url(&url),
                install_ui::dim(&format!("({})", address.interface_type)),
            ));
        }

        if https
            && let Ok(ca_cert_path) = lpm_cert::paths::ca_cert_path()
            && ca_cert_path.exists()
        {
            if allow_ca_bootstrap {
                let ca_cert_data = lpm_common::read_file_capped(
                    &ca_cert_path,
                    lpm_common::TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
                )?;
                if !ca_cert_data.is_empty() {
                    let ca_port = start_ca_cert_server(ca_cert_data).await?;
                    dev_ui::blank_line();
                    dev_ui::trusted_detail_line(
                        "Mobile",
                        install_ui::terminal_line!(
                            "First time on mobile? Visit {} to install the CA certificate",
                            install_ui::url(&format!("http://{}:{ca_port}", primary.ip)),
                        ),
                    );
                }
            } else {
                dev_ui::blank_line();
                dev_ui::trusted_detail_line(
                    "Mobile",
                    install_ui::terminal_line!(
                        "enable with {} or copy {} to the device manually",
                        install_ui::cyan("--allow-ca-bootstrap"),
                        install_ui::cyan("rootCA.pem"),
                    ),
                );
            }
        }
    } else {
        dev_ui::warn("no IPv4 network interfaces found");
    }

    let qr_code = primary
        .map(|address| format_network_url(scheme, &address.ip, address.is_ipv6, port, base_path))
        .and_then(|url| lpm_network::qr::render_qr_code(&url).ok())
        .unwrap_or_default();
    if !qr_code.is_empty() {
        dev_ui::blank_line();
        dev_ui::untrusted_block(&qr_code);
    }
    for warning in &network_info.warnings {
        dev_ui::warn(warning);
    }
    dev_ui::blank_line();
    Ok(network_addr)
}

fn format_network_url(
    scheme: &str,
    address: &str,
    is_ipv6: bool,
    port: u16,
    base_path: &str,
) -> String {
    if is_ipv6 {
        format!("{scheme}://[{address}]:{port}{base_path}")
    } else {
        format!("{scheme}://{address}:{port}{base_path}")
    }
}

fn upsert_extra_env(extra_env: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some((_, existing)) = extra_env.iter_mut().find(|(env_key, _)| env_key == key) {
        *existing = value;
    } else {
        extra_env.push((key.to_string(), value));
    }
}

/// Convert orchestrator's `ServiceStatus` to dashboard's `ServiceStatus`.
///
/// The two enums are structurally similar but live in different crates.
fn convert_service_status(
    status: &lpm_runner::orchestrator::ServiceStatus,
) -> lpm_dashboard::ServiceStatus {
    match status {
        lpm_runner::orchestrator::ServiceStatus::Pending
        | lpm_runner::orchestrator::ServiceStatus::Starting => {
            lpm_dashboard::ServiceStatus::Starting
        }
        lpm_runner::orchestrator::ServiceStatus::WaitingForDep(dep) => {
            lpm_dashboard::ServiceStatus::WaitingForDep(dep.clone())
        }
        lpm_runner::orchestrator::ServiceStatus::Ready => lpm_dashboard::ServiceStatus::Ready,
        lpm_runner::orchestrator::ServiceStatus::ReadinessFailed(error) => {
            lpm_dashboard::ServiceStatus::ReadinessFailed(error.clone())
        }
        lpm_runner::orchestrator::ServiceStatus::Crashed(code) => {
            lpm_dashboard::ServiceStatus::Crashed(format!("exit code {code}"))
        }
        lpm_runner::orchestrator::ServiceStatus::Stopped => lpm_dashboard::ServiceStatus::Stopped,
    }
}

/// Determine whether the browser should be opened after readiness check.
///
/// Returns `true` only when the service is ready, the user hasn't disabled
/// browser opening (`--no-open`), and we're not running in CI.
fn should_open_browser(ready: bool, no_open: bool, is_ci: bool) -> bool {
    ready && !no_open && !is_ci
}

/// Detect if running in CI environment.
fn is_ci() -> bool {
    std::env::var("CI").is_ok()
        || std::env::var("CONTINUOUS_INTEGRATION").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
}

async fn start_ca_cert_server(ca_cert_data: Vec<u8>) -> Result<u16, LpmError> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| LpmError::Network(format!("bind mobile CA bootstrap server: {error}")))?;
    let port = listener
        .local_addr()
        .map_err(|error| LpmError::Network(format!("read CA bootstrap address: {error}")))?
        .port();
    tokio::spawn(serve_ca_cert(listener, Arc::<[u8]>::from(ca_cert_data)));
    Ok(port)
}

async fn serve_ca_cert(listener: tokio::net::TcpListener, ca_cert_data: Arc<[u8]>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CONNECTION_LIMIT: usize = 16;
    const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    let permits = Arc::new(tokio::sync::Semaphore::new(CONNECTION_LIMIT));
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => break,
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            continue;
        };

        let cert_data = Arc::clone(&ca_cert_data);
        tokio::spawn(async move {
            let _permit = permit;
            let request = async {
                let mut buf = [0u8; 4096];
                if stream.read(&mut buf).await? == 0 {
                    return Ok::<(), std::io::Error>(());
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/x-pem-file\r\n\
                     Content-Disposition: attachment; filename=\"lpm-ca.pem\"\r\n\
                     Content-Length: {}\r\n\
                     Cache-Control: no-store\r\n\
                     Connection: close\r\n\
                     \r\n",
                    cert_data.len()
                );
                stream.write_all(response.as_bytes()).await?;
                stream.write_all(&cert_data).await?;
                stream.flush().await
            };
            let _ = tokio::time::timeout(IO_TIMEOUT, request).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_state::compute_install_hash;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn internal_dev_port_excludes_the_explicit_inspector_port() {
        let (public_port, inspector_port) = (30_000..60_000)
            .find_map(|public_port| {
                let public =
                    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, public_port))
                        .ok()?;
                let inspector_port = public_port.checked_add(1)?;
                let inspector =
                    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, inspector_port))
                        .ok()?;
                drop(inspector);
                drop(public);
                Some((public_port, inspector_port))
            })
            .expect("two consecutive test ports");

        let selected = find_internal_dev_port_excluding(public_port, Some(inspector_port)).unwrap();

        assert_ne!(selected, inspector_port);
    }

    #[test]
    fn single_service_port_planning_loads_the_manifest_once() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"devDependencies":{"vite":"^7.0.0"}}"#,
        )
        .unwrap();
        let loads = std::cell::Cell::new(0);

        let args =
            single_service_managed_port_args_with(project.path(), "vite", 5174, |directory| {
                loads.set(loads.get() + 1);
                lpm_cert::framework::CommandPortPlanner::load(directory)
            })
            .unwrap();

        assert_eq!(args, ["--port", "5174", "--strictPort"]);
        assert_eq!(loads.get(), 1);
    }

    #[cfg(unix)]
    async fn start_proxy_test_upstream(response: &'static str) -> u16 {
        use axum::Router;
        use axum::routing::get;

        let listener = tokio::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(get(move || async move { response })),
            )
            .await
            .unwrap();
        });
        port
    }

    #[cfg(unix)]
    async fn wait_for_test_proxy(socket_path: &Path) {
        for _ in 0..100 {
            if lpm_proxy::send_request_to_path(socket_path, lpm_proxy::ProxyRequest::Status)
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("proxy control socket did not become ready");
    }

    #[cfg(unix)]
    async fn stop_test_proxy(
        socket_path: &Path,
        server: tokio::task::JoinHandle<Result<(), lpm_proxy::ProxyError>>,
    ) {
        let stopped = lpm_proxy::send_request_to_path(socket_path, lpm_proxy::ProxyRequest::Stop)
            .await
            .unwrap();
        assert_eq!(stopped, lpm_proxy::ProxyResponse::Stopped);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mobile_ca_bootstrap_drops_an_idle_connection() {
        use tokio::io::AsyncReadExt;

        let port = start_ca_cert_server(b"test certificate".to_vec())
            .await
            .unwrap();
        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];

        let read = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut byte))
            .await
            .expect("idle bootstrap connection must be closed within the timeout")
            .unwrap();

        assert_eq!(read, 0);
    }

    #[test]
    fn local_proxy_rejects_a_high_tls_port_that_differs_from_lpm_json() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                port: Some(9443),
                http_redirect: Some(false),
            }),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: Some("127.0.0.1:10443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        let error = validate_local_proxy_listener_contract(&config, &status).unwrap_err();

        assert!(error.contains("9443"), "got {error}");
        assert!(error.contains("10443"), "got {error}");
    }

    #[test]
    fn local_proxy_accepts_scheme_qualified_tls_listener_status() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                port: Some(9443),
                http_redirect: Some(false),
            }),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: Some("https://127.0.0.1:9443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        validate_local_proxy_listener_contract(&config, &status).unwrap();
    }

    #[test]
    fn local_proxy_accepts_an_assigned_port_for_an_ephemeral_tls_request() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                port: Some(0),
                http_redirect: Some(false),
            }),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: Some("127.0.0.1:10443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        validate_local_proxy_listener_contract(&config, &status).unwrap();
    }

    #[test]
    fn local_proxy_accepts_a_disabled_redirect_when_lpm_json_does_not_specify_one() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                port: Some(9443),
                http_redirect: None,
            }),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: Some("127.0.0.1:9443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        validate_local_proxy_listener_contract(&config, &status).unwrap();
    }

    #[test]
    fn local_proxy_rejects_a_nonstandard_privileged_tls_port_mismatch() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                port: Some(444),
                http_redirect: Some(false),
            }),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: Some("127.0.0.1:10443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        let error = validate_local_proxy_listener_contract(&config, &status).unwrap_err();

        assert!(error.contains("444"), "got {error}");
        assert!(error.contains("10443"), "got {error}");
    }

    #[test]
    fn local_proxy_rejects_a_redirect_listener_disabled_by_lpm_json() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                port: Some(9443),
                http_redirect: Some(false),
            }),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: Some("127.0.0.1:8080".to_string()),
            tls_addr: Some("127.0.0.1:9443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        let error = validate_local_proxy_listener_contract(&config, &status).unwrap_err();

        assert!(error.contains("redirect"), "got {error}");
        assert!(error.contains("disabled"), "got {error}");
    }

    #[test]
    fn local_proxy_allows_a_forwarded_backend_for_privileged_tls_and_redirect_ports() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            services: HashMap::from([(
                "web".to_string(),
                lpm_runner::lpm_json::ServiceConfig {
                    command: "node server.js".to_string(),
                    host: Some("web.localhost".to_string()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let status = lpm_proxy::ProxyStatus {
            running: true,
            pid: Some(42),
            http_addr: None,
            http_redirect_addr: Some("127.0.0.1:9080".to_string()),
            tls_addr: Some("127.0.0.1:9443".to_string()),
            routes: Vec::new(),
            stale: false,
            state_error: None,
        };

        validate_local_proxy_listener_contract(&config, &status).unwrap();
    }

    fn remove_staged_dev_session(root: &lpm_common::LpmRoot) {
        let staged = fs::read_dir(root.dev_sessions_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".next"))
            })
            .expect("prepared dev session did not create a staged record");
        fs::remove_file(staged).unwrap();
    }

    #[test]
    fn selecting_the_primary_endpoint_preserves_it_for_future_route_rebuilds() {
        let endpoints = lpm_runner::orchestrator::ServiceEndpointMap::from([
            (
                "web".to_string(),
                lpm_runner::dev_endpoint::DevEndpoint {
                    target: LocalTarget::loopback(LocalScheme::Http, 3000),
                    owner_pid: Some(1),
                    owner_identity: None,
                    service: Some("web".to_string()),
                },
            ),
            (
                "api".to_string(),
                lpm_runner::dev_endpoint::DevEndpoint {
                    target: LocalTarget::loopback(LocalScheme::Http, 4000),
                    owner_pid: Some(2),
                    owner_identity: None,
                    service: Some("api".to_string()),
                },
            ),
        ]);

        let selected = endpoints.get("web").cloned().unwrap();

        assert_eq!(selected.target.port, 3000);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints["web"].target.port, 3000);
    }

    #[tokio::test]
    async fn tunnel_publication_wait_rejects_a_dropped_connection_attempt() {
        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<(), String>>();
        drop(sender);

        let error = wait_for_tunnel_readiness(receiver, std::time::Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("stopped before confirming readiness")
        );
    }

    #[tokio::test]
    async fn tunnel_publication_wait_reports_the_connection_failure() {
        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<(), String>>();
        sender
            .send(Err("relay rejected token".to_string()))
            .unwrap();

        let error = wait_for_tunnel_readiness(receiver, std::time::Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("relay rejected token"));
    }

    #[tokio::test]
    async fn tunnel_shutdown_reports_a_panicked_task() {
        let tunnel_handle = tokio::spawn(async {
            panic!("injected tunnel task panic");
        });

        let error = shutdown_spawned_tunnel(Some(tunnel_handle), None)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("tunnel task failed during shutdown")
        );
        assert!(error.to_string().contains("injected tunnel task panic"));
    }

    #[tokio::test]
    async fn failed_multi_service_preparation_closes_inspector_and_flushes_captures() {
        let project = TempDir::new().unwrap();
        let db = lpm_inspect::db::InspectorDb::open(project.path()).unwrap();
        let state = lpm_inspect::state::InspectorState::with_db_pending(db.clone());
        state
            .start_session_immediate(
                "setup-session".to_string(),
                None,
                3000,
                Some("web".to_string()),
            )
            .unwrap();
        state
            .push(lpm_tunnel::webhook::CapturedWebhook {
                id: "queued-before-setup-failure".to_string(),
                timestamp: "2026-08-14T12:00:00Z".to_string(),
                method: "POST".to_string(),
                path: "/hook".to_string(),
                request_headers: HashMap::new(),
                request_body: b"request".to_vec(),
                response_status: 202,
                response_headers: HashMap::new(),
                response_body: b"accepted".to_vec(),
                duration_ms: 1,
                provider: None,
                summary: "queued capture".to_string(),
                signature_diagnostic: None,
                auto_acked: false,
            })
            .await;
        let inspector = lpm_inspect::start(state.clone(), 0).await.unwrap();
        let inspector_port = inspector.port;

        let error = cleanup_failed_multi_service_preparation(
            LpmError::Script("injected multi-service preparation failure".to_string()),
            None,
            None,
            None,
            Some(state),
            Some(inspector),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("injected multi-service preparation failure")
        );
        assert!(
            db.get_webhook("queued-before-setup-failure")
                .await
                .unwrap()
                .is_some()
        );
        let rebound = lpm_inspect::start(
            lpm_inspect::state::InspectorState::pending(),
            inspector_port,
        )
        .await
        .expect("failed setup cleanup must release the inspector listener");
        rebound.shutdown().await.unwrap();
    }

    #[test]
    fn tunnel_finalization_preserves_primary_and_every_cleanup_failure() {
        let cleanup = combine_tunnel_cleanup_results(
            Err(LpmError::Tunnel("capture task failed".to_string())),
            Err(LpmError::Tunnel("inspector session end failed".to_string())),
        );

        let error = compose_tunnel_runtime_and_cleanup(
            Err(LpmError::Script("runtime failed".to_string())),
            cleanup,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("runtime failed"), "{error}");
        assert!(error.contains("capture task failed"), "{error}");
        assert!(error.contains("inspector session end failed"), "{error}");
    }

    #[test]
    fn tunnel_shutdown_boundary_returns_only_after_task_acknowledgement() {
        let (boundary, shutdown_rx, completion) = TunnelShutdownBoundary::new();
        let acknowledged = Arc::new(AtomicBool::new(false));
        let task_acknowledged = Arc::clone(&acknowledged);
        let task = std::thread::spawn(move || {
            shutdown_rx.blocking_recv().unwrap();
            task_acknowledged.store(true, Ordering::Release);
            drop(completion);
        });

        boundary.request_and_wait().unwrap();
        task.join().unwrap();

        assert!(acknowledged.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn failed_initial_publication_keeps_runtime_and_tunnel_surfaces_hidden() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);
        let old_target = LocalTarget::loopback(LocalScheme::Http, 3000);
        let new_target = LocalTarget::loopback(LocalScheme::Http, 4000);
        let endpoint = lpm_runner::dev_endpoint::DevEndpoint {
            target: new_target.clone(),
            owner_pid: Some(42),
            owner_identity: None,
            service: Some("web".to_string()),
        };
        let endpoints = lpm_runner::orchestrator::ServiceEndpointMap::from([(
            "web".to_string(),
            endpoint.clone(),
        )]);
        let prepared_session = lpm_runner::dev_session::PreparedDevSession::prepare(
            project.path(),
            new_target.clone(),
            endpoint.owner_pid,
            endpoint.owner_identity.clone(),
            endpoint.service.clone(),
            false,
        )
        .unwrap();
        let frontend_slot = Arc::new(Mutex::new(None));
        let session_slot = Arc::new(Mutex::new(None));
        let endpoint_slot = Arc::new(Mutex::new(
            lpm_runner::orchestrator::ServiceEndpointMap::new(),
        ));
        let inspector_db = lpm_inspect::db::InspectorDb::open(project.path()).unwrap();
        let inspector = lpm_inspect::state::InspectorState::with_db_for_target(
            old_target.clone(),
            inspector_db,
        );
        let tunnel_target = Arc::new(RwLock::new(old_target.clone()));
        let tunnel_published = Arc::new(AtomicBool::new(false));
        let tunnel_publication = TunnelReadyPublication {
            session: lpm_tunnel::TunnelSession {
                tunnel_url: "https://example.lpm.fyi".to_string(),
                domain: "example.lpm.fyi".to_string(),
                session_id: "session".to_string(),
                local_port: new_target.port,
                plan: None,
                base_domain: None,
                domain_kind: None,
                session_expires_at: None,
                session_max_ms: None,
                limits: None,
            },
            local_target_url: new_target.url(),
            tunnel_auth: None,
            usage: None,
        };
        let runtime_handle = tokio::runtime::Handle::current();

        let error = publish_initial_runtime(
            &runtime_handle,
            &endpoint,
            endpoints,
            DevFrontends {
                child_target: new_target.clone(),
                local_target: new_target,
                network_port: None,
                upstream: None,
                handles: Vec::new(),
            },
            prepared_session,
            &frontend_slot,
            &session_slot,
            &endpoint_slot,
            Some(&inspector),
            Some(&tunnel_target),
            Some(&tunnel_publication),
            Some(&tunnel_published),
            None,
            || Err(LpmError::Script("injected publication failure".into())),
        )
        .unwrap_err();

        assert!(error.to_string().contains("injected publication failure"));
        assert!(frontend_slot.lock().unwrap().is_none());
        assert!(session_slot.lock().unwrap().is_none());
        assert!(endpoint_slot.lock().unwrap().is_empty());
        assert_eq!(inspector.local_target(), old_target);
        assert_eq!(*tunnel_target.read().unwrap(), old_target);
        assert!(!tunnel_published.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_initial_session_commit_keeps_tunnel_publication_hidden() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        let socket_path = root.proxy_socket();
        let state_path = root.proxy_state();
        let server_socket = socket_path.clone();
        let server_state = state_path.clone();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);
        let server = tokio::spawn(async move {
            lpm_proxy::serve_control_at_path(&server_socket, &server_state).await
        });
        wait_for_test_proxy(&socket_path).await;
        let old_target = LocalTarget::loopback(LocalScheme::Http, 3000);
        let new_target = LocalTarget::loopback(LocalScheme::Http, 4000);
        let endpoint = lpm_runner::dev_endpoint::DevEndpoint {
            target: new_target.clone(),
            owner_pid: None,
            owner_identity: None,
            service: Some("web".to_string()),
        };
        let prepared_session = lpm_runner::dev_session::PreparedDevSession::prepare(
            project.path(),
            new_target.clone(),
            None,
            None,
            endpoint.service.clone(),
            false,
        )
        .unwrap();
        let inspector_db = lpm_inspect::db::InspectorDb::open(project.path()).unwrap();
        let inspector = lpm_inspect::state::InspectorState::with_db_for_target(
            old_target.clone(),
            inspector_db.clone(),
        );
        let tunnel_target = Arc::new(RwLock::new(old_target.clone()));
        let tunnel_published = Arc::new(AtomicBool::new(false));
        let tunnel_publication = TunnelReadyPublication {
            session: lpm_tunnel::TunnelSession {
                tunnel_url: "https://example.lpm.fyi".to_string(),
                domain: "example.lpm.fyi".to_string(),
                session_id: "session".to_string(),
                local_port: new_target.port,
                plan: None,
                base_domain: None,
                domain_kind: None,
                session_expires_at: None,
                session_max_ms: None,
                limits: None,
            },
            local_target_url: new_target.url(),
            tunnel_auth: None,
            usage: None,
        };
        let runtime_handle = tokio::runtime::Handle::current();
        let frontend_slot = Arc::new(Mutex::new(None));
        let session_slot = Arc::new(Mutex::new(None));
        let endpoint_slot = Arc::new(Mutex::new(
            lpm_runner::orchestrator::ServiceEndpointMap::new(),
        ));
        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        let proxy_plan = prepare_initial_proxy_route_plan(
            project.path(),
            vec![lpm_runner::local_domains::LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream: LocalTarget::loopback(LocalScheme::Http, 4000),
                service: Some("web".to_string()),
            }],
            Arc::clone(&proxy_lease),
        )
        .await
        .unwrap();

        let error = tokio::task::block_in_place(|| {
            publish_initial_runtime(
                &runtime_handle,
                &endpoint,
                lpm_runner::orchestrator::ServiceEndpointMap::from([(
                    "web".to_string(),
                    endpoint.clone(),
                )]),
                DevFrontends {
                    child_target: new_target.clone(),
                    local_target: new_target,
                    network_port: None,
                    upstream: None,
                    handles: Vec::new(),
                },
                prepared_session,
                &frontend_slot,
                &session_slot,
                &endpoint_slot,
                Some(&inspector),
                Some(&tunnel_target),
                Some(&tunnel_publication),
                Some(&tunnel_published),
                Some(proxy_plan),
                || {
                    remove_staged_dev_session(&root);
                    Ok(())
                },
            )
        })
        .unwrap_err();

        assert!(error.to_string().contains("No such file or directory"));
        assert!(inspector.get_tunnel_url().await.is_none());
        assert!(inspector_db.list_sessions(10).await.unwrap().is_empty());
        assert_eq!(inspector.local_target(), old_target);
        assert_eq!(*tunnel_target.read().unwrap(), old_target);
        assert!(!tunnel_published.load(Ordering::Acquire));
        assert!(frontend_slot.lock().unwrap().is_none());
        assert!(session_slot.lock().unwrap().is_none());
        assert!(endpoint_slot.lock().unwrap().is_empty());
        let proxy_snapshot = proxy_route_snapshot(&proxy_lease).await;
        assert!(proxy_snapshot.is_empty(), "{proxy_snapshot:?}");

        release_proxy_lease(&proxy_lease).await.unwrap();
        stop_test_proxy(&socket_path, server).await;
    }

    #[test]
    fn privileged_port_detection() {
        assert!(is_privileged_port(80));
        assert!(is_privileged_port(443));
        assert!(is_privileged_port(1));
        assert!(is_privileged_port(1023));
        assert!(!is_privileged_port(1024));
        assert!(!is_privileged_port(3000));
        assert!(!is_privileged_port(8080));
    }

    #[test]
    fn network_urls_preserve_base_paths_and_bracket_ipv6_addresses() {
        assert_eq!(
            format_network_url("http", "192.0.2.10", false, 5173, "/app/"),
            "http://192.0.2.10:5173/app/"
        );
        assert_eq!(
            format_network_url("https", "2001:db8::1", true, 8443, "/app/"),
            "https://[2001:db8::1]:8443/app/"
        );
    }

    #[test]
    fn is_ci_detects_ci_env() {
        // Verify the function exists and returns bool — value depends on environment
        let _result: bool = is_ci();
    }

    #[test]
    fn first_script_binary_name_detects_plain_framework_entrypoint() {
        assert_eq!(
            first_script_binary_name("next dev --turbo").as_deref(),
            Some("next"),
        );
    }

    #[test]
    fn first_script_binary_name_skips_assignments_and_env_wrappers() {
        assert_eq!(
            first_script_binary_name("NODE_OPTIONS=--trace-warnings cross-env FOO=bar vite --host")
                .as_deref(),
            Some("vite"),
        );
    }

    #[test]
    fn first_script_binary_name_returns_none_for_runtime_commands() {
        assert_eq!(first_script_binary_name("node server.js"), None);
    }

    #[test]
    fn first_script_binary_name_returns_none_for_path_commands() {
        assert_eq!(
            first_script_binary_name("./node_modules/.bin/next dev"),
            None
        );
    }

    #[test]
    fn lan_listener_must_match_the_verified_child_owner() {
        let ip = "192.0.2.10".parse::<IpAddr>().unwrap();
        let rows = vec![lpm_runner::ports::ListeningPort {
            port: 5173,
            address: Some(ip.to_string()),
            address_family: Some(lpm_runner::ports::ListeningAddressFamily::Ipv4),
            pid: Some(200),
            process: Some("unrelated".to_string()),
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        }];

        assert!(!lan_listener_is_owned_by_child(&rows, ip, 5173, Some(100),));
        assert!(lan_listener_is_owned_by_child(&rows, ip, 5173, Some(200),));
        assert!(!lan_listener_is_owned_by_child(&rows, ip, 5173, None));
    }

    #[test]
    fn ipv6_wildcard_listener_does_not_authenticate_an_ipv4_lan_target() {
        let ip = "192.0.2.10".parse::<IpAddr>().unwrap();
        let rows = vec![lpm_runner::ports::ListeningPort {
            port: 5173,
            address: None,
            address_family: Some(lpm_runner::ports::ListeningAddressFamily::Ipv6),
            pid: Some(200),
            process: Some("node".to_string()),
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        }];

        assert!(!lan_listener_is_owned_by_child(&rows, ip, 5173, Some(200)));
    }

    #[tokio::test]
    async fn an_https_child_rejects_a_different_requested_public_port() {
        let project = TempDir::new().unwrap();
        let child = LocalTarget::loopback(LocalScheme::Https, 5173);

        let result = start_single_service_frontends(
            project.path(),
            child,
            None,
            true,
            false,
            Some(4000),
            None,
        )
        .await;
        let Err(error) = result else {
            panic!("an existing HTTPS child cannot be remapped without a TLS-aware frontend");
        };

        assert!(error.to_string().contains("already serves HTTPS"));
        assert!(error.to_string().contains("5173"));
        assert!(error.to_string().contains("4000"));
    }

    #[tokio::test]
    async fn an_https_child_rejects_lpm_tls_termination_mode() {
        let project = TempDir::new().unwrap();
        let child = LocalTarget::loopback(LocalScheme::Https, 5173);

        let result =
            start_single_service_frontends(project.path(), child, None, true, false, None, None)
                .await;
        let Err(error) = result else {
            panic!("LPM TLS termination requires a plain HTTP child");
        };

        assert!(error.to_string().contains("already serves HTTPS"));
        assert!(error.to_string().contains("plain HTTP"));
    }

    #[tokio::test]
    async fn an_https_child_does_not_claim_unavailable_lan_forwarding() {
        let project = TempDir::new().unwrap();
        let child = LocalTarget::loopback(LocalScheme::Https, 5173);

        let result =
            start_single_service_frontends(project.path(), child, None, false, true, None, None)
                .await;
        let Err(error) = result else {
            panic!("an HTTPS loopback child cannot be advertised on the LAN without forwarding");
        };

        assert!(error.to_string().contains("HTTPS child"));
        assert!(error.to_string().contains("--network"));
    }

    #[tokio::test]
    async fn a_local_domain_route_rejects_an_https_child() {
        let project = TempDir::new().unwrap();
        let routes = vec![lpm_runner::local_domains::LocalDomainRoute {
            host: "app.localhost".to_string(),
            upstream: LocalTarget::loopback(LocalScheme::Https, 5173),
            service: Some("web".to_string()),
        }];

        let Err(error) = prepare_proxy_routes(project.path(), &routes).await else {
            panic!("the local-domain proxy cannot safely forward to a framework HTTPS child");
        };

        assert!(error.to_string().contains("requires a plain HTTP child"));
        assert!(error.to_string().contains("https://127.0.0.1:5173/"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preparing_proxy_routes_keeps_the_candidate_generation_hidden() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        let socket_path = root.proxy_socket();
        let state_path = root.proxy_state();
        let server_socket = socket_path.clone();
        let server_state = state_path.clone();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);
        let server = tokio::spawn(async move {
            lpm_proxy::serve_control_at_path(&server_socket, &server_state).await
        });
        wait_for_test_proxy(&socket_path).await;

        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        let route = |port| lpm_runner::local_domains::LocalDomainRoute {
            host: "app.localhost".to_string(),
            upstream: LocalTarget::loopback(LocalScheme::Http, port),
            service: Some("web".to_string()),
        };
        register_proxy_route_plan(project.path(), vec![route(3000)], Arc::clone(&proxy_lease))
            .await
            .unwrap();

        let candidate =
            prepare_proxy_route_plan(project.path(), vec![route(4000)], Arc::clone(&proxy_lease))
                .await
                .unwrap();
        let listed = lpm_proxy::send_request_to_path(&socket_path, lpm_proxy::ProxyRequest::List)
            .await
            .unwrap();
        let lpm_proxy::ProxyResponse::Routes { routes } = listed else {
            panic!("expected proxy route listing");
        };

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].upstream_port, 3000);

        candidate.rollback().await.unwrap();
        release_proxy_lease(&proxy_lease).await.unwrap();
        stop_test_proxy(&socket_path, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn committed_proxy_routes_restore_the_previous_generation_before_acceptance() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        let socket_path = root.proxy_socket();
        let state_path = root.proxy_state();
        let server_socket = socket_path.clone();
        let server_state = state_path.clone();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);
        let server = tokio::spawn(async move {
            lpm_proxy::serve_control_at_path(&server_socket, &server_state).await
        });
        wait_for_test_proxy(&socket_path).await;

        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        let route = |port| lpm_runner::local_domains::LocalDomainRoute {
            host: "app.localhost".to_string(),
            upstream: LocalTarget::loopback(LocalScheme::Http, port),
            service: Some("web".to_string()),
        };
        register_proxy_route_plan(project.path(), vec![route(3000)], Arc::clone(&proxy_lease))
            .await
            .unwrap();
        let published =
            prepare_proxy_route_plan(project.path(), vec![route(4000)], Arc::clone(&proxy_lease))
                .await
                .unwrap()
                .commit_reversible()
                .await
                .unwrap();

        assert_eq!(
            proxy_route_snapshot(&proxy_lease).await[0].upstream_port,
            4000
        );
        published.rollback().await.unwrap();
        assert_eq!(
            proxy_route_snapshot(&proxy_lease).await[0].upstream_port,
            3000
        );

        release_proxy_lease(&proxy_lease).await.unwrap();
        stop_test_proxy(&socket_path, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rolling_back_proxy_routes_keeps_the_previous_bridge_reachable() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        let socket_path = root.proxy_socket();
        let state_path = root.proxy_state();
        let server_socket = socket_path.clone();
        let server_state = state_path.clone();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);
        let server = tokio::spawn(async move {
            lpm_proxy::serve_control_at_path(&server_socket, &server_state).await
        });
        wait_for_test_proxy(&socket_path).await;

        let old_port = start_proxy_test_upstream("old generation").await;
        let new_port = start_proxy_test_upstream("new generation").await;
        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        register_proxy_route_plan(
            project.path(),
            vec![lpm_runner::local_domains::LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream: LocalTarget {
                    scheme: LocalScheme::Http,
                    address: std::net::Ipv6Addr::LOCALHOST.into(),
                    port: old_port,
                    base_path: "/old".to_string(),
                },
                service: Some("web".to_string()),
            }],
            Arc::clone(&proxy_lease),
        )
        .await
        .unwrap();

        let plan = prepare_proxy_route_plan(
            project.path(),
            vec![lpm_runner::local_domains::LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream: LocalTarget {
                    scheme: LocalScheme::Http,
                    address: std::net::Ipv6Addr::LOCALHOST.into(),
                    port: new_port,
                    base_path: "/new".to_string(),
                },
                service: Some("web".to_string()),
            }],
            Arc::clone(&proxy_lease),
        )
        .await
        .unwrap();

        plan.rollback().await.unwrap();
        let old_bridge_port = proxy_route_snapshot(&proxy_lease).await[0].upstream_port;
        let response = reqwest::get(format!("http://127.0.0.1:{old_bridge_port}/health"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert_eq!(response, "old generation");
        drop(proxy_lease);
        for _ in 0..100 {
            let listed =
                lpm_proxy::send_request_to_path(&socket_path, lpm_proxy::ProxyRequest::List)
                    .await
                    .unwrap();
            if listed == (lpm_proxy::ProxyResponse::Routes { routes: Vec::new() }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        stop_test_proxy(&socket_path, server).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_proxy_replacement_rolls_back_before_the_next_request() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        async fn read_request(
            lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        ) -> lpm_proxy::ProxyRequest {
            let line = lines.next_line().await.unwrap().unwrap();
            serde_json::from_str(&line).unwrap()
        }

        async fn write_response(
            writer: &mut tokio::net::unix::OwnedWriteHalf,
            response: &lpm_proxy::ProxyResponse,
        ) {
            let mut encoded = serde_json::to_vec(response).unwrap();
            encoded.push(b'\n');
            writer.write_all(&encoded).await.unwrap();
            writer.flush().await.unwrap();
        }

        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        let socket_path = root.proxy_socket();
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let (replacement_applied_tx, replacement_applied_rx) = tokio::sync::oneshot::channel();
        let (allow_response_tx, allow_response_rx) = tokio::sync::oneshot::channel();
        let (rollback_applied_tx, rollback_applied_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            let lpm_proxy::ProxyRequest::RegisterStagedLease { .. } =
                read_request(&mut lines).await
            else {
                panic!("expected a staged connection-backed lease registration");
            };
            let lease_id = lpm_proxy::RouteLeaseId::from_raw(1);
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::Registered { lease_id },
            )
            .await;

            let lpm_proxy::ProxyRequest::Stage {
                lease_id: initial_lease,
                publication_id: initial_publication,
                routes: old_routes,
            } = read_request(&mut lines).await
            else {
                panic!("expected the initial staged routes");
            };
            assert_eq!(initial_lease, lease_id);
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::Staged {
                    publication_id: initial_publication,
                },
            )
            .await;
            let lpm_proxy::ProxyRequest::Commit {
                lease_id: initial_commit_lease,
                publication_id: initial_commit,
            } = read_request(&mut lines).await
            else {
                panic!("expected the initial publication commit");
            };
            assert_eq!(initial_commit_lease, lease_id);
            assert_eq!(initial_commit, initial_publication);
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::Committed {
                    publication_id: initial_publication,
                },
            )
            .await;

            let lpm_proxy::ProxyRequest::Stage {
                lease_id: candidate_lease,
                publication_id: candidate_publication,
                routes: candidate_routes,
            } = read_request(&mut lines).await
            else {
                panic!("expected the candidate stage");
            };
            assert_eq!(candidate_lease, lease_id);
            assert_ne!(candidate_routes, old_routes);
            replacement_applied_tx.send(()).unwrap();
            allow_response_rx.await.unwrap();
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::Staged {
                    publication_id: candidate_publication,
                },
            )
            .await;

            let lpm_proxy::ProxyRequest::Rollback {
                lease_id: rollback_lease_id,
                publication_id: rollback_publication,
            } = read_request(&mut lines).await
            else {
                panic!("expected cancellation rollback before another request");
            };
            assert_eq!(rollback_lease_id, lease_id);
            assert_eq!(rollback_publication, candidate_publication);
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::RolledBack {
                    publication_id: candidate_publication,
                },
            )
            .await;
            rollback_applied_tx.send(()).unwrap();

            let lpm_proxy::ProxyRequest::Stage { .. } = read_request(&mut lines).await else {
                panic!("expected the stage after cancellation rollback");
            };
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::Error {
                    message: "injected replacement rejection".to_string(),
                },
            )
            .await;

            let lpm_proxy::ProxyRequest::Release {
                lease_id: released_lease,
            } = read_request(&mut lines).await
            else {
                panic!("expected lease release after the rejected stage");
            };
            assert_eq!(released_lease, lease_id);
            write_response(
                &mut writer,
                &lpm_proxy::ProxyResponse::Released { removed: 1 },
            )
            .await;
        });
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);

        let old_port = start_proxy_test_upstream("old generation").await;
        let new_port = start_proxy_test_upstream("candidate generation").await;
        let rejected_port = start_proxy_test_upstream("rejected generation").await;
        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        let route = |port, base_path: &str| lpm_runner::local_domains::LocalDomainRoute {
            host: "app.localhost".to_string(),
            upstream: LocalTarget {
                scheme: LocalScheme::Http,
                address: std::net::Ipv6Addr::LOCALHOST.into(),
                port,
                base_path: base_path.to_string(),
            },
            service: Some("web".to_string()),
        };
        register_proxy_route_plan(
            project.path(),
            vec![route(old_port, "/old")],
            Arc::clone(&proxy_lease),
        )
        .await
        .unwrap();

        let replacement_project = project.path().to_path_buf();
        let replacement_lease = Arc::clone(&proxy_lease);
        let replacement = tokio::spawn(async move {
            prepare_proxy_route_plan(
                &replacement_project,
                vec![route(new_port, "/candidate")],
                replacement_lease,
            )
            .await
        });
        replacement_applied_rx.await.unwrap();
        replacement.abort();
        let _ = replacement.await;
        allow_response_tx.send(()).unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), rollback_applied_rx)
            .await
            .expect("cancelled replacement did not roll back the daemon route")
            .unwrap();
        let Err(error) = prepare_proxy_route_plan(
            project.path(),
            vec![route(rejected_port, "/rejected")],
            Arc::clone(&proxy_lease),
        )
        .await
        else {
            panic!("the daemon rejection must not consume a stale replacement response");
        };

        assert!(error.to_string().contains("injected replacement rejection"));
        release_proxy_lease(&proxy_lease).await.unwrap();
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_primary_publication_keeps_every_runtime_surface_on_the_old_generation() {
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let root = lpm_common::LpmRoot::from_dir(home.path());
        let socket_path = root.proxy_socket();
        let state_path = root.proxy_state();
        let server_socket = socket_path.clone();
        let server_state = state_path.clone();
        let _env = crate::test_env::ScopedEnv::set([(
            "LPM_HOME",
            std::ffi::OsString::from(home.path().as_os_str()),
        )]);
        let server = tokio::spawn(async move {
            lpm_proxy::serve_control_at_path(&server_socket, &server_state).await
        });
        wait_for_test_proxy(&socket_path).await;

        let old_port = start_proxy_test_upstream("old generation").await;
        let new_port = start_proxy_test_upstream("new generation").await;
        let old_target = LocalTarget {
            scheme: LocalScheme::Http,
            address: std::net::Ipv6Addr::LOCALHOST.into(),
            port: old_port,
            base_path: "/old".to_string(),
        };
        let new_target = LocalTarget {
            scheme: LocalScheme::Http,
            address: std::net::Ipv6Addr::LOCALHOST.into(),
            port: new_port,
            base_path: "/new".to_string(),
        };
        let proxy_lease = Arc::new(tokio::sync::Mutex::new(None));
        register_proxy_route_plan(
            project.path(),
            vec![lpm_runner::local_domains::LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream: old_target.clone(),
                service: Some("web".to_string()),
            }],
            Arc::clone(&proxy_lease),
        )
        .await
        .unwrap();
        let proxy_plan = prepare_proxy_route_plan(
            project.path(),
            vec![lpm_runner::local_domains::LocalDomainRoute {
                host: "app.localhost".to_string(),
                upstream: new_target.clone(),
                service: Some("web".to_string()),
            }],
            Arc::clone(&proxy_lease),
        )
        .await
        .unwrap();

        let old_endpoint = lpm_runner::dev_endpoint::DevEndpoint {
            target: old_target.clone(),
            owner_pid: None,
            owner_identity: None,
            service: Some("web".to_string()),
        };
        let new_endpoint = lpm_runner::dev_endpoint::DevEndpoint {
            target: new_target.clone(),
            owner_pid: None,
            owner_identity: None,
            service: Some("web".to_string()),
        };
        let old_session = lpm_runner::dev_session::DevSessionLease::register(
            project.path(),
            old_target.clone(),
            None,
            None,
            Some("web".to_string()),
            false,
        )
        .unwrap();
        let prepared_session = lpm_runner::dev_session::PreparedDevSession::prepare(
            project.path(),
            new_target.clone(),
            None,
            None,
            Some("web".to_string()),
            false,
        )
        .unwrap();
        let frontend_slot = Arc::new(Mutex::new(Some(DevFrontends {
            child_target: old_target.clone(),
            local_target: old_target.clone(),
            network_port: None,
            upstream: None,
            handles: Vec::new(),
        })));
        let dev_session_slot = Arc::new(Mutex::new(Some(old_session)));
        let service_endpoint_slot = Arc::new(Mutex::new(
            lpm_runner::orchestrator::ServiceEndpointMap::from([("web".to_string(), old_endpoint)]),
        ));
        let inspector = lpm_inspect::state::InspectorState::new_for_target(old_target.clone());
        let tunnel_target = Arc::new(RwLock::new(old_target.clone()));
        let runtime_handle = tokio::runtime::Handle::current();

        let error = tokio::task::block_in_place(|| {
            publish_primary_endpoint(
                &runtime_handle,
                "web".to_string(),
                new_endpoint,
                &frontend_slot,
                &dev_session_slot,
                &service_endpoint_slot,
                Some(&inspector),
                Some(&tunnel_target),
                prepared_session,
                Some(proxy_plan),
                || {
                    remove_staged_dev_session(&root);
                    Ok(())
                },
            )
        })
        .unwrap_err();

        assert!(error.to_string().contains("No such file or directory"));
        assert_eq!(
            frontend_slot.lock().unwrap().as_ref().unwrap().child_target,
            old_target
        );
        assert_eq!(
            service_endpoint_slot.lock().unwrap()["web"].target,
            old_target
        );
        assert_eq!(inspector.local_target(), old_target);
        assert_eq!(*tunnel_target.read().unwrap(), old_target);
        let session_path = fs::read_dir(root.dev_sessions_dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let session: lpm_runner::dev_session::ActiveDevSession =
            serde_json::from_slice(&fs::read(session_path).unwrap()).unwrap();
        assert_eq!(session.target, old_target);
        let old_bridge_port = proxy_route_snapshot(&proxy_lease).await[0].upstream_port;
        let response = reqwest::get(format!("http://127.0.0.1:{old_bridge_port}/health"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(response, "old generation");

        drop(frontend_slot);
        drop(dev_session_slot);
        drop(proxy_lease);
        for _ in 0..100 {
            let listed =
                lpm_proxy::send_request_to_path(&socket_path, lpm_proxy::ProxyRequest::List)
                    .await
                    .unwrap();
            if listed == (lpm_proxy::ProxyResponse::Routes { routes: Vec::new() }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        stop_test_proxy(&socket_path, server).await;
    }

    #[test]
    fn auto_copy_env_example_creates_env() {
        let dir = TempDir::new().unwrap();
        let example = dir.path().join(".env.example");
        fs::write(&example, "KEY=value\n").unwrap();

        auto_copy_env_example(dir.path()).unwrap();

        let env_content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(env_content, "KEY=value\n");
    }

    #[test]
    fn auto_copy_env_example_no_overwrite() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "EXISTING=yes\n").unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=value\n").unwrap();

        auto_copy_env_example(dir.path()).unwrap();

        let env_content = fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(env_content, "EXISTING=yes\n"); // Not overwritten
    }

    #[test]
    fn auto_copy_env_example_no_example_file() {
        let dir = TempDir::new().unwrap();
        auto_copy_env_example(dir.path()).unwrap();
        assert!(!dir.path().join(".env").exists()); // Nothing created
    }

    #[cfg(unix)]
    #[test]
    fn auto_copy_env_example_rejects_a_symlink_outside_the_project() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "EXFILTRATED=value\n").unwrap();
        symlink(outside.path(), dir.path().join(".env.example")).unwrap();

        let result = auto_copy_env_example(dir.path());

        assert!(result.is_err(), "outside symlink must be rejected");
        assert!(!dir.path().join(".env").exists());
    }

    #[test]
    fn auto_copy_env_example_rejects_oversized_input_without_a_partial_env() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".env.example"),
            vec![b'x'; lpm_common::CONFIG_FILE_SIZE_CAP_BYTES as usize + 1],
        )
        .unwrap();

        let result = auto_copy_env_example(dir.path());

        assert!(result.is_err(), "oversized .env.example must be rejected");
        assert!(!dir.path().join(".env").exists());
    }

    #[cfg(unix)]
    #[test]
    fn auto_copy_env_example_creates_a_private_env_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env.example"), "SECRET=value\n").unwrap();

        auto_copy_env_example(dir.path()).unwrap();

        let mode = fs::metadata(dir.path().join(".env"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn dashboard_service_logs_share_one_global_memory_budget() {
        let services = ["api", "web", "worker"]
            .into_iter()
            .map(|name| {
                (
                    name.to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node server.js".to_string(),
                        ..Default::default()
                    },
                )
            })
            .collect();
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            services,
            ..Default::default()
        };
        let mut dashboard_services = build_dashboard_services(&config).unwrap();
        for service in &mut dashboard_services {
            service.logs.push("x".repeat(6 * 1024 * 1024));
        }

        let retained: usize = dashboard_services
            .iter()
            .map(|service| service.logs.retained_bytes())
            .sum();
        assert!(retained <= 16 * 1024 * 1024, "retained {retained} bytes");
    }

    #[test]
    fn format_duration_ms() {
        let d = std::time::Duration::from_millis(42);
        assert_eq!(format_duration(d), "42ms");
    }

    #[test]
    fn format_duration_secs() {
        let d = std::time::Duration::from_millis(3200);
        assert_eq!(format_duration(d), "3.2s");
    }

    #[test]
    fn webhook_status_formatter_plain_content_is_stable() {
        assert_eq!(
            console::strip_ansi_codes(&format_dev_webhook_status(200)).into_owned(),
            "200"
        );
        assert_eq!(
            console::strip_ansi_codes(&format_dev_webhook_status(404)).into_owned(),
            "404"
        );
        assert_eq!(
            console::strip_ansi_codes(&format_dev_webhook_status(500)).into_owned(),
            "500"
        );
    }

    #[test]
    fn webhook_line_uses_slim_detail_shape_without_legacy_tag() {
        let line = format_dev_webhook_line("post", "/stripe", 502, 37, "Stripe: payment");
        let plain = console::strip_ansi_codes(&line);

        assert_eq!(
            plain,
            "  tunnel POST /stripe -> 502 (37ms) — Stripe: payment !"
        );
        assert!(
            !plain.contains("[tunnel]") && !plain.contains('›'),
            "webhook row must not use the old tag or a phase glyph: {plain:?}"
        );
    }

    #[test]
    fn auto_copy_env_example_returns_status() {
        let dir = TempDir::new().unwrap();
        let example = dir.path().join(".env.example");
        fs::write(&example, "KEY=value\n").unwrap();

        let status = auto_copy_env_example(dir.path()).unwrap();
        assert_eq!(status, Some("created from .env.example".to_string()));
    }

    #[test]
    fn auto_copy_env_example_existing_returns_loaded() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "EXISTING=yes\n").unwrap();
        fs::write(dir.path().join(".env.example"), "KEY=value\n").unwrap();

        let status = auto_copy_env_example(dir.path()).unwrap();
        assert_eq!(status, Some(".env loaded".to_string()));
    }

    #[test]
    fn startup_banner_lines_use_slim_wording_for_created_env() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".nvmrc"), "22\n").unwrap();

        let info = StartupInfo {
            deps_status: "installed in 11ms".to_string(),
            env_status: Some("created from .env.example".to_string()),
            https_active: true,
            tunnel_url: None,
            tunnel_source: Some("lpm.json".to_string()),
            network_addr: Some("192.168.1.42:3000".to_string()),
            node_version: Some("v22.22.1".to_string()),
            node_source: Some("from .nvmrc".to_string()),
            inspector_url: Some("http://127.0.0.1:53412".to_string()),
            proxy_lines: vec![StartupProxyLine {
                host: "web.localhost".to_string(),
                target: "localhost:3000".to_string(),
                service: Some("web".to_string()),
            }],
        };

        assert_eq!(
            startup_banner_lines(&info, dir.path()),
            vec![
                StartupBannerLine {
                    label: "Node",
                    value: "v22.22.1".to_string(),
                    hint: Some("(from .nvmrc)".to_string()),
                },
                StartupBannerLine {
                    label: "Deps",
                    value: "installed in 11ms".to_string(),
                    hint: None,
                },
                StartupBannerLine {
                    label: "Env",
                    value: "created".to_string(),
                    hint: Some("(.env.example)".to_string()),
                },
                StartupBannerLine {
                    label: "HTTPS",
                    value: "enabled".to_string(),
                    hint: Some("(trusted local certificate)".to_string()),
                },
                StartupBannerLine {
                    label: "Proxy",
                    value: "https://web.localhost -> localhost:3000".to_string(),
                    hint: Some("(web)".to_string()),
                },
                StartupBannerLine {
                    label: "Tunnel",
                    value: "connecting...".to_string(),
                    hint: Some("(lpm.json)".to_string()),
                },
                StartupBannerLine {
                    label: "Inspect",
                    value: "http://127.0.0.1:53412".to_string(),
                    hint: None,
                },
                StartupBannerLine {
                    label: "Network",
                    value: "192.168.1.42:3000".to_string(),
                    hint: None,
                },
            ]
        );
    }

    #[test]
    fn startup_banner_lines_use_system_node_and_loaded_env_wording() {
        let dir = TempDir::new().unwrap();

        let info = StartupInfo {
            deps_status: "up to date (2ms)".to_string(),
            env_status: Some(".env loaded".to_string()),
            https_active: false,
            tunnel_url: Some("https://demo.lpm.dev".to_string()),
            tunnel_source: Some("--domain".to_string()),
            network_addr: None,
            node_version: Some("v20.11.0".to_string()),
            node_source: Some("system PATH".to_string()),
            inspector_url: None,
            proxy_lines: Vec::new(),
        };

        assert_eq!(
            startup_banner_lines(&info, dir.path()),
            vec![
                StartupBannerLine {
                    label: "Node",
                    value: "v20.11.0".to_string(),
                    hint: Some("(system PATH)".to_string()),
                },
                StartupBannerLine {
                    label: "Deps",
                    value: "up to date".to_string(),
                    hint: Some("(2ms)".to_string()),
                },
                StartupBannerLine {
                    label: "Env",
                    value: "loaded".to_string(),
                    hint: Some("(.env)".to_string()),
                },
                StartupBannerLine {
                    label: "Tunnel",
                    value: "https://demo.lpm.dev".to_string(),
                    hint: Some("(--domain)".to_string()),
                },
            ]
        );
    }

    #[test]
    fn startup_proxy_lines_do_not_publish_service_ports_before_assignment() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            services: HashMap::from([
                (
                    "api".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        host: Some("api.localhost".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "next dev".to_string(),
                        host: Some("web.localhost".to_string()),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        assert_eq!(
            startup_proxy_lines_from_config(&config),
            vec![
                StartupProxyLine {
                    host: "api.localhost".to_string(),
                    target: "resolving endpoint".to_string(),
                    service: Some("api".to_string()),
                },
                StartupProxyLine {
                    host: "web.localhost".to_string(),
                    target: "resolving endpoint".to_string(),
                    service: Some("web".to_string()),
                },
            ]
        );
    }

    #[test]
    fn startup_proxy_lines_do_not_publish_the_single_script_port_before_discovery() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            startup_proxy_lines_from_config(&config),
            vec![StartupProxyLine {
                host: "app.localhost".to_string(),
                target: "resolving endpoint".to_string(),
                service: None,
            }]
        );
    }

    #[test]
    fn dashboard_service_hosts_include_service_and_primary_proxy_hosts() {
        let config = lpm_runner::lpm_json::LpmJsonConfig {
            proxy: Some(lpm_runner::lpm_json::ProxyConfig {
                host: Some("app.localhost".to_string()),
                ..Default::default()
            }),
            services: HashMap::from([
                (
                    "api".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node api.js".to_string(),
                        port: Some(4000),
                        host: Some("api.localhost".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "next dev".to_string(),
                        port: Some(3000),
                        host: Some("web.localhost".to_string()),
                        primary: true,
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        assert_eq!(
            dashboard_service_hosts(&config, "web"),
            vec!["web.localhost".to_string(), "app.localhost".to_string()]
        );
    }

    #[test]
    fn dashboard_service_names_match_the_orchestrator_dependency_order() {
        let services = HashMap::from([
            (
                "zdb".to_string(),
                lpm_runner::lpm_json::ServiceConfig {
                    command: "postgres".to_string(),
                    ..Default::default()
                },
            ),
            (
                "api".to_string(),
                lpm_runner::lpm_json::ServiceConfig {
                    command: "node api.js".to_string(),
                    depends_on: vec!["zdb".to_string()],
                    ..Default::default()
                },
            ),
        ]);

        let names: Vec<_> = dashboard_service_names(&services)
            .unwrap()
            .into_iter()
            .collect();

        assert_eq!(names, vec!["zdb", "api"]);
    }

    #[test]
    fn dashboard_orchestrator_panic_is_reported_as_a_fatal_event() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_dashboard_orchestrator(Some(tx), || panic!("injected orchestrator panic"))
        }));
        let result = unwind.expect("dashboard orchestrator panic must be contained");

        assert!(result.is_err());
        let event = rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        match event {
            lpm_dashboard::DashboardEvent::FatalError(error) => {
                assert!(error.contains("service orchestrator panicked"));
            }
            _ => panic!("dashboard did not receive the fatal orchestrator event"),
        }
    }

    #[test]
    fn filtered_config_excludes_inactive_service_hosts_from_runtime_planning() {
        let mut config = lpm_runner::lpm_json::LpmJsonConfig {
            services: HashMap::from([
                (
                    "api".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node api.js".to_string(),
                        host: Some("api.localhost".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    lpm_runner::lpm_json::ServiceConfig {
                        command: "node web.js".to_string(),
                        host: Some("web.localhost".to_string()),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        config.services = lpm_runner::service_graph::select_active_services(
            &config.services,
            &["web".to_string()],
        )
        .unwrap();

        assert_eq!(
            lpm_runner::local_domains::configured_hostnames(&config),
            vec!["web.localhost"]
        );
        assert_eq!(
            startup_proxy_lines_from_config(&config)
                .into_iter()
                .map(|line| line.host)
                .collect::<Vec<_>>(),
            vec!["web.localhost"]
        );
    }

    #[test]
    fn cert_prompt_field_keeps_label_and_value_on_one_aligned_line() {
        let line = format_cert_prompt_field("Fingerprint:", "sha256:abc");

        assert!(
            line.contains("Fingerprint:") && line.contains("sha256:abc"),
            "cert prompt field must include label and value: {line:?}"
        );
    }

    #[test]
    fn auto_copy_env_example_no_example_returns_none() {
        let dir = TempDir::new().unwrap();
        let status = auto_copy_env_example(dir.path()).unwrap();
        assert_eq!(status, None);
    }

    // ── compute_install_hash tests ───────────��─────────────────────────

    #[test]
    fn compute_install_hash_deterministic() {
        let h1 = compute_install_hash("pkg", "lock");
        let h2 = compute_install_hash("pkg", "lock");
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_install_hash_different_inputs() {
        let h1 = compute_install_hash("pkg1", "lock");
        let h2 = compute_install_hash("pkg2", "lock");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_install_hash_different_lockfile() {
        let h1 = compute_install_hash("pkg", "lock-v1");
        let h2 = compute_install_hash("pkg", "lock-v2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_install_hash_is_hex_sha256() {
        let h = compute_install_hash("test", "data");
        // SHA-256 hex digest is always 64 hex chars
        assert_eq!(h.len(), 64, "expected 64-char hex digest, got {}", h.len());
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should be hex: {h}"
        );
    }

    // ── needs_install tests ───────��──────────────────────────────────���─

    #[test]
    fn needs_install_no_package_json() {
        let dir = TempDir::new().unwrap();
        assert!(!needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_no_hash_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"test"}"#).unwrap();
        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_hash_matches_but_no_node_modules() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::write(dir.path().join("lpm.lock"), "").unwrap();

        let hash = compute_install_hash(pkg, "");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_hash_matches_with_node_modules() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::write(dir.path().join("lpm.lock"), "").unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        let hash = compute_install_hash(pkg, "");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

        assert!(!needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_hash_mismatch() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"test","version":"2.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("lpm.lock"), "").unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), "old_hash_value").unwrap();

        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_missing_lockfile() {
        // the unified predicate now requires lockfile existence
        // (stronger semantics from install.rs). A missing lockfile means
        // deps aren't properly installed, so needs_install returns true.
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        let hash = compute_install_hash(pkg, "");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &hash).unwrap();

        assert!(needs_install(dir.path()).0);
    }

    #[test]
    fn needs_install_lockfile_changed() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();

        let old_hash = compute_install_hash(pkg, "old-lock-content");
        fs::create_dir_all(dir.path().join(".lpm")).unwrap();
        fs::write(dir.path().join(".lpm/install-hash"), &old_hash).unwrap();

        fs::write(dir.path().join("lpm.lock"), "new-lock-content").unwrap();

        assert!(needs_install(dir.path()).0);
    }

    // ── domain separator prevents ambiguous concatenation ──

    #[test]
    fn compute_install_hash_domain_separator() {
        // "ab" + "cd" must differ from "abc" + "d" — the null separator prevents collision
        let h1 = compute_install_hash("ab", "cd");
        let h2 = compute_install_hash("abc", "d");
        assert_ne!(
            h1, h2,
            "domain separator should prevent 'ab'+'cd' == 'abc'+'d'"
        );
    }

    // ── needs_install returns hash ──

    #[test]
    fn needs_install_returns_hash() {
        let dir = TempDir::new().unwrap();
        let pkg = r#"{"name":"test"}"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();

        let (stale, hash) = needs_install(dir.path());
        assert!(stale);
        assert!(
            hash.is_some(),
            "hash should be returned when package.json exists"
        );
        assert_eq!(hash.as_ref().unwrap().len(), 64, "should be SHA-256 hex");
    }

    #[test]
    fn needs_install_no_package_json_returns_none_hash() {
        let dir = TempDir::new().unwrap();
        let (stale, hash) = needs_install(dir.path());
        assert!(!stale);
        assert!(hash.is_none());
    }

    /// Dev composed contract: `auto_install_if_stale` leaves the same
    /// metadata-rich `.lpm/install-hash` shape as the install pipeline.
    /// This calls `auto_install_if_stale` against an empty-deps project
    /// (no network needed; the install pipeline short-circuits at the
    /// empty-deps branch), then asserts the install-hash file is v8 shape.
    /// A future regression that reintroduces a parallel bare-hash overwrite
    /// in `auto_install_if_stale` or the dev flow fails here immediately.
    #[tokio::test]
    async fn auto_install_if_stale_writes_complete_install_state_for_empty_deps() {
        // Isolate every env var the install pipeline reads so a
        // developer's exported state can't pollute the test. `LPM_HOME`
        // redirects the store + cache + global config away from the
        // user's real `~/.lpm/`. `LPM_LINKER` is cleared so the install
        // resolves to the default Isolated. CI env vars are cleared so
        // OIDC paths don't fire.
        let home = TempDir::new().unwrap();
        let project = TempDir::new().unwrap();
        let p = project.path();
        let pkg = r#"{"name":"dev-auto-install-v6","version":"1.0.0","dependencies":{}}"#;
        fs::write(p.join("package.json"), pkg).unwrap();

        let _env = crate::test_env::ScopedEnv::update([
            (
                "LPM_HOME",
                Some(std::ffi::OsString::from(home.path().as_os_str())),
            ),
            (
                "HOME",
                Some(std::ffi::OsString::from(home.path().as_os_str())),
            ),
            ("LPM_LINKER", None),
            (lpm_store::v2::ENV_V2_OBJECT_INTEGRITY, None),
            ("LPM_TOKEN", None),
            ("NPM_TOKEN", None),
            ("GITHUB_ACTIONS", None),
            ("GITLAB_CI", None),
            ("LPM_FORCE_FILE_AUTH", Some(std::ffi::OsString::from("1"))),
            ("LPM_NO_UPDATE_CHECK", Some(std::ffi::OsString::from("1"))),
        ]);

        // RegistryClient::new() doesn't make network calls; the
        // empty-deps install short-circuits before any registry round-
        // trip would fire.
        let client = lpm_registry::RegistryClient::new();

        // Pre-condition: project is stale (no install-hash yet).
        let (stale_before, _) = needs_install(p);
        assert!(
            stale_before,
            "fresh project must look stale before auto_install_if_stale runs"
        );

        // Exercise the real dev/install handoff.
        let result = auto_install_if_stale(&client, p, &[]).await;
        assert!(
            result.is_ok(),
            "auto_install_if_stale must succeed on empty-deps project, got: {result:?}"
        );

        // Load-bearing pin: install-hash on disk has the complete metadata shape.
        // A regression that reintroduces `fs::write(install_hash, &bare_hash)`
        // anywhere in the dev path — inside auto_install_if_stale or a
        // helper it calls — fails the line-count assertion here.
        let on_disk = fs::read_to_string(p.join(".lpm").join("install-hash"))
            .expect("install-hash must exist after auto_install_if_stale");
        let lines: Vec<&str> = on_disk.lines().collect();
        assert_eq!(
            lines.len(),
            9,
            "install-hash MUST contain 9 lines (hash + m: + l: + i: + p: + a: + e: + n: + b:), got:\n{on_disk}\n\
             A bare-hash overwrite anywhere in the dev path would fail here."
        );
        assert_eq!(lines[0].len(), 64, "line 1 must be a SHA-256 hex hash");
        assert!(
            lines[1].starts_with("m:"),
            "line 2 must be mtime, got {:?}",
            lines[1]
        );
        // flipped `LinkerMode::default()` from
        // Isolated to Hoisted. The hash file's third line reflects
        // whatever default `auto_install_if_stale` resolves through
        // the linker chain — when no override is set, that's the
        // current default's `as_str()`. Asserting on the literal
        // `LinkerMode::default()` keeps the test stable across
        // future default flips.
        assert_eq!(
            lines[2],
            format!("l:{}", lpm_linker::LinkerMode::default().as_str()),
            "line 3 must be linker, got {:?}",
            lines[2]
        );
        assert_eq!(lines[3], "i:source", "line 4 must be integrity policy");
        assert!(
            lines[4].starts_with("p:"),
            "line 5 must be platform tuple, got {:?}",
            lines[4]
        );
        assert_eq!(
            lines[5], "a:disabled",
            "line 6 must record install-time source analysis"
        );
        assert_eq!(
            lines[6], "e:none",
            "line 7 must record unconstrained dependency engines"
        );
        assert_eq!(
            lines[7], "n:none",
            "line 8 must reserve Node runtime fingerprint metadata"
        );
        assert_eq!(
            lines[8], "b:not-required",
            "line 9 must record that importer state is TOML-only"
        );

        // Round-trip: needs_install reads the complete shape as up-to-date.
        let (stale_after, hash) = needs_install(p);
        assert!(
            !stale_after,
            "after auto_install_if_stale, needs_install must report up-to-date"
        );
        assert_eq!(
            hash.as_deref(),
            Some(lines[0]),
            "needs_install must return the same hash that's on disk"
        );
    }

    // ── should_open_browser logic ──

    #[test]
    fn should_open_browser_ready_and_allowed() {
        assert!(should_open_browser(true, false, false));
    }

    #[test]
    fn should_open_browser_not_ready() {
        assert!(!should_open_browser(false, false, false));
        assert!(!should_open_browser(false, true, false));
        assert!(!should_open_browser(false, false, true));
        assert!(!should_open_browser(false, true, true));
    }

    #[test]
    fn should_open_browser_no_open_flag() {
        assert!(!should_open_browser(true, true, false));
    }

    #[test]
    fn should_open_browser_ci_env() {
        assert!(!should_open_browser(true, false, true));
    }

    // ── convert_service_status tests ────────────────────────────────

    #[test]
    fn convert_pending_to_starting() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Pending);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Starting);
    }

    #[test]
    fn convert_starting_to_starting() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Starting);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Starting);
    }

    #[test]
    fn convert_ready() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Ready);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Ready);
    }

    #[test]
    fn convert_readiness_failure() {
        let result = convert_service_status(
            &lpm_runner::orchestrator::ServiceStatus::ReadinessFailed("timed out".to_string()),
        );
        assert_eq!(
            result,
            lpm_dashboard::ServiceStatus::ReadinessFailed("timed out".to_string())
        );
    }

    #[test]
    fn convert_crashed() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Crashed(1));
        assert_eq!(
            result,
            lpm_dashboard::ServiceStatus::Crashed("exit code 1".to_string())
        );
    }

    #[test]
    fn convert_waiting_for_dep() {
        let result = convert_service_status(
            &lpm_runner::orchestrator::ServiceStatus::WaitingForDep("db".to_string()),
        );
        assert_eq!(
            result,
            lpm_dashboard::ServiceStatus::WaitingForDep("db".to_string())
        );
    }

    #[test]
    fn convert_stopped() {
        let result = convert_service_status(&lpm_runner::orchestrator::ServiceStatus::Stopped);
        assert_eq!(result, lpm_dashboard::ServiceStatus::Stopped);
    }

    // ── Dashboard event bridge test ─────────────────────────────────

    #[test]
    fn orchestrator_events_bridge_to_dashboard_events() {
        use lpm_runner::orchestrator::OrchestratorEvent;

        let (dash_tx, dash_rx) = std::sync::mpsc::channel::<lpm_dashboard::DashboardEvent>();
        let (orch_tx, orch_rx) = std::sync::mpsc::channel::<OrchestratorEvent>();

        // Spawn the bridge thread (same pattern as dev.rs)
        let dash_tx_clone = dash_tx;
        std::thread::spawn(move || {
            while let Ok(event) = orch_rx.recv() {
                let dash_event = match event {
                    OrchestratorEvent::ServiceLog {
                        service_index,
                        line,
                        ..
                    } => lpm_dashboard::DashboardEvent::ServiceLog {
                        index: service_index,
                        line,
                    },
                    OrchestratorEvent::StatusChange {
                        service_index,
                        status,
                    } => lpm_dashboard::DashboardEvent::StatusChange {
                        index: service_index,
                        status: convert_service_status(&status),
                    },
                };
                if dash_tx_clone.send(dash_event).is_err() {
                    break;
                }
            }
        });

        // Send orchestrator events
        orch_tx
            .send(OrchestratorEvent::ServiceLog {
                service_index: 0,
                line: "server started".to_string(),
                is_stderr: false,
            })
            .unwrap();
        orch_tx
            .send(OrchestratorEvent::StatusChange {
                service_index: 1,
                status: lpm_runner::orchestrator::ServiceStatus::Ready,
            })
            .unwrap();
        drop(orch_tx); // Close the channel

        // Verify dashboard receives converted events
        let event1 = dash_rx.recv().unwrap();
        match event1 {
            lpm_dashboard::DashboardEvent::ServiceLog { index, line } => {
                assert_eq!(index, 0);
                assert_eq!(line, "server started");
            }
            _ => panic!("expected ServiceLog"),
        }

        let event2 = dash_rx.recv().unwrap();
        match event2 {
            lpm_dashboard::DashboardEvent::StatusChange { index, status } => {
                assert_eq!(index, 1);
                assert_eq!(status, lpm_dashboard::ServiceStatus::Ready);
            }
            _ => panic!("expected StatusChange"),
        }
    }

    // ── Dashboard command mapping test ─────────────────────────────

    #[test]
    fn dashboard_commands_map_to_the_matching_orchestrator_intents() {
        use lpm_runner::orchestrator::OrchestratorCommand;

        assert_eq!(
            dashboard_orchestrator_command(lpm_dashboard::DashboardCommand::RestartService(2)),
            OrchestratorCommand::RestartService(2)
        );
        assert_eq!(
            dashboard_orchestrator_command(lpm_dashboard::DashboardCommand::StopService(0)),
            OrchestratorCommand::StopService(0)
        );
        assert_eq!(
            dashboard_orchestrator_command(lpm_dashboard::DashboardCommand::StopAll),
            OrchestratorCommand::StopAll
        );
    }

    #[test]
    fn webhook_event_forwarded_to_dashboard() {
        let (dash_tx, dash_rx) = std::sync::mpsc::channel::<lpm_dashboard::DashboardEvent>();

        let webhook = lpm_tunnel::webhook::CapturedWebhook {
            id: "wh-test".to_string(),
            timestamp: "T12:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            request_headers: std::collections::HashMap::new(),
            request_body: Vec::new(),
            response_status: 200,
            response_headers: std::collections::HashMap::new(),
            response_body: Vec::new(),
            duration_ms: 42,
            provider: None,
            summary: "test".to_string(),
            signature_diagnostic: None,
            auto_acked: false,
        };

        // Send webhook event (same pattern as dev.rs consumer)
        dash_tx
            .send(lpm_dashboard::DashboardEvent::WebhookCaptured(Arc::new(
                webhook,
            )))
            .unwrap();

        // Verify dashboard receives it
        let event = dash_rx.recv().unwrap();
        match event {
            lpm_dashboard::DashboardEvent::WebhookCaptured(wh) => {
                assert_eq!(wh.id, "wh-test");
                assert_eq!(wh.method, "POST");
                assert_eq!(wh.response_status, 200);
            }
            _ => panic!("expected WebhookCaptured"),
        }
    }
}
