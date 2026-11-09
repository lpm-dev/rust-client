//! `lpm mcp serve`: the stdio MCP server an editor launches.

use super::hosted::HostedRegistry;
use super::local_tools::{self, LocalTool, LocalTools};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig, SubscriptionFilter,
};
use rmcp::service::{Peer, RequestContext, SubscriptionContext};
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How long a tool listing waits for the registry's tools. The local tools
/// shouldn't wait on a slow network, and the registry's tools are announced
/// when they arrive.
const LISTING_WAIT: Duration = Duration::from_secs(5);

/// The first wait before the registry's tools are asked for again after a
/// listing went without them, doubled after each failure up to the longest.
const RECOVERY_FIRST_WAIT: Duration = Duration::from_secs(2);
const RECOVERY_LONGEST_WAIT: Duration = Duration::from_secs(60);

const INSTRUCTIONS: &str = "LPM.dev is a package registry for JavaScript and Swift. Its packages are named @lpm.dev/owner.package-name.
- Find packages with lpm_search, and evaluate one with lpm_package before recommending or installing it.
- Install a package as a dependency with lpm_install, or copy a package's source into a project to customize it with lpm_add. Both take the project's absolute path.
- Check a project's installed dependencies with lpm_audit.
Registry tools read what the LPM.dev account signed in with `lpm login` can read, and public packages without one.";

pub(super) async fn serve(
    client: &RegistryClient,
    explicit_token: Option<&str>,
) -> Result<(), LpmError> {
    let retired = tokio::task::spawn_blocking(super::remove_retired_runtime);
    let server = LpmServer {
        hosted: Arc::new(HostedRegistry::new(client.clone_with_config())),
        local: LocalTools::new(
            std::env::current_exe()?,
            client,
            explicit_token.map(str::to_owned),
        ),
        tools_changed: Arc::new(tokio::sync::watch::Sender::new(())),
        recovering: Arc::new(AtomicBool::new(false)),
    };
    let running = server
        .serve(rmcp::transport::stdio_pipes())
        .await
        .map_err(|error| LpmError::Registry(format!("the MCP server couldn't start: {error}")))?;
    running
        .waiting()
        .await
        .map_err(|error| LpmError::Registry(format!("the MCP server stopped: {error}")))?;
    let _ = retired.await;
    Ok(())
}

struct LpmServer {
    hosted: Arc<HostedRegistry>,
    local: LocalTools,
    /// Signalled when the registry's tools arrive after a listing went
    /// without them, for `subscriptions/listen` streams.
    tools_changed: Arc<tokio::sync::watch::Sender<()>>,
    /// Whether the registry's tools are being asked for again.
    recovering: Arc<AtomicBool>,
}

impl LpmServer {
    /// Keep asking for the registry's tools after a listing went without
    /// them, and tell the client when they arrive, so they appear without
    /// restarting the server.
    fn recover_registry_tools(&self, peer: Peer<RoleServer>) {
        if self.recovering.swap(true, Ordering::AcqRel) {
            return;
        }
        let hosted = Arc::clone(&self.hosted);
        let tools_changed = Arc::clone(&self.tools_changed);
        let recovering = Arc::clone(&self.recovering);
        tokio::spawn(async move {
            let mut wait = RECOVERY_FIRST_WAIT;
            loop {
                tokio::time::sleep(wait).await;
                if hosted.tools().await.is_ok() {
                    break;
                }
                wait = (wait * 2).min(RECOVERY_LONGEST_WAIT);
            }
            recovering.store(false, Ordering::Release);
            tools_changed.send_replace(());
            // A 2026-07-28 client hears of the change on its listen stream;
            // an earlier one takes the notification unscoped.
            let earlier_revision = peer.peer_info().is_some_and(|info| {
                info.protocol_version.as_str() < ProtocolVersion::V_2026_07_28.as_str()
            });
            if earlier_revision && let Err(error) = peer.notify_tool_list_changed().await {
                tracing::debug!(
                    target: "lpm_cli::mcp",
                    "the client couldn't be told the tools changed: {error}"
                );
            }
        });
    }
}

impl ServerHandler for LpmServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
            .with_server_info(
                Implementation::new("lpm", env!("CARGO_PKG_VERSION"))
                    .with_title("LPM")
                    .with_description(
                        "Search and evaluate LPM.dev packages, and install, add, and audit them in projects on this machine.",
                    )
                    .with_website_url("https://lpm.dev/docs/ai/mcp"),
            )
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let local = local_tools::definitions();
        let mut tools = Vec::with_capacity(local.len() + 8);
        match tokio::time::timeout(LISTING_WAIT, self.hosted.tools()).await {
            Ok(Ok(registry)) => tools.extend(
                registry
                    .iter()
                    .filter(|tool| LocalTool::named(&tool.name).is_none())
                    .cloned(),
            ),
            Ok(Err(failure)) => {
                tracing::warn!(
                    target: "lpm_cli::mcp",
                    "listing only the local tools for now: {}",
                    self.hosted.explain(&failure)
                );
                self.recover_registry_tools(context.peer);
            }
            Err(_) => {
                tracing::warn!(
                    target: "lpm_cli::mcp",
                    "listing only the local tools for now: the registry's MCP server didn't list its tools within {} seconds",
                    LISTING_WAIT.as_secs()
                );
                self.recover_registry_tools(context.peer);
            }
        }
        tools.extend_from_slice(local);
        Ok(ListToolsResult::with_all_items(tools))
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        let mut accepted = SubscriptionFilter::new();
        accepted.tools_list_changed = requested.tools_list_changed;
        Some(accepted)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let mut changes = self.tools_changed.subscribe();
        loop {
            tokio::select! {
                () = context.cancelled() => return Ok(()),
                changed = changes.changed() => {
                    if changed.is_err() || context.sink().notify_tool_list_changed().await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let result = match LocalTool::named(&request.name) {
            Some(tool) => self.local.call(tool, request.arguments, context.ct).await,
            // A registry call runs to its end even when the client cancels it:
            // stopping one mid-refresh could lose a rotated refresh token the
            // registry has already issued, and with it the user's login.
            None => {
                self.hosted
                    .call_tool(&request.name, request.arguments)
                    .await?
            }
        };
        Ok(result.into())
    }
}
