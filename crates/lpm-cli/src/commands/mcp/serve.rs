//! `lpm mcp serve`: the stdio MCP server an editor launches.

use super::hosted::HostedRegistry;
use super::local_tools::{self, LocalTool, LocalTools};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, ServiceExt};

const INSTRUCTIONS: &str = "LPM.dev is a package registry for JavaScript and Swift. Its packages are named @lpm.dev/owner.package-name.
- Find packages with lpm_search, and evaluate one with lpm_package before recommending or installing it.
- Install a package as a dependency with lpm_install, or copy a package's source into a project to customize it with lpm_add. Both take the project's absolute path.
- Check a project's installed dependencies with lpm_audit.
Registry tools read what the LPM.dev account signed in with `lpm login` can read, and public packages without one.";

pub(super) async fn serve(client: &RegistryClient) -> Result<(), LpmError> {
    super::remove_retired_runtime();
    let server = LpmServer {
        hosted: HostedRegistry::new(client.clone_with_config()),
        local: LocalTools::new(std::env::current_exe()?, client),
    };
    let running = server
        .serve(rmcp::transport::stdio_pipes())
        .await
        .map_err(|error| LpmError::Registry(format!("the MCP server couldn't start: {error}")))?;
    running
        .waiting()
        .await
        .map_err(|error| LpmError::Registry(format!("the MCP server stopped: {error}")))?;
    Ok(())
}

struct LpmServer {
    hosted: HostedRegistry,
    local: LocalTools,
}

impl ServerHandler for LpmServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let local = local_tools::definitions();
        let mut tools = Vec::with_capacity(local.len() + 8);
        match self.hosted.tools().await {
            Ok(registry) => tools.extend(
                registry
                    .iter()
                    .filter(|tool| LocalTool::named(&tool.name).is_none())
                    .cloned(),
            ),
            Err(failure) => tracing::warn!(
                target: "lpm_cli::mcp",
                "listing only the local tools: {}",
                self.hosted.explain(&failure)
            ),
        }
        tools.extend_from_slice(local);
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let result = match LocalTool::named(&request.name) {
            Some(tool) => self.local.call(tool, request.arguments, context.ct).await,
            None => {
                self.hosted
                    .call_tool(&request.name, request.arguments)
                    .await?
            }
        };
        Ok(result.into())
    }
}
