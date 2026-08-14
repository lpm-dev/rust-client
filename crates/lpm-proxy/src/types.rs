use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub host: String,
    pub upstream_port: u16,
    pub project_dir: PathBuf,
    pub service: Option<String>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RouteLeaseId(pub(crate) u64);

impl RouteLeaseId {
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RouteLeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredRoute {
    pub host: String,
    pub upstream_port: u16,
    pub project_dir: PathBuf,
    pub service: Option<String>,
    pub lease_id: RouteLeaseId,
    pub owner_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteStatus {
    pub host: String,
    pub upstream_port: u16,
    pub project_dir: PathBuf,
    pub service: Option<String>,
    pub lease_id: RouteLeaseId,
    pub owner_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyDaemonState {
    pub pid: u32,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub http_addr: Option<String>,
    #[serde(default)]
    pub http_redirect_addr: Option<String>,
    #[serde(default)]
    pub tls_addr: Option<String>,
    #[serde(default)]
    pub routes: Vec<RouteStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub http_addr: Option<String>,
    pub http_redirect_addr: Option<String>,
    pub tls_addr: Option<String>,
    pub routes: Vec<RouteStatus>,
    pub stale: bool,
    pub state_error: Option<String>,
}

impl ProxyStatus {
    pub fn not_running() -> Self {
        Self {
            running: false,
            pid: None,
            http_addr: None,
            http_redirect_addr: None,
            tls_addr: None,
            routes: Vec::new(),
            stale: false,
            state_error: None,
        }
    }

    pub(crate) fn stale(
        pid: Option<u32>,
        http_addr: Option<String>,
        http_redirect_addr: Option<String>,
        tls_addr: Option<String>,
        state_error: Option<String>,
    ) -> Self {
        Self {
            running: false,
            pid,
            http_addr,
            http_redirect_addr,
            tls_addr,
            routes: Vec::new(),
            stale: true,
            state_error,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ProxyDaemonOptions {
    pub http_port: Option<u16>,
    pub http_redirect_port: Option<u16>,
    pub tls_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProxyRequest {
    Status,
    List,
    Register {
        owner_pid: u32,
        routes: Vec<Route>,
    },
    RegisterLease {
        owner_pid: u32,
        routes: Vec<Route>,
    },
    RegisterStagedLease {
        owner_pid: u32,
    },
    Stage {
        lease_id: RouteLeaseId,
        publication_id: u64,
        routes: Vec<Route>,
    },
    Commit {
        lease_id: RouteLeaseId,
        publication_id: u64,
    },
    Rollback {
        lease_id: RouteLeaseId,
        publication_id: u64,
    },
    Replace {
        lease_id: RouteLeaseId,
        routes: Vec<Route>,
    },
    Release {
        lease_id: RouteLeaseId,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ProxyResponse {
    Status { status: ProxyStatus },
    Routes { routes: Vec<RouteStatus> },
    Registered { lease_id: RouteLeaseId },
    Staged { publication_id: u64 },
    Committed { publication_id: u64 },
    RolledBack { publication_id: u64 },
    Replaced,
    Released { removed: usize },
    Stopped,
    Error { message: String },
}
