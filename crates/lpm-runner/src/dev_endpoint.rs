use crate::ports;
use lpm_common::{LocalScheme, LocalTarget};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub(crate) const ENDPOINT_DISCOVERY_CANCELLED: &str = "endpoint discovery cancelled";

#[derive(Debug, Clone, PartialEq, Eq)]
/// Child-owned local endpoint discovered during dev-server startup.
pub struct DevEndpoint {
    /// Reachable loopback target advertised or opened by the child.
    pub target: LocalTarget,
    /// Service name when discovered by the multi-service orchestrator.
    pub service: Option<String>,
    /// Process that owns the listening socket when the platform reports it.
    pub owner_pid: Option<u32>,
    /// Kernel creation identity verified before and after reachability.
    pub owner_identity: Option<ports::ProcessIdentity>,
}

#[derive(Debug)]
/// Listening sockets present before a child command is spawned.
pub struct ListenerSnapshot {
    listeners: HashSet<ports::ListeningSocketIdentity>,
}

impl ListenerSnapshot {
    /// Capture the currently visible listening TCP sockets.
    pub fn capture() -> Self {
        let rows = ports::list_listening_ports();
        let mut listeners = HashSet::with_capacity(rows.len());
        listeners.extend(rows.iter().map(ports::ListeningPort::socket_identity));
        Self { listeners }
    }

    #[inline]
    fn contains(&self, listener: &ports::ListeningPort) -> bool {
        self.listeners.contains(&listener.socket_identity())
    }
}

/// Resolve a reachable endpoint opened by the spawned process tree.
///
/// Advertised loopback URLs are accepted only after listener ownership is
/// verified against `baseline`. When `requested_port` is set, a child that
/// binds a different advertised port returns an error.
pub fn resolve_spawned_endpoint(
    project_dir: &Path,
    root_pid: u32,
    baseline: &ListenerSnapshot,
    requested_port: Option<u16>,
    candidates: &Receiver<LocalTarget>,
    child_exited: &Arc<AtomicBool>,
    timeout: Duration,
) -> Result<Option<DevEndpoint>, String> {
    let result = resolve_spawned_endpoint_until(
        project_dir,
        root_pid,
        Some(baseline),
        requested_port,
        candidates,
        Instant::now() + timeout,
        || child_exited.load(Ordering::Acquire),
    );
    if child_exited.load(Ordering::Acquire)
        && matches!(&result, Err(error) if error == ENDPOINT_DISCOVERY_CANCELLED)
    {
        Ok(None)
    } else {
        result
    }
}

pub(crate) fn resolve_spawned_endpoint_until(
    project_dir: &Path,
    root_pid: u32,
    baseline: Option<&ListenerSnapshot>,
    requested_port: Option<u16>,
    candidates: &Receiver<LocalTarget>,
    deadline: Instant,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<Option<DevEndpoint>, String> {
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    let mut advertised = Vec::with_capacity(4);
    let mut last_owned = Vec::new();

    loop {
        if should_cancel() {
            return Err(ENDPOINT_DISCOVERY_CANCELLED.to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(endpoint_timeout_error(requested_port, &last_owned));
        }
        match candidates.recv_timeout(remaining.min(Duration::from_millis(75))) {
            Ok(candidate) => push_unique_target(&mut advertised, candidate),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if should_cancel() {
                    return Err(ENDPOINT_DISCOVERY_CANCELLED.to_string());
                }
            }
        }
        while let Ok(candidate) = candidates.try_recv() {
            push_unique_target(&mut advertised, candidate);
        }

        let Some(owned) = owned_listeners_for_process_tree(
            &project_dir,
            baseline,
            root_pid,
            &advertised,
            requested_port,
            deadline,
            &mut should_cancel,
        ) else {
            if should_cancel() {
                return Err(ENDPOINT_DISCOVERY_CANCELLED.to_string());
            }
            if Instant::now() >= deadline {
                return Err(endpoint_timeout_error(requested_port, &last_owned));
            }
            continue;
        };
        last_owned = owned;
        let owned = &last_owned;

        for target in &advertised {
            let Some(listener) = owned
                .iter()
                .find(|listener| listener_matches_target(listener, target))
            else {
                continue;
            };
            let Some(owner_identity) = listener_remains_owned_after_reachability(
                listener,
                target,
                || target_is_reachable(target),
                || {
                    owned_listeners_for_process_tree(
                        &project_dir,
                        baseline,
                        root_pid,
                        &advertised,
                        requested_port,
                        deadline,
                        &mut should_cancel,
                    )
                    .unwrap_or_default()
                },
            ) else {
                continue;
            };
            if let Some(expected) = requested_port
                && target.port != expected
            {
                return Err(format!(
                    "the dev server ignored `--port {expected}` and started on port {}; configure the framework to accept the requested port or remove `--port`",
                    target.port
                ));
            }
            return Ok(Some(DevEndpoint {
                target: target.clone(),
                service: None,
                owner_pid: listener.pid,
                owner_identity: Some(owner_identity),
            }));
        }

        if let Some(expected) = requested_port {
            for target in loopback_targets(LocalScheme::Http, expected, "/") {
                if let Some(listener) = owned
                    .iter()
                    .find(|listener| listener_matches_target(listener, &target))
                    && let Some(owner_identity) = listener_remains_owned_after_reachability(
                        listener,
                        &target,
                        || target_is_reachable(&target),
                        || {
                            owned_listeners_for_process_tree(
                                &project_dir,
                                baseline,
                                root_pid,
                                &advertised,
                                requested_port,
                                deadline,
                                &mut should_cancel,
                            )
                            .unwrap_or_default()
                        },
                    )
                {
                    return Ok(Some(DevEndpoint {
                        target,
                        service: None,
                        owner_pid: listener.pid,
                        owner_identity: Some(owner_identity),
                    }));
                }
            }
            if should_cancel() {
                return Err(ENDPOINT_DISCOVERY_CANCELLED.to_string());
            }
        } else {
            if owned.len() == 1 {
                let listener = &owned[0];
                for target in loopback_targets(LocalScheme::Http, listener.port, "/") {
                    if listener_matches_target(listener, &target)
                        && let Some(owner_identity) = listener_remains_owned_after_reachability(
                            listener,
                            &target,
                            || target_is_reachable(&target),
                            || {
                                owned_listeners_for_process_tree(
                                    &project_dir,
                                    baseline,
                                    root_pid,
                                    &advertised,
                                    requested_port,
                                    deadline,
                                    &mut should_cancel,
                                )
                                .unwrap_or_default()
                            },
                        )
                    {
                        return Ok(Some(DevEndpoint {
                            target,
                            service: None,
                            owner_pid: listener.pid,
                            owner_identity: Some(owner_identity),
                        }));
                    }
                }
            }

            if should_cancel() || (!ports::process_is_running(root_pid) && owned.is_empty()) {
                return Err(ENDPOINT_DISCOVERY_CANCELLED.to_string());
            }
        }
        if (should_cancel() || !ports::process_is_running(root_pid)) && owned.is_empty() {
            return Err(ENDPOINT_DISCOVERY_CANCELLED.to_string());
        }
        if Instant::now() >= deadline {
            return Err(endpoint_timeout_error(requested_port, owned));
        }
    }
}

fn endpoint_timeout_error(requested_port: Option<u16>, owned: &[ports::ListeningPort]) -> String {
    if let Some(expected) = requested_port {
        return format!("timed out waiting for the launched dev server to own port {expected}");
    }
    if owned.len() > 1 {
        let mut ports: Vec<u16> = owned.iter().map(|listener| listener.port).collect();
        ports.sort_unstable();
        ports.dedup();
        return format!(
            "the launched dev command opened multiple ports ({}) and did not advertise a primary HTTP endpoint",
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    "timed out waiting for the launched dev server to open a local HTTP endpoint".to_string()
}

fn owned_listeners_for_process_tree(
    project_dir: &Path,
    baseline: Option<&ListenerSnapshot>,
    root_pid: u32,
    advertised: &[LocalTarget],
    requested_port: Option<u16>,
    deadline: Instant,
    should_cancel: &mut dyn FnMut() -> bool,
) -> Option<Vec<ports::ListeningPort>> {
    let root = HashSet::from([root_pid]);
    let root_rows = ports::list_listening_ports_for_pids_until(&root, deadline, should_cancel)?;
    let root_has_target = root_rows.iter().any(|listener| {
        requested_port == Some(listener.port)
            || advertised.iter().any(|target| target.port == listener.port)
    });
    if root_has_target
        || (requested_port.is_none() && advertised.is_empty() && root_rows.len() == 1)
    {
        return Some(root_rows);
    }

    let descendants = ports::descendant_process_snapshot_until(root_pid, deadline, should_cancel)?;
    let descendant_ids = descendants.process_ids();
    let mut scoped_rows = if descendant_ids.len() == 1 {
        root_rows
    } else {
        ports::list_listening_ports_for_pids_until(&descendant_ids, deadline, should_cancel)?
    };
    if descendant_ids.len() > 1 && !scoped_rows.is_empty() {
        let revalidated_descendants =
            ports::descendant_process_snapshot_until(root_pid, deadline, should_cancel)?;
        scoped_rows.retain(|listener| {
            listener
                .pid
                .is_some_and(|pid| descendants.contains_same_process(pid, &revalidated_descendants))
        });
    }
    if !scoped_rows.is_empty() {
        return Some(scoped_rows);
    }

    let Some(baseline) = baseline else {
        return Some(Vec::new());
    };
    Some(
        ports::list_listening_ports_until(deadline, should_cancel)?
            .into_iter()
            .filter(|listener| !baseline.contains(listener))
            .filter(|listener| {
                listener.pid.is_some_and(|pid| descendants.contains(pid))
                    || listener_path_matches_project(listener.cwd.as_deref(), project_dir)
                    || listener_path_matches_project(listener.project_dir.as_deref(), project_dir)
            })
            .collect(),
    )
}

#[cfg(test)]
fn new_owned_listener_for_port_from_rows(
    project_dir: &Path,
    baseline: &ListenerSnapshot,
    descendants: &HashSet<u32>,
    port: u16,
    rows: impl IntoIterator<Item = ports::ListeningPort>,
) -> Option<ports::ListeningPort> {
    rows.into_iter().find(|listener| {
        listener.port == port && !baseline.contains(listener) && {
            listener.pid.is_some_and(|pid| descendants.contains(&pid))
                || listener_path_matches_project(listener.cwd.as_deref(), project_dir)
                || listener_path_matches_project(listener.project_dir.as_deref(), project_dir)
        }
    })
}

/// Extract loopback HTTP and WebSocket targets from one child-output line.
pub fn parse_local_targets(line: &str) -> Vec<LocalTarget> {
    const SCHEMES: [(&str, LocalScheme); 4] = [
        ("https://", LocalScheme::Https),
        ("http://", LocalScheme::Http),
        ("wss://", LocalScheme::Https),
        ("ws://", LocalScheme::Http),
    ];

    let mut targets = Vec::with_capacity(2);
    for (prefix, scheme) in SCHEMES {
        let mut remainder = line;
        while let Some(offset) = remainder.find(prefix) {
            let candidate = &remainder[offset + prefix.len()..];
            for target in parse_local_target(candidate, scheme) {
                push_unique_target(&mut targets, target);
            }
            remainder = &candidate[candidate
                .char_indices()
                .nth(1)
                .map_or(candidate.len(), |(index, _)| index)..];
        }
    }
    targets
}

fn parse_local_target(candidate: &str, scheme: LocalScheme) -> Vec<LocalTarget> {
    let token_end = candidate
        .char_indices()
        .find_map(|(index, character)| {
            (character.is_whitespace()
                || matches!(character, '"' | '\'' | '<' | '>' | '`' | '\u{1b}'))
            .then_some(index)
        })
        .unwrap_or(candidate.len());
    let token = candidate[..token_end].trim_end_matches([',', ';', ')']);
    let authority_end = token.find(['/', '?', '#']).unwrap_or(token.len());
    let authority = &token[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Vec::new();
    }

    let Some((addresses, port)) = parse_loopback_authority(authority, scheme) else {
        return Vec::new();
    };
    if port == 0 {
        return Vec::new();
    }
    let base_path = if authority_end < token.len() && token.as_bytes()[authority_end] == b'/' {
        let path_and_more = &token[authority_end..];
        let path_end = path_and_more
            .find(['?', '#'])
            .unwrap_or(path_and_more.len());
        &path_and_more[..path_end]
    } else {
        "/"
    };
    loopback_targets_from(addresses, scheme, port, base_path)
}

fn parse_loopback_authority(authority: &str, scheme: LocalScheme) -> Option<(Vec<IpAddr>, u16)> {
    let default_port = match scheme {
        LocalScheme::Http => 80,
        LocalScheme::Https => 443,
    };
    if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed.find(']')?;
        let host = &bracketed[..closing];
        let address = host.parse::<Ipv6Addr>().ok()?;
        if !address.is_loopback() && !address.is_unspecified() {
            return None;
        }
        let suffix = &bracketed[closing + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix.strip_prefix(':')?.parse::<u16>().ok()?
        };
        let connect_address = if address.is_unspecified() {
            Ipv6Addr::LOCALHOST
        } else {
            address
        };
        return Some((vec![IpAddr::V6(connect_address)], port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port.parse::<u16>().ok()?),
        _ => (authority, default_port),
    };
    let addresses = match host.to_ascii_lowercase().as_str() {
        "localhost" => vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        "127.0.0.1" | "0.0.0.0" => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        _ => return None,
    };
    Some((addresses, port))
}

fn loopback_targets(scheme: LocalScheme, port: u16, base_path: &str) -> Vec<LocalTarget> {
    loopback_targets_from(
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        scheme,
        port,
        base_path,
    )
}

fn loopback_targets_from(
    addresses: Vec<IpAddr>,
    scheme: LocalScheme,
    port: u16,
    base_path: &str,
) -> Vec<LocalTarget> {
    addresses
        .into_iter()
        .map(|address| LocalTarget {
            scheme,
            address,
            port,
            base_path: base_path.to_string(),
        })
        .collect()
}

fn push_unique_target(targets: &mut Vec<LocalTarget>, candidate: LocalTarget) {
    if !targets.contains(&candidate) {
        targets.push(candidate);
    }
}

fn target_is_reachable(target: &LocalTarget) -> bool {
    TcpStream::connect_timeout(
        &std::net::SocketAddr::new(target.address, target.port),
        Duration::from_millis(200),
    )
    .is_ok()
}

fn listener_matches_target(listener: &ports::ListeningPort, target: &LocalTarget) -> bool {
    listener.listens_on(target.address, target.port)
}

fn listener_remains_owned_after_reachability(
    initial_listener: &ports::ListeningPort,
    target: &LocalTarget,
    reachability: impl FnOnce() -> bool,
    refresh_owned_listeners: impl FnOnce() -> Vec<ports::ListeningPort>,
) -> Option<ports::ProcessIdentity> {
    let initial_owner_pid = initial_listener.pid?;
    let initial_identity = ports::process_identity_for_pid(initial_owner_pid)?;
    if !reachability() {
        return None;
    }
    let remains_owned = refresh_owned_listeners().into_iter().any(|listener| {
        listener.pid == Some(initial_owner_pid) && listener_matches_target(&listener, target)
    });
    if !remains_owned {
        return None;
    }
    let refreshed_identity = ports::process_identity_for_pid(initial_owner_pid)?;
    (initial_identity == refreshed_identity).then_some(refreshed_identity)
}

fn listener_path_matches_project(listener_path: Option<&Path>, project_dir: &Path) -> bool {
    let Some(listener_path) = listener_path else {
        return false;
    };
    let listener_path = listener_path
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(listener_path));
    listener_path.starts_with(project_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listening_port(address: &str, port: u16, pid: u32) -> ports::ListeningPort {
        ports::ListeningPort {
            port,
            address: Some(address.to_string()),
            address_family: address.parse::<IpAddr>().ok().map(|address| match address {
                IpAddr::V4(_) => ports::ListeningAddressFamily::Ipv4,
                IpAddr::V6(_) => ports::ListeningAddressFamily::Ipv6,
            }),
            pid: Some(pid),
            process: Some("node".to_string()),
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        }
    }

    #[test]
    fn parses_vite_local_url() {
        let targets = parse_local_targets("  ➜  Local:   http://localhost:5173/");

        assert_eq!(
            targets,
            vec![
                LocalTarget::loopback(LocalScheme::Http, 5173),
                LocalTarget {
                    scheme: LocalScheme::Http,
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    port: 5173,
                    base_path: "/".to_string(),
                },
            ]
        );
    }

    #[test]
    fn parses_https_ipv6_and_base_path() {
        let targets = parse_local_targets("ready at https://[::1]:8443/app?mode=dev");

        assert_eq!(
            targets,
            vec![LocalTarget {
                scheme: LocalScheme::Https,
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 8443,
                base_path: "/app".to_string(),
            }]
        );
    }

    #[test]
    fn rejects_external_and_credentialed_urls() {
        assert!(parse_local_targets("https://example.com:8443/").is_empty());
        assert!(parse_local_targets("http://user@localhost:3000/").is_empty());
    }

    #[test]
    fn descendant_pairs_include_the_complete_process_tree() {
        let descendants =
            ports::descendant_process_ids_from_pairs(10, [(11, 10), (12, 11), (20, 1)]);

        assert_eq!(descendants, HashSet::from([10, 11, 12]));
    }

    #[test]
    fn requested_port_returns_no_endpoint_when_the_spawned_process_has_exited() {
        let baseline = ListenerSnapshot::capture();
        let (_candidate_tx, candidate_rx) = std::sync::mpsc::channel();
        let child_exited = Arc::new(AtomicBool::new(true));

        let result = resolve_spawned_endpoint(
            Path::new("."),
            u32::MAX,
            &baseline,
            Some(4567),
            &candidate_rx,
            &child_exited,
            Duration::from_millis(100),
        );

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn requested_port_resolves_an_ipv6_only_listener() {
        let baseline = ListenerSnapshot::capture();
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_candidate_tx, candidate_rx) = std::sync::mpsc::channel();
        let child_exited = Arc::new(AtomicBool::new(false));

        let result = resolve_spawned_endpoint(
            Path::new("."),
            std::process::id(),
            &baseline,
            Some(port),
            &candidate_rx,
            &child_exited,
            Duration::from_millis(500),
        )
        .unwrap()
        .unwrap();

        assert_eq!(result.target.address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        drop(listener);
    }

    #[test]
    fn ipv4_reachability_cannot_authenticate_an_ipv6_child_listener() {
        let project = tempfile::TempDir::new().unwrap();
        let unrelated_ipv4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = unrelated_ipv4.local_addr().unwrap().port();
        let baseline = ListenerSnapshot::capture();
        let ready_path = project.path().join("ipv6-ready");
        let script = "const fs=require('fs');const port=Number(process.argv[1]);const ready=process.argv[2];const server=require('net').createServer(()=>{});server.listen(port,'::1',()=>fs.writeFileSync(ready,'ready'))";
        let mut child = std::process::Command::new("node")
            .args(["-e", script, &port.to_string()])
            .arg(&ready_path)
            .current_dir(project.path())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready_path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            ready_path.exists(),
            "IPv6 child listener did not become ready"
        );
        let (candidate_tx, candidate_rx) = std::sync::mpsc::channel();
        candidate_tx
            .send(LocalTarget::loopback(LocalScheme::Http, port))
            .unwrap();
        let child_exited = Arc::new(AtomicBool::new(false));

        let result = resolve_spawned_endpoint(
            project.path(),
            child.id(),
            &baseline,
            Some(port),
            &candidate_rx,
            &child_exited,
            Duration::from_secs(2),
        );

        let _ = child.kill();
        let _ = child.wait();
        drop(unrelated_ipv4);
        assert_eq!(
            result.unwrap().unwrap().target.address,
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn unverified_advertised_url_does_not_hide_the_unique_owned_listener() {
        let project = tempfile::TempDir::new().unwrap();
        let baseline = ListenerSnapshot::capture();
        let port_path = project.path().join("owned-port");
        let script = "const fs=require('fs');const path=process.argv[1];const server=require('http').createServer((_,response)=>response.end('ok'));server.listen(0,'127.0.0.1',()=>{const tmp=`${path}.tmp`;fs.writeFileSync(tmp,String(server.address().port));fs.renameSync(tmp,path)})";
        let mut child = std::process::Command::new("node")
            .args(["-e", script])
            .arg(&port_path)
            .current_dir(project.path())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let owned_port = loop {
            match std::fs::read_to_string(&port_path) {
                Ok(port) => break port.parse::<u16>().unwrap(),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child did not publish its listener port: {error}");
                }
            }
        };
        let incidental_port = if owned_port == u16::MAX {
            owned_port - 1
        } else {
            owned_port + 1
        };
        let (candidate_tx, candidate_rx) = std::sync::mpsc::channel();
        candidate_tx
            .send(LocalTarget::loopback(LocalScheme::Http, incidental_port))
            .unwrap();
        let child_exited = Arc::new(AtomicBool::new(false));

        let result = resolve_spawned_endpoint(
            project.path(),
            child.id(),
            &baseline,
            None,
            &candidate_rx,
            &child_exited,
            Duration::from_secs(2),
        );

        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(result.unwrap().unwrap().target.port, owned_port);
    }

    #[test]
    fn same_port_baseline_owner_does_not_hide_a_new_descendant_listener() {
        let port = 5173;
        let baseline = ListenerSnapshot {
            listeners: HashSet::from([listening_port("127.0.0.1", port, 10).socket_identity()]),
        };
        let descendants = HashSet::from([20]);
        let rows = vec![
            listening_port("127.0.0.1", port, 10),
            listening_port("::1", port, 20),
        ];

        let selected = new_owned_listener_for_port_from_rows(
            Path::new("."),
            &baseline,
            &descendants,
            port,
            rows,
        )
        .unwrap();

        assert_eq!(selected.pid, Some(20));
        assert_eq!(selected.address.as_deref(), Some("::1"));
    }

    #[test]
    fn listener_project_matching_does_not_accept_an_unrelated_parent_directory() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("workspace").join("app");
        let child = project.join("packages").join("web");
        std::fs::create_dir_all(&child).unwrap();
        let project = project.canonicalize().unwrap();

        assert!(!listener_path_matches_project(Some(temp.path()), &project));
        assert!(listener_path_matches_project(Some(&child), &project));
    }

    #[test]
    fn listener_handoff_after_reachability_fails_closed() {
        let port = 5173;
        let target = LocalTarget::loopback(LocalScheme::Http, port);
        let initial = listening_port("127.0.0.1", port, 20);
        let replacement = listening_port("127.0.0.1", port, 30);

        assert!(
            listener_remains_owned_after_reachability(
                &initial,
                &target,
                || true,
                || vec![replacement],
            )
            .is_none()
        );
    }
}
