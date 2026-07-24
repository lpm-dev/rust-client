use crate::ports;
use lpm_common::{LocalScheme, LocalTarget};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Child-owned local endpoint discovered during dev-server startup.
pub struct DevEndpoint {
    /// Reachable loopback target advertised or opened by the child.
    pub target: LocalTarget,
    /// Service name when discovered by the multi-service orchestrator.
    pub service: Option<String>,
    /// Process that owns the listening socket when the platform reports it.
    pub owner_pid: Option<u32>,
}

#[derive(Debug)]
/// Listening sockets present before a child command is spawned.
pub struct ListenerSnapshot {
    listeners: HashSet<(u16, Option<u32>)>,
}

impl ListenerSnapshot {
    /// Capture the currently visible listening TCP sockets.
    pub fn capture() -> Self {
        let rows = ports::list_listening_ports();
        let mut listeners = HashSet::with_capacity(rows.len());
        listeners.extend(rows.into_iter().map(|row| (row.port, row.pid)));
        Self { listeners }
    }

    #[inline]
    fn contains(&self, port: u16, pid: Option<u32>) -> bool {
        self.listeners.contains(&(port, pid))
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
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    let started = Instant::now();
    let mut advertised = Vec::with_capacity(4);

    loop {
        match candidates.recv_timeout(Duration::from_millis(75)) {
            Ok(candidate) => push_unique_target(&mut advertised, candidate),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if child_exited.load(Ordering::Acquire) {
                    return Ok(None);
                }
            }
        }
        while let Ok(candidate) = candidates.try_recv() {
            push_unique_target(&mut advertised, candidate);
        }

        let descendants = ports::descendant_process_ids(root_pid);

        for target in &advertised {
            let Some(listener) =
                new_owned_listener_for_port(&project_dir, baseline, &descendants, target.port)
            else {
                continue;
            };
            if !target_is_reachable(target) {
                continue;
            }
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
            }));
        }

        if let Some(expected) = requested_port {
            if let Some(listener) =
                new_owned_listener_for_port(&project_dir, baseline, &descendants, expected)
            {
                for target in loopback_targets(LocalScheme::Http, expected, "/") {
                    if target_is_reachable(&target) {
                        return Ok(Some(DevEndpoint {
                            target,
                            service: None,
                            owner_pid: listener.pid,
                        }));
                    }
                }
            }
            if child_exited.load(Ordering::Acquire) {
                return Ok(None);
            }
        } else {
            let owned = new_owned_listeners(&project_dir, baseline, &descendants);
            if owned.len() == 1 {
                let listener = &owned[0];
                for target in loopback_targets(LocalScheme::Http, listener.port, "/") {
                    if target_is_reachable(&target) {
                        return Ok(Some(DevEndpoint {
                            target,
                            service: None,
                            owner_pid: listener.pid,
                        }));
                    }
                }
            }

            if child_exited.load(Ordering::Acquire)
                || (!ports::process_is_running(root_pid) && owned.is_empty())
            {
                return Ok(None);
            }
        }
        if (child_exited.load(Ordering::Acquire) || !ports::process_is_running(root_pid))
            && new_owned_listeners(&project_dir, baseline, &descendants).is_empty()
        {
            return Ok(None);
        }
        if started.elapsed() >= timeout {
            if let Some(expected) = requested_port {
                return Err(format!(
                    "timed out waiting for the launched dev server to own port {expected}"
                ));
            }
            let owned = new_owned_listeners(&project_dir, baseline, &descendants);
            if owned.len() > 1 {
                let mut ports: Vec<u16> = owned.iter().map(|listener| listener.port).collect();
                ports.sort_unstable();
                ports.dedup();
                return Err(format!(
                    "the launched dev command opened multiple ports ({}) and did not advertise a primary HTTP endpoint",
                    ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            return Err(
                "timed out waiting for the launched dev server to open a local HTTP endpoint"
                    .to_string(),
            );
        }
    }
}

fn new_owned_listener_for_port(
    project_dir: &Path,
    baseline: &ListenerSnapshot,
    descendants: &HashSet<u32>,
    port: u16,
) -> Option<ports::ListeningPort> {
    new_owned_listener_for_port_from_rows(
        project_dir,
        baseline,
        descendants,
        port,
        ports::list_listening_ports(),
    )
}

fn new_owned_listener_for_port_from_rows(
    project_dir: &Path,
    baseline: &ListenerSnapshot,
    descendants: &HashSet<u32>,
    port: u16,
    rows: impl IntoIterator<Item = ports::ListeningPort>,
) -> Option<ports::ListeningPort> {
    rows.into_iter().find(|listener| {
        listener.port == port && !baseline.contains(listener.port, listener.pid) && {
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

fn new_owned_listeners(
    project_dir: &Path,
    baseline: &ListenerSnapshot,
    descendants: &HashSet<u32>,
) -> Vec<ports::ListeningPort> {
    ports::list_listening_ports()
        .into_iter()
        .filter(|listener| !baseline.contains(listener.port, listener.pid))
        .filter(|listener| {
            listener.pid.is_some_and(|pid| descendants.contains(&pid))
                || listener_path_matches_project(listener.cwd.as_deref(), project_dir)
                || listener_path_matches_project(listener.project_dir.as_deref(), project_dir)
        })
        .collect()
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
    fn unverified_advertised_url_does_not_hide_the_unique_owned_listener() {
        let project = tempfile::TempDir::new().unwrap();
        let owned_port = ports::find_available_port(49000).unwrap();
        let incidental_port = ports::find_available_port(owned_port.saturating_add(1)).unwrap();
        let baseline = ListenerSnapshot::capture();
        let script = "require('http').createServer((_, response) => response.end('ok')).listen(Number(process.argv[1]), '127.0.0.1')";
        let mut child = std::process::Command::new("node")
            .args(["-e", script, &owned_port.to_string()])
            .current_dir(project.path())
            .spawn()
            .unwrap();
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
            listeners: HashSet::from([(port, Some(10))]),
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
}
