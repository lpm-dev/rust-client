use crate::install_ui;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use lpm_runner::ports::{self, ListeningPort};
use std::collections::{BTreeMap, HashMap};
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

/// Run the `lpm ports` command.
pub async fn run(
    action: &str,
    target: Option<&str>,
    project_dir: &Path,
    json_output: bool,
    all: bool,
    yes: bool,
    pid: Option<u32>,
) -> Result<(), LpmError> {
    match parse_command(action, target, all, pid)? {
        PortsCommand::List { all } => run_list(project_dir, json_output, all),
        PortsCommand::Inspect(port) => {
            run_inspect(port, json_output);
            Ok(())
        }
        PortsCommand::Kill(target) => run_kill(target, json_output, yes),
        PortsCommand::Reset => run_reset(project_dir, json_output),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PortsCommand {
    List { all: bool },
    Inspect(u16),
    Kill(KillTarget),
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KillTarget {
    Port(u16),
    Range { start: u16, end: u16 },
    Pid(u32),
}

#[derive(Debug, Clone)]
struct KillCandidate {
    pid: u32,
    process: Option<String>,
    ports: Vec<u16>,
}

fn parse_command(
    action: &str,
    target: Option<&str>,
    all: bool,
    pid: Option<u32>,
) -> Result<PortsCommand, LpmError> {
    if all {
        if action != "list" || target.is_some() || pid.is_some() {
            return Err(LpmError::Script(
                "`--all` cannot be combined with another ports action".into(),
            ));
        }
        return Ok(PortsCommand::List { all: true });
    }

    if let Some(pid) = pid {
        if action != "kill" || target.is_some() {
            return Err(LpmError::Script(
                "`--pid` is only valid as `lpm ports kill --pid <pid>`".into(),
            ));
        }
        return Ok(PortsCommand::Kill(KillTarget::Pid(pid)));
    }

    match action {
        "list" | "" => {
            if target.is_some() {
                return Err(LpmError::Script(
                    "`lpm ports list` does not accept a port argument".into(),
                ));
            }
            Ok(PortsCommand::List { all: false })
        }
        "all" => {
            if target.is_some() {
                return Err(LpmError::Script(
                    "`lpm ports all` does not accept a port argument".into(),
                ));
            }
            Ok(PortsCommand::List { all: true })
        }
        "inspect" => {
            let raw = target.ok_or_else(|| {
                LpmError::Script("missing port number. Usage: lpm ports inspect <port>".into())
            })?;
            Ok(PortsCommand::Inspect(parse_port(raw)?))
        }
        "kill" => {
            let raw = target.ok_or_else(|| {
                LpmError::Script(
                    "missing target. Usage: lpm ports kill <port|start-end> or lpm ports kill --pid <pid>"
                        .into(),
                )
            })?;
            Ok(PortsCommand::Kill(parse_kill_target(raw)?))
        }
        "reset" => {
            if target.is_some() {
                return Err(LpmError::Script(
                    "`lpm ports reset` does not accept a port argument".into(),
                ));
            }
            Ok(PortsCommand::Reset)
        }
        maybe_port => {
            if target.is_some() {
                return Err(LpmError::Script(format!(
                    "unknown ports action '{maybe_port}'. Available: list, all, inspect, kill, reset"
                )));
            }
            Ok(PortsCommand::Inspect(parse_port(maybe_port)?))
        }
    }
}

fn parse_port(raw: &str) -> Result<u16, LpmError> {
    raw.parse::<u16>()
        .map_err(|_| LpmError::Script(format!("invalid port '{raw}'")))
}

fn parse_kill_target(raw: &str) -> Result<KillTarget, LpmError> {
    if let Some((start, end)) = parse_port_range(raw)? {
        return Ok(KillTarget::Range { start, end });
    }
    Ok(KillTarget::Port(parse_port(raw)?))
}

fn parse_port_range(raw: &str) -> Result<Option<(u16, u16)>, LpmError> {
    if !raw.contains('-') {
        return Ok(None);
    }

    let Some((start, end)) = raw.split_once('-') else {
        return Ok(None);
    };
    if start.is_empty() || end.is_empty() || end.contains('-') {
        return Err(LpmError::Script(format!(
            "invalid port range '{raw}'. Use start-end, for example 3000-3010"
        )));
    }

    let start = parse_port(start)?;
    let end = parse_port(end)?;
    if start > end {
        return Err(LpmError::Script(format!(
            "invalid port range '{raw}': start must be <= end"
        )));
    }
    Ok(Some((start, end)))
}

fn run_list(project_dir: &Path, json_output: bool, all: bool) -> Result<(), LpmError> {
    if all {
        let rows = ports::list_listening_ports();
        render_listening_ports("all", &rows, json_output);
        return Ok(());
    }

    let config = lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;
    let services = config
        .as_ref()
        .map(|c| &c.services)
        .filter(|s| !s.is_empty());

    if let Some(services) = services {
        run_declared_service_list(project_dir, services, json_output);
        return Ok(());
    }

    let rows = project_listening_ports(project_dir);
    render_listening_ports("project", &rows, json_output);
    Ok(())
}

fn run_declared_service_list(
    project_dir: &Path,
    services: &std::collections::HashMap<String, lpm_json::ServiceConfig>,
    json_output: bool,
) {
    let port_overrides = ports::read_port_overrides(project_dir);
    if json_output {
        let ports: Vec<serde_json::Value> = services
            .iter()
            .filter_map(|(name, config)| {
                service_list_port(name, config, &port_overrides).map(|port| {
                    let status = match ports::check_port(port) {
                        ports::PortStatus::Free => "free",
                        ports::PortStatus::InUse { .. } => "in_use",
                    };
                    serde_json::json!({
                        "service": name,
                        "port": port,
                        "status": status,
                    })
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "success": true, "ports": ports }));
        return;
    }

    let rows: Vec<_> = services
        .iter()
        .filter_map(|(name, config)| {
            service_list_port(name, config, &port_overrides).map(|port| {
                let status = match ports::check_port(port) {
                    ports::PortStatus::Free => crate::install_ui::terminal_line!(
                        "{} {}",
                        install_ui::bullet(true),
                        install_ui::status_ok("ready")
                    ),
                    ports::PortStatus::InUse { pid, process_name } => {
                        let owner = match (&pid, &process_name) {
                            (Some(p), Some(n)) => format!("{n} (PID {p})"),
                            (Some(p), None) => format!("PID {p}"),
                            _ => "unknown".to_string(),
                        };
                        crate::install_ui::terminal_line!(
                            "{} {} ({})",
                            install_ui::bullet(true),
                            install_ui::status_ok("listening"),
                            install_ui::dim(&owner)
                        )
                    }
                };
                (name.as_str(), port, status)
            })
        })
        .collect();

    if rows.is_empty() {
        install_ui::warn("No declared service ports");
        return;
    }

    let service_width = rows
        .iter()
        .map(|(name, _, _)| name.len())
        .chain(std::iter::once("Service".len()))
        .max()
        .unwrap_or("Service".len());

    println!(
        "{}  {}   {}",
        install_ui::dim(&format!("{:<service_width$}", "Service")),
        install_ui::dim("Port"),
        install_ui::dim("Status")
    );
    for (name, port, status) in &rows {
        let name = format!("{name:<service_width$}");
        println!(
            "{}",
            crate::install_ui::terminal_line!(
                "{}  {}  {}",
                name,
                install_ui::yellow(&format!("{port:<5}")),
                status
            )
        );
    }
    println!();
    install_ui::done_untrusted(&format!(
        "{} declared service {}",
        rows.len(),
        if rows.len() == 1 { "port" } else { "ports" }
    ));
}

fn service_list_port(
    name: &str,
    config: &lpm_json::ServiceConfig,
    port_overrides: &HashMap<String, u16>,
) -> Option<u16> {
    config.port.or_else(|| {
        config
            .host
            .as_ref()
            .and_then(|_| port_overrides.get(name).copied())
    })
}

fn project_listening_ports(project_dir: &Path) -> Vec<ListeningPort> {
    let canonical_project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    ports::list_listening_ports()
        .into_iter()
        .filter(|row| {
            row.cwd.as_deref().is_some_and(|cwd| {
                cwd.starts_with(&canonical_project_dir) || cwd.starts_with(project_dir)
            }) || row
                .project_dir
                .as_deref()
                .is_some_and(|dir| dir == canonical_project_dir || dir == project_dir)
        })
        .collect()
}

fn render_listening_ports(scope: &str, rows: &[ListeningPort], json_output: bool) {
    if json_output {
        let ports: Vec<_> = rows.iter().map(listening_port_json).collect();
        println!(
            "{}",
            serde_json::json!({ "success": true, "scope": scope, "ports": ports })
        );
        return;
    }

    if rows.is_empty() {
        install_ui::warn_untrusted(match scope {
            "all" => "No listening TCP ports found",
            _ => "No listening TCP ports found for this project",
        });
        return;
    }

    print_listening_port_table(rows);
    println!();
    install_ui::done_untrusted(&format!(
        "{} listening {}",
        rows.len(),
        if rows.len() == 1 { "port" } else { "ports" }
    ));
}

fn print_listening_port_table(rows: &[ListeningPort]) {
    let process_width = bounded_width(
        rows.iter()
            .map(|row| display_or_dash(row.process.as_deref()).chars().count()),
        "Process".len(),
        28,
    );
    let project_width = bounded_width(
        rows.iter()
            .map(|row| display_or_dash(row.project.as_deref()).chars().count()),
        "Project".len(),
        28,
    );
    let framework_width = bounded_width(
        rows.iter()
            .map(|row| display_or_dash(row.framework.as_deref()).chars().count()),
        "Framework".len(),
        22,
    );

    println!(
        "{}  {}  {}  {}  {}  {}",
        install_ui::dim("Port"),
        install_ui::dim(&format!("{:<process_width$}", "Process")),
        install_ui::dim("PID"),
        install_ui::dim(&format!("{:<project_width$}", "Project")),
        install_ui::dim(&format!("{:<framework_width$}", "Framework")),
        install_ui::dim("Status")
    );

    for row in rows {
        let process = fit_cell(display_or_dash(row.process.as_deref()), process_width);
        let project = fit_cell(display_or_dash(row.project.as_deref()), project_width);
        let framework = fit_cell(display_or_dash(row.framework.as_deref()), framework_width);
        let pid = row
            .pid
            .map_or_else(|| "-".to_string(), |pid| pid.to_string());
        let status = format!(
            "{} {}",
            install_ui::bullet(true),
            install_ui::status_ok("listening")
        );
        println!(
            "{}  {process:<process_width$}  {pid:<5}  {}  {framework:<framework_width$}  {status}",
            install_ui::green(&format!("{:<5}", row.port)),
            install_ui::yellow(&format!("{project:<project_width$}")),
        );
    }
}

fn bounded_width(widths: impl Iterator<Item = usize>, header: usize, max: usize) -> usize {
    widths
        .chain(std::iter::once(header))
        .max()
        .unwrap_or(header)
        .min(max)
}

fn display_or_dash(value: Option<&str>) -> &str {
    value.filter(|value| !value.is_empty()).unwrap_or("-")
}

fn fit_cell(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }

    if width <= 3 {
        return value.chars().take(width).collect();
    }

    let mut out: String = value.chars().take(width - 3).collect();
    out.push_str("...");
    out
}

fn listening_port_json(row: &ListeningPort) -> serde_json::Value {
    serde_json::json!({
        "port": row.port,
        "address": row.address.as_deref(),
        "pid": row.pid,
        "process": row.process.as_deref(),
        "command": row.command.as_deref(),
        "cwd": path_json(row.cwd.as_ref()),
        "projectDir": path_json(row.project_dir.as_ref()),
        "project": row.project.as_deref(),
        "framework": row.framework.as_deref(),
        "uptime": row.uptime.as_deref(),
        "status": "listening",
    })
}

fn path_json(path: Option<&PathBuf>) -> serde_json::Value {
    path.map_or(serde_json::Value::Null, |path| {
        serde_json::Value::String(path.display().to_string())
    })
}

fn run_inspect(port: u16, json_output: bool) {
    let matches: Vec<ListeningPort> = ports::list_listening_ports()
        .into_iter()
        .filter(|row| row.port == port)
        .collect();

    if matches.is_empty() {
        render_empty_inspect(port, json_output);
        return;
    }

    if json_output {
        let listeners: Vec<_> = matches.iter().map(listening_port_json).collect();
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "port": port,
                "status": "listening",
                "listeners": listeners,
            })
        );
        return;
    }

    print_listening_port_table(&matches);
    println!();
    install_ui::done_untrusted(&format!("Port {port} is listening"));
}

fn render_empty_inspect(port: u16, json_output: bool) {
    match ports::check_port(port) {
        ports::PortStatus::Free => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "port": port, "status": "free", "listeners": [] })
                );
            } else {
                install_ui::done_untrusted(&format!("Port {port} is not in use"));
            }
        }
        ports::PortStatus::InUse { pid, process_name } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "port": port,
                        "status": "in_use",
                        "listeners": [{
                            "port": port,
                            "pid": pid,
                            "process": process_name,
                            "status": "in_use"
                        }]
                    })
                );
            } else {
                let owner = owner_display(pid, process_name.as_deref());
                install_ui::done_untrusted(&format!("Port {port} is in use by {owner}"));
            }
        }
    }
}

fn run_kill(target: KillTarget, json_output: bool, yes: bool) -> Result<(), LpmError> {
    match target {
        KillTarget::Port(port) => run_kill_port(port, json_output),
        KillTarget::Pid(pid) => run_kill_pid(pid, json_output),
        KillTarget::Range { start, end } => run_kill_range(start, end, json_output, yes),
    }
}

fn run_kill_port(port: u16, json_output: bool) -> Result<(), LpmError> {
    match ports::check_port(port) {
        ports::PortStatus::Free => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "port": port, "status": "already_free" })
                );
            } else {
                install_ui::done_untrusted(&format!("Port {port} is not in use"));
            }
        }
        ports::PortStatus::InUse { pid, process_name } => {
            let owner = owner_display(pid, process_name.as_deref());
            ports::kill_port_owner(port).map_err(LpmError::Script)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "port": port, "killed": owner })
                );
            } else {
                install_ui::done_untrusted(&format!("Killed {owner} on port {port}"));
            }
        }
    }
    Ok(())
}

fn run_kill_pid(pid: u32, json_output: bool) -> Result<(), LpmError> {
    let snapshot = ports::list_listening_ports();
    let owned_ports: Vec<u16> = snapshot
        .iter()
        .filter(|row| row.pid == Some(pid))
        .map(|row| row.port)
        .collect();
    let process = snapshot
        .iter()
        .find(|row| row.pid == Some(pid))
        .and_then(|row| row.process.clone());

    ports::kill_pid(pid).map_err(LpmError::Script)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "pid": pid,
                "process": process,
                "ports": owned_ports,
            })
        );
    } else {
        let owner = owner_display(Some(pid), process.as_deref());
        install_ui::done_untrusted(&format!("Killed {owner}"));
    }
    Ok(())
}

fn run_kill_range(start: u16, end: u16, json_output: bool, yes: bool) -> Result<(), LpmError> {
    let candidates = kill_candidates_for_range(start, end);
    if candidates.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "range": { "start": start, "end": end },
                    "killed": [],
                    "status": "no_listeners",
                })
            );
        } else {
            install_ui::done_untrusted(&format!("No listening ports found in {start}-{end}"));
        }
        return Ok(());
    }

    confirm_range_kill(start, end, &candidates, json_output, yes)?;

    let mut killed = Vec::new();
    for candidate in candidates {
        let still_owned_ports = ports::kill_pid_if_owns_ports(candidate.pid, &candidate.ports)
            .map_err(LpmError::Script)?;
        if still_owned_ports.is_empty() {
            continue;
        }

        killed.push(serde_json::json!({
            "pid": candidate.pid,
            "process": candidate.process,
            "ports": still_owned_ports,
        }));
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "range": { "start": start, "end": end },
                "killed": killed,
            })
        );
    } else {
        install_ui::done_untrusted(&format!(
            "Killed {} {} in {start}-{end}",
            killed.len(),
            if killed.len() == 1 {
                "process"
            } else {
                "processes"
            }
        ));
    }
    Ok(())
}

fn kill_candidates_for_range(start: u16, end: u16) -> Vec<KillCandidate> {
    kill_candidates_from_rows(ports::list_listening_ports(), start, end)
}

fn kill_candidates_from_rows(
    rows: impl IntoIterator<Item = ListeningPort>,
    start: u16,
    end: u16,
) -> Vec<KillCandidate> {
    let mut by_pid: BTreeMap<u32, KillCandidate> = BTreeMap::new();
    for row in rows
        .into_iter()
        .filter(|row| row.port >= start && row.port <= end)
    {
        let Some(pid) = row.pid else {
            continue;
        };
        let entry = by_pid.entry(pid).or_insert_with(|| KillCandidate {
            pid,
            process: row.process.clone(),
            ports: Vec::new(),
        });
        if !entry.ports.contains(&row.port) {
            entry.ports.push(row.port);
        }
        if entry.process.is_none() {
            entry.process = row.process;
        }
    }
    by_pid.into_values().collect()
}

fn confirm_range_kill(
    start: u16,
    end: u16,
    candidates: &[KillCandidate],
    json_output: bool,
    yes: bool,
) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if json_output || !std::io::stdin().is_terminal() {
        return Err(LpmError::Script(format!(
            "range kill {start}-{end} matches {} process(es); pass --yes to confirm",
            candidates.len()
        )));
    }

    let confirmed = cliclack::confirm(format!(
        "Kill {} process(es) listening in {start}-{end}?",
        candidates.len()
    ))
    .interact()
    .map_err(crate::prompt::prompt_err)?;
    if !confirmed {
        return Err(LpmError::Script(
            "aborted by user; no processes were killed".into(),
        ));
    }
    Ok(())
}

fn owner_display(pid: Option<u32>, process_name: Option<&str>) -> String {
    match (pid, process_name) {
        (Some(pid), Some(name)) => format!("{name} (PID {pid})"),
        (Some(pid), None) => format!("PID {pid}"),
        _ => "unknown".to_string(),
    }
}

fn run_reset(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    ports::clear_port_overrides(project_dir)?;

    if json_output {
        println!("{}", serde_json::json!({ "success": true, "reset": true }));
    } else {
        install_ui::done("Port overrides cleared for this project");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_treats_bare_number_as_inspect_port() {
        assert_eq!(
            parse_command("3000", None, false, None).unwrap(),
            PortsCommand::Inspect(3000)
        );
    }

    #[test]
    fn parse_command_accepts_all_aliases() {
        assert_eq!(
            parse_command("all", None, false, None).unwrap(),
            PortsCommand::List { all: true }
        );
        assert_eq!(
            parse_command("list", None, true, None).unwrap(),
            PortsCommand::List { all: true }
        );
    }

    #[test]
    fn parse_command_requires_pid_flag_for_pid_kill() {
        assert_eq!(
            parse_command("kill", None, false, Some(48213)).unwrap(),
            PortsCommand::Kill(KillTarget::Pid(48213))
        );
        assert_eq!(
            parse_command("kill", Some("48213"), false, None).unwrap(),
            PortsCommand::Kill(KillTarget::Port(48213))
        );
    }

    #[test]
    fn parse_kill_target_accepts_inclusive_port_range() {
        assert_eq!(
            parse_kill_target("3000-3010").unwrap(),
            KillTarget::Range {
                start: 3000,
                end: 3010
            }
        );
    }

    #[test]
    fn parse_kill_target_rejects_descending_range() {
        let err = parse_kill_target("3010-3000").unwrap_err().to_string();

        assert!(
            err.contains("start must be <= end"),
            "descending range must report the ordering problem, got: {err}"
        );
    }

    #[test]
    fn range_kill_candidates_dedupe_ports_by_pid() {
        let candidates = kill_candidates_from_rows(
            [
                listening_port(3000, Some(42), Some("node")),
                listening_port(3000, Some(42), Some("node")),
                listening_port(3001, Some(42), None),
                listening_port(3002, None, Some("unknown")),
                listening_port(4000, Some(99), Some("redis")),
            ],
            3000,
            3010,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].pid, 42);
        assert_eq!(candidates[0].process.as_deref(), Some("node"));
        assert_eq!(candidates[0].ports, vec![3000, 3001]);
    }

    #[test]
    fn service_list_port_uses_persisted_assignment_for_host_only_services() {
        let mut overrides = HashMap::new();
        overrides.insert("web".to_string(), 3123);
        let host_only = lpm_json::ServiceConfig {
            command: "node server.js".to_string(),
            host: Some("web.localhost".to_string()),
            ..Default::default()
        };
        let declared = lpm_json::ServiceConfig {
            command: "node api.js".to_string(),
            port: Some(3000),
            host: Some("api.localhost".to_string()),
            ..Default::default()
        };

        assert_eq!(service_list_port("web", &host_only, &overrides), Some(3123));
        assert_eq!(service_list_port("api", &declared, &overrides), Some(3000));
        assert_eq!(service_list_port("worker", &host_only, &overrides), None);
    }

    fn listening_port(port: u16, pid: Option<u32>, process: Option<&str>) -> ListeningPort {
        ListeningPort {
            port,
            address: Some("127.0.0.1".to_string()),
            pid,
            process: process.map(str::to_string),
            command: None,
            cwd: None,
            project_dir: None,
            project: None,
            framework: None,
            uptime: None,
        }
    }
}
