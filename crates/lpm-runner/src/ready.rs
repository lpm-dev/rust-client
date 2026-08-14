//! Service readiness checks.
//!
//! Polls TCP ports or HTTP endpoints until a service is ready,
//! used to enforce `dependsOn` ordering during startup.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const MAX_HTTP_STATUS_LINE_BYTES: usize = 8 * 1024;
const MAX_HTTP_REQUEST_TARGET_BYTES: usize = 8 * 1024;

/// Wait for a TCP port to accept connections.
///
/// Polls every 100ms until the port is reachable or the timeout expires.
pub fn wait_for_port(port: u16, timeout_secs: u64) -> Result<Duration, String> {
    wait_for_port_until(port, timeout_secs, || false)
}

pub(crate) fn wait_for_port_until(
    port: u16,
    timeout_secs: u64,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<Duration, String> {
    let start = Instant::now();
    wait_for_port_until_deadline(
        port,
        start,
        start + Duration::from_secs(timeout_secs),
        timeout_secs,
        &mut should_cancel,
    )
}

pub(crate) fn wait_for_port_until_deadline(
    port: u16,
    start: Instant,
    deadline: Instant,
    timeout_secs: u64,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<Duration, String> {
    wait_for_port_until_deadline_with_connector(
        port,
        start,
        deadline,
        timeout_secs,
        &mut should_cancel,
        |address, timeout| TcpStream::connect_timeout(&address, timeout).map(drop),
    )
}

fn wait_for_port_until_deadline_with_connector(
    port: u16,
    start: Instant,
    deadline: Instant,
    timeout_secs: u64,
    should_cancel: &mut impl FnMut() -> bool,
    mut connect: impl FnMut(SocketAddr, Duration) -> std::io::Result<()>,
) -> Result<Duration, String> {
    let poll_interval = Duration::from_millis(100);

    loop {
        if should_cancel() {
            return Err("readiness cancelled".to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for port {port} ({timeout_secs}s)\n\n\
				     Possible causes:\n\
				     • The service crashed — check output above\n\
				     • The service uses a different port — set \"port\" in lpm.json\n\
				     • The service needs more time — set \"readyTimeout\" in lpm.json"
            ));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        match connect(
            SocketAddr::from(([127, 0, 0, 1], port)),
            remaining.min(Duration::from_millis(200)),
        ) {
            Ok(_) => return Ok(start.elapsed()),
            Err(_) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if sleep_until_cancelled(poll_interval.min(remaining), should_cancel) {
                    return Err("readiness cancelled".to_string());
                }
            }
        }
    }
}

/// Wait for an HTTP URL to return a 2xx status code.
///
/// Polls every 500ms until the URL responds with success or the timeout expires.
///
/// Only plain HTTP is supported. HTTPS URLs are rejected immediately with a
/// clear error message — the raw-TCP client cannot perform TLS handshakes.
pub fn wait_for_url(url: &str, timeout_secs: u64) -> Result<Duration, String> {
    wait_for_url_until(url, timeout_secs, || false)
}

pub(crate) fn wait_for_url_until(
    url: &str,
    timeout_secs: u64,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<Duration, String> {
    let start = Instant::now();
    wait_for_url_until_deadline(
        url,
        start,
        start + Duration::from_secs(timeout_secs),
        timeout_secs,
        &mut should_cancel,
    )
}

pub(crate) fn wait_for_url_until_deadline(
    url: &str,
    start: Instant,
    deadline: Instant,
    timeout_secs: u64,
    mut should_cancel: impl FnMut() -> bool,
) -> Result<Duration, String> {
    // Reject HTTPS URLs early with a clear message instead of a confusing TCP error
    if url.starts_with("https://") {
        return Err(format!(
            "HTTPS readiness checks are not supported. \
			 Use an HTTP URL for \"readyUrl\" in lpm.json, or configure your \
			 service to expose an HTTP health endpoint.\n\
			 \n\
			 Got: {url}"
        ));
    }

    // Reject non-localhost URLs to prevent SSRF: a malicious lpm.json could
    // use readyUrl to probe internal network services.
    if !is_localhost_url(url) {
        return Err(format!(
            "readyUrl must point to localhost for security. \
			 Non-local URLs are rejected to prevent SSRF attacks.\n\
			 \n\
			 Got: {url}\n\
			 Use: http://localhost:<port>/health or http://127.0.0.1:<port>/health"
        ));
    }

    let poll_interval = Duration::from_millis(500);

    loop {
        if should_cancel() {
            return Err("readiness cancelled".to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for {url} ({timeout_secs}s)\n\n\
				     Possible causes:\n\
				     • The service crashed — check output above\n\
				     • The URL is incorrect — check \"readyUrl\" in lpm.json\n\
				     • The service needs more time — set \"readyTimeout\" in lpm.json"
            ));
        }

        // Use a simple TCP-level check + HTTP request via stdlib
        // We don't pull in reqwest here to keep lpm-runner lightweight
        match ureq_get_until(url, deadline, &mut should_cancel) {
            Ok(status) if (200..300).contains(&status) => return Ok(start.elapsed()),
            Err(error) if error == "readiness cancelled" => return Err(error),
            _ => {
                if Instant::now() >= deadline {
                    continue;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if sleep_until_cancelled(poll_interval.min(remaining), &mut should_cancel) {
                    return Err("readiness cancelled".to_string());
                }
            }
        }
    }
}

fn sleep_until_cancelled(duration: Duration, should_cancel: &mut impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if should_cancel() {
            return true;
        }
        std::thread::sleep(
            Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    should_cancel()
}

/// Check if a URL points to localhost (127.0.0.1, ::1, or "localhost").
///
/// Used to prevent SSRF: readyUrl must only target local services.
fn is_localhost_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let after_scheme = lower.strip_prefix("http://").unwrap_or("");
    is_localhost_host(after_scheme)
}

/// Check if the host portion (after `http://`) is localhost.
/// Must be exactly "localhost", "127.0.0.1", or "[::1]" followed by
/// end-of-string, ':', or '/'.
fn is_localhost_host(host_and_rest: &str) -> bool {
    for prefix in &["localhost", "127.0.0.1", "[::1]"] {
        if let Some(rest) = host_and_rest.strip_prefix(prefix)
            && (rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
        {
            return true;
        }
    }
    false
}

/// Minimal HTTP GET using stdlib (no external deps).
#[cfg(test)]
fn ureq_get(url: &str) -> Result<u16, String> {
    ureq_get_until(url, Instant::now() + Duration::from_secs(2), &mut || false)
}

fn ureq_get_until(
    url: &str,
    deadline: Instant,
    should_cancel: &mut impl FnMut() -> bool,
) -> Result<u16, String> {
    let url = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map_or(url, |_| &url[7..]);
    let (host_port, path) = match url.find('/') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, "/"),
    };
    if path.len() > MAX_HTTP_REQUEST_TARGET_BYTES
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err("invalid readyUrl: request target contains unsafe characters".to_string());
    }

    let (addresses, address_count) = local_http_addresses(host_port)?;
    let mut stream = None;
    let mut last_error = None;
    for address in addresses.into_iter().take(address_count) {
        if should_cancel() {
            return Err("readiness cancelled".to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("readiness deadline elapsed".to_string());
        }
        match TcpStream::connect_timeout(&address, remaining.min(Duration::from_millis(100))) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut stream = stream.ok_or_else(|| match last_error {
        Some(error) => format!("connection failed: {error}"),
        None => "invalid address: no addresses resolved".to_string(),
    })?;

    stream
        .set_write_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        ))
        .ok();

    let request = format!("GET {path} HTTP/1.0\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;

    let mut status_line = Vec::with_capacity(64);
    let mut chunk = [0u8; 1024];
    loop {
        if should_cancel() {
            return Err("readiness cancelled".to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("readiness deadline elapsed".to_string());
        }
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_millis(25))))
            .ok();
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let bytes = &chunk[..read];
                let end = bytes
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |index| index + 1);
                status_line.extend_from_slice(&bytes[..end]);
                if status_line.len() > MAX_HTTP_STATUS_LINE_BYTES {
                    return Err(format!(
                        "HTTP status line exceeds {MAX_HTTP_STATUS_LINE_BYTES} bytes"
                    ));
                }
                if end < bytes.len() || status_line.ends_with(b"\n") {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => return Err(format!("read failed: {error}")),
        }
    }
    let Some(status_line) = status_line.strip_suffix(b"\r\n") else {
        return Err("invalid HTTP response: incomplete status line".to_string());
    };
    let status_line = std::str::from_utf8(status_line)
        .map_err(|_| "invalid HTTP response: malformed status line".to_string())?;

    let mut parts = status_line.split_ascii_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid HTTP response: malformed status line".to_string());
    }

    status
        .parse()
        .map_err(|_| "invalid HTTP response: malformed status line".to_string())
}

fn local_http_addresses(host_port: &str) -> Result<([SocketAddr; 2], usize), String> {
    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| "invalid address: unterminated IPv6 host".to_string())?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = parse_http_port(suffix)?;
        (host, port)
    } else if let Some((host, port)) = host_port.split_once(':') {
        if port.contains(':') {
            return Err("invalid address: IPv6 hosts must use brackets".to_string());
        }
        (host, parse_http_port(&format!(":{port}"))?)
    } else {
        (host_port, 80)
    };

    let ipv4 = SocketAddr::from(([127, 0, 0, 1], port));
    if host.eq_ignore_ascii_case("localhost") {
        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        Ok(([ipv4, ipv6], 2))
    } else if host == "127.0.0.1" {
        Ok(([ipv4, ipv4], 1))
    } else if host == "::1" {
        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        Ok(([ipv6, ipv6], 1))
    } else {
        Err("invalid address: readyUrl host must be localhost".to_string())
    }
}

fn parse_http_port(suffix: &str) -> Result<u16, String> {
    if suffix.is_empty() {
        return Ok(80);
    }
    let port = suffix
        .strip_prefix(':')
        .filter(|port| !port.is_empty())
        .ok_or_else(|| "invalid address: malformed port".to_string())?
        .parse::<u16>()
        .map_err(|error| format!("invalid address: malformed port: {error}"))?;
    if port == 0 {
        return Err("invalid address: port must be greater than zero".to_string());
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn wait_for_port_succeeds_when_listening() {
        // Bind a port, then wait for it — should succeed immediately
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let duration = wait_for_port(port, 5).unwrap();
        assert!(duration.as_millis() < 500, "should be fast: {duration:?}");
    }

    #[test]
    fn wait_for_port_times_out() {
        // Use a port that's definitely not listening
        let result = wait_for_port(49999, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }

    #[test]
    fn wait_for_port_returns_duration() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let duration = wait_for_port(port, 5).unwrap();
        assert!(duration.as_secs() < 5);
    }

    #[test]
    fn tcp_readiness_connect_attempt_never_exceeds_the_remaining_deadline() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(20);
        let mut observed_timeout = None;

        let result = wait_for_port_until_deadline_with_connector(
            30_000,
            start,
            deadline,
            1,
            &mut || false,
            |_address, timeout| {
                observed_timeout.get_or_insert(timeout);
                Err(std::io::Error::from(ErrorKind::ConnectionRefused))
            },
        );

        assert!(result.is_err());
        assert!(
            observed_timeout.is_some_and(|timeout| timeout <= Duration::from_millis(20)),
            "connect timeout exceeded the readiness deadline: {observed_timeout:?}"
        );
    }

    #[test]
    fn wait_for_port_timeout_message_is_actionable() {
        // Use port 1 (privileged, never listening as non-root) to guarantee timeout
        let result = wait_for_port(1, 1);
        let err = result.unwrap_err();
        assert!(
            err.contains("Possible causes"),
            "error should contain actionable hints: {err}"
        );
        assert!(
            err.contains("readyTimeout"),
            "error should mention readyTimeout config: {err}"
        );
    }

    #[test]
    fn https_url_returns_clear_error() {
        let result = wait_for_url("https://localhost:8443/health", 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("HTTPS readiness checks are not supported"),
            "should return clear HTTPS error, got: {err}"
        );
    }

    // ── SSRF protection tests ────────────────────────────────────────

    #[test]
    fn is_localhost_url_accepts_localhost() {
        assert!(is_localhost_url("http://localhost:3000/health"));
        assert!(is_localhost_url("http://localhost/"));
        assert!(is_localhost_url("http://127.0.0.1:4000"));
        assert!(is_localhost_url("http://127.0.0.1/health"));
        assert!(is_localhost_url("http://[::1]:8080/ready"));
    }

    #[test]
    fn is_localhost_url_rejects_external() {
        assert!(!is_localhost_url("http://evil.com/health"));
        assert!(!is_localhost_url("http://169.254.169.254/"));
        assert!(!is_localhost_url("http://10.0.0.1:3000/health"));
        assert!(!is_localhost_url("http://192.168.1.1/"));
        assert!(!is_localhost_url("http://localhost.evil.com/"));
    }

    #[test]
    fn wait_for_url_rejects_non_localhost() {
        let result = wait_for_url("http://169.254.169.254/latest/meta-data/", 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("readyUrl must point to localhost"),
            "got: {err}"
        );
    }

    #[test]
    fn wait_for_url_rejects_evil_domain() {
        let result = wait_for_url("http://evil.com/health", 1);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("readyUrl must point to localhost")
        );
    }

    #[test]
    fn wait_for_url_allows_localhost() {
        // This will time out (no server) but should NOT be rejected by SSRF check
        let result = wait_for_url("http://127.0.0.1:49996/health", 1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("timed out"),
            "should timeout not SSRF reject: {err}"
        );
    }

    #[test]
    fn wait_for_url_timeout_message_is_actionable() {
        let result = wait_for_url("http://127.0.0.1:49997/health", 1);
        let err = result.unwrap_err();
        assert!(
            err.contains("Possible causes"),
            "error should contain actionable hints: {err}"
        );
        assert!(
            err.contains("readyUrl"),
            "error should mention readyUrl config: {err}"
        );
    }

    #[test]
    fn http_readiness_respects_the_configured_deadline_when_the_server_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });
        let started = Instant::now();

        let result = wait_for_url(&format!("http://{address}/health"), 1);
        let elapsed = started.elapsed();
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert!(result.is_err());
        assert!(
            elapsed < Duration::from_millis(1500),
            "stalled HTTP readiness exceeded its one-second deadline: {elapsed:?}"
        );
    }

    #[test]
    fn http_readiness_cancellation_interrupts_a_stalled_status_line() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });
        let started = Instant::now();

        let result = wait_for_url_until(&format!("http://{address}/health"), 30, || {
            started.elapsed() >= Duration::from_millis(100)
        });
        let elapsed = started.elapsed();
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert_eq!(result.unwrap_err(), "readiness cancelled");
        assert!(
            elapsed < Duration::from_millis(700),
            "cancellation remained blocked on the HTTP status line: {elapsed:?}"
        );
    }

    #[test]
    fn http_readiness_returns_after_status_line_without_waiting_for_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"HTTP/1.0 204 No Content\r\n").unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });

        let started = Instant::now();
        let status = ureq_get(&format!("http://{address}/health"));
        let elapsed = started.elapsed();
        release_tx.send(()).unwrap();
        server.join().unwrap();

        assert_eq!(status.unwrap(), 204);
        assert!(
            elapsed < Duration::from_millis(500),
            "status parsing waited for the response body: {elapsed:?}"
        );
    }

    #[test]
    fn http_readiness_connects_to_localhost_names() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"HTTP/1.0 200 OK\r\n").unwrap();
        });

        let status = ureq_get(&format!("http://localhost:{port}/health"));
        if status.is_err() {
            TcpStream::connect(address).unwrap();
        }
        server.join().unwrap();

        assert_eq!(status.unwrap(), 200);
    }

    #[test]
    fn http_readiness_rejects_request_target_header_injection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n");
        });

        let status = ureq_get(&format!("http://{address}/health\r\nX-Injected: true"));
        if status.is_err() {
            let mut release = TcpStream::connect(address).unwrap();
            release.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        }
        server.join().unwrap();

        assert_eq!(
            status.unwrap_err(),
            "invalid readyUrl: request target contains unsafe characters"
        );
    }

    #[test]
    fn http_readiness_rejects_oversized_status_lines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let read = stream.read(&mut request).unwrap();
            assert!(read > 0);
            stream.write_all(b"HTTP/1.0 200 ").unwrap();
            stream.write_all(&vec![b'x'; 9 * 1024]).unwrap();
            stream.write_all(b"\r\n").unwrap();
        });

        let status = ureq_get(&format!("http://{address}/health"));
        server.join().unwrap();

        let error = status.unwrap_err();
        assert!(
            error.contains("HTTP status line exceeds 8192 bytes"),
            "oversized status line returned the wrong error: {error}"
        );
    }

    #[test]
    fn http_readiness_rejects_status_lines_without_a_terminator() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let read = stream.read(&mut request).unwrap();
            assert!(read > 0);
            stream.write_all(b"HTTP/1.0 200 OK").unwrap();
        });

        let status = ureq_get(&format!("http://{address}/health"));
        server.join().unwrap();

        assert_eq!(
            status.unwrap_err(),
            "invalid HTTP response: incomplete status line"
        );
    }

    #[test]
    fn http_readiness_rejects_malformed_http_versions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"NOT-HTTP 200 OK\r\n").unwrap();
        });

        let status = ureq_get(&format!("http://{address}/health"));
        server.join().unwrap();

        assert_eq!(
            status.unwrap_err(),
            "invalid HTTP response: malformed status line"
        );
    }
}
