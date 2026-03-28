//! Service readiness checks.
//!
//! Polls TCP ports or HTTP endpoints until a service is ready,
//! used to enforce `dependsOn` ordering during startup.

use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Wait for a TCP port to accept connections.
///
/// Polls every 100ms until the port is reachable or the timeout expires.
pub fn wait_for_port(port: u16, timeout_secs: u64) -> Result<Duration, String> {
	let start = Instant::now();
	let timeout = Duration::from_secs(timeout_secs);
	let poll_interval = Duration::from_millis(100);

	loop {
		if start.elapsed() > timeout {
			return Err(format!(
				"timed out waiting for port {port} ({timeout_secs}s)\n\n\
				     Possible causes:\n\
				     • The service crashed — check output above\n\
				     • The service uses a different port — set \"port\" in lpm.json\n\
				     • The service needs more time — set \"readyTimeout\" in lpm.json"
			));
		}

		match TcpStream::connect_timeout(
			&format!("127.0.0.1:{port}").parse().unwrap(),
			Duration::from_millis(200),
		) {
			Ok(_) => return Ok(start.elapsed()),
			Err(_) => std::thread::sleep(poll_interval),
		}
	}
}

/// Wait for an HTTP URL to return a 2xx status code.
///
/// Polls every 500ms until the URL responds with success or the timeout expires.
pub fn wait_for_url(url: &str, timeout_secs: u64) -> Result<Duration, String> {
	let start = Instant::now();
	let timeout = Duration::from_secs(timeout_secs);
	let poll_interval = Duration::from_millis(500);

	loop {
		if start.elapsed() > timeout {
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
		match ureq_get(url) {
			Ok(status) if (200..300).contains(&status) => return Ok(start.elapsed()),
			_ => std::thread::sleep(poll_interval),
		}
	}
}

/// Minimal HTTP GET using stdlib (no external deps).
fn ureq_get(url: &str) -> Result<u16, String> {
	// Parse URL to get host:port and path
	let url = url.strip_prefix("http://").unwrap_or(url);
	let (host_port, path) = match url.find('/') {
		Some(i) => (&url[..i], &url[i..]),
		None => (url, "/"),
	};

	let stream = TcpStream::connect_timeout(
		&host_port.parse().map_err(|e| format!("invalid address: {e}"))?,
		Duration::from_secs(2),
	)
	.map_err(|e| format!("connection failed: {e}"))?;

	stream
		.set_read_timeout(Some(Duration::from_secs(2)))
		.ok();
	stream
		.set_write_timeout(Some(Duration::from_secs(2)))
		.ok();

	use std::io::{Read, Write};
	let request = format!("GET {path} HTTP/1.0\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
	let mut stream = stream;
	stream
		.write_all(request.as_bytes())
		.map_err(|e| format!("write failed: {e}"))?;

	let mut response = String::new();
	stream
		.read_to_string(&mut response)
		.map_err(|e| format!("read failed: {e}"))?;

	// Parse status code from "HTTP/1.x STATUS ..."
	let status_line = response.lines().next().unwrap_or("");
	let status = status_line
		.split_whitespace()
		.nth(1)
		.and_then(|s| s.parse::<u16>().ok())
		.unwrap_or(0);

	Ok(status)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::TcpListener;

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
	fn wait_for_port_timeout_message_is_actionable() {
		let result = wait_for_port(49998, 1);
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
}
