//! Firewall detection.
//!
//! Checks if the system firewall is enabled and may block incoming network
//! connections. Currently supports macOS Application Firewall.

use std::process::Command;

/// Check if the system firewall may block incoming connections.
///
/// Returns a warning message if the firewall is enabled, or None.
pub fn check_firewall() -> Option<String> {
	#[cfg(target_os = "macos")]
	{
		check_firewall_macos()
	}

	#[cfg(not(target_os = "macos"))]
	{
		None
	}
}

#[cfg(target_os = "macos")]
fn check_firewall_macos() -> Option<String> {
	let output = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
		.arg("--getglobalstate")
		.output()
		.ok()?;

	let stdout = String::from_utf8_lossy(&output.stdout);

	if stdout.contains("enabled") {
		Some(
			"macOS firewall is enabled — network access may be blocked. \
			 Fix: System Settings → Network → Firewall → Allow lpm"
				.to_string(),
		)
	} else {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn firewall_check_does_not_crash() {
		// Just verify it doesn't panic — result depends on system state
		let _ = check_firewall();
	}
}
