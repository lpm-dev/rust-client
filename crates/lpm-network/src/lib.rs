//! Network interface discovery, QR code generation, and mDNS for LPM dev runner.
//!
//! Provides network-related utilities for `lpm dev --network`:
//! - Discover local network interfaces and filter to useful ones
//! - Generate terminal QR codes for mobile device access
//! - Detect VPN and firewall interference
//! - mDNS/Bonjour service advertisement

pub mod firewall;
pub mod interfaces;
pub mod qr;
pub mod vpn;

use lpm_common::LpmError;

/// Complete network information for display.
#[derive(Debug)]
pub struct NetworkInfo {
	/// All usable network addresses, sorted by preference.
	pub addresses: Vec<NetworkAddress>,
	/// The primary (most likely usable) address.
	pub primary: Option<NetworkAddress>,
	/// QR code string for terminal display (empty if terminal too small).
	pub qr_code: String,
	/// Warnings to show the user (VPN detected, firewall enabled, etc.).
	pub warnings: Vec<String>,
}

/// A network address with metadata.
#[derive(Debug, Clone)]
pub struct NetworkAddress {
	/// The IP address.
	pub ip: String,
	/// Network interface name (e.g., en0, wlan0).
	pub interface_name: String,
	/// Human-readable interface type.
	pub interface_type: InterfaceType,
	/// Whether this is the preferred address.
	pub is_preferred: bool,
	/// Whether this is IPv6.
	pub is_ipv6: bool,
}

/// Type of network interface.
#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceType {
	WiFi,
	Ethernet,
	Vpn,
	Docker,
	Loopback,
	Other,
}

impl std::fmt::Display for InterfaceType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			InterfaceType::WiFi => write!(f, "Wi-Fi"),
			InterfaceType::Ethernet => write!(f, "Ethernet"),
			InterfaceType::Vpn => write!(f, "VPN"),
			InterfaceType::Docker => write!(f, "Docker"),
			InterfaceType::Loopback => write!(f, "Loopback"),
			InterfaceType::Other => write!(f, "Other"),
		}
	}
}

/// Get complete network information for the given port and protocol.
pub fn get_network_info(port: u16, https: bool) -> Result<NetworkInfo, LpmError> {
	let scheme = if https { "https" } else { "http" };

	// Discover interfaces
	let all_addrs = interfaces::get_network_addresses()
		.map_err(|e| LpmError::Cert(format!("failed to discover network interfaces: {e}")))?;

	// Filter to usable addresses
	let addresses: Vec<NetworkAddress> = all_addrs
		.into_iter()
		.filter(|a| {
			a.interface_type != InterfaceType::Loopback
				&& a.interface_type != InterfaceType::Docker
		})
		.collect();

	let primary = addresses.iter().find(|a| a.is_preferred).cloned()
		.or_else(|| addresses.first().cloned());

	// Generate QR code for primary address
	let qr_code = if let Some(ref addr) = primary {
		let url = if addr.is_ipv6 {
			format!("{scheme}://[{}]:{port}", addr.ip)
		} else {
			format!("{scheme}://{}:{port}", addr.ip)
		};
		qr::render_qr_code(&url).unwrap_or_default()
	} else {
		String::new()
	};

	// Collect warnings
	let mut warnings = Vec::new();

	if let Some(vpn_info) = vpn::detect_vpn(&addresses) {
		warnings.push(format!(
			"VPN detected ({}) — phone may not reach your network IP. \
			 Try: disconnect VPN, or use --tunnel for remote access",
			vpn_info
		));
	}

	if let Some(fw_warning) = firewall::check_firewall() {
		warnings.push(fw_warning);
	}

	Ok(NetworkInfo {
		addresses,
		primary,
		qr_code,
		warnings,
	})
}
