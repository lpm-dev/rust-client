//! Network interface discovery and classification.
//!
//! Enumerates local network interfaces, classifies them (WiFi, Ethernet, VPN, Docker),
//! filters out unusable ones, and selects the preferred address.

use crate::{InterfaceType, NetworkAddress};

/// Get all usable network addresses, sorted by preference.
///
/// Filters out loopback and link-local addresses. Classifies interfaces
/// by type (WiFi, Ethernet, VPN, Docker). Marks the most likely usable
/// address as preferred.
pub fn get_network_addresses() -> Result<Vec<NetworkAddress>, String> {
	let ifaces = if_addrs::get_if_addrs()
		.map_err(|e| format!("failed to enumerate network interfaces: {e}"))?;

	let mut addresses: Vec<NetworkAddress> = ifaces
		.into_iter()
		.filter(|iface| {
			let ip = iface.ip();

			// Skip loopback
			if ip.is_loopback() {
				return false;
			}

			// Skip link-local (169.254.*)
			if let std::net::IpAddr::V4(v4) = ip {
				if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
					return false;
				}
			}

			// Skip IPv6 link-local (fe80::)
			if let std::net::IpAddr::V6(v6) = ip {
				if (v6.segments()[0] & 0xffc0) == 0xfe80 {
					return false;
				}
			}

			true
		})
		.map(|iface| {
			let ip = iface.ip();
			let name = iface.name.clone();
			let iface_type = classify_interface(&name, &ip);
			let is_ipv6 = ip.is_ipv6();

			NetworkAddress {
				ip: ip.to_string(),
				interface_name: name,
				interface_type: iface_type,
				is_preferred: false,
				is_ipv6,
			}
		})
		.collect();

	// Sort: WiFi IPv4 first, then Ethernet IPv4, then others, then IPv6
	addresses.sort_by(|a, b| {
		let score = |addr: &NetworkAddress| -> u8 {
			let type_score = match addr.interface_type {
				InterfaceType::WiFi => 0,
				InterfaceType::Ethernet => 1,
				InterfaceType::Other => 2,
				InterfaceType::Vpn => 3,
				InterfaceType::Docker => 4,
				InterfaceType::Loopback => 5,
			};
			let ipv6_penalty: u8 = if addr.is_ipv6 { 10 } else { 0 };
			type_score + ipv6_penalty
		};
		score(a).cmp(&score(b))
	});

	// Mark first non-Docker, non-VPN, IPv4 address as preferred
	if let Some(preferred) = addresses.iter_mut().find(|a| {
		!a.is_ipv6
			&& a.interface_type != InterfaceType::Docker
			&& a.interface_type != InterfaceType::Vpn
	}) {
		preferred.is_preferred = true;
	}

	Ok(addresses)
}

/// Classify a network interface by its name and IP address.
fn classify_interface(name: &str, ip: &std::net::IpAddr) -> InterfaceType {
	let name_lower = name.to_lowercase();

	// Docker interfaces
	if name_lower.starts_with("docker")
		|| name_lower.starts_with("br-")
		|| name_lower == "docker0"
	{
		return InterfaceType::Docker;
	}

	// Docker default bridge IP range (172.17.0.0/16 only).
	// The broader 172.16.0.0/12 range includes corporate VPNs and cloud VPCs,
	// so we only match the Docker default bridge network.
	if let std::net::IpAddr::V4(v4) = ip {
		let octets = v4.octets();
		if octets[0] == 172 && octets[1] == 17 {
			return InterfaceType::Docker;
		}
	}

	// VPN interfaces
	if name_lower.starts_with("utun")    // macOS VPN
		|| name_lower.starts_with("tun")  // Linux VPN
		|| name_lower.starts_with("tap")  // Linux VPN (tap)
		|| name_lower.starts_with("wg")   // WireGuard
	{
		return InterfaceType::Vpn;
	}

	// WiFi interfaces
	// Note: on macOS, en0 is typically WiFi on laptops but may be Ethernet
	// on Mac Pro/Mini. Without shelling out to `networksetup`, we classify
	// en0 as WiFi (most common case) and accept the rare misclassification.
	#[cfg(target_os = "macos")]
	if name_lower == "en0" {
		return InterfaceType::WiFi;
	}
	#[cfg(target_os = "linux")]
	if name_lower.starts_with("wlan") || name_lower.starts_with("wlp") {
		return InterfaceType::WiFi;
	}

	// Ethernet interfaces
	#[cfg(target_os = "macos")]
	if name_lower.starts_with("en") {
		return InterfaceType::Ethernet;
	}
	#[cfg(target_os = "linux")]
	if name_lower.starts_with("eth") || name_lower.starts_with("enp") {
		return InterfaceType::Ethernet;
	}

	// Loopback
	if name_lower == "lo" || name_lower == "lo0" {
		return InterfaceType::Loopback;
	}

	InterfaceType::Other
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::IpAddr;

	#[test]
	fn classify_docker_interface() {
		let ip: IpAddr = "172.17.0.1".parse().unwrap();
		assert_eq!(classify_interface("docker0", &ip), InterfaceType::Docker);
		assert_eq!(classify_interface("br-abc123", &ip), InterfaceType::Docker);
	}

	#[test]
	fn classify_vpn_interface() {
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		assert_eq!(classify_interface("utun3", &ip), InterfaceType::Vpn);
		assert_eq!(classify_interface("tun0", &ip), InterfaceType::Vpn);
		assert_eq!(classify_interface("wg0", &ip), InterfaceType::Vpn);
	}

	#[test]
	fn classify_docker_by_ip_range() {
		let ip: IpAddr = "172.17.0.5".parse().unwrap();
		assert_eq!(classify_interface("veth123", &ip), InterfaceType::Docker);
	}

	#[test]
	fn docker_ip_range_only_172_17() {
		// 172.17.0.1 is Docker default bridge — should be Docker
		let docker_ip: IpAddr = "172.17.0.1".parse().unwrap();
		assert_eq!(classify_interface("unknown0", &docker_ip), InterfaceType::Docker);

		// 172.18.0.1 could be corporate VPN/VPC — should NOT be Docker
		let vpc_ip: IpAddr = "172.18.0.1".parse().unwrap();
		assert_ne!(classify_interface("unknown0", &vpc_ip), InterfaceType::Docker);

		// 172.16.5.1 could be corporate VPN — should NOT be Docker
		let vpn_ip: IpAddr = "172.16.5.1".parse().unwrap();
		assert_ne!(classify_interface("unknown0", &vpn_ip), InterfaceType::Docker);
	}

	#[test]
	fn get_addresses_filters_loopback() {
		let addrs = get_network_addresses().unwrap();
		for addr in &addrs {
			assert_ne!(addr.ip, "127.0.0.1", "loopback should be filtered");
			assert_ne!(addr.ip, "::1", "loopback should be filtered");
		}
	}

	#[test]
	fn preferred_is_ipv4_non_docker() {
		let addrs = get_network_addresses().unwrap();
		if let Some(preferred) = addrs.iter().find(|a| a.is_preferred) {
			assert!(!preferred.is_ipv6, "preferred should be IPv4");
			assert_ne!(preferred.interface_type, InterfaceType::Docker);
			assert_ne!(preferred.interface_type, InterfaceType::Vpn);
		}
	}
}
