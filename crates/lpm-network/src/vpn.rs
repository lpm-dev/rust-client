//! VPN detection.
//!
//! Detects active VPN connections by checking for VPN-type network interfaces.
//! When a VPN is active, phones on the local network may not be able to reach
//! the dev server's network IP.

use crate::{InterfaceType, NetworkAddress};

/// Detect if a VPN is active by checking for VPN-type interfaces.
///
/// Returns the VPN interface name if detected, or None.
pub fn detect_vpn(addresses: &[NetworkAddress]) -> Option<String> {
    addresses
        .iter()
        .find(|a| a.interface_type == InterfaceType::Vpn)
        .map(|a| a.interface_name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_vpn_when_present() {
        let addrs = vec![
            NetworkAddress {
                ip: "192.168.1.42".to_string(),
                interface_name: "en0".to_string(),
                interface_type: InterfaceType::WiFi,
                is_preferred: true,
                is_ipv6: false,
            },
            NetworkAddress {
                ip: "10.8.0.2".to_string(),
                interface_name: "utun3".to_string(),
                interface_type: InterfaceType::Vpn,
                is_preferred: false,
                is_ipv6: false,
            },
        ];

        let vpn = detect_vpn(&addrs);
        assert_eq!(vpn, Some("utun3".to_string()));
    }

    #[test]
    fn no_vpn_detected() {
        let addrs = vec![NetworkAddress {
            ip: "192.168.1.42".to_string(),
            interface_name: "en0".to_string(),
            interface_type: InterfaceType::WiFi,
            is_preferred: true,
            is_ipv6: false,
        }];

        assert!(detect_vpn(&addrs).is_none());
    }
}
