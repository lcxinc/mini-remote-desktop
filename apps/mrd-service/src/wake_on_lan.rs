use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, UdpSocket};

const DEFAULT_BROADCAST_ADDR: &str = "255.255.255.255:9";
const MAGIC_PACKET_LEN: usize = 102;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeOnLanSendResult {
    pub mac_address: String,
    pub broadcast_addr: String,
    pub packet_bytes: usize,
}

pub fn send_wake_on_lan(
    mac_address: &str,
    broadcast_addr: Option<&str>,
) -> Result<WakeOnLanSendResult> {
    let mac = parse_mac_address(mac_address)?;
    let packet = build_magic_packet(mac);
    let addr = parse_broadcast_addr(broadcast_addr)?;
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind Wake-on-LAN UDP socket")?;
    socket
        .set_broadcast(true)
        .context("enable UDP broadcast for Wake-on-LAN")?;
    socket
        .send_to(&packet, addr)
        .with_context(|| format!("send Wake-on-LAN magic packet to {addr}"))?;

    Ok(WakeOnLanSendResult {
        mac_address: format_mac_address(mac),
        broadcast_addr: addr.to_string(),
        packet_bytes: packet.len(),
    })
}

fn parse_broadcast_addr(value: Option<&str>) -> Result<SocketAddr> {
    value
        .unwrap_or(DEFAULT_BROADCAST_ADDR)
        .parse()
        .map_err(|error| anyhow!("invalid Wake-on-LAN broadcast address: {error}"))
}

fn parse_mac_address(value: &str) -> Result<[u8; 6]> {
    let hex: String = value
        .chars()
        .filter(|ch| *ch != ':' && *ch != '-' && *ch != '.')
        .collect();
    if hex.len() != 12 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid Wake-on-LAN MAC address; expected 12 hex digits"
        ));
    }

    let mut mac = [0_u8; 6];
    for (index, octet) in mac.iter_mut().enumerate() {
        let start = index * 2;
        *octet = u8::from_str_radix(&hex[start..start + 2], 16)
            .context("parse Wake-on-LAN MAC address octet")?;
    }
    Ok(mac)
}

fn build_magic_packet(mac: [u8; 6]) -> [u8; MAGIC_PACKET_LEN] {
    let mut packet = [0_u8; MAGIC_PACKET_LEN];
    packet[..6].fill(0xFF);
    for index in 0..16 {
        let start = 6 + index * 6;
        packet[start..start + 6].copy_from_slice(&mac);
    }
    packet
}

fn format_mac_address(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_packet_repeats_target_mac_sixteen_times() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap();
        let packet = build_magic_packet(mac);

        assert_eq!(packet.len(), MAGIC_PACKET_LEN);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        for index in 0..16 {
            let start = 6 + index * 6;
            assert_eq!(
                &packet[start..start + 6],
                &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
            );
        }
    }

    #[test]
    fn mac_parser_accepts_common_notations_and_normalizes_case() {
        assert_eq!(
            format_mac_address(parse_mac_address("aa-bb-cc-dd-ee-ff").unwrap()),
            "AA:BB:CC:DD:EE:FF"
        );
        assert_eq!(
            format_mac_address(parse_mac_address("aabbccddeeff").unwrap()),
            "AA:BB:CC:DD:EE:FF"
        );
    }

    #[test]
    fn mac_parser_rejects_invalid_addresses() {
        assert!(parse_mac_address("not-a-mac").is_err());
        assert!(parse_mac_address("AA:BB:CC:DD:EE").is_err());
    }
}
