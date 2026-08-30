pub(super) const LAN_ANNOUNCE_MAC_ADDRESS_ENV: &str = "MRD_LAN_ANNOUNCE_MAC_ADDRESS";

pub(super) fn local_lan_announcement_mac_address() -> Option<String> {
    if let Some(mac_address) = std::env::var(LAN_ANNOUNCE_MAC_ADDRESS_ENV)
        .ok()
        .and_then(|value| normalize_lan_mac_address(&value))
    {
        return Some(mac_address);
    }

    let networks = sysinfo::Networks::new_with_refreshed_list();
    select_lan_announcement_mac_address(
        networks.values().map(|data| data.mac_address().to_string()),
    )
}

pub(super) fn select_lan_announcement_mac_address<I, S>(candidates: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    candidates
        .into_iter()
        .find_map(|candidate| normalize_lan_mac_address(candidate.as_ref()))
}

pub(super) fn normalize_lan_mac_address(value: &str) -> Option<String> {
    let normalized: String = value
        .trim()
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | '.'))
        .map(|ch| ch.to_ascii_uppercase())
        .collect();

    if normalized.len() != 12 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    let bytes = normalized
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| std::str::from_utf8(chunk).ok())
        .collect::<Option<Vec<_>>>()?;

    if bytes.iter().all(|byte| *byte == "00") || bytes.iter().all(|byte| *byte == "FF") {
        return None;
    }

    Some(bytes.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lan_mac_address_accepts_common_notations() {
        assert_eq!(
            normalize_lan_mac_address("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            normalize_lan_mac_address("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            normalize_lan_mac_address("aabb.ccdd.eeff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    #[test]
    fn normalize_lan_mac_address_rejects_unusable_values() {
        for value in [
            "",
            "not-a-mac",
            "00:00:00:00:00:00",
            "FF:FF:FF:FF:FF:FF",
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:FF:00",
        ] {
            assert_eq!(normalize_lan_mac_address(value), None, "{value}");
        }
    }

    #[test]
    fn select_lan_announcement_mac_address_uses_first_valid_candidate() {
        assert_eq!(
            select_lan_announcement_mac_address([
                "00:00:00:00:00:00",
                "invalid",
                "12-34-56-78-9a-bc",
                "AA:BB:CC:DD:EE:FF",
            ])
            .as_deref(),
            Some("12:34:56:78:9A:BC")
        );
    }
}
