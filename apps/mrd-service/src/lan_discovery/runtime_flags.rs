#[cfg(any(windows, target_os = "macos", test))]
pub(super) fn env_bool_override(value: Option<&str>) -> Option<bool> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        "" => None,
        _ => None,
    }
}
