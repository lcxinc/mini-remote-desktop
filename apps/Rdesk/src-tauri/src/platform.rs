use serde::Serialize;
use tauri::WebviewWindow;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NativeBackdropStatus {
    pub platform: &'static str,
    pub effect: &'static str,
    pub applied: bool,
    pub detail: String,
}

impl NativeBackdropStatus {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    pub fn applied(platform: &'static str, effect: &'static str) -> Self {
        Self {
            platform,
            effect,
            applied: true,
            detail: "Native backdrop applied".to_string(),
        }
    }

    pub fn unavailable(platform: &'static str, detail: impl Into<String>) -> Self {
        Self {
            platform,
            effect: "Unavailable",
            applied: false,
            detail: detail.into(),
        }
    }
}

pub fn configure_main_window(window: &WebviewWindow) -> NativeBackdropStatus {
    if let Err(error) = window.set_decorations(false) {
        eprintln!("failed to apply frameless chrome: {error}");
    }

    apply_native_backdrop(window)
}

#[cfg(target_os = "windows")]
fn apply_native_backdrop(window: &WebviewWindow) -> NativeBackdropStatus {
    use window_vibrancy::{apply_acrylic, apply_blur, apply_mica, apply_tabbed};

    match apply_tabbed(window, Some(true)) {
        Ok(_) => NativeBackdropStatus::applied("Windows", "Tabbed Mica"),
        Err(tabbed_error) => match apply_mica(window, Some(true)) {
            Ok(_) => NativeBackdropStatus::applied("Windows", "Mica"),
            Err(mica_error) => match apply_acrylic(window, Some((18, 24, 28, 160))) {
                Ok(_) => NativeBackdropStatus::applied("Windows", "Acrylic"),
                Err(acrylic_error) => match apply_blur(window, Some((18, 24, 28, 125))) {
                    Ok(_) => NativeBackdropStatus::applied("Windows", "Blur"),
                    Err(blur_error) => NativeBackdropStatus::unavailable(
                        "Windows",
                        format!(
                            "Tabbed Mica failed: {tabbed_error}; Mica failed: {mica_error}; Acrylic failed: {acrylic_error}; Blur failed: {blur_error}"
                        ),
                    ),
                },
            },
        },
    }
}

#[cfg(target_os = "macos")]
fn apply_native_backdrop(window: &WebviewWindow) -> NativeBackdropStatus {
    use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial, NSVisualEffectState};

    match apply_vibrancy(
        window,
        NSVisualEffectMaterial::HudWindow,
        Some(NSVisualEffectState::Active),
        Some(26.0),
    ) {
        Ok(_) => NativeBackdropStatus::applied("macOS", "Vibrancy"),
        Err(error) => NativeBackdropStatus::unavailable("macOS", error.to_string()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn apply_native_backdrop(_window: &WebviewWindow) -> NativeBackdropStatus {
    NativeBackdropStatus::unavailable(
        std::env::consts::OS,
        "Native backdrop is not supported on this platform",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backdrop_status_records_failure() {
        let unavailable = NativeBackdropStatus::unavailable("Linux", "unsupported");
        assert!(!unavailable.applied);
        assert_eq!(unavailable.effect, "Unavailable");
    }
}
