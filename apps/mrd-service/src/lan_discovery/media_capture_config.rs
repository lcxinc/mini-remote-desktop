#[cfg(windows)]
use anyhow::Result;
use mrd_ipc::MediaProfile;
#[cfg(windows)]
use std::sync::OnceLock;

#[cfg(windows)]
use super::media_frame_preparation::{even_dimension, h264_target_dimensions};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LanCaptureConfigKey {
    pub(super) source_id: String,
    width: u32,
    height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DynamicWindowFpsConfigKey {
    source_id: String,
    width: u32,
    height: u32,
    fps: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CaptureSourceFailure {
    pub(super) code: &'static str,
    pub(super) message: String,
}

pub(super) fn window_capture_source_error(
    source_id: &str,
    detail: impl AsRef<str>,
) -> CaptureSourceFailure {
    CaptureSourceFailure {
        code: "WINDOW_CAPTURE_SOURCE_NOT_FOUND",
        message: format!(
            "Window capture source '{}' is unavailable: {}",
            source_id,
            detail.as_ref()
        ),
    }
}

pub(super) fn format_capture_source_failure(
    source_id: &str,
    message: String,
    is_window_source_id: impl FnOnce(&str) -> bool,
) -> String {
    if is_window_source_id(source_id) {
        let failure = window_capture_source_error(source_id, &message);
        format!("{}: {}", failure.code, failure.message)
    } else {
        message
    }
}

pub(super) fn lan_capture_config_key(
    source_id: &str,
    profile: &MediaProfile,
) -> LanCaptureConfigKey {
    LanCaptureConfigKey {
        source_id: source_id.to_string(),
        width: profile.width,
        height: profile.height,
    }
}

pub(super) fn dynamic_window_fps_config_key(
    source_id: &str,
    profile: &MediaProfile,
) -> DynamicWindowFpsConfigKey {
    DynamicWindowFpsConfigKey {
        source_id: source_id.to_string(),
        width: profile.width,
        height: profile.height,
        fps: profile.fps,
    }
}

pub(super) fn lan_capture_config_matches(
    active: Option<&LanCaptureConfigKey>,
    source_id: &str,
    profile: &MediaProfile,
) -> bool {
    active
        .map(|config| {
            config.source_id == source_id
                && config.width == profile.width
                && config.height == profile.height
        })
        .unwrap_or(false)
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsLanCaptureBackend {
    DxgiShared,
    WinrtWindowShared,
    Winrt,
}

#[cfg(windows)]
pub(super) fn windows_lan_capture_backend(
    source_id: &str,
    nvenc_h264_available: bool,
) -> WindowsLanCaptureBackend {
    let normalized = source_id.trim().to_ascii_lowercase();
    if normalized.starts_with("windows:display-shared:") {
        WindowsLanCaptureBackend::DxgiShared
    } else if normalized.starts_with("windows:window:")
        && windows_lan_window_capture_uses_shared_texture(nvenc_h264_available)
    {
        WindowsLanCaptureBackend::WinrtWindowShared
    } else {
        WindowsLanCaptureBackend::Winrt
    }
}

#[cfg(windows)]
pub(super) fn windows_lan_capture_backend_for_profile(
    source_id: &str,
    source_width: usize,
    source_height: usize,
    profile: &MediaProfile,
    nvenc_h264_available: bool,
) -> WindowsLanCaptureBackend {
    let backend = windows_lan_capture_backend(source_id, nvenc_h264_available);
    if matches!(backend, WindowsLanCaptureBackend::WinrtWindowShared)
        && windows_lan_profile_requires_scaling_path(source_width, source_height, profile)
    {
        WindowsLanCaptureBackend::Winrt
    } else {
        backend
    }
}

#[cfg(windows)]
fn windows_lan_profile_requires_scaling_path(
    source_width: usize,
    source_height: usize,
    profile: &MediaProfile,
) -> bool {
    let (target_width, target_height) =
        h264_target_dimensions(source_width, source_height, profile);
    let native_width = even_dimension(source_width).max(2);
    let native_height = even_dimension(source_height).max(2);
    target_width < native_width || target_height < native_height
}

#[cfg(windows)]
pub(super) fn windows_lan_window_capture_uses_shared_texture(nvenc_h264_available: bool) -> bool {
    nvenc_h264_available
}

#[cfg(windows)]
pub(super) fn windows_lan_nvenc_h264_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| mrd_encode_nvenc::NvencH264Encoder::probe_h264_available().is_ok())
}

#[cfg(windows)]
pub(super) fn parse_windows_window_source_id(source_id: &str) -> Result<isize> {
    crate::capture_source::parse_windows_window_hwnd_source_id(source_id)
}

pub(super) fn is_windows_window_source_id(source_id: &str) -> bool {
    source_id
        .trim()
        .to_ascii_lowercase()
        .starts_with("windows:window:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_window_fps_key_tracks_fps_separately_from_capture_config() {
        let source_id = "windows:window:0x1234";
        let profile_60 = MediaProfile {
            width: 1920,
            height: 1080,
            fps: 60,
            ..MediaProfile::default()
        };
        let profile_120 = MediaProfile {
            fps: 120,
            ..profile_60.clone()
        };

        assert_eq!(
            lan_capture_config_key(source_id, &profile_60),
            lan_capture_config_key(source_id, &profile_120)
        );
        assert_ne!(
            dynamic_window_fps_config_key(source_id, &profile_60),
            dynamic_window_fps_config_key(source_id, &profile_120)
        );
    }

    #[test]
    fn capture_config_match_ignores_fps_but_rejects_dimension_changes() {
        let source_id = "windows:display:0";
        let active = LanCaptureConfigKey {
            source_id: source_id.to_string(),
            width: 1920,
            height: 1080,
        };
        let same_capture_profile = MediaProfile {
            width: 1920,
            height: 1080,
            fps: 144,
            ..MediaProfile::default()
        };
        let resized_profile = MediaProfile {
            width: 2560,
            height: 1440,
            ..same_capture_profile.clone()
        };

        assert!(lan_capture_config_matches(
            Some(&active),
            source_id,
            &same_capture_profile
        ));
        assert!(!lan_capture_config_matches(
            Some(&active),
            source_id,
            &resized_profile
        ));
        assert!(!lan_capture_config_matches(
            Some(&active),
            "windows:display:1",
            &same_capture_profile
        ));
    }

    #[test]
    fn window_source_failure_keeps_window_context() {
        let message = format_capture_source_failure(
            "windows:window:0x0",
            "window hwnd must not be zero".to_string(),
            |source_id| source_id.starts_with("windows:window:"),
        );

        assert!(message.starts_with("WINDOW_CAPTURE_SOURCE_NOT_FOUND:"));
        assert!(message.contains("windows:window:0x0"));
        assert!(!message.contains("display"));
    }

    #[test]
    fn non_window_source_failure_keeps_original_message() {
        let message = format_capture_source_failure(
            "windows:display:0",
            "display source failed".to_string(),
            |source_id| source_id.starts_with("windows:window:"),
        );

        assert_eq!(message, "display source failed");
    }

    #[cfg(windows)]
    #[test]
    fn windows_capture_backend_for_profile_uses_cpu_scaling_path_for_reduced_window() {
        assert_eq!(
            windows_lan_capture_backend_for_profile(
                "windows:window:0x1234",
                1280,
                720,
                &MediaProfile {
                    width: 960,
                    height: 540,
                    fps: 144,
                    bitrate_mbps: 80,
                    ..MediaProfile::default()
                },
                true,
            ),
            WindowsLanCaptureBackend::Winrt
        );
    }
}
