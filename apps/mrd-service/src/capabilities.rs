use mrd_ipc::{
    CapabilityConstraint, CapabilityConstraintStatus, CapabilityDomain, CapabilityItem,
    CapabilityPlatform, CapabilityProfile, CapabilitySnapshot, CapabilityStatus, LanPeerInfo,
    MediaProfile, ScenarioEvaluation, ScenarioEvaluationReason, ScenarioEvaluationStatus,
};
use std::{
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy)]
enum CapabilityProbeMode {
    Runtime,
    Static,
}

pub fn local_capability_snapshot() -> CapabilitySnapshot {
    local_capability_snapshot_with_mode(CapabilityProbeMode::Runtime)
}

pub fn local_capability_snapshot_static() -> CapabilitySnapshot {
    local_capability_snapshot_with_mode(CapabilityProbeMode::Static)
}

fn local_capability_snapshot_with_mode(probe_mode: CapabilityProbeMode) -> CapabilitySnapshot {
    let platform = current_platform();
    CapabilitySnapshot {
        schema_version: SCHEMA_VERSION,
        platform: platform.clone(),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: local_capabilities(platform, probe_mode),
        constraints: default_constraints(),
        profiles: default_profiles(),
        updated_at_ms: now_ms(),
    }
}

pub fn evaluate_scenario_profile_against_snapshot(
    snapshot: &CapabilitySnapshot,
    scenario_id: &str,
    requested_profile: Option<MediaProfile>,
) -> ScenarioEvaluation {
    evaluate_against_snapshot(snapshot, scenario_id, requested_profile)
}

pub fn peer_capability_snapshot(peer: &LanPeerInfo) -> CapabilitySnapshot {
    let capabilities = peer
        .transports
        .iter()
        .map(|transport| format!("transport.{transport}"))
        .chain(peer.media_capabilities.iter().cloned())
        .map(|id| {
            let (status, reason) = advertised_capability_status(&id);
            CapabilityItem {
                label: id.clone(),
                domain: capability_domain_from_id(&id),
                id,
                status,
                platform: CapabilityPlatform::Unknown,
                reason,
                detail: Some(format!("advertised by LAN peer {}", peer.device_id.0)),
                requires: Vec::new(),
                conflicts_with: Vec::new(),
                depends_on: Vec::new(),
                fallback_ids: Vec::new(),
                last_probe_time_ms: None,
            }
        })
        .collect();

    CapabilitySnapshot {
        schema_version: SCHEMA_VERSION,
        platform: CapabilityPlatform::Unknown,
        service_version: peer
            .service_build_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        capabilities,
        constraints: default_constraints(),
        profiles: default_profiles(),
        updated_at_ms: now_ms(),
    }
}

pub fn apply_control_input_capability_status(
    snapshot: &mut CapabilitySnapshot,
    input_injector_available: bool,
) {
    if input_injector_available {
        return;
    }

    if let Some(item) = snapshot
        .capabilities
        .iter_mut()
        .find(|item| item.id == "control.keyboard_mouse")
    {
        item.status = CapabilityStatus::Unsupported;
        item.reason = Some("Input injector is unavailable on this host.".to_string());
    }
}

fn evaluate_against_snapshot(
    snapshot: &CapabilitySnapshot,
    scenario_id: &str,
    requested_profile: Option<MediaProfile>,
) -> ScenarioEvaluation {
    let profile = snapshot
        .profiles
        .iter()
        .find(|profile| profile.id == scenario_id)
        .cloned();
    let required_capabilities = profile
        .as_ref()
        .map(|profile| profile.required_capabilities.clone())
        .unwrap_or_default();

    let mut missing_capabilities = Vec::new();
    let mut degraded = false;
    let mut reasons = Vec::new();
    for capability_id in &required_capabilities {
        match snapshot
            .capabilities
            .iter()
            .find(|item| item.id == *capability_id)
        {
            Some(item) if capability_status_runs(&item.status) => {
                if matches!(
                    item.status,
                    CapabilityStatus::Supported | CapabilityStatus::Degraded
                ) {
                    degraded = true;
                    reasons.push(reason(
                        "capability.degraded",
                        "warning",
                        format!(
                            "{} is {}, runtime may run below preferred parity.",
                            item.id,
                            capability_status_label(&item.status)
                        ),
                        Some(item.id.clone()),
                    ));
                }
            }
            Some(item) => {
                missing_capabilities.push(item.id.clone());
                reasons.push(reason(
                    "capability.blocked",
                    "error",
                    item.reason.clone().unwrap_or_else(|| {
                        format!(
                            "{} is {} and cannot satisfy this scenario.",
                            item.id,
                            capability_status_label(&item.status)
                        )
                    }),
                    Some(item.id.clone()),
                ));
            }
            None => {
                missing_capabilities.push(capability_id.clone());
                reasons.push(reason(
                    "capability.missing",
                    "error",
                    format!("{capability_id} is not advertised by this endpoint."),
                    Some(capability_id.clone()),
                ));
            }
        }
    }

    let mut selected_profile = requested_profile.or_else(|| profile.as_ref().map(profile_to_media));
    if let Some(selected) = selected_profile.as_mut() {
        if selected.codec.trim().is_empty() {
            selected.codec = profile
                .as_ref()
                .map(|profile| profile.codec.clone())
                .unwrap_or_else(|| "h264".to_string());
        }
    }

    let status = if profile.is_none() && selected_profile.is_none() {
        reasons.push(reason(
            "profile.unknown",
            "error",
            format!("Scenario profile {scenario_id} is not known by this service."),
            None,
        ));
        ScenarioEvaluationStatus::Blocked
    } else if !missing_capabilities.is_empty() {
        ScenarioEvaluationStatus::Blocked
    } else if degraded {
        ScenarioEvaluationStatus::Degraded
    } else {
        reasons.push(reason(
            "profile.ready",
            "info",
            "All required capabilities are present.".to_string(),
            None,
        ));
        ScenarioEvaluationStatus::Ready
    };

    let fallback_profile = if matches!(status, ScenarioEvaluationStatus::Blocked) {
        snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "diagnostic.software")
            .map(profile_to_media)
    } else {
        None
    };

    ScenarioEvaluation {
        scenario_id: scenario_id.to_string(),
        status,
        selected_profile,
        transport_kind: Some(transport_for_scenario(scenario_id, &required_capabilities)),
        reasons,
        required_capabilities,
        missing_capabilities,
        fallback_profile,
    }
}

fn profile_to_media(profile: &CapabilityProfile) -> MediaProfile {
    MediaProfile {
        width: profile.width,
        height: profile.height,
        fps: profile.fps,
        bitrate_mbps: profile.bitrate_mbps,
        codec: profile.codec.clone(),
        codec_profile: profile.codec_profile.clone(),
        bit_depth: profile.bit_depth,
        chroma_subsampling: profile.chroma_subsampling.clone(),
        pixel_format: profile.pixel_format.clone(),
        hdr_enabled: profile.hdr_enabled,
        color_mode: profile.color_mode.clone(),
        color_pipeline: profile.color_pipeline.clone(),
    }
}

fn capability_status_runs(status: &CapabilityStatus) -> bool {
    matches!(
        status,
        CapabilityStatus::Available
            | CapabilityStatus::Usable
            | CapabilityStatus::Supported
            | CapabilityStatus::Degraded
    )
}

fn capability_status_label(status: &CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Supported => "supported",
        CapabilityStatus::Available => "available",
        CapabilityStatus::Usable => "usable",
        CapabilityStatus::Degraded => "degraded",
        CapabilityStatus::PermissionMissing => "permission_missing",
        CapabilityStatus::DriverMissing => "driver_missing",
        CapabilityStatus::HardwareMissing => "hardware_missing",
        CapabilityStatus::Unimplemented => "unimplemented",
        CapabilityStatus::Unsupported => "unsupported",
        CapabilityStatus::Unknown => "unknown",
    }
}

fn advertised_capability_status(id: &str) -> (CapabilityStatus, Option<String>) {
    if is_unwired_h266_software_capability(id) {
        let (status, reason) = software_vvc_combined_status(CapabilityProbeMode::Static);
        (status, Some(reason))
    } else {
        (CapabilityStatus::Available, None)
    }
}

fn is_unwired_h266_software_capability(id: &str) -> bool {
    let normalized = id.trim().to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "software_vvc"
            | "vvc_software"
            | "software_h266"
            | "h266_software"
            | "encode.software_vvc"
            | "encode.vvc_software"
            | "encode.software_h266"
            | "encode.h266_software"
            | "decode.software_vvc"
            | "decode.vvc_software"
            | "decode.software_h266"
            | "decode.h266_software"
    )
}

fn reason(
    code: impl Into<String>,
    severity: impl Into<String>,
    message: impl Into<String>,
    capability_id: Option<String>,
) -> ScenarioEvaluationReason {
    ScenarioEvaluationReason {
        code: code.into(),
        severity: severity.into(),
        message: message.into(),
        capability_id,
    }
}

fn transport_for_scenario(scenario_id: &str, required_capabilities: &[String]) -> String {
    if scenario_id.starts_with("wan.")
        || required_capabilities
            .iter()
            .any(|id| id == "transport.webrtc")
    {
        "webrtc".to_string()
    } else if required_capabilities
        .iter()
        .any(|id| id == "transport.quic" || id == "transport.quic_datagram")
        || scenario_id.starts_with("lan.")
        || scenario_id.starts_with("quality.")
    {
        "quic".to_string()
    } else {
        "loopback".to_string()
    }
}

fn capability_domain_from_id(id: &str) -> CapabilityDomain {
    match id.split_once('.').map(|(prefix, _)| prefix).unwrap_or(id) {
        "capture" => CapabilityDomain::Capture,
        "capture_source" => CapabilityDomain::CaptureSource,
        "encode" => CapabilityDomain::Encode,
        "decode" => CapabilityDomain::Decode,
        "render" => CapabilityDomain::Render,
        "memory" => CapabilityDomain::Memory,
        "transport" | "quic" | "webrtc" => CapabilityDomain::Transport,
        "control" => CapabilityDomain::Control,
        "audio" => CapabilityDomain::Audio,
        "service" => CapabilityDomain::Service,
        "security" => CapabilityDomain::Security,
        _ => CapabilityDomain::Service,
    }
}

fn local_capabilities(
    platform: CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> Vec<CapabilityItem> {
    let mut items = Vec::new();

    add_capture_capabilities(&mut items, &platform);
    add_capture_source_capabilities(&mut items, &platform);
    add_encode_capabilities(&mut items, &platform, probe_mode);
    add_decode_capabilities(&mut items, &platform, probe_mode);
    add_render_capabilities(&mut items, &platform, probe_mode);
    add_memory_capabilities(&mut items, &platform, probe_mode);
    add_transport_capabilities(&mut items, &platform);
    add_control_capabilities(&mut items, &platform);
    add_audio_capabilities(&mut items, &platform);
    add_service_capabilities(&mut items, &platform, probe_mode);
    add_security_capabilities(&mut items, &platform);

    items
}

fn add_capture_capabilities(items: &mut Vec<CapabilityItem>, platform: &CapabilityPlatform) {
    match platform {
        CapabilityPlatform::Windows => {
            push_available(
                items,
                platform,
                CapabilityDomain::Capture,
                "capture.dxgi",
                "DXGI",
            );
            push_available(
                items,
                platform,
                CapabilityDomain::Capture,
                "capture.winrt",
                "WinRT/WGC",
            );
        }
        CapabilityPlatform::Macos => {
            push_supported(
                items,
                platform,
                CapabilityDomain::Capture,
                "capture.macos",
                "ScreenCaptureKit",
                "macOS capture is available through the Rdesk harness path.",
            );
        }
        CapabilityPlatform::Linux => {
            #[cfg(target_os = "linux")]
            let status = if mrd_capture_pipewire::PipewireScreenCapture::is_wayland_available() {
                if mrd_capture_pipewire::PipewireScreenCapture::is_pipewire_available() {
                    (
                        CapabilityStatus::Supported,
                        "Wayland capture requires portal session approval before it is usable.",
                    )
                } else {
                    (
                        CapabilityStatus::DriverMissing,
                        "Wayland capture requires PipeWire and xdg-desktop-portal runtime support.",
                    )
                }
            } else if mrd_capture_pipewire::PipewireScreenCapture::is_x11_available() {
                (
                    CapabilityStatus::Available,
                    "X11 capture backend is available for the current desktop session.",
                )
            } else {
                (
                    CapabilityStatus::Unsupported,
                    "No DISPLAY or WAYLAND_DISPLAY session was detected.",
                )
            };

            #[cfg(not(target_os = "linux"))]
            let status = (
                CapabilityStatus::Unsupported,
                "Linux capture probe is only compiled on Linux.",
            );

            push_item(
                items,
                platform,
                CapabilityDomain::Capture,
                "capture.linux",
                "Linux screen capture",
                status.0,
                Some(status.1),
            );
        }
        _ => {}
    }

    push_available(
        items,
        platform,
        CapabilityDomain::Capture,
        "capture.synthetic",
        "Synthetic capture",
    );
}

fn add_capture_source_capabilities(items: &mut Vec<CapabilityItem>, platform: &CapabilityPlatform) {
    push_available(
        items,
        platform,
        CapabilityDomain::CaptureSource,
        "capture_source.display",
        "Display capture",
    );
    let shared_status = if matches!(platform, CapabilityPlatform::Windows) {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unimplemented
    };
    push_item(
        items,
        platform,
        CapabilityDomain::CaptureSource,
        "capture_source.display_shared",
        "Shared display capture",
        shared_status,
        if matches!(platform, CapabilityPlatform::Windows) {
            None
        } else {
            Some("Shared desktop texture capture is not wired for this platform.")
        },
    );
    push_available(
        items,
        platform,
        CapabilityDomain::CaptureSource,
        "capture_source.window",
        "Window capture",
    );
}

fn add_encode_capabilities(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) {
    push_degraded(
        items,
        platform,
        CapabilityDomain::Encode,
        "encode.openh264",
        "OpenH264",
        "Software encoder fallback; usable but below hardware path parity.",
    );
    let (vvc_encode_status, vvc_encode_reason) = software_vvc_encode_status(probe_mode);
    push_item(
        items,
        platform,
        CapabilityDomain::Encode,
        "encode.software_vvc",
        "Software H.266/VVC encode",
        vvc_encode_status,
        Some(vvc_encode_reason.as_str()),
    );

    let (h264_status, h264_reason) = match probe_mode {
        CapabilityProbeMode::Runtime => probe_nvenc_h264_status(platform),
        CapabilityProbeMode::Static => static_nvenc_status(platform, "NVENC H.264"),
    };
    push_item(
        items,
        platform,
        CapabilityDomain::Encode,
        "encode.nvenc_h264",
        "NVENC H.264",
        h264_status,
        Some(h264_reason.as_str()),
    );

    let (hevc_status, hevc_reason) = match probe_mode {
        CapabilityProbeMode::Runtime => probe_nvenc_hevc_status(platform),
        CapabilityProbeMode::Static => static_nvenc_status(platform, "NVENC HEVC"),
    };
    push_item(
        items,
        platform,
        CapabilityDomain::Encode,
        "encode.nvenc_hevc",
        "NVENC HEVC",
        hevc_status,
        Some(hevc_reason.as_str()),
    );

    let (hevc_main10_status, hevc_main10_reason) = match probe_mode {
        CapabilityProbeMode::Runtime => probe_nvenc_hevc_main10_status(platform),
        CapabilityProbeMode::Static => static_nvenc_status(platform, "NVENC HEVC Main10"),
    };
    push_item(
        items,
        platform,
        CapabilityDomain::Encode,
        "encode.nvenc_hevc_main10",
        "NVENC HEVC Main10",
        hevc_main10_status,
        Some(hevc_main10_reason.as_str()),
    );

    let (av1_status, av1_reason) = nvenc_av1_status(platform, probe_mode);
    push_item(
        items,
        platform,
        CapabilityDomain::Encode,
        "encode.nvenc_av1",
        "NVENC AV1",
        av1_status,
        Some(av1_reason.as_str()),
    );

    if matches!(platform, CapabilityPlatform::Macos) {
        let (h264_status, h264_reason) =
            macos_videotoolbox_h264_encode_status(platform, probe_mode);
        push_item(
            items,
            platform,
            CapabilityDomain::Encode,
            "encode.videotoolbox_h264",
            "VideoToolbox H.264",
            h264_status,
            Some(h264_reason.as_str()),
        );
        let (hevc_status, hevc_reason) =
            macos_videotoolbox_hevc_encode_status(platform, probe_mode);
        push_item(
            items,
            platform,
            CapabilityDomain::Encode,
            "encode.videotoolbox_hevc",
            "VideoToolbox HEVC",
            hevc_status,
            Some(hevc_reason.as_str()),
        );
    }
}

fn add_decode_capabilities(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) {
    push_degraded(
        items,
        platform,
        CapabilityDomain::Decode,
        "decode.software",
        "Software H.264 decode",
        "Software decoder fallback; usable but below hardware path parity.",
    );
    let (vvc_decode_status, vvc_decode_reason) = software_vvc_decode_status(probe_mode);
    push_item(
        items,
        platform,
        CapabilityDomain::Decode,
        "decode.software_vvc",
        "Software H.266/VVC decode",
        vvc_decode_status,
        Some(vvc_decode_reason.as_str()),
    );

    let nvdec_status = if matches!(platform, CapabilityPlatform::Windows) {
        let (status, reason) = match probe_mode {
            CapabilityProbeMode::Runtime => probe_nvdec_h264_status(platform),
            CapabilityProbeMode::Static => static_windows_runtime_status("NVDEC H.264"),
        };
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.nvdec",
            "NVDEC",
            status,
            Some(reason.as_str()),
        );
        let (hevc_status, hevc_reason) = match probe_mode {
            CapabilityProbeMode::Runtime => probe_nvdec_hevc_status(platform),
            CapabilityProbeMode::Static => static_windows_runtime_status("NVDEC HEVC"),
        };
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.nvdec_hevc",
            "NVDEC HEVC",
            hevc_status,
            Some(hevc_reason.as_str()),
        );
        let (hevc_main10_status, hevc_main10_reason) = match probe_mode {
            CapabilityProbeMode::Runtime => probe_nvdec_hevc_main10_status(platform),
            CapabilityProbeMode::Static => static_windows_runtime_status("NVDEC HEVC Main10"),
        };
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.nvdec_hevc_main10",
            "NVDEC HEVC Main10",
            hevc_main10_status,
            Some(hevc_main10_reason.as_str()),
        );
        None
    } else {
        Some((
            CapabilityStatus::Unimplemented,
            "NVDEC runtime probing is only wired for Windows in service-owned capability snapshots.",
        ))
    };
    if let Some((status, reason)) = nvdec_status {
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.nvdec",
            "NVDEC",
            status,
            Some(reason),
        );
    }

    if matches!(platform, CapabilityPlatform::Linux) {
        #[cfg(target_os = "linux")]
        let (status, reason) = match mrd_decode::probe_linux_h264_hardware_available() {
            Ok(label) => (
                CapabilityStatus::Supported,
                format!("{label} is available through the Linux GStreamer decode path."),
            ),
            Err(error) => (
                CapabilityStatus::DriverMissing,
                format!(
                    "Linux H.264 hardware decode requires GStreamer plus a VA/NVIDIA H.264 decoder element: {error}"
                ),
            ),
        };

        #[cfg(not(target_os = "linux"))]
        let (status, reason) = (
            CapabilityStatus::Unsupported,
            "Linux H.264 hardware decode is only compiled on Linux.".to_string(),
        );

        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.linux_h264",
            "Linux H.264 hardware decode",
            status,
            Some(reason.as_str()),
        );

        #[cfg(target_os = "linux")]
        let (status, reason) = match mrd_decode::probe_linux_hevc_hardware_available() {
            Ok(label) => (
                CapabilityStatus::Supported,
                format!("{label} is available through the Linux GStreamer decode path."),
            ),
            Err(error) => (
                CapabilityStatus::DriverMissing,
                format!(
                    "Linux HEVC hardware decode requires GStreamer plus a VA/NVIDIA HEVC decoder element: {error}"
                ),
            ),
        };

        #[cfg(not(target_os = "linux"))]
        let (status, reason) = (
            CapabilityStatus::Unsupported,
            "Linux HEVC hardware decode is only compiled on Linux.".to_string(),
        );

        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.linux_hevc",
            "Linux HEVC hardware decode",
            status,
            Some(reason.as_str()),
        );

        #[cfg(target_os = "linux")]
        let (status, reason) = match mrd_decode::probe_linux_hevc_main10_hardware_available() {
            Ok(label) => (
                CapabilityStatus::Supported,
                format!("{label} is available through the Linux GStreamer decode path."),
            ),
            Err(error) => (
                CapabilityStatus::DriverMissing,
                format!(
                    "Linux HEVC Main10 hardware decode requires GStreamer plus a VA/NVIDIA HEVC decoder element: {error}"
                ),
            ),
        };

        #[cfg(not(target_os = "linux"))]
        let (status, reason) = (
            CapabilityStatus::Unsupported,
            "Linux HEVC Main10 hardware decode is only compiled on Linux.".to_string(),
        );

        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.linux_hevc_main10",
            "Linux HEVC Main10 hardware decode",
            status,
            Some(reason.as_str()),
        );
    }

    if matches!(platform, CapabilityPlatform::Macos) {
        let (h264_status, h264_reason) =
            macos_videotoolbox_h264_decode_status(platform, probe_mode);
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.videotoolbox_h264",
            "VideoToolbox H.264 decode",
            h264_status,
            Some(h264_reason.as_str()),
        );
        let (hevc_status, hevc_reason) =
            macos_videotoolbox_hevc_decode_status(platform, probe_mode);
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.videotoolbox_hevc",
            "VideoToolbox HEVC decode",
            hevc_status,
            Some(hevc_reason.as_str()),
        );
        let (decode_status, decode_reason) = macos_videotoolbox_decode_status(platform, probe_mode);
        push_item(
            items,
            platform,
            CapabilityDomain::Decode,
            "decode.videotoolbox",
            "VideoToolbox decode",
            decode_status,
            Some(decode_reason.as_str()),
        );
    }

    let (ffmpeg_status, ffmpeg_reason) = ffmpeg_tool_status(probe_mode);
    push_item(
        items,
        platform,
        CapabilityDomain::Decode,
        "decode.ffmpeg_h264",
        "FFmpeg H.264",
        ffmpeg_status.clone(),
        Some(ffmpeg_reason.as_str()),
    );
    push_item(
        items,
        platform,
        CapabilityDomain::Decode,
        "decode.ffmpeg_hevc",
        "FFmpeg HEVC",
        ffmpeg_status.clone(),
        Some(ffmpeg_reason.as_str()),
    );
    push_item(
        items,
        platform,
        CapabilityDomain::Decode,
        "decode.ffmpeg_vvc",
        "FFmpeg VVC",
        ffmpeg_status,
        Some(ffmpeg_reason.as_str()),
    );
}

fn add_render_capabilities(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) {
    match platform {
        CapabilityPlatform::Windows => {
            let (d3d11_status, d3d11_reason) = match probe_mode {
                CapabilityProbeMode::Runtime => probe_d3d11_render_status(platform),
                CapabilityProbeMode::Static => static_windows_runtime_status("D3D11 renderer"),
            };
            push_item(
                items,
                platform,
                CapabilityDomain::Render,
                "render.d3d11",
                "D3D11",
                d3d11_status,
                Some(d3d11_reason.as_str()),
            );
            push_item(
                items,
                platform,
                CapabilityDomain::Render,
                "render.d3d12_native",
                "D3D12 native",
                CapabilityStatus::Unimplemented,
                Some("D3D12 renderer is probe-only and not wired as mainline display."),
            );
            push_supported(
                items,
                platform,
                CapabilityDomain::Render,
                "render.opengl",
                "OpenGL",
                "OpenGL renderer supports CPU-backed frames and WGL/DX interop for D3D11 shared NV12 when available; D3D11 remains the Windows high-performance path.",
            );
        }
        CapabilityPlatform::Macos => push_supported(
            items,
            platform,
            CapabilityDomain::Render,
            "render.macos",
            "Metal",
            "Metal renderer is wired in the Rdesk harness path.",
        ),
        CapabilityPlatform::Linux => push_supported(
            items,
            platform,
            CapabilityDomain::Render,
            "render.linux",
            "Linux native renderer",
            "Linux renderer is wired in the Rdesk harness path.",
        ),
        _ => {}
    }

    push_degraded(
        items,
        platform,
        CapabilityDomain::Render,
        "render.webview",
        "WebView fallback",
        "WebView render is diagnostic fallback, not native display parity.",
    );
}

fn add_memory_capabilities(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) {
    push_available(
        items,
        platform,
        CapabilityDomain::Memory,
        "memory.cpu",
        "CPU memory",
    );
    let (status, reason) = if matches!(platform, CapabilityPlatform::Windows) {
        let (status, reason) = match probe_mode {
            CapabilityProbeMode::Runtime => probe_d3d11_render_status(platform),
            CapabilityProbeMode::Static => static_windows_runtime_status("D3D11 shared texture"),
        };
        (
            status,
            Some(format!(
                "D3D11 shared texture follows D3D11 runtime probe: {reason}"
            )),
        )
    } else {
        (
            CapabilityStatus::Unimplemented,
            Some("D3D11 shared texture interop is Windows-only.".to_string()),
        )
    };
    push_item(
        items,
        platform,
        CapabilityDomain::Memory,
        "memory.d3d11_shared",
        "D3D11 shared texture",
        status,
        reason.as_deref(),
    );
}

fn static_nvenc_status(platform: &CapabilityPlatform, label: &str) -> (CapabilityStatus, String) {
    if matches!(
        platform,
        CapabilityPlatform::Windows | CapabilityPlatform::Linux | CapabilityPlatform::Macos
    ) {
        (
            CapabilityStatus::Supported,
            format!("{label} is platform-declared; runtime probe refresh is pending."),
        )
    } else {
        unsupported_nvenc_status(label)
    }
}

fn static_windows_runtime_status(label: &str) -> (CapabilityStatus, String) {
    (
        CapabilityStatus::Supported,
        format!("{label} is platform-declared on Windows; runtime probe refresh is pending."),
    )
}

fn static_macos_runtime_status(label: &str) -> (CapabilityStatus, String) {
    (
        CapabilityStatus::Supported,
        format!("{label} is platform-declared on macOS; runtime probe refresh is pending."),
    )
}

fn unsupported_macos_status(label: &str) -> (CapabilityStatus, String) {
    (
        CapabilityStatus::Unsupported,
        format!("{label} is only supported on macOS in the current product mode."),
    )
}

fn macos_videotoolbox_h264_encode_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Macos) {
        return unsupported_macos_status("VideoToolbox H.264 encode");
    }

    match probe_mode {
        CapabilityProbeMode::Static => static_macos_runtime_status("VideoToolbox H.264 encode"),
        CapabilityProbeMode::Runtime => {
            #[cfg(target_os = "macos")]
            {
                static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
                RESULT
                    .get_or_init(|| {
                        classify_runtime_probe(
                            "VideoToolbox H.264 encode",
                            mrd_codec_videotoolbox::VideoToolboxH264Encoder::new(640, 480, 30)
                                .map(|_| ())
                                .map_err(|error| error.to_string()),
                        )
                    })
                    .clone()
            }

            #[cfg(not(target_os = "macos"))]
            {
                unsupported_macos_status("VideoToolbox H.264 encode")
            }
        }
    }
}

fn macos_videotoolbox_hevc_encode_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Macos) {
        return unsupported_macos_status("VideoToolbox HEVC encode");
    }

    match probe_mode {
        CapabilityProbeMode::Static => static_macos_runtime_status("VideoToolbox HEVC encode"),
        CapabilityProbeMode::Runtime => {
            #[cfg(target_os = "macos")]
            {
                static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
                RESULT
                    .get_or_init(|| {
                        classify_runtime_probe(
                            "VideoToolbox HEVC encode",
                            mrd_codec_videotoolbox::VideoToolboxHevcEncoder::new(640, 480, 30)
                                .map(|_| ())
                                .map_err(|error| error.to_string()),
                        )
                    })
                    .clone()
            }

            #[cfg(not(target_os = "macos"))]
            {
                unsupported_macos_status("VideoToolbox HEVC encode")
            }
        }
    }
}

fn macos_videotoolbox_h264_decode_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Macos) {
        return unsupported_macos_status("VideoToolbox H.264 decode");
    }

    match probe_mode {
        CapabilityProbeMode::Static => static_macos_runtime_status("VideoToolbox H.264 decode"),
        CapabilityProbeMode::Runtime => {
            if !videotoolbox_decoder_enabled() {
                return (
                    CapabilityStatus::Unsupported,
                    "VideoToolbox decode is disabled by MRD_DISABLE_VIDEOTOOLBOX_DECODER."
                        .to_string(),
                );
            }

            #[cfg(target_os = "macos")]
            {
                static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
                RESULT
                    .get_or_init(|| {
                        classify_runtime_probe(
                            "VideoToolbox H.264 decode",
                            mrd_codec_videotoolbox::VideoToolboxH264Decoder::new()
                                .map(|_| ())
                                .map_err(|error| error.to_string()),
                        )
                    })
                    .clone()
            }

            #[cfg(not(target_os = "macos"))]
            {
                unsupported_macos_status("VideoToolbox H.264 decode")
            }
        }
    }
}

fn macos_videotoolbox_hevc_decode_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Macos) {
        return unsupported_macos_status("VideoToolbox HEVC decode");
    }

    match probe_mode {
        CapabilityProbeMode::Static => static_macos_runtime_status("VideoToolbox HEVC decode"),
        CapabilityProbeMode::Runtime => {
            if !videotoolbox_decoder_enabled() {
                return (
                    CapabilityStatus::Unsupported,
                    "VideoToolbox decode is disabled by MRD_DISABLE_VIDEOTOOLBOX_DECODER."
                        .to_string(),
                );
            }

            #[cfg(target_os = "macos")]
            {
                static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
                RESULT
                    .get_or_init(|| {
                        classify_runtime_probe(
                            "VideoToolbox HEVC decode",
                            mrd_codec_videotoolbox::VideoToolboxHevcDecoder::new()
                                .map(|_| ())
                                .map_err(|error| error.to_string()),
                        )
                    })
                    .clone()
            }

            #[cfg(not(target_os = "macos"))]
            {
                unsupported_macos_status("VideoToolbox HEVC decode")
            }
        }
    }
}

fn macos_videotoolbox_decode_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Macos) {
        return unsupported_macos_status("VideoToolbox decode");
    }

    if matches!(probe_mode, CapabilityProbeMode::Static) {
        return static_macos_runtime_status("VideoToolbox H.264/HEVC decode");
    }

    let (h264_status, h264_reason) = macos_videotoolbox_h264_decode_status(platform, probe_mode);
    let (hevc_status, hevc_reason) = macos_videotoolbox_hevc_decode_status(platform, probe_mode);
    let h264_runs = capability_status_runs(&h264_status);
    let hevc_runs = capability_status_runs(&hevc_status);
    match (h264_runs, hevc_runs) {
        (true, true) => (
            CapabilityStatus::Available,
            "VideoToolbox H.264 and HEVC decode runtime probes succeeded.".to_string(),
        ),
        (true, false) => (
            CapabilityStatus::Degraded,
            format!(
                "VideoToolbox H.264 decode is available, but HEVC decode is not: {hevc_reason}"
            ),
        ),
        (false, true) => (
            CapabilityStatus::Degraded,
            format!(
                "VideoToolbox HEVC decode is available, but H.264 decode is not: {h264_reason}"
            ),
        ),
        (false, false)
            if matches!(&h264_status, CapabilityStatus::Unsupported)
                && matches!(&hevc_status, CapabilityStatus::Unsupported) =>
        {
            (
                CapabilityStatus::Unsupported,
                format!("{h264_reason}; {hevc_reason}"),
            )
        }
        (false, false) => (
            CapabilityStatus::DriverMissing,
            format!("{h264_reason}; {hevc_reason}"),
        ),
    }
}

fn macos_hevc_main_media_profile_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Macos) {
        return (
            CapabilityStatus::Supported,
            "HEVC Main 8-bit 4:2:0 is declared for this platform when paired with HEVC encoder and decoder capabilities."
                .to_string(),
        );
    }

    match probe_mode {
        CapabilityProbeMode::Static => (
            CapabilityStatus::Supported,
            "HEVC Main 8-bit 4:2:0 is platform-declared on macOS; runtime probe refresh is pending."
                .to_string(),
        ),
        CapabilityProbeMode::Runtime => {
            let (encode_status, encode_reason) =
                macos_videotoolbox_hevc_encode_status(platform, probe_mode);
            if capability_status_runs(&encode_status) {
                (
                    CapabilityStatus::Available,
                    "VideoToolbox HEVC encoder supports HEVC Main 8-bit 4:2:0.".to_string(),
                )
            } else {
                (encode_status, encode_reason)
            }
        }
    }
}

fn videotoolbox_decoder_enabled() -> bool {
    !matches!(
        std::env::var("MRD_DISABLE_VIDEOTOOLBOX_DECODER").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn probe_nvenc_h264_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(
        platform,
        CapabilityPlatform::Windows | CapabilityPlatform::Linux
    ) {
        return unsupported_nvenc_status("NVENC H.264");
    }

    #[cfg(any(windows, target_os = "linux"))]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVENC H.264",
                    mrd_encode_nvenc::NvencH264Encoder::probe_h264_available()
                        .map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        unsupported_nvenc_status("NVENC H.264")
    }
}

fn probe_nvenc_hevc_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(
        platform,
        CapabilityPlatform::Windows | CapabilityPlatform::Linux
    ) {
        return unsupported_nvenc_status("NVENC HEVC");
    }

    #[cfg(any(windows, target_os = "linux"))]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVENC HEVC",
                    mrd_encode_nvenc::NvencHevcEncoder::probe_hevc_available()
                        .map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        unsupported_nvenc_status("NVENC HEVC")
    }
}

fn probe_nvenc_hevc_main10_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(
        platform,
        CapabilityPlatform::Windows | CapabilityPlatform::Linux
    ) {
        return unsupported_nvenc_status("NVENC HEVC Main10");
    }

    #[cfg(any(windows, target_os = "linux"))]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVENC HEVC Main10",
                    mrd_encode_nvenc::NvencHevcEncoder::probe_hevc_main10_available()
                        .map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        unsupported_nvenc_status("NVENC HEVC Main10")
    }
}

fn nvenc_av1_status(
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Windows) {
        return unsupported_nvenc_status("NVENC AV1");
    }

    match probe_mode {
        CapabilityProbeMode::Static => static_windows_runtime_status("NVENC AV1"),
        CapabilityProbeMode::Runtime => probe_nvenc_av1_status(platform),
    }
}

fn probe_nvenc_av1_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Windows) {
        return unsupported_nvenc_status("NVENC AV1");
    }

    #[cfg(windows)]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVENC AV1",
                    mrd_encode_nvenc_av1::NvencAv1Encoder::probe_av1_available()
                        .map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(windows))]
    {
        unsupported_nvenc_status("NVENC AV1")
    }
}

fn unsupported_nvenc_status(label: &str) -> (CapabilityStatus, String) {
    (
        CapabilityStatus::Unsupported,
        format!("{label} is not supported on this platform in the current product mode."),
    )
}

fn probe_nvdec_h264_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Windows) {
        return (
            CapabilityStatus::Unimplemented,
            "NVDEC runtime probing is only wired for Windows in service-owned capability snapshots."
                .to_string(),
        );
    }

    #[cfg(windows)]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVDEC H.264",
                    mrd_decode_nvdec::probe_h264_available().map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(windows))]
    {
        (
            CapabilityStatus::Unimplemented,
            "NVDEC runtime probing is only compiled on Windows.".to_string(),
        )
    }
}

fn probe_nvdec_hevc_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Windows) {
        return (
            CapabilityStatus::Unimplemented,
            "NVDEC HEVC runtime probing is only wired for Windows in service-owned capability snapshots."
                .to_string(),
        );
    }

    #[cfg(windows)]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVDEC HEVC",
                    mrd_decode_nvdec::probe_hevc_available().map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(windows))]
    {
        (
            CapabilityStatus::Unimplemented,
            "NVDEC HEVC runtime probing is only compiled on Windows.".to_string(),
        )
    }
}

fn probe_nvdec_hevc_main10_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Windows) {
        return (
            CapabilityStatus::Unimplemented,
            "NVDEC HEVC Main10 runtime probing is only wired for Windows in service-owned capability snapshots."
                .to_string(),
        );
    }

    #[cfg(windows)]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                classify_runtime_probe(
                    "NVDEC HEVC Main10",
                    mrd_decode_nvdec::probe_hevc_main10_available()
                        .map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(windows))]
    {
        (
            CapabilityStatus::Unimplemented,
            "NVDEC HEVC Main10 runtime probing is only compiled on Windows.".to_string(),
        )
    }
}

fn probe_d3d11_render_status(platform: &CapabilityPlatform) -> (CapabilityStatus, String) {
    if !matches!(platform, CapabilityPlatform::Windows) {
        return (
            CapabilityStatus::Unimplemented,
            "D3D11 rendering is Windows-only.".to_string(),
        );
    }

    #[cfg(windows)]
    {
        static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
        RESULT
            .get_or_init(|| {
                use mrd_render::RendererFactory as _;
                classify_runtime_probe(
                    "D3D11 renderer",
                    mrd_render_d3d11::D3d11RendererFactory
                        .create()
                        .map(|_| ())
                        .map_err(|error| error.to_string()),
                )
            })
            .clone()
    }

    #[cfg(not(windows))]
    {
        (
            CapabilityStatus::Unimplemented,
            "D3D11 rendering is only compiled on Windows.".to_string(),
        )
    }
}

fn classify_runtime_probe(label: &str, result: Result<(), String>) -> (CapabilityStatus, String) {
    match result {
        Ok(()) => (
            CapabilityStatus::Available,
            format!("{label} runtime probe succeeded."),
        ),
        Err(error) => (
            CapabilityStatus::DriverMissing,
            format!("{label} runtime probe failed: {error}"),
        ),
    }
}

fn ffmpeg_tool_status(probe_mode: CapabilityProbeMode) -> (CapabilityStatus, String) {
    match probe_mode {
        CapabilityProbeMode::Static => (
            CapabilityStatus::Supported,
            "FFmpeg is optional tooling; runtime availability is determined by configured paths, managed install, or PATH."
                .to_string(),
        ),
        CapabilityProbeMode::Runtime => {
            static RESULT: OnceLock<(CapabilityStatus, String)> = OnceLock::new();
            RESULT
                .get_or_init(|| {
                    let probe = mrd_ffmpeg::probe_ffmpeg(&mrd_ffmpeg::golden_settings());
                    if probe.available {
                        (
                            CapabilityStatus::Available,
                            format!(
                                "FFmpeg probe succeeded with {} and {}.",
                                probe
                                    .ffmpeg_path
                                    .as_ref()
                                    .map(|path| path.display().to_string())
                                    .unwrap_or_else(|| "ffmpeg".to_string()),
                                probe
                                    .ffprobe_path
                                    .as_ref()
                                    .map(|path| path.display().to_string())
                                    .unwrap_or_else(|| "ffprobe".to_string())
                            ),
                        )
                    } else {
                        (
                            CapabilityStatus::DriverMissing,
                            probe.reason.unwrap_or_else(|| {
                                "FFmpeg tools were not found in configured paths or PATH."
                                    .to_string()
                            }),
                        )
                    }
                })
                .clone()
        }
    }
}

fn software_vvc_combined_status(probe_mode: CapabilityProbeMode) -> (CapabilityStatus, String) {
    let (encode_status, encode_reason) = software_vvc_encode_status(probe_mode);
    let (decode_status, decode_reason) = software_vvc_decode_status(probe_mode);
    if capability_status_runs(&encode_status) && capability_status_runs(&decode_status) {
        (
            CapabilityStatus::Supported,
            format!(
                "VVenC encode and VVdeC decode are feature-gated and available: {encode_reason}; {decode_reason}"
            ),
        )
    } else if !capability_status_runs(&encode_status) {
        (encode_status, encode_reason)
    } else {
        (decode_status, decode_reason)
    }
}

fn software_vvc_encode_status(probe_mode: CapabilityProbeMode) -> (CapabilityStatus, String) {
    #[cfg(not(feature = "production-vvc-software-codec"))]
    {
        let _ = probe_mode;
        (
            CapabilityStatus::Unimplemented,
            "H.266/VVC software encode requires mrd-service feature production-vvc-software-codec, mrd-encode-vvenc feature software-vvenc, and libvvenc >= 1.13.0."
                .to_string(),
        )
    }

    #[cfg(feature = "production-vvc-software-codec")]
    {
        match probe_mode {
            CapabilityProbeMode::Static => (
                CapabilityStatus::Supported,
                "H.266/VVC software encode is compiled through VVenC; runtime probe is pending."
                    .to_string(),
            ),
            CapabilityProbeMode::Runtime => {
                match mrd_encode_vvenc::probe_vvenc_software_encoder_available() {
                    Ok(()) => (
                        CapabilityStatus::Available,
                        "H.266/VVC software encode is available through VVenC.".to_string(),
                    ),
                    Err(error) => (
                        CapabilityStatus::DriverMissing,
                        format!(
                        "H.266/VVC software encode requires a working libvvenc runtime: {error}"
                    ),
                    ),
                }
            }
        }
    }
}

fn software_vvc_decode_status(probe_mode: CapabilityProbeMode) -> (CapabilityStatus, String) {
    if !cfg!(feature = "production-vvc-software-codec") {
        return (
            CapabilityStatus::Unimplemented,
            "H.266/VVC software decode requires mrd-service feature production-vvc-software-codec and mrd-decode feature software-vvdec."
                .to_string(),
        );
    }

    match probe_mode {
        CapabilityProbeMode::Static => (
            CapabilityStatus::Supported,
            "H.266/VVC software decode is compiled through VVdeC; runtime probe is pending."
                .to_string(),
        ),
        CapabilityProbeMode::Runtime => match mrd_decode::create_decoder("software_vvc") {
            Ok(_) => (
                CapabilityStatus::Available,
                "H.266/VVC software decode is available through VVdeC.".to_string(),
            ),
            Err(error) => (
                CapabilityStatus::DriverMissing,
                format!("H.266/VVC software decode requires a working VVdeC runtime: {error}"),
            ),
        },
    }
}

fn add_transport_capabilities(items: &mut Vec<CapabilityItem>, platform: &CapabilityPlatform) {
    for (id, label) in [
        ("transport.loopback", "In-process loopback"),
        ("transport.webrtc", "WebRTC RTP"),
        ("transport.quic", "QUIC"),
        ("transport.quic_datagram", "QUIC datagram media"),
        (
            "transport.media_profile_control_v1",
            "Media profile control v1",
        ),
        (
            "transport.capture_source_control_v1",
            "Capture source control v1",
        ),
    ] {
        push_available(items, platform, CapabilityDomain::Transport, id, label);
    }
}

fn add_control_capabilities(items: &mut Vec<CapabilityItem>, platform: &CapabilityPlatform) {
    if matches!(platform, CapabilityPlatform::Windows) {
        push_available(
            items,
            platform,
            CapabilityDomain::Control,
            "control.keyboard_mouse",
            "Keyboard and mouse control",
        );
    } else {
        push_item(
            items,
            platform,
            CapabilityDomain::Control,
            "control.keyboard_mouse",
            "Keyboard and mouse control",
            CapabilityStatus::Unsupported,
            Some("Input injection is currently implemented only for Windows SendInput."),
        );
    }
    let (remote_power_status, remote_power_reason) =
        remote_power_control_status_from_env_lookup(|key| std::env::var(key).ok());
    push_item(
        items,
        platform,
        CapabilityDomain::Control,
        "control.remote_power",
        "Remote restart and shutdown",
        remote_power_status,
        Some(remote_power_reason.as_str()),
    );
}

fn remote_power_control_status_from_env_lookup<E>(env_lookup: E) -> (CapabilityStatus, String)
where
    E: Fn(&str) -> Option<String>,
{
    let _legacy_environment_lookup = env_lookup;
    (
        CapabilityStatus::Unsupported,
        "Legacy unsigned LAN remote power control is disabled; remote power requires signed authorization."
            .to_string(),
    )
}

fn add_audio_capabilities(items: &mut Vec<CapabilityItem>, platform: &CapabilityPlatform) {
    push_item(
        items,
        platform,
        CapabilityDomain::Audio,
        "audio.system",
        "System audio",
        CapabilityStatus::Unimplemented,
        Some("Audio capture/playback is outside the current media pipeline."),
    );
}

fn add_service_capabilities(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    probe_mode: CapabilityProbeMode,
) {
    push_available(
        items,
        platform,
        CapabilityDomain::Service,
        "service.ipc",
        "Local IPC",
    );
    push_available(
        items,
        platform,
        CapabilityDomain::Service,
        "service.lan_discovery",
        "LAN discovery",
    );
    push_supported(
        items,
        platform,
        CapabilityDomain::Service,
        "service.tray",
        "Service tray",
        "Tray availability depends on the active desktop environment.",
    );
    push_supported(
        items,
        platform,
        CapabilityDomain::Service,
        "service.autostart",
        "Autostart",
        "Autostart support is provided by platform shell adapters.",
    );
    push_available(
        items,
        platform,
        CapabilityDomain::Service,
        "service.file_transfer.local",
        "Local file transfer",
    );
    push_item(
        items,
        platform,
        CapabilityDomain::Service,
        "service.file_transfer.external_bridge",
        "External file transfer bridge",
        CapabilityStatus::Unimplemented,
        Some(
            "Reserved for R-File provider integration; MRD currently keeps service-owned local copy/list/cancel as the active path.",
        ),
    );
    if matches!(
        platform,
        CapabilityPlatform::Windows | CapabilityPlatform::Linux | CapabilityPlatform::Macos
    ) {
        let (status, reason) = if matches!(platform, CapabilityPlatform::Macos) {
            macos_hevc_main_media_profile_status(platform, probe_mode)
        } else {
            (
                CapabilityStatus::Supported,
                "HEVC Main 8-bit 4:2:0 is the default LAN high-performance profile when encoder and decoder probes pass."
                    .to_string(),
            )
        };
        push_item(
            items,
            platform,
            CapabilityDomain::Service,
            "media.hevc_main_420_8bit",
            "HEVC Main 8-bit 4:2:0",
            status,
            Some(reason.as_str()),
        );
    }
    if matches!(platform, CapabilityPlatform::Windows) {
        push_supported(
            items,
            platform,
            CapabilityDomain::Service,
            "media.hevc_main10_420_10bit",
            "HEVC Main10 10-bit 4:2:0",
            "LAN HEVC Main10 profile metadata; NVENC Main10 encode and Main10 decode probes still gate runtime use.",
        );
        push_supported(
            items,
            platform,
            CapabilityDomain::Service,
            "media.color_mode_v1",
            "GPU color mode transform",
            "LAN color mode profile metadata and GPU-side transform contract for full, grayscale, monochrome, and low-chroma modes.",
        );
    }
    let (ffmpeg_status, ffmpeg_reason) = ffmpeg_tool_status(probe_mode);
    push_item(
        items,
        platform,
        CapabilityDomain::Service,
        "service.ffmpeg",
        "FFmpeg tools",
        ffmpeg_status,
        Some(ffmpeg_reason.as_str()),
    );
}

fn add_security_capabilities(items: &mut Vec<CapabilityItem>, platform: &CapabilityPlatform) {
    push_available(
        items,
        platform,
        CapabilityDomain::Security,
        "security.quic_tls",
        "QUIC TLS",
    );
    push_supported(
        items,
        platform,
        CapabilityDomain::Security,
        "security.consent",
        "Session consent",
        "Consent and pairing UX are still being migrated into service-owned flows.",
    );
}

fn default_constraints() -> Vec<CapabilityConstraint> {
    vec![
        CapabilityConstraint {
            id: "openh264_requires_cpu_input".to_string(),
            applies_to: vec![
                "encode.openh264".to_string(),
                "memory.d3d11_shared".to_string(),
            ],
            status: CapabilityConstraintStatus::RequiresCopy,
            reason: "OpenH264 requires CPU-backed input unless an explicit copy step is inserted."
                .to_string(),
            fallback_ids: vec!["memory.cpu".to_string()],
        },
        CapabilityConstraint {
            id: "d3d12_probe_only".to_string(),
            applies_to: vec!["render.d3d12_native".to_string()],
            status: CapabilityConstraintStatus::Block,
            reason: "D3D12 native renderer is probe-only and not wired as mainline display."
                .to_string(),
            fallback_ids: vec!["render.d3d11".to_string(), "render.webview".to_string()],
        },
        CapabilityConstraint {
            id: "opengl_d3d11_shared_interop_hybrid".to_string(),
            applies_to: vec![
                "render.opengl".to_string(),
                "memory.d3d11_shared".to_string(),
            ],
            status: CapabilityConstraintStatus::Degrade,
            reason: "OpenGL accepts D3D11 shared NV12 through WGL/DX interop when available and readback fallback otherwise; D3D11 native remains preferred for parity."
                .to_string(),
            fallback_ids: vec!["render.d3d11".to_string()],
        },
        CapabilityConstraint {
            id: "webview_degraded_render".to_string(),
            applies_to: vec!["render.webview".to_string()],
            status: CapabilityConstraintStatus::Degrade,
            reason: "WebView render is a visual fallback, not native renderer parity.".to_string(),
            fallback_ids: Vec::new(),
        },
    ]
}

fn default_profiles() -> Vec<CapabilityProfile> {
    vec![
        profile(
            "smoke.720p30",
            1280,
            720,
            30,
            8,
            "h264",
            vec!["transport.loopback", "encode.openh264", "decode.software"],
        ),
        profile(
            "interactive.1080p60",
            1920,
            1080,
            60,
            20,
            "hevc",
            vec![
                "encode.nvenc_hevc",
                "decode.nvdec_hevc",
                "media.hevc_main_420_8bit",
                "render.d3d11",
                "memory.d3d11_shared",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "compat.h264.1080p60",
            1920,
            1080,
            60,
            20,
            "h264",
            vec![
                "encode.nvenc_h264",
                "decode.nvdec",
                "render.d3d11",
                "memory.d3d11_shared",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "lan.2k144",
            2560,
            1440,
            144,
            64,
            "hevc",
            vec![
                "encode.nvenc_hevc",
                "decode.nvdec_hevc",
                "media.hevc_main_420_8bit",
                "render.d3d11",
                "memory.d3d11_shared",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "lan.2k144.main10",
            2560,
            1440,
            144,
            80,
            "hevc",
            vec![
                "encode.nvenc_hevc_main10",
                "decode.nvdec_hevc_main10",
                "media.hevc_main10_420_10bit",
                "render.d3d11",
                "memory.d3d11_shared",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "lan.macos.2k144",
            2560,
            1440,
            144,
            80,
            "h264",
            vec![
                "capture.macos",
                "encode.videotoolbox_h264",
                "decode.videotoolbox_h264",
                "memory.cpu",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "lan.macos.hevc.2k144",
            2560,
            1440,
            144,
            40,
            "hevc",
            vec![
                "capture.macos",
                "encode.videotoolbox_hevc",
                "decode.videotoolbox_hevc",
                "media.hevc_main_420_8bit",
                "memory.cpu",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "lan.1600p165",
            2560,
            1600,
            165,
            80,
            "hevc",
            vec![
                "encode.nvenc_hevc",
                "decode.nvdec_hevc",
                "media.hevc_main_420_8bit",
                "render.d3d11",
                "memory.d3d11_shared",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "quality.4k60",
            3840,
            2160,
            60,
            80,
            "hevc",
            vec![
                "encode.nvenc_hevc",
                "decode.nvdec_hevc",
                "media.hevc_main_420_8bit",
                "render.d3d11",
                "memory.d3d11_shared",
                "transport.quic_datagram",
                "transport.media_profile_control_v1",
            ],
        ),
        profile(
            "diagnostic.software",
            1280,
            720,
            30,
            6,
            "h264",
            vec![
                "capture.synthetic",
                "encode.openh264",
                "decode.software",
                "render.webview",
            ],
        ),
    ]
}

fn profile(
    id: &str,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_mbps: u32,
    codec: &str,
    required_capabilities: Vec<&str>,
) -> CapabilityProfile {
    let metadata = default_profile_media_metadata(id, codec);
    CapabilityProfile {
        id: id.to_string(),
        width,
        height,
        fps,
        bitrate_mbps,
        codec: codec.to_string(),
        codec_profile: metadata.codec_profile,
        bit_depth: metadata.bit_depth,
        chroma_subsampling: metadata.chroma_subsampling,
        pixel_format: metadata.pixel_format,
        hdr_enabled: metadata.hdr_enabled,
        color_mode: metadata.color_mode,
        color_pipeline: metadata.color_pipeline,
        latency_budget_ms: None,
        min_stable_fps_ratio: Some(0.8),
        max_drop_ratio: Some(0.02),
        required_capabilities: required_capabilities
            .into_iter()
            .map(ToString::to_string)
            .collect(),
    }
}

struct CapabilityProfileMediaMetadata {
    codec_profile: Option<String>,
    bit_depth: Option<u8>,
    chroma_subsampling: Option<String>,
    pixel_format: Option<String>,
    hdr_enabled: Option<bool>,
    color_mode: Option<String>,
    color_pipeline: Option<String>,
}

fn default_profile_media_metadata(id: &str, codec: &str) -> CapabilityProfileMediaMetadata {
    let normalized_codec = codec.trim().to_ascii_lowercase().replace('.', "");
    let requests_main10 = id.to_ascii_lowercase().contains("main10");
    if (normalized_codec == "hevc" || normalized_codec == "h265") && requests_main10 {
        return CapabilityProfileMediaMetadata {
            codec_profile: Some("main10".to_string()),
            bit_depth: Some(10),
            chroma_subsampling: Some("4:2:0".to_string()),
            pixel_format: Some("p010".to_string()),
            hdr_enabled: Some(true),
            color_mode: Some("full".to_string()),
            color_pipeline: Some("hdr_main10".to_string()),
        };
    }

    match normalized_codec.as_str() {
        "hevc" | "h265" => CapabilityProfileMediaMetadata {
            codec_profile: Some("main".to_string()),
            bit_depth: Some(8),
            chroma_subsampling: Some("4:2:0".to_string()),
            pixel_format: Some("nv12".to_string()),
            hdr_enabled: Some(false),
            color_mode: Some("full".to_string()),
            color_pipeline: Some("sdr8".to_string()),
        },
        "h264" | "av1" => CapabilityProfileMediaMetadata {
            codec_profile: Some("main".to_string()),
            bit_depth: Some(8),
            chroma_subsampling: Some("4:2:0".to_string()),
            pixel_format: Some("nv12".to_string()),
            hdr_enabled: Some(false),
            color_mode: Some("full".to_string()),
            color_pipeline: Some("sdr8".to_string()),
        },
        _ => CapabilityProfileMediaMetadata {
            codec_profile: None,
            bit_depth: None,
            chroma_subsampling: None,
            pixel_format: None,
            hdr_enabled: None,
            color_mode: None,
            color_pipeline: None,
        },
    }
}

fn push_available(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    domain: CapabilityDomain,
    id: &str,
    label: &str,
) {
    push_item(
        items,
        platform,
        domain,
        id,
        label,
        CapabilityStatus::Available,
        None,
    );
}

fn push_supported(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    domain: CapabilityDomain,
    id: &str,
    label: &str,
    reason: &str,
) {
    push_item(
        items,
        platform,
        domain,
        id,
        label,
        CapabilityStatus::Supported,
        Some(reason),
    );
}

fn push_degraded(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    domain: CapabilityDomain,
    id: &str,
    label: &str,
    reason: &str,
) {
    push_item(
        items,
        platform,
        domain,
        id,
        label,
        CapabilityStatus::Degraded,
        Some(reason),
    );
}

fn push_item(
    items: &mut Vec<CapabilityItem>,
    platform: &CapabilityPlatform,
    domain: CapabilityDomain,
    id: &str,
    label: &str,
    status: CapabilityStatus,
    reason: Option<&str>,
) {
    items.push(CapabilityItem {
        id: id.to_string(),
        domain,
        label: label.to_string(),
        status,
        platform: platform.clone(),
        reason: reason.map(ToString::to_string),
        detail: None,
        requires: Vec::new(),
        conflicts_with: Vec::new(),
        depends_on: Vec::new(),
        fallback_ids: Vec::new(),
        last_probe_time_ms: None,
    });
}

fn current_platform() -> CapabilityPlatform {
    if cfg!(windows) {
        CapabilityPlatform::Windows
    } else if cfg!(target_os = "macos") {
        CapabilityPlatform::Macos
    } else if cfg!(target_os = "linux") {
        CapabilityPlatform::Linux
    } else {
        CapabilityPlatform::Unknown
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_includes_platform_domains_and_profiles() {
        let snapshot = local_capability_snapshot();

        assert_eq!(snapshot.schema_version, 1);
        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "transport.quic_datagram"));
        assert!(snapshot
            .profiles
            .iter()
            .any(|profile| profile.id == "lan.2k144"));
        assert!(snapshot
            .profiles
            .iter()
            .any(|profile| profile.id == "lan.1600p165"));
        let interactive = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "interactive.1080p60")
            .expect("interactive.1080p60 profile");
        assert_eq!(interactive.codec, "hevc");
        assert!(interactive
            .required_capabilities
            .contains(&"encode.nvenc_hevc".to_string()));
        assert!(snapshot
            .profiles
            .iter()
            .any(|profile| profile.id == "compat.h264.1080p60" && profile.codec == "h264"));
        assert!(snapshot
            .constraints
            .iter()
            .any(|constraint| constraint.id == "openh264_requires_cpu_input"));
        let openh264_constraint = snapshot
            .constraints
            .iter()
            .find(|constraint| constraint.id == "openh264_requires_cpu_input")
            .expect("OpenH264 CPU input constraint");
        assert_eq!(
            openh264_constraint.status,
            CapabilityConstraintStatus::RequiresCopy
        );
        assert!(snapshot
            .constraints
            .iter()
            .any(|constraint| constraint.id == "opengl_d3d11_shared_interop_hybrid"));
        #[cfg(windows)]
        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "render.opengl"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_exposes_hevc_decode_and_profiles() {
        let snapshot = local_capability_snapshot_static();

        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "decode.nvdec_hevc"));
        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "decode.nvdec_hevc_main10"));

        let lan_2k144 = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "lan.2k144")
            .expect("lan.2k144 profile");
        assert_eq!(lan_2k144.codec, "hevc");
        assert!(lan_2k144
            .required_capabilities
            .contains(&"encode.nvenc_hevc".to_string()));
        assert!(lan_2k144
            .required_capabilities
            .contains(&"decode.nvdec_hevc".to_string()));
        assert!(lan_2k144
            .required_capabilities
            .contains(&"render.d3d11".to_string()));
        assert!(lan_2k144
            .required_capabilities
            .contains(&"memory.d3d11_shared".to_string()));
    }

    #[test]
    fn static_snapshot_includes_optional_ffmpeg_capabilities() {
        let snapshot = local_capability_snapshot_static();

        let service = snapshot
            .capabilities
            .iter()
            .find(|item| item.id == "service.ffmpeg")
            .expect("service.ffmpeg capability");
        assert!(matches!(
            service.status,
            CapabilityStatus::Supported | CapabilityStatus::Degraded
        ));

        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "decode.ffmpeg_h264"));
        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "decode.ffmpeg_hevc"));
        assert!(snapshot
            .capabilities
            .iter()
            .any(|item| item.id == "decode.ffmpeg_vvc"));
    }

    #[test]
    fn static_snapshot_reserves_file_transfer_provider_capabilities() {
        let snapshot = local_capability_snapshot_static();

        let local = snapshot
            .capabilities
            .iter()
            .find(|item| item.id == "service.file_transfer.local")
            .expect("local file transfer capability");
        assert_eq!(local.status, CapabilityStatus::Available);

        let external_bridge = snapshot
            .capabilities
            .iter()
            .find(|item| item.id == "service.file_transfer.external_bridge")
            .expect("external file transfer bridge reservation");
        assert_eq!(external_bridge.status, CapabilityStatus::Unimplemented);
        assert!(external_bridge
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("R-File"));
    }

    #[test]
    fn remote_power_control_capability_rejects_legacy_env_opt_in() {
        let disabled = remote_power_control_status_from_env_lookup(|_| None);
        assert_eq!(disabled.0, CapabilityStatus::Unsupported);
        assert!(disabled.1.contains("signed authorization"));

        let enabled = remote_power_control_status_from_env_lookup(|key| match key {
            "MRD_ENABLE_REMOTE_POWER_ACTIONS" => Some("yes".to_string()),
            _ => None,
        });
        assert_eq!(enabled.0, CapabilityStatus::Unsupported);
        assert_eq!(enabled.1, disabled.1);
    }

    #[test]
    fn local_snapshot_advertises_remote_power_control_capability() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Windows, CapabilityProbeMode::Static);
        let remote_power = capabilities
            .iter()
            .find(|item| item.id == "control.remote_power")
            .expect("remote power control capability");

        assert_eq!(remote_power.domain, CapabilityDomain::Control);
        assert_eq!(remote_power.status, CapabilityStatus::Unsupported);
        assert!(remote_power
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("signed authorization")));
    }

    #[test]
    fn macos_videotoolbox_decode_is_advertised_for_lan_receiver_path() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Macos, CapabilityProbeMode::Static);
        for id in [
            "decode.videotoolbox",
            "decode.videotoolbox_h264",
            "decode.videotoolbox_hevc",
        ] {
            let decode = capabilities
                .iter()
                .find(|item| item.id == id)
                .expect("macOS VideoToolbox decode capability");

            assert_eq!(decode.status, CapabilityStatus::Supported);
        }
    }

    #[test]
    fn macos_videotoolbox_hevc_encode_is_advertised_for_lan_sender_path() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Macos, CapabilityProbeMode::Static);
        let encode = capabilities
            .iter()
            .find(|item| item.id == "encode.videotoolbox_hevc")
            .expect("macOS VideoToolbox HEVC encode capability");

        assert_eq!(encode.status, CapabilityStatus::Supported);
    }

    #[test]
    fn macos_hevc_main_media_profile_capability_is_advertised() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Macos, CapabilityProbeMode::Static);
        let media = capabilities
            .iter()
            .find(|item| item.id == "media.hevc_main_420_8bit")
            .expect("macOS HEVC Main 8-bit 4:2:0 media capability");

        assert_eq!(media.status, CapabilityStatus::Supported);
    }

    #[test]
    fn windows_color_and_main10_media_profile_capabilities_are_advertised() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Windows, CapabilityProbeMode::Static);

        let color = capabilities
            .iter()
            .find(|item| item.id == "media.color_mode_v1")
            .expect("LAN color mode media capability");
        let main10 = capabilities
            .iter()
            .find(|item| item.id == "media.hevc_main10_420_10bit")
            .expect("HEVC Main10 10-bit 4:2:0 media capability");

        assert_eq!(color.status, CapabilityStatus::Supported);
        assert_eq!(main10.status, CapabilityStatus::Supported);
    }

    #[test]
    fn snapshot_exposes_lan_2k144_main10_profile() {
        let snapshot = local_capability_snapshot_static();

        let profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "lan.2k144.main10")
            .expect("lan.2k144.main10 profile");

        assert_eq!(profile.width, 2560);
        assert_eq!(profile.height, 1440);
        assert_eq!(profile.fps, 144);
        assert_eq!(profile.bitrate_mbps, 80);
        assert_eq!(profile.codec, "hevc");
        assert_eq!(profile.codec_profile.as_deref(), Some("main10"));
        assert_eq!(profile.bit_depth, Some(10));
        assert_eq!(profile.chroma_subsampling.as_deref(), Some("4:2:0"));
        assert_eq!(profile.pixel_format.as_deref(), Some("p010"));
        assert_eq!(profile.hdr_enabled, Some(true));
        assert_eq!(profile.color_mode.as_deref(), Some("full"));
        assert_eq!(profile.color_pipeline.as_deref(), Some("hdr_main10"));
        assert_eq!(
            profile.required_capabilities,
            vec![
                "encode.nvenc_hevc_main10".to_string(),
                "decode.nvdec_hevc_main10".to_string(),
                "media.hevc_main10_420_10bit".to_string(),
                "render.d3d11".to_string(),
                "memory.d3d11_shared".to_string(),
                "transport.quic_datagram".to_string(),
                "transport.media_profile_control_v1".to_string(),
            ]
        );
    }

    #[test]
    fn scenario_evaluation_preserves_lan_2k144_main10_media_metadata() {
        let snapshot = CapabilitySnapshot {
            schema_version: SCHEMA_VERSION,
            platform: CapabilityPlatform::Windows,
            service_version: "test".to_string(),
            capabilities: local_capabilities(
                CapabilityPlatform::Windows,
                CapabilityProbeMode::Static,
            ),
            constraints: default_constraints(),
            profiles: default_profiles(),
            updated_at_ms: 1,
        };

        let evaluation =
            evaluate_scenario_profile_against_snapshot(&snapshot, "lan.2k144.main10", None);
        let selected = evaluation
            .selected_profile
            .expect("lan.2k144.main10 selected media profile");

        assert_eq!(selected.width, 2560);
        assert_eq!(selected.height, 1440);
        assert_eq!(selected.fps, 144);
        assert_eq!(selected.bitrate_mbps, 80);
        assert_eq!(selected.codec, "hevc");
        assert_eq!(selected.codec_profile.as_deref(), Some("main10"));
        assert_eq!(selected.bit_depth, Some(10));
        assert_eq!(selected.chroma_subsampling.as_deref(), Some("4:2:0"));
        assert_eq!(selected.pixel_format.as_deref(), Some("p010"));
        assert_eq!(selected.hdr_enabled, Some(true));
        assert_eq!(selected.color_mode.as_deref(), Some("full"));
        assert_eq!(selected.color_pipeline.as_deref(), Some("hdr_main10"));
    }

    #[test]
    fn macos_snapshot_exposes_native_2k144_profile() {
        let snapshot = local_capability_snapshot_static();

        let profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "lan.macos.2k144")
            .expect("lan.macos.2k144 profile");

        assert_eq!(profile.width, 2560);
        assert_eq!(profile.height, 1440);
        assert_eq!(profile.fps, 144);
        assert_eq!(profile.bitrate_mbps, 80);
        assert_eq!(profile.codec, "h264");
        assert!(profile
            .required_capabilities
            .contains(&"capture.macos".to_string()));
        assert!(profile
            .required_capabilities
            .contains(&"encode.videotoolbox_h264".to_string()));
        assert!(profile
            .required_capabilities
            .contains(&"decode.videotoolbox_h264".to_string()));
        assert!(!profile
            .required_capabilities
            .contains(&"decode.videotoolbox_hevc".to_string()));
        assert!(!profile
            .required_capabilities
            .contains(&"render.macos".to_string()));
    }

    #[test]
    fn macos_snapshot_exposes_native_hevc_2k144_profile() {
        let snapshot = local_capability_snapshot_static();

        let profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "lan.macos.hevc.2k144")
            .expect("lan.macos.hevc.2k144 profile");

        assert_eq!(profile.width, 2560);
        assert_eq!(profile.height, 1440);
        assert_eq!(profile.fps, 144);
        assert_eq!(profile.bitrate_mbps, 40);
        assert_eq!(profile.codec, "hevc");
        assert!(profile
            .required_capabilities
            .contains(&"encode.videotoolbox_hevc".to_string()));
        assert!(profile
            .required_capabilities
            .contains(&"decode.videotoolbox_hevc".to_string()));
        assert!(!profile
            .required_capabilities
            .contains(&"decode.videotoolbox_h264".to_string()));
        assert!(profile
            .required_capabilities
            .contains(&"media.hevc_main_420_8bit".to_string()));
        assert!(!profile
            .required_capabilities
            .contains(&"encode.nvenc_hevc".to_string()));
        assert!(!profile
            .required_capabilities
            .contains(&"render.d3d11".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_runtime_videotoolbox_capabilities_follow_runtime_probes() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Macos, CapabilityProbeMode::Runtime);
        let status_runs = |id: &str| {
            let item = capabilities
                .iter()
                .find(|item| item.id == id)
                .unwrap_or_else(|| panic!("missing capability {id}"));
            capability_status_runs(&item.status)
        };
        let h264_encode =
            mrd_codec_videotoolbox::VideoToolboxH264Encoder::new(640, 480, 30).is_ok();
        let hevc_encode =
            mrd_codec_videotoolbox::VideoToolboxHevcEncoder::new(640, 480, 30).is_ok();
        let h264_decode = videotoolbox_decoder_enabled()
            && mrd_codec_videotoolbox::VideoToolboxH264Decoder::new().is_ok();
        let hevc_decode = videotoolbox_decoder_enabled()
            && mrd_codec_videotoolbox::VideoToolboxHevcDecoder::new().is_ok();

        assert_eq!(status_runs("encode.videotoolbox_h264"), h264_encode);
        assert_eq!(status_runs("encode.videotoolbox_hevc"), hevc_encode);
        assert_eq!(status_runs("decode.videotoolbox_h264"), h264_decode);
        assert_eq!(status_runs("decode.videotoolbox_hevc"), hevc_decode);
        assert_eq!(status_runs("media.hevc_main_420_8bit"), hevc_encode);
    }

    #[test]
    fn wired_nvenc_av1_is_advertised_as_static_supported() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Windows, CapabilityProbeMode::Static);
        let av1 = capabilities
            .iter()
            .find(|item| item.id == "encode.nvenc_av1")
            .expect("NVENC AV1 capability");

        assert_eq!(av1.status, CapabilityStatus::Supported);
        assert!(av1
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("runtime probe refresh is pending"));
    }

    #[test]
    fn h266_software_codec_paths_are_not_advertised_as_runnable() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Windows, CapabilityProbeMode::Static);
        let encode = capabilities
            .iter()
            .find(|item| item.id == "encode.software_vvc")
            .expect("software VVC encode capability");
        let decode = capabilities
            .iter()
            .find(|item| item.id == "decode.software_vvc")
            .expect("software VVC decode capability");

        assert_eq!(encode.status, CapabilityStatus::Unimplemented);
        assert_eq!(decode.status, CapabilityStatus::Unimplemented);
    }

    #[test]
    fn h266_peer_media_capabilities_are_not_advertised_as_runnable() {
        let peer = LanPeerInfo {
            device_id: mrd_proto::DeviceId("peer-vvc".to_string()),
            device_name: "peer".to_string(),
            device_type: "desktop".to_string(),
            ip: "127.0.0.1".to_string(),
            discovery_port: 0,
            p2p_control_addr: "127.0.0.1:0".to_string(),
            transports: vec!["quic".to_string()],
            protocol_version: 1,
            service_build_id: Some("test".to_string()),
            media_protocol_version: Some(3),
            media_capabilities: vec![
                "encode.software_vvc".to_string(),
                "decode.software_h266".to_string(),
            ],
            mac_address: None,
            age_ms: 0,
            p2p_available: true,
        };

        let snapshot = peer_capability_snapshot(&peer);
        let encode = snapshot
            .capabilities
            .iter()
            .find(|item| item.id == "encode.software_vvc")
            .expect("peer software VVC encode capability");
        let decode = snapshot
            .capabilities
            .iter()
            .find(|item| item.id == "decode.software_h266")
            .expect("peer software H.266 decode capability");

        assert_eq!(encode.status, CapabilityStatus::Unimplemented);
        assert_eq!(decode.status, CapabilityStatus::Unimplemented);
    }

    #[test]
    fn keyboard_mouse_control_is_available_on_windows_static_snapshot() {
        let capabilities =
            local_capabilities(CapabilityPlatform::Windows, CapabilityProbeMode::Static);
        let control = capabilities
            .iter()
            .find(|item| item.id == "control.keyboard_mouse")
            .expect("keyboard/mouse control capability");

        assert_eq!(control.status, CapabilityStatus::Available);
    }

    #[test]
    fn default_profiles_do_not_require_ffmpeg() {
        let snapshot = local_capability_snapshot_static();

        assert!(snapshot.profiles.iter().all(|profile| profile
            .required_capabilities
            .iter()
            .all(|id| !id.contains("ffmpeg"))));
    }
}
