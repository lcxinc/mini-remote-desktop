// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unexpected_cfgs)]
#![allow(clippy::incompatible_msrv)]

mod app_settings;
#[cfg(test)]
mod benchmark;
mod device_info;
mod frame_sink;
mod ipc_client;
mod platform;
#[cfg(test)]
mod quic_host;
#[cfg(test)]
mod quic_transport_harness;
mod remote_display_surface;
#[cfg(test)]
mod render_host;
mod render_probe;
mod render_proxy;
mod render_window_registry;
mod resource_monitor;
mod service_manager;
mod test_harness;
mod test_orchestrator;
mod webrtc_host;
mod webrtc_media;

use app_settings::{
    default_settings_path, load_settings, save_settings, AppSettings, DecodePolicy,
};
use device_info::HardwareInfo;
use mrd_pipeline_core::VideoCodec;
use mrd_proto::SessionId;
use remote_display_surface::{
    NativeRenderSurfaceSnapshot, NativeSurfaceControlFrameSize, NativeSurfaceRect,
    RemoteDisplaySurfaceManager,
};
use render_window_registry::{
    NativeSurfaceServiceAction, PendingRenderWindow, RenderWindowContext, RenderWindowRegistry,
};
use resource_monitor::{ResourceMonitor, SystemResourceSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    webview::PageLoadEvent,
    AppHandle, Manager, PhysicalPosition, WebviewWindow, WebviewWindowBuilder,
};

const TRAY_ICON_ID: &str = "rdesk-tray";
const TRAY_MENU_SHOW_ID: &str = "rdesk-tray-show";
const TRAY_MENU_HIDE_ID: &str = "rdesk-tray-hide";
const TRAY_MENU_CENTER_ID: &str = "rdesk-tray-center";
const TRAY_MENU_QUIT_ID: &str = "rdesk-tray-quit";
const SINGLE_INSTANCE_ADDR: &str = "127.0.0.1:47631";
const RDESK_SINGLE_INSTANCE_ADDR_ENV: &str = "MRD_RDESK_SINGLE_INSTANCE_ADDR";
const LAN_E2E_AUTORUN_ENV: &str = "MRD_LAN_E2E_AUTORUN";
const LAN_E2E_SCENARIO_ENV: &str = "MRD_LAN_E2E_SCENARIO";
const LAN_E2E_TARGET_DEVICE_ID_ENV: &str = "MRD_LAN_E2E_TARGET_DEVICE_ID";
const LAN_E2E_TRANSPORT_ENV: &str = "MRD_LAN_E2E_TRANSPORT";
const LAN_E2E_TIMEOUT_MS_ENV: &str = "MRD_LAN_E2E_TIMEOUT_MS";
const LAN_E2E_MIN_SAMPLE_DURATION_MS_ENV: &str = "MRD_LAN_E2E_MIN_SAMPLE_DURATION_MS";
const LAN_E2E_MIN_DECODED_FRAMES_ENV: &str = "MRD_LAN_E2E_MIN_DECODED_FRAMES";
const LAN_E2E_MIN_FPS_ENV: &str = "MRD_LAN_E2E_MIN_FPS";
const LAN_E2E_MIN_RENDER_FPS_ENV: &str = "MRD_LAN_E2E_MIN_RENDER_FPS";
const LAN_E2E_STOP_ON_COMPLETE_ENV: &str = "MRD_LAN_E2E_STOP_ON_COMPLETE";
const LAN_E2E_REPORT_PATH_ENV: &str = "MRD_LAN_E2E_REPORT_PATH";
const LAN_E2E_PROFILE_WIDTH_ENV: &str = "MRD_LAN_E2E_PROFILE_WIDTH";
const LAN_E2E_PROFILE_HEIGHT_ENV: &str = "MRD_LAN_E2E_PROFILE_HEIGHT";
const LAN_E2E_PROFILE_FPS_ENV: &str = "MRD_LAN_E2E_PROFILE_FPS";
const LAN_E2E_PROFILE_BITRATE_MBPS_ENV: &str = "MRD_LAN_E2E_PROFILE_BITRATE_MBPS";
const LAN_E2E_PROFILE_CODEC_ENV: &str = "MRD_LAN_E2E_PROFILE_CODEC";
const LAN_E2E_PROFILE_CODEC_PROFILE_ENV: &str = "MRD_LAN_E2E_PROFILE_CODEC_PROFILE";
const LAN_E2E_PROFILE_BIT_DEPTH_ENV: &str = "MRD_LAN_E2E_PROFILE_BIT_DEPTH";
const LAN_E2E_PROFILE_CHROMA_SUBSAMPLING_ENV: &str = "MRD_LAN_E2E_PROFILE_CHROMA_SUBSAMPLING";
const LAN_E2E_PROFILE_PIXEL_FORMAT_ENV: &str = "MRD_LAN_E2E_PROFILE_PIXEL_FORMAT";
const LAN_E2E_PROFILE_HDR_ENABLED_ENV: &str = "MRD_LAN_E2E_PROFILE_HDR_ENABLED";
const LAN_E2E_PROFILE_COLOR_MODE_ENV: &str = "MRD_LAN_E2E_PROFILE_COLOR_MODE";
const LAN_E2E_PROFILE_COLOR_PIPELINE_ENV: &str = "MRD_LAN_E2E_PROFILE_COLOR_PIPELINE";
const LAN_E2E_DISPLAY_MODE_POLICY_ENV: &str = "MRD_LAN_E2E_DISPLAY_MODE_POLICY";
const LAN_E2E_CAPTURE_SOURCE_ID_ENV: &str = "MRD_LAN_E2E_CAPTURE_SOURCE_ID";
const LAN_E2E_CAPTURE_SOURCE_KIND_ENV: &str = "MRD_LAN_E2E_CAPTURE_SOURCE_KIND";
const LAN_E2E_RENDER_DISPLAY_SOURCE_ID_ENV: &str = "MRD_LAN_E2E_RENDER_DISPLAY_SOURCE_ID";
const LAN_E2E_EXPECTED_PEER_BUILD_ID_ENV: &str = "MRD_LAN_E2E_EXPECTED_PEER_BUILD_ID";
const LAN_E2E_RENDER_PROFILE_CAP_ENV: &str = "MRD_LAN_E2E_RENDER_PROFILE_CAP";
const LAN_E2E_RENDER_DISPLAY_ENV: &str = "MRD_LAN_E2E_RENDER_DISPLAY";
const LAN_E2E_ADAPTIVE_ENV: &str = "MRD_LAN_E2E_ADAPTIVE";
const MAINLINE_E2E_ARTIFACT_ROOT_ENV: &str = "MRD_E2E_ARTIFACT_ROOT";
const MAINLINE_E2E_ARTIFACT_KIND: &str = "mainline_e2e_artifacts_v1";

static APP_IS_QUITTING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayAction {
    ShowWindow,
    HideWindow,
    CenterWindow,
    QuitUi,
}

#[derive(Clone)]
struct AppState {
    settings_path: std::path::PathBuf,
    // Service lifecycle manager - controls mrd-service
    service_manager: std::sync::Arc<service_manager::ServiceManager>,
    // Test harness for end-to-end pipeline visualization
    test_harness: std::sync::Arc<std::sync::Mutex<test_harness::TestHarness>>,
    // Test orchestrator - unified test execution and management
    test_orchestrator: std::sync::Arc<test_orchestrator::TestOrchestrator>,
    // Lightweight resource sampler for the test workbench title bar
    resource_monitor: std::sync::Arc<std::sync::Mutex<ResourceMonitor>>,
    // Remote display windows: frameless web chrome plus optional native DX11 surface.
    render_window_registry: std::sync::Arc<std::sync::Mutex<RenderWindowRegistry>>,
    remote_display_surfaces: std::sync::Arc<std::sync::Mutex<RemoteDisplaySurfaceManager>>,
    render_proxy: std::sync::Arc<render_proxy::RenderProxyRegistry>,
    // Local browser WebRTC preview host for the remote display window Web mode.
    webrtc_host: std::sync::Arc<tokio::sync::Mutex<webrtc_host::WebrtcHost>>,
}

/// 设备注册响应
#[derive(Debug, Serialize, Deserialize)]
struct DeviceRegistrationResponse {
    device_id: String,
    device_name: String,
    access_token: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DecodePolicyResponse {
    decode_policy: String,
}

#[derive(Debug, Serialize)]
struct ControlInputAcceptedDto {
    session_id: String,
    lane: mrd_ipc::ControlInputLane,
    event_count: u32,
}

#[derive(Debug, Serialize)]
struct WakeOnLanSentDto {
    device_id: String,
    mac_address: String,
    broadcast_addr: String,
    packet_bytes: usize,
}

#[derive(Debug, Serialize)]
struct RemoteDevicePowerActionAcceptedDto {
    device_id: String,
    action: mrd_ipc::RemoteDevicePowerAction,
}

#[derive(Debug, Serialize)]
struct ClientDiagnostics {
    app_pid: u32,
    app_exe_path: Option<String>,
    current_dir: Option<String>,
    log_dir: String,
    service_exe_path: String,
    service_stdout_log: String,
    service_stderr_log: String,
}

#[derive(Debug, Serialize)]
struct BrowserWebrtcPreviewAnswer {
    session_id: String,
    answer_sdp: String,
}

fn ensure_rustls_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Tauri 命令：获取硬件信息
#[tauri::command]
fn get_hardware_info() -> Result<HardwareInfo, String> {
    Ok(device_info::get_hardware_info())
}

#[tauri::command]
async fn get_system_resource_snapshot(
    state: tauri::State<'_, AppState>,
    target: Option<String>,
) -> Result<SystemResourceSnapshot, String> {
    let service_pid = query_service_pid().await;
    let harness_running = state.test_harness.lock().unwrap().get_metrics().is_running;
    let target_kind = target.as_deref().unwrap_or("auto");
    let (target_pid, target_name) = match target_kind {
        "display" | "rdesk" | "rdesk-display" => (Some(std::process::id()), "Rdesk display"),
        "mrd-service" | "service" => (service_pid, "mrd-service"),
        _ if harness_running => (Some(std::process::id()), "Rdesk Workbench"),
        _ if service_pid.is_some() => (service_pid, "mrd-service"),
        _ => (Some(std::process::id()), "Rdesk Workbench"),
    };

    Ok(state
        .resource_monitor
        .lock()
        .unwrap()
        .snapshot_for_process(target_pid, target_name))
}

async fn query_service_pid() -> Option<u32> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    match client.send_request(IpcRequest::ServiceHealth).await {
        Ok(IpcResponse::ServiceHealth { status }) => status.pid,
        _ => None,
    }
}

#[tauri::command]
fn start_drag_window(window: WebviewWindow) -> Result<(), String> {
    window.start_dragging().map_err(|err| err.to_string())
}

#[tauri::command]
fn minimize_window(window: WebviewWindow) -> Result<(), String> {
    window.minimize().map_err(|err| err.to_string())
}

#[tauri::command]
fn toggle_maximize_window(window: WebviewWindow) -> Result<bool, String> {
    if window.is_maximized().map_err(|err| err.to_string())? {
        window.unmaximize().map_err(|err| err.to_string())?;
        Ok(false)
    } else {
        window.maximize().map_err(|err| err.to_string())?;
        Ok(true)
    }
}

#[tauri::command]
fn hide_to_tray(window: WebviewWindow) -> Result<(), String> {
    window.hide().map_err(|err| err.to_string())
}

#[tauri::command]
fn show_window(app_handle: AppHandle) -> Result<(), String> {
    show_main_window(&app_handle)
}

#[tauri::command]
fn center_window(window: WebviewWindow) -> Result<(), String> {
    window.center().map_err(|err| err.to_string())
}

#[tauri::command]
fn close_window(window: WebviewWindow) -> Result<(), String> {
    window.hide().map_err(|err| err.to_string())
}

#[tauri::command]
fn set_window_decorations(window: WebviewWindow, decorated: bool) -> Result<(), String> {
    window
        .set_decorations(decorated)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn apply_native_chrome(window: WebviewWindow) -> platform::NativeBackdropStatus {
    platform::configure_main_window(&window)
}

// Tauri derives the stable IPC field names from this command signature.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
fn open_remote_display_window(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    session_id: String,
    surface_id: Option<String>,
    preferred_display_source_id: Option<String>,
    avoid_capture_source_id: Option<String>,
    capture_source_id: Option<String>,
    profile_width: Option<u32>,
    profile_height: Option<u32>,
    profile_fps: Option<u32>,
    profile_bitrate_mbps: Option<u32>,
    profile_codec: Option<String>,
    profile_codec_profile: Option<String>,
    profile_bit_depth: Option<u32>,
    profile_chroma_subsampling: Option<String>,
    profile_pixel_format: Option<String>,
    profile_hdr_enabled: Option<bool>,
    profile_color_mode: Option<String>,
    profile_color_pipeline: Option<String>,
) -> Result<RenderWindowContext, String> {
    let spec = {
        let mut registry = state.render_window_registry.lock().unwrap();
        let mut query_params = remote_display_profile_query_params(
            profile_width,
            profile_height,
            profile_fps,
            profile_bitrate_mbps,
            profile_codec,
            profile_codec_profile,
            profile_bit_depth,
            profile_chroma_subsampling,
            profile_pixel_format,
            profile_hdr_enabled,
            profile_color_mode,
            profile_color_pipeline,
        );
        if let Some(capture_source_id) =
            capture_source_id.filter(|source_id| !source_id.trim().is_empty())
        {
            query_params.push(("captureSourceId".to_string(), capture_source_id));
        }
        let session_id = SessionId(session_id);
        if query_params.is_empty() {
            registry.reserve_window(session_id, surface_id)?
        } else {
            registry.reserve_window_with_query(session_id, surface_id, query_params)?
        }
    };

    let context = {
        let mut registry = state.render_window_registry.lock().unwrap();
        let session_window_count = registry.register_window(
            spec.session_id.clone(),
            spec.label.clone(),
            spec.surface_id.clone(),
        );
        RenderWindowContext {
            label: spec.label.clone(),
            session_id: spec.session_id.0.clone(),
            surface_id: spec.surface_id.clone(),
            role: "controller".to_string(),
            renderer_attached: false,
            render_mode: "web".to_string(),
            native_surface_attached: false,
            session_window_count,
        }
    };

    let app_for_window = app.clone();
    let state_for_window = state.inner().clone();
    std::thread::spawn(move || {
        let build_app = app_for_window.clone();
        if let Err(error) = app_for_window.run_on_main_thread(move || {
            if let Err(error) = build_remote_display_window(
                &build_app,
                state_for_window,
                spec,
                preferred_display_source_id,
                avoid_capture_source_id,
            ) {
                eprintln!("{error}");
            }
        }) {
            eprintln!("schedule remote display window failed: {error}");
        }
    });

    Ok(context)
}

// This helper mirrors the stable Tauri command's profile fields one-for-one.
#[allow(clippy::too_many_arguments)]
fn remote_display_profile_query_params(
    profile_width: Option<u32>,
    profile_height: Option<u32>,
    profile_fps: Option<u32>,
    profile_bitrate_mbps: Option<u32>,
    profile_codec: Option<String>,
    profile_codec_profile: Option<String>,
    profile_bit_depth: Option<u32>,
    profile_chroma_subsampling: Option<String>,
    profile_pixel_format: Option<String>,
    profile_hdr_enabled: Option<bool>,
    profile_color_mode: Option<String>,
    profile_color_pipeline: Option<String>,
) -> Vec<(String, String)> {
    let mut params = Vec::new();
    push_remote_display_query_param(&mut params, "profileWidth", profile_width);
    push_remote_display_query_param(&mut params, "profileHeight", profile_height);
    push_remote_display_query_param(&mut params, "profileFps", profile_fps);
    push_remote_display_query_param(&mut params, "profileBitrateMbps", profile_bitrate_mbps);
    push_remote_display_query_param(&mut params, "profileCodec", profile_codec);
    push_remote_display_query_param(&mut params, "profileCodecProfile", profile_codec_profile);
    push_remote_display_query_param(&mut params, "profileBitDepth", profile_bit_depth);
    push_remote_display_query_param(
        &mut params,
        "profileChromaSubsampling",
        profile_chroma_subsampling,
    );
    push_remote_display_query_param(&mut params, "profilePixelFormat", profile_pixel_format);
    push_remote_display_query_param(&mut params, "profileHdrEnabled", profile_hdr_enabled);
    push_remote_display_query_param(&mut params, "profileColorMode", profile_color_mode);
    push_remote_display_query_param(&mut params, "profileColorPipeline", profile_color_pipeline);
    params
}

fn push_remote_display_query_param<T: ToString>(
    params: &mut Vec<(String, String)>,
    key: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        params.push((key.to_string(), value.to_string()));
    }
}

#[cfg(test)]
mod remote_display_profile_query_tests {
    use super::*;

    #[test]
    fn remote_display_profile_query_params_include_color_metadata() {
        let params = remote_display_profile_query_params(
            Some(2560),
            Some(1440),
            Some(144),
            Some(40),
            Some("hevc".to_string()),
            Some("main10".to_string()),
            Some(10),
            Some("4:2:0".to_string()),
            Some("p010".to_string()),
            Some(true),
            Some("monochrome".to_string()),
            Some("hdr_main10".to_string()),
        );

        assert!(params.contains(&("profileColorMode".to_string(), "monochrome".to_string())));
        assert!(params.contains(&("profileColorPipeline".to_string(), "hdr_main10".to_string())));
    }
}

fn build_remote_display_window(
    app: &AppHandle,
    state: AppState,
    spec: PendingRenderWindow,
    preferred_display_source_id: Option<String>,
    avoid_capture_source_id: Option<String>,
) -> Result<(), String> {
    let label = spec.label.clone();
    let session_id = spec.session_id.0.clone();
    let (window_width, window_height) = render_window_registry::render_window_initial_inner_size();
    let window = WebviewWindowBuilder::new(app, spec.label.clone(), spec.url)
        .title(format!("Rdesk Display {}", spec.session_id.0))
        .decorations(false)
        .resizable(true)
        .inner_size(window_width, window_height)
        .min_inner_size(720.0, 420.0)
        .visible(false)
        .build()
        .map_err(|error| format!("create remote display window failed: {error}"))?;

    remote_display_window_placement_result(place_remote_display_window(
        app,
        &window,
        preferred_display_source_id.as_deref(),
        avoid_capture_source_id.as_deref(),
    ))?;

    let cleanup_app = app.clone();
    let cleanup_state = state.clone();
    window.on_window_event(move |event| {
        if matches!(
            event,
            tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
        ) {
            cleanup_remote_display_window(
                &cleanup_app,
                &cleanup_state,
                &label,
                Some(session_id.clone()),
                "window_close",
            );
        }
    });

    window
        .show()
        .map_err(|error| format!("show remote display window failed: {error}"))?;
    let _ = window.set_focus();
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RemoteDisplayMonitorPlacement {
    name: Option<String>,
    primary: bool,
    position_x: i32,
    position_y: i32,
    width: u32,
    height: u32,
}

fn place_remote_display_window(
    app: &AppHandle,
    window: &WebviewWindow,
    preferred_display_source_id: Option<&str>,
    avoid_capture_source_id: Option<&str>,
) -> Result<(), String> {
    let monitors = app
        .available_monitors()
        .map_err(|error| format!("list monitors failed: {error}"))?
        .into_iter();
    let primary_monitor = app
        .primary_monitor()
        .ok()
        .flatten()
        .map(|monitor| RemoteDisplayMonitorPlacement {
            name: monitor.name().cloned(),
            primary: true,
            position_x: monitor.position().x,
            position_y: monitor.position().y,
            width: monitor.size().width,
            height: monitor.size().height,
        })
        .map(|monitor| {
            (
                monitor.name.as_deref().map(normalize_display_name),
                monitor.position_x,
                monitor.position_y,
                monitor.width,
                monitor.height,
            )
        });
    let monitors = monitors
        .map(|monitor| {
            let name = monitor.name().cloned();
            let position_x = monitor.position().x;
            let position_y = monitor.position().y;
            let width = monitor.size().width;
            let height = monitor.size().height;
            let normalized_name = name.as_deref().map(normalize_display_name);
            let primary = primary_monitor.as_ref().is_some_and(
                |(primary_name, primary_x, primary_y, primary_width, primary_height)| {
                    let name_matches = primary_name
                        .as_deref()
                        .zip(normalized_name.as_deref())
                        .is_some_and(|(left, right)| left == right);
                    name_matches
                        || (*primary_x == position_x
                            && *primary_y == position_y
                            && *primary_width == width
                            && *primary_height == height)
                },
            );
            RemoteDisplayMonitorPlacement {
                name,
                primary,
                position_x,
                position_y,
                width,
                height,
            }
        })
        .collect::<Vec<_>>();

    if let Some(placement) = choose_remote_display_window_placement(
        &monitors,
        preferred_display_source_id,
        avoid_capture_source_id,
    ) {
        let x = placement.position_x.saturating_add(48);
        let y = placement.position_y.saturating_add(48);
        window
            .set_position(PhysicalPosition::new(x, y))
            .map_err(|error| format!("position remote display window failed: {error}"))?;
    }
    Ok(())
}

fn remote_display_window_placement_result(result: Result<(), String>) -> Result<(), String> {
    if let Err(error) = result {
        eprintln!(
            "position remote display window failed; continuing with default placement: {error}"
        );
    }
    Ok(())
}

fn choose_remote_display_window_placement(
    monitors: &[RemoteDisplayMonitorPlacement],
    preferred_display_source_id: Option<&str>,
    avoid_capture_source_id: Option<&str>,
) -> Option<RemoteDisplayMonitorPlacement> {
    if monitors.is_empty() {
        return None;
    }

    if let Some(preferred_name) = preferred_display_source_id
        .and_then(|source_id| display_name_for_preferred_display_source_id(monitors, source_id))
    {
        let normalized_preferred = normalize_display_name(&preferred_name);
        if let Some(monitor) = monitors.iter().find(|monitor| {
            monitor
                .name
                .as_deref()
                .map(normalize_display_name)
                .as_deref()
                == Some(normalized_preferred.as_str())
        }) {
            return Some(monitor.clone());
        }
    }

    let avoided_name = avoid_capture_source_id
        .and_then(display_name_for_capture_source_id)
        .map(|name| normalize_display_name(&name));
    if let Some(avoided_name) = avoided_name {
        if let Some(monitor) = monitors.iter().find(|monitor| {
            monitor
                .name
                .as_deref()
                .map(normalize_display_name)
                .as_deref()
                != Some(avoided_name.as_str())
        }) {
            return Some(monitor.clone());
        }
    }

    None
}

fn display_name_for_preferred_display_source_id(
    monitors: &[RemoteDisplayMonitorPlacement],
    source_id: &str,
) -> Option<String> {
    display_name_for_capture_source_id(source_id).or_else(|| {
        let source_index = display_source_index_from_source_id(source_id)?;
        let mut sorted = monitors
            .iter()
            .filter(|monitor| monitor.name.as_deref().is_some())
            .collect::<Vec<_>>();
        sorted.sort_by_key(|monitor| {
            (
                !monitor.primary,
                monitor.position_x,
                monitor.position_y,
                monitor
                    .name
                    .as_deref()
                    .map(normalize_display_name)
                    .unwrap_or_default(),
            )
        });
        sorted.get(source_index)?.name.clone()
    })
}

fn display_name_for_capture_source_id(source_id: &str) -> Option<String> {
    let trimmed = source_id.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(display_number) = display_number_from_display_name(trimmed) {
        return Some(format!("\\\\.\\DISPLAY{display_number}"));
    }

    None
}

fn display_source_index_from_source_id(source_id: &str) -> Option<usize> {
    let trimmed = source_id.trim();
    let parts = trimmed.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        ["windows", "display", index] | ["windows", "display-shared", index] => index.parse().ok(),
        ["display", index] => index.parse().ok(),
        _ => None,
    }
}

fn display_number_from_display_name(value: &str) -> Option<u32> {
    let upper = value.to_ascii_uppercase();
    let display_index = upper.find("DISPLAY")?;
    let digits = upper[display_index + "DISPLAY".len()..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u32>().ok()
}

fn normalize_display_name(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn cleanup_remote_display_window(
    app: &AppHandle,
    state: &AppState,
    label: &str,
    _session_id_hint: Option<String>,
    reason: &'static str,
) {
    let window = app.get_webview_window(label);
    if let Err(error) = state
        .remote_display_surfaces
        .lock()
        .unwrap()
        .detach(label, window.as_ref())
    {
        eprintln!("remote display surface cleanup failed for {label}: {error}");
    }

    let removed = state
        .render_window_registry
        .lock()
        .unwrap()
        .remove_window_entry(label);

    let Some((session_id, remaining_windows)) = removed else {
        return;
    };
    let session_id = session_id.0;

    if remaining_windows == 0 {
        if is_local_pipeline_preview_session(&session_id) {
            stop_test_harness_async(state.test_harness.clone(), label.to_string());
        }
        stop_browser_webrtc_preview_async(state.webrtc_host.clone(), session_id.clone());
        stop_session_async(session_id, reason);
    }
}

fn is_local_pipeline_preview_session(session_id: &str) -> bool {
    session_id == "local-preview" || session_id.starts_with("local-display-test")
}

fn stop_test_harness_async(
    harness: std::sync::Arc<std::sync::Mutex<test_harness::TestHarness>>,
    label: String,
) {
    std::thread::spawn(move || {
        if let Err(error) = harness.lock().unwrap().stop() {
            eprintln!("test harness cleanup failed for {label}: {error}");
        }
    });
}

fn stop_browser_webrtc_preview_async(
    host: std::sync::Arc<tokio::sync::Mutex<webrtc_host::WebrtcHost>>,
    session_id: String,
) {
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Runtime::new() else {
            eprintln!("create runtime for browser webrtc preview cleanup failed: {session_id}");
            return;
        };

        rt.block_on(async move {
            let session_id = SessionId(session_id);
            let mut host = host.lock().await;
            if host.snapshot(&session_id).is_some() {
                if let Err(error) = host.close_session(&session_id).await {
                    eprintln!(
                        "browser webrtc preview cleanup failed for {}: {error}",
                        session_id.0
                    );
                }
            }
        });
    });
}

fn stop_session_async(session_id: String, reason: &'static str) {
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Runtime::new() else {
            eprintln!("create runtime for session cleanup failed: {session_id}");
            return;
        };

        rt.block_on(async move {
            use mrd_ipc::{IpcRequest, IpcResponse};
            let mut client = mrd_ipc::client::IpcClient::new();
            match client
                .send_request(IpcRequest::StopSession {
                    session_id: SessionId(session_id.clone()),
                })
                .await
            {
                Ok(IpcResponse::SessionStopped { .. }) => {}
                Ok(IpcResponse::Error { code, message }) => {
                    eprintln!(
                        "stop session on {reason} failed for {session_id}: {code}: {message}"
                    );
                }
                Ok(_) => {
                    eprintln!(
                        "stop session on {reason} returned unexpected response for {session_id}"
                    );
                }
                Err(error) => {
                    eprintln!("stop session on {reason} failed for {session_id}: {error}");
                }
            }
        });
    });
}

#[tauri::command]
fn list_remote_display_windows(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> Vec<RenderWindowContext> {
    state
        .render_window_registry
        .lock()
        .unwrap()
        .list_window_contexts(&app, &SessionId(session_id))
}

#[tauri::command]
fn current_remote_display_window_context(
    window: WebviewWindow,
    state: tauri::State<'_, AppState>,
) -> Option<RenderWindowContext> {
    state
        .render_window_registry
        .lock()
        .unwrap()
        .context_for_label(window.app_handle(), window.label())
}

#[tauri::command]
fn close_remote_display_window(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    label: String,
) -> Result<(), String> {
    let window = app
        .get_webview_window(&label)
        .ok_or_else(|| format!("remote display window not found: {label}"))?;
    cleanup_remote_display_window(&app, state.inner(), &label, None, "window_close_command");
    window
        .close()
        .map_err(|error| format!("close remote display window failed: {error}"))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn browser_webrtc_preview_start(
    state: tauri::State<'_, AppState>,
    session_id: String,
    offer_sdp: String,
    fps: Option<u32>,
    width: Option<u32>,
    height: Option<u32>,
    codec: Option<String>,
    h264_profile: Option<String>,
    bitrate_mbps: Option<u32>,
    source_id: Option<String>,
) -> Result<BrowserWebrtcPreviewAnswer, String> {
    ensure_rustls_crypto_provider();

    // The Tauri preview sender consumes encoded access units from the already
    // running local test harness. Width/height/bitrate/source are applied when
    // that harness run is started from the frontend.
    let _ = (width, height, bitrate_mbps, source_id);
    let session_id = SessionId(session_id);
    let fps = fps.unwrap_or(60).clamp(1, 144);
    let h264_profile = h264_profile.unwrap_or_else(|| "baseline".to_string());
    let codec = browser_webrtc_preview_codec_from_label(codec.as_deref())?;
    let encoded_access_units = state
        .test_harness
        .lock()
        .unwrap()
        .subscribe_encoded_access_units();
    let mut host = state.webrtc_host.lock().await;
    match codec {
        VideoCodec::H264 => {
            host.prepare_browser_h264_sender(session_id.clone(), fps, &h264_profile)
                .await?;
        }
        VideoCodec::Hevc => {
            host.prepare_browser_hevc_sender(session_id.clone(), fps)
                .await?;
        }
        VideoCodec::Av1 => {
            host.prepare_browser_av1_sender(session_id.clone(), fps)
                .await?;
        }
        VideoCodec::Vvc => {
            return Err(
                "browser WebRTC preview does not support H.266/VVC in current browsers".to_string(),
            );
        }
    }
    host.apply_remote_offer(session_id.clone(), offer_sdp)
        .await?;
    let answer = host.create_answer(session_id.clone()).await?;
    host.start_encoded_access_unit_sender_with_codec(
        session_id,
        fps,
        codec,
        &h264_profile,
        encoded_access_units,
    )
    .await?;

    Ok(BrowserWebrtcPreviewAnswer {
        session_id: answer.session_id.0,
        answer_sdp: answer.sdp,
    })
}

fn browser_webrtc_preview_codec_from_label(codec: Option<&str>) -> Result<VideoCodec, String> {
    match codec
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("h264" | "h.264" | "avc" | "avc1") => Ok(VideoCodec::H264),
        Some("hevc" | "h265" | "h.265" | "hev1" | "hvc1") => Ok(VideoCodec::Hevc),
        Some("av1") => Ok(VideoCodec::Av1),
        Some("vvc" | "h266" | "h.266") => {
            Err("browser WebRTC preview does not support H.266/VVC in current browsers".to_string())
        }
        Some(other) => Err(format!("unsupported browser WebRTC preview codec: {other}")),
    }
}

#[cfg(test)]
mod browser_webrtc_preview_tests {
    use super::*;

    #[test]
    fn browser_webrtc_preview_codec_labels_parse_h264_and_hevc() {
        assert_eq!(
            browser_webrtc_preview_codec_from_label(None).unwrap(),
            VideoCodec::H264
        );
        assert_eq!(
            browser_webrtc_preview_codec_from_label(Some("h265")).unwrap(),
            VideoCodec::Hevc
        );
        assert_eq!(
            browser_webrtc_preview_codec_from_label(Some("h.265")).unwrap(),
            VideoCodec::Hevc
        );
        assert_eq!(
            browser_webrtc_preview_codec_from_label(Some("hevc")).unwrap(),
            VideoCodec::Hevc
        );
    }

    #[test]
    fn browser_webrtc_preview_codec_labels_parse_av1() {
        assert_eq!(
            browser_webrtc_preview_codec_from_label(Some("av1")).unwrap(),
            VideoCodec::Av1
        );
    }

    #[test]
    fn browser_webrtc_preview_codec_rejects_vvc() {
        let error = browser_webrtc_preview_codec_from_label(Some("h266")).unwrap_err();

        assert!(error.contains("H.266/VVC"));
    }
}

#[tauri::command]
async fn browser_webrtc_preview_stop(
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> Result<(), String> {
    let session_id = SessionId(session_id);
    let mut host = state.webrtc_host.lock().await;
    if host.snapshot(&session_id).is_some() {
        host.close_session(&session_id).await?;
    }
    Ok(())
}

// Tauri derives the stable IPC field names from this command signature.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
async fn configure_remote_display_native_surface(
    window: WebviewWindow,
    state: tauri::State<'_, AppState>,
    rect: NativeSurfaceRect,
    enabled: bool,
    visible: Option<bool>,
    control_frame_size: Option<NativeSurfaceControlFrameSize>,
    pointer_control_enabled: Option<bool>,
    keyboard_control_enabled: Option<bool>,
) -> Result<NativeRenderSurfaceSnapshot, String> {
    let label = window.label().to_string();
    let app_handle = window.app_handle().clone();
    let pointer_control_enabled = pointer_control_enabled.unwrap_or(false);
    let keyboard_control_enabled = keyboard_control_enabled.unwrap_or(false);
    let initial_context = state
        .render_window_registry
        .lock()
        .unwrap()
        .context_for_label(&app_handle, &label);
    #[cfg(windows)]
    let desired_control_session = (enabled
        && (pointer_control_enabled || keyboard_control_enabled))
        .then(|| {
            initial_context
                .as_ref()
                .map(|context| context.session_id.clone())
        })
        .flatten();

    #[cfg(windows)]
    {
        let current_binding = native_surface_control_binding_for_label(
            &app_handle,
            state.inner().clone(),
            label.clone(),
        )?;
        let binding_changed = current_binding.as_ref().is_some_and(|binding| {
            desired_control_session.as_deref() != Some(binding.session_id.as_str())
                || pointer_control_enabled != binding.pointer_enabled
                || keyboard_control_enabled != binding.keyboard_enabled
        });
        if binding_changed {
            if let Some(binding) = current_binding.as_ref() {
                set_native_surface_control_binding_for_label(
                    &app_handle,
                    state.inner().clone(),
                    label.clone(),
                    None,
                    false,
                    false,
                )?;
                release_native_surface_control_binding(&binding.session_id).await?;
            }
        }
    }
    eprintln!(
        "render-surface ui configure request label={label} enabled={enabled} visible={visible:?} pointer_control={pointer_control_enabled} keyboard_control={keyboard_control_enabled}"
    );
    let snapshot = configure_native_surface_for_window(
        &window,
        state.inner().clone(),
        rect,
        enabled,
        visible.unwrap_or(enabled),
        control_frame_size,
    )?;
    drop(window);

    let (context, service_action, recorded_optimistic_attach) = {
        let mut registry = state.render_window_registry.lock().unwrap();
        let context = registry.context_for_label(&app_handle, &label);
        let service_action = context.as_ref().map(|_| {
            registry.native_surface_service_action(
                &label,
                snapshot.attached,
                &snapshot.backend,
                snapshot.hwnd.as_deref(),
            )
        });
        let recorded_optimistic_attach =
            matches!(service_action, Some(NativeSurfaceServiceAction::Attach));
        if recorded_optimistic_attach {
            registry.record_native_surface_service_binding(
                &label,
                snapshot.attached,
                &snapshot.backend,
                snapshot.hwnd.as_deref(),
            );
        }
        (context, service_action, recorded_optimistic_attach)
    };

    let service_action_label = match service_action.as_ref() {
        Some(NativeSurfaceServiceAction::Attach) => "attach",
        Some(NativeSurfaceServiceAction::Detach) => "detach",
        Some(NativeSurfaceServiceAction::Unchanged) => "unchanged",
        None => "none",
    };
    eprintln!(
        "render-surface ui configured label={label} enabled={enabled} attached={} backend={} hwnd={:?} context_session={} context_surface={} service_action={}",
        snapshot.attached,
        snapshot.backend,
        snapshot.hwnd,
        context
            .as_ref()
            .map(|context| context.session_id.as_str())
            .unwrap_or("-"),
        context
            .as_ref()
            .map(|context| context.surface_id.as_str())
            .unwrap_or("-"),
        service_action_label
    );

    #[cfg(windows)]
    if snapshot.attached {
        let session_id = desired_control_session.clone();
        set_native_surface_control_binding_for_label(
            &app_handle,
            state.inner().clone(),
            label.clone(),
            session_id.clone(),
            pointer_control_enabled,
            keyboard_control_enabled,
        )
        .map_err(|error| {
            format!(
                "render-surface input binding failed label={label} session_id={} error={error}",
                session_id.as_deref().unwrap_or("-")
            )
        })?;
    }

    if snapshot.attached && context.is_none() {
        let _ = detach_native_surface_for_label(&app_handle, state.inner().clone(), label.clone());
        return Err("remote display window context is not registered".to_string());
    }

    if let Some(context) = context.clone() {
        let result = match service_action.unwrap_or(NativeSurfaceServiceAction::Unchanged) {
            NativeSurfaceServiceAction::Attach => {
                let render_proxy_endpoint = if snapshot.backend == "macos" {
                    let window_handle = snapshot
                        .hwnd
                        .as_deref()
                        .and_then(parse_native_handle)
                        .ok_or_else(|| {
                            "macOS native render surface is missing a render target handle"
                                .to_string()
                        })?;
                    state.render_proxy.attach_surface(
                        &context.session_id,
                        &context.surface_id,
                        window_handle as isize,
                    )?
                } else {
                    None
                };
                eprintln!(
                    "render-surface ui ipc attach session_id={} surface_id={} backend={} hwnd={:?} render_proxy={}",
                    context.session_id,
                    context.surface_id,
                    snapshot.backend,
                    snapshot.hwnd,
                    render_proxy_endpoint.as_deref().unwrap_or("-")
                );
                send_attach_render_surface(
                    context.session_id.clone(),
                    context.surface_id.clone(),
                    snapshot.backend.clone(),
                    snapshot.hwnd.as_deref().and_then(parse_native_handle),
                    render_proxy_endpoint,
                )
                .await
            }
            NativeSurfaceServiceAction::Detach => {
                eprintln!(
                    "render-surface ui ipc detach session_id={} surface_id={}",
                    context.session_id, context.surface_id
                );
                state
                    .render_proxy
                    .detach_surface(&context.session_id, &context.surface_id);
                send_detach_render_surface(context.session_id.clone(), context.surface_id.clone())
                    .await
            }
            NativeSurfaceServiceAction::Unchanged => Ok(()),
        };

        if let Err(error) = result {
            eprintln!(
                "render-surface ui ipc failed label={label} session_id={} surface_id={} error={error}",
                context.session_id, context.surface_id
            );
            if snapshot.attached {
                state
                    .render_proxy
                    .detach_surface(&context.session_id, &context.surface_id);
                let _ = detach_native_surface_for_label(
                    &app_handle,
                    state.inner().clone(),
                    label.clone(),
                );
                if let Ok(context) = state
                    .render_window_registry
                    .lock()
                    .unwrap()
                    .set_render_mode(&app_handle, &label, "web".to_string(), false)
                {
                    notify_remote_render_surface_configured(context, snapshot.clone());
                }
                if recorded_optimistic_attach {
                    state
                        .render_window_registry
                        .lock()
                        .unwrap()
                        .record_native_surface_service_binding(
                            &label,
                            false,
                            &snapshot.backend,
                            None,
                        );
                }
                return Err(error);
            }
            tracing::warn!(%error, "failed to notify mrd-service about detached native render surface");
        } else if !matches!(service_action, Some(NativeSurfaceServiceAction::Unchanged)) {
            eprintln!(
                "render-surface ui ipc ok label={label} session_id={} surface_id={} action={service_action_label}",
                context.session_id, context.surface_id
            );
            if !recorded_optimistic_attach {
                state
                    .render_window_registry
                    .lock()
                    .unwrap()
                    .record_native_surface_service_binding(
                        &label,
                        snapshot.attached,
                        &snapshot.backend,
                        snapshot.hwnd.as_deref(),
                    );
            }
        }
    }

    let render_mode = render_mode_for_native_surface(&snapshot);
    if let Ok(context) = state
        .render_window_registry
        .lock()
        .unwrap()
        .set_render_mode(
            &app_handle,
            &label,
            render_mode.to_string(),
            snapshot.attached,
        )
    {
        notify_remote_render_surface_configured(context, snapshot.clone());
    }

    Ok(snapshot)
}

#[cfg(windows)]
fn configure_native_surface_for_window(
    window: &WebviewWindow,
    state: AppState,
    rect: NativeSurfaceRect,
    enabled: bool,
    visible: bool,
    control_frame_size: Option<NativeSurfaceControlFrameSize>,
) -> Result<NativeRenderSurfaceSnapshot, String> {
    let scheduler_window = window.clone();
    let surface_window = window.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    scheduler_window
        .run_on_main_thread(move || {
            let result = state.remote_display_surfaces.lock().unwrap().configure(
                &surface_window,
                rect,
                enabled,
                visible,
                control_frame_size,
            );
            let _ = sender.send(result);
        })
        .map_err(|error| format!("schedule native surface update failed: {error}"))?;

    receiver
        .recv()
        .map_err(|error| format!("native surface update failed: {error}"))?
}

#[cfg(not(windows))]
fn configure_native_surface_for_window(
    window: &WebviewWindow,
    state: AppState,
    rect: NativeSurfaceRect,
    enabled: bool,
    visible: bool,
    control_frame_size: Option<NativeSurfaceControlFrameSize>,
) -> Result<NativeRenderSurfaceSnapshot, String> {
    state.remote_display_surfaces.lock().unwrap().configure(
        window,
        rect,
        enabled,
        visible,
        control_frame_size,
    )
}

#[cfg(windows)]
fn detach_native_surface_for_label(
    app_handle: &AppHandle,
    state: AppState,
    label: String,
) -> Result<bool, String> {
    let app_handle = app_handle.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    app_handle
        .run_on_main_thread(move || {
            let result = state
                .remote_display_surfaces
                .lock()
                .unwrap()
                .detach(&label, None);
            let _ = sender.send(result);
        })
        .map_err(|error| format!("schedule native surface detach failed: {error}"))?;

    receiver
        .recv()
        .map_err(|error| format!("native surface detach failed: {error}"))?
}

#[cfg(not(windows))]
fn detach_native_surface_for_label(
    _app_handle: &AppHandle,
    state: AppState,
    label: String,
) -> Result<bool, String> {
    state
        .remote_display_surfaces
        .lock()
        .unwrap()
        .detach(&label, None)
}

#[cfg(windows)]
fn set_native_surface_control_binding_for_label(
    app_handle: &AppHandle,
    state: AppState,
    label: String,
    session_id: Option<String>,
    pointer_enabled: bool,
    keyboard_enabled: bool,
) -> Result<Option<remote_display_surface::NativeSurfaceControlBindingSnapshot>, String> {
    let app_handle = app_handle.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    app_handle
        .run_on_main_thread(move || {
            let result = state
                .remote_display_surfaces
                .lock()
                .unwrap()
                .set_control_binding(&label, session_id, pointer_enabled, keyboard_enabled);
            let _ = sender.send(result);
        })
        .map_err(|error| format!("schedule native surface input session update failed: {error}"))?;

    receiver
        .recv()
        .map_err(|error| format!("native surface input session update failed: {error}"))?
}

#[cfg(windows)]
fn native_surface_control_binding_for_label(
    app_handle: &AppHandle,
    state: AppState,
    label: String,
) -> Result<Option<remote_display_surface::NativeSurfaceControlBindingSnapshot>, String> {
    let app_handle = app_handle.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    app_handle
        .run_on_main_thread(move || {
            let binding = state
                .remote_display_surfaces
                .lock()
                .unwrap()
                .control_binding(&label);
            let _ = sender.send(binding);
        })
        .map_err(|error| format!("schedule native surface input binding read failed: {error}"))?;

    receiver
        .recv()
        .map_err(|error| format!("native surface input binding read failed: {error}"))
}

#[cfg(windows)]
async fn release_native_surface_control_binding(session_id: &str) -> Result<(), String> {
    use mrd_ipc::{ControlInputEvent, IpcRequest, IpcResponse, RemoteReasonCode};

    let endpoint = mrd_ipc::transport::IpcEndpoint::service_from_env_or_default();
    let mut client = mrd_ipc::client::IpcClient::with_endpoint(endpoint);
    let response = client
        .send_request(IpcRequest::SendControlInput {
            session_id: SessionId(session_id.to_string()),
            event: ControlInputEvent::ReleaseAll,
        })
        .await
        .map_err(|error| format!("native input cleanup IPC failed: {error}"))?;
    match response {
        IpcResponse::ControlInputAccepted { .. } => Ok(()),
        IpcResponse::RemoteAccessError { failure, .. }
            if matches!(
                failure.code,
                RemoteReasonCode::GrantExpired
                    | RemoteReasonCode::GrantRevoked
                    | RemoteReasonCode::PolicyChanged
                    | RemoteReasonCode::RouteLost
            ) =>
        {
            // The authoritative service terminal transition owns pressed-state cleanup.
            Ok(())
        }
        IpcResponse::RemoteAccessError { failure, .. } => Err(format!(
            "native input cleanup rejected ({:?}): {}",
            failure.code, failure.message
        )),
        IpcResponse::Error { code, message } => {
            Err(format!("native input cleanup rejected ({code}): {message}"))
        }
        other => Err(format!(
            "unexpected native input cleanup response: {other:?}"
        )),
    }
}

fn render_mode_for_native_surface(snapshot: &NativeRenderSurfaceSnapshot) -> &'static str {
    match (snapshot.attached, snapshot.backend.as_str()) {
        (true, "macos") => "macos_native",
        (true, "linux") => "linux_native",
        (true, _) => "d3d11_native",
        (false, _) => "web",
    }
}

fn notify_remote_render_surface_configured(
    context: RenderWindowContext,
    snapshot: NativeRenderSurfaceSnapshot,
) {
    let _ = (context, snapshot);
}

fn parse_native_handle(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    match hex {
        Some(hex) => i64::from_str_radix(hex, 16).ok(),
        None => trimmed.parse::<i64>().ok(),
    }
}

async fn send_attach_render_surface(
    session_id: String,
    surface_id: String,
    backend: String,
    window_handle: Option<i64>,
    render_proxy_endpoint: Option<String>,
) -> Result<(), String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::AttachRenderSurface {
            session_id: SessionId(session_id),
            surface_id,
            backend,
            window_handle,
            render_proxy_endpoint,
        })
        .await
        .map_err(|error| error.to_string())?;

    match response {
        IpcResponse::RenderSurfaceAttached { .. } => Ok(()),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

async fn send_detach_render_surface(session_id: String, surface_id: String) -> Result<(), String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::DetachRenderSurface {
            session_id: SessionId(session_id),
            surface_id,
        })
        .await
        .map_err(|error| error.to_string())?;

    match response {
        IpcResponse::RenderSurfaceDetached { .. } => Ok(()),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

#[tauri::command]
fn present_test_harness_frame_on_native_surface(
    window: WebviewWindow,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let label = window.label().to_string();
    let target = state
        .remote_display_surfaces
        .lock()
        .unwrap()
        .render_target_handle(&label);
    let Some(target) = target else {
        return Ok(false);
    };

    present_native_probe_frame(target)
}

#[cfg(target_os = "macos")]
fn present_native_probe_frame(target: isize) -> Result<bool, String> {
    present_native_frame(target, build_native_probe_frame(640, 360))
}

#[cfg(target_os = "macos")]
fn present_native_frame(target: isize, frame: mrd_render::RenderFrame) -> Result<bool, String> {
    use mrd_render::{RenderTarget, RendererFactory};

    let factory = mrd_render_macos::MacosRendererFactory;
    let mut renderer = factory
        .create()
        .map_err(|error| format!("create Metal probe renderer failed: {error}"))?;
    renderer
        .attach_target(RenderTarget::WindowHandle(target))
        .map_err(|error| format!("attach Metal probe renderer failed: {error}"))?;
    renderer
        .upload_frame(frame)
        .map_err(|error| format!("present Metal probe frame failed: {error}"))?;

    let snapshot = renderer.snapshot();
    Ok(snapshot.attached_to_target && snapshot.uploaded_frame_count > 0)
}

#[cfg(windows)]
fn present_native_probe_frame(target: isize) -> Result<bool, String> {
    present_native_frame(target, build_native_probe_frame(640, 360))
}

#[cfg(windows)]
fn present_native_frame(target: isize, frame: mrd_render::RenderFrame) -> Result<bool, String> {
    use mrd_render::{RenderTarget, RendererFactory};

    let factory = mrd_render_d3d11::D3d11RendererFactory;
    let mut renderer = factory
        .create()
        .map_err(|error| format!("create D3D11 probe renderer failed: {error}"))?;
    renderer
        .attach_target(RenderTarget::WindowHandle(target))
        .map_err(|error| format!("attach D3D11 probe renderer failed: {error}"))?;
    renderer
        .upload_frame(frame)
        .map_err(|error| format!("present D3D11 probe frame failed: {error}"))?;

    let snapshot = renderer.snapshot();
    Ok(snapshot.attached_to_target && snapshot.uploaded_frame_count > 0)
}

#[cfg(target_os = "linux")]
fn present_native_probe_frame(target: isize) -> Result<bool, String> {
    present_native_frame(target, build_native_probe_frame(640, 360))
}

#[cfg(target_os = "linux")]
fn present_native_frame(target: isize, frame: mrd_render::RenderFrame) -> Result<bool, String> {
    use mrd_render::{RenderTarget, RendererFactory};

    let factory = mrd_render_linux::LinuxRendererFactory;
    let mut renderer = factory
        .create()
        .map_err(|error| format!("create Linux probe renderer failed: {error}"))?;
    renderer
        .attach_target(RenderTarget::WindowHandle(target))
        .map_err(|error| format!("attach Linux probe renderer failed: {error}"))?;
    renderer
        .upload_frame(frame)
        .map_err(|error| format!("present Linux probe frame failed: {error}"))?;

    let snapshot = renderer.snapshot();
    Ok(snapshot.attached_to_target && snapshot.uploaded_frame_count > 0)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn present_native_probe_frame(_target: isize) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn present_native_frame(_target: isize, _frame: mrd_render::RenderFrame) -> Result<bool, String> {
    Ok(false)
}

fn build_native_probe_frame(width: usize, height: usize) -> mrd_render::RenderFrame {
    let mut bgra = vec![0_u8; width * height * 4];
    for y in 0..height {
        for x in 0..width {
            let offset = (y * width + x) * 4;
            let checker = ((x / 40) + (y / 40)) % 2 == 0;
            let edge = x < 12 || y < 12 || x + 12 >= width || y + 12 >= height;
            let (r, g, b) = if edge {
                (255, 255, 255)
            } else if checker {
                (20, 210, 255)
            } else {
                (240, 70, 120)
            };
            bgra[offset] = b;
            bgra[offset + 1] = g;
            bgra[offset + 2] = r;
            bgra[offset + 3] = 255;
        }
    }

    mrd_render::RenderFrame::from_bgra32(width, height, bgra)
}

#[tauri::command]
fn get_client_diagnostics(state: tauri::State<'_, AppState>) -> ClientDiagnostics {
    let service_exe_path = state
        .service_manager
        .service_exe_path()
        .display()
        .to_string();

    ClientDiagnostics {
        app_pid: std::process::id(),
        app_exe_path: std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
        current_dir: std::env::current_dir()
            .ok()
            .map(|path| path.display().to_string()),
        log_dir: service_manager::runtime_log_dir().display().to_string(),
        service_exe_path,
        service_stdout_log: service_manager::service_stdout_log_path()
            .display()
            .to_string(),
        service_stderr_log: service_manager::service_stderr_log_path()
            .display()
            .to_string(),
    }
}

#[tauri::command]
fn open_diagnostics_folder() -> Result<(), String> {
    let log_dir = service_manager::runtime_log_dir();
    std::fs::create_dir_all(&log_dir).map_err(|error| error.to_string())?;

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("explorer.exe");
        command.arg(&log_dir);
        command
    };

    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("open");
        command.arg(&log_dir);
        command
    };

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(&log_dir);
        command
    };

    command.spawn().map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
fn automation_write_report(report: serde_json::Value) -> Result<Option<String>, String> {
    if is_mainline_e2e_artifact_report(&report) {
        let artifact_dir = write_mainline_e2e_artifacts(&report)?;
        if let Some(path) = lan_e2e_report_path() {
            write_json_file(&path, &report, "automation report")?;
        }
        return Ok(Some(artifact_dir.display().to_string()));
    }

    let Some(path) = lan_e2e_report_path() else {
        return Ok(None);
    };
    write_json_file(&path, &report, "automation report")?;
    Ok(Some(path.display().to_string()))
}

fn lan_e2e_report_path() -> Option<std::path::PathBuf> {
    let Ok(path) = std::env::var(LAN_E2E_REPORT_PATH_ENV) else {
        return None;
    };
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(path))
}

fn write_json_file(
    path: &std::path::Path,
    value: &serde_json::Value,
    label: &str,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {label} directory failed: {error}"))?;
        }
    }

    let content = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {label} failed: {error}"))?;
    std::fs::write(path, content).map_err(|error| format!("write {label} failed: {error}"))?;
    Ok(())
}

fn is_mainline_e2e_artifact_report(report: &serde_json::Value) -> bool {
    report.get("kind").and_then(serde_json::Value::as_str) == Some(MAINLINE_E2E_ARTIFACT_KIND)
}

fn write_mainline_e2e_artifacts(report: &serde_json::Value) -> Result<std::path::PathBuf, String> {
    let run_id = report
        .get("run_id")
        .and_then(serde_json::Value::as_str)
        .map(safe_artifact_path_segment)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "mainline E2E report is missing run_id".to_string())?;
    let artifact_date = report
        .get("artifact_date")
        .and_then(serde_json::Value::as_str)
        .map(safe_artifact_path_segment)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-date".to_string());
    let artifact_dir = mainline_e2e_artifact_root()
        .join(artifact_date)
        .join(run_id);
    std::fs::create_dir_all(&artifact_dir)
        .map_err(|error| format!("create mainline E2E artifact directory failed: {error}"))?;

    let mut summary = report.clone();
    if let Some(object) = summary.as_object_mut() {
        object.remove("metrics_csv");
    }
    write_json_file(
        &artifact_dir.join("summary.json"),
        &summary,
        "mainline E2E summary",
    )?;

    let timeline = serde_json::json!({
        "run_id": report.get("run_id").cloned().unwrap_or(serde_json::Value::Null),
        "scenario_id": report.get("scenario_id").cloned().unwrap_or(serde_json::Value::Null),
        "generated_at": report.get("generated_at").cloned().unwrap_or(serde_json::Value::Null),
        "stage_events": report.get("stage_events").cloned().unwrap_or_else(|| serde_json::json!([])),
        "fault_events": report.get("fault_events").cloned().unwrap_or_else(|| serde_json::json!([])),
    });
    write_json_file(
        &artifact_dir.join("timeline.json"),
        &timeline,
        "mainline E2E timeline",
    )?;

    let metrics_csv = report
        .get("metrics_csv")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(
            "timestamp,sample_duration_ms,frames_decoded,frames_dropped,render_frames_presented\n",
        );
    std::fs::write(artifact_dir.join("metrics.csv"), metrics_csv)
        .map_err(|error| format!("write mainline E2E metrics failed: {error}"))?;

    write_mainline_e2e_structured_logs(&artifact_dir, report)?;
    let first_frame_written = write_optional_base64_png(
        report,
        "first_frame_png_base64",
        &artifact_dir.join("first-frame.png"),
    )?;
    let last_frame_written = write_optional_base64_png(
        report,
        "last_frame_png_base64",
        &artifact_dir.join("last-frame.png"),
    )?;

    let mut generated_paths = vec![
        "summary.json".to_string(),
        "timeline.json".to_string(),
        "metrics.csv".to_string(),
        "controller.log".to_string(),
        "agent.log".to_string(),
    ];
    if first_frame_written {
        generated_paths.push("first-frame.png".to_string());
    }
    if last_frame_written {
        generated_paths.push("last-frame.png".to_string());
    }

    if report
        .get("final_status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|status| status != "completed")
        || report.get("failure_reason").is_some()
        || report.get("human_message").is_some()
    {
        let failure_reason = report
            .get("failure_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("none");
        let human_message = report
            .get("human_message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let failure_text = format!(
            "status: {}\nfailure_reason: {failure_reason}\nhuman_message: {human_message}\n",
            report
                .get("final_status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
        );
        std::fs::write(artifact_dir.join("failure.txt"), failure_text)
            .map_err(|error| format!("write mainline E2E failure report failed: {error}"))?;
        generated_paths.push("failure.txt".to_string());
    }

    let missing_optional_paths = [
        (!first_frame_written).then_some("first-frame.png"),
        (!last_frame_written).then_some("last-frame.png"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    generated_paths.push("artifact_manifest.json".to_string());
    let manifest = serde_json::json!({
        "schema_version": 1,
        "run_id": report.get("run_id").cloned().unwrap_or(serde_json::Value::Null),
        "scenario_id": report.get("scenario_id").cloned().unwrap_or(serde_json::Value::Null),
        "generated_at": report.get("generated_at").cloned().unwrap_or(serde_json::Value::Null),
        "artifact_descriptors": report.get("artifacts").cloned().unwrap_or_else(|| serde_json::json!([])),
        "generated_paths": generated_paths,
        "missing_optional_paths": missing_optional_paths,
    });
    write_json_file(
        &artifact_dir.join("artifact_manifest.json"),
        &manifest,
        "mainline E2E artifact manifest",
    )?;

    Ok(artifact_dir)
}

fn write_mainline_e2e_structured_logs(
    artifact_dir: &std::path::Path,
    report: &serde_json::Value,
) -> Result<(), String> {
    let controller_log = serde_json::json!({
        "role": "controller",
        "run_id": report.get("run_id").cloned().unwrap_or(serde_json::Value::Null),
        "scenario_id": report.get("scenario_id").cloned().unwrap_or(serde_json::Value::Null),
        "git_commit": report.get("git_commit").cloned().unwrap_or(serde_json::Value::Null),
        "controller": report.get("controller").cloned().unwrap_or(serde_json::Value::Null),
        "summary": report.get("summary").cloned().unwrap_or(serde_json::Value::Null),
        "classification": report.get("classification").cloned().unwrap_or(serde_json::Value::Null),
    });
    write_structured_log_file(
        &artifact_dir.join("controller.log"),
        "Mainline E2E Controller Log",
        &controller_log,
    )?;

    let agent_log = serde_json::json!({
        "role": "agent",
        "run_id": report.get("run_id").cloned().unwrap_or(serde_json::Value::Null),
        "scenario_id": report.get("scenario_id").cloned().unwrap_or(serde_json::Value::Null),
        "agent": report.get("agent").cloned().unwrap_or(serde_json::Value::Null),
        "available": report.get("agent").is_some(),
    });
    write_structured_log_file(
        &artifact_dir.join("agent.log"),
        "Mainline E2E Agent Log",
        &agent_log,
    )
}

fn write_structured_log_file(
    path: &std::path::Path,
    title: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| format!("serialize mainline E2E structured log failed: {error}"))?;
    std::fs::write(path, format!("# {title}\n\n{json}\n"))
        .map_err(|error| format!("write mainline E2E structured log failed: {error}"))
}

fn write_optional_base64_png(
    report: &serde_json::Value,
    field: &str,
    path: &std::path::Path,
) -> Result<bool, String> {
    let Some(encoded) = report
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };
    let encoded = encoded
        .split_once("base64,")
        .map(|(_, payload)| payload)
        .unwrap_or(encoded);
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| format!("decode {field} failed: {error}"))?;
    std::fs::write(path, bytes).map_err(|error| format!("write {field} failed: {error}"))?;
    Ok(true)
}

fn mainline_e2e_artifact_root() -> std::path::PathBuf {
    std::env::var(MAINLINE_E2E_ARTIFACT_ROOT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join("artifacts")
                .join("e2e")
        })
}

fn safe_artifact_path_segment(value: &str) -> String {
    let trimmed = value.trim().trim_matches('.');
    let mut segment = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            segment.push(ch);
        } else {
            segment.push('-');
        }
    }
    segment.trim_matches('-').to_string()
}

#[cfg(test)]
mod automation_report_tests {
    use super::*;

    #[test]
    fn mainline_e2e_artifact_writer_creates_canonical_files() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-e2e-artifacts")
            .join(format!("writer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var(MAINLINE_E2E_ARTIFACT_ROOT_ENV, &root);

        let report = serde_json::json!({
            "kind": MAINLINE_E2E_ARTIFACT_KIND,
            "schema_version": 1,
            "run_id": "run:one",
            "artifact_date": "2026-06-11",
            "generated_at": 1781157600000u64,
            "git_commit": "abc123",
            "scenario_id": "cross.e2e.remote_display_smoke",
            "final_status": "failed",
            "failure_reason": "no_remote_frames",
            "human_message": "no frames arrived",
            "agent": {
                "device_id": "agent-device",
                "service_build_id": "abc123"
            },
            "artifacts": [
                {
                    "path": "summary.json",
                    "kind": "summary_json",
                    "required": true,
                    "status": "generated"
                }
            ],
            "stage_events": [{"stage": "sample", "status": "failed"}],
            "fault_events": [],
            "metrics_csv": "timestamp,frames_decoded\n1781157600000,0\n",
            "first_frame_png_base64": "AQID",
        });

        let artifact_dir = write_mainline_e2e_artifacts(&report).unwrap();

        assert_eq!(artifact_dir, root.join("2026-06-11").join("run-one"));
        assert!(artifact_dir.join("summary.json").exists());
        assert!(artifact_dir.join("timeline.json").exists());
        assert!(artifact_dir.join("controller.log").exists());
        assert!(artifact_dir.join("agent.log").exists());
        assert!(artifact_dir.join("artifact_manifest.json").exists());
        assert_eq!(
            std::fs::read_to_string(artifact_dir.join("metrics.csv")).unwrap(),
            "timestamp,frames_decoded\n1781157600000,0\n"
        );
        assert_eq!(
            std::fs::read(artifact_dir.join("first-frame.png")).unwrap(),
            vec![1, 2, 3]
        );
        assert!(std::fs::read_to_string(artifact_dir.join("failure.txt"))
            .unwrap()
            .contains("failure_reason: no_remote_frames"));
        let manifest =
            std::fs::read_to_string(artifact_dir.join("artifact_manifest.json")).unwrap();
        assert!(manifest.contains("first-frame.png"));
        assert!(manifest.contains("last-frame.png"));

        std::env::remove_var(MAINLINE_E2E_ARTIFACT_ROOT_ENV);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn safe_artifact_path_segment_removes_path_separators() {
        assert_eq!(
            safe_artifact_path_segment("../run:one/device id"),
            "run-one-device-id"
        );
    }
}

// nvdec_runtime_probe - moved to rdesk-legacy-harness package
#[tauri::command]
fn nvdec_runtime_probe() -> Result<serde_json::Value, String> {
    Err(
        "nvdec_runtime_probe moved to mrd-service - use rdesk-legacy-harness for testing"
            .to_string(),
    )
}

#[tauri::command]
async fn decode_policy(_state: tauri::State<'_, AppState>) -> Result<DecodePolicyResponse, String> {
    // Decode policy is now managed by mrd-service
    // Return current policy from settings
    Err("Use IPC to query decode policy from mrd-service".to_string())
}

#[tauri::command]
async fn set_decode_policy(
    state: tauri::State<'_, AppState>,
    decode_policy: String,
) -> Result<DecodePolicyResponse, String> {
    let decode_policy = parse_decode_policy(&decode_policy)?;
    // Save to settings only - actual policy application happens in mrd-service
    set_decode_policy_with(&state.settings_path, decode_policy).await
}

#[tauri::command]
fn ffmpeg_probe(
    state: tauri::State<'_, AppState>,
) -> Result<mrd_ffmpeg::FfmpegProbeResult, String> {
    ffmpeg_probe_at_path(&state.settings_path)
}

#[tauri::command]
async fn ffmpeg_download(
    state: tauri::State<'_, AppState>,
) -> Result<mrd_ffmpeg::FfmpegInstallResult, String> {
    ffmpeg_download_at_path(&state.settings_path).await
}

#[tauri::command]
fn ffmpeg_reset_golden_settings(state: tauri::State<'_, AppState>) -> Result<AppSettings, String> {
    reset_ffmpeg_settings_at_path(&state.settings_path)
}

// ============================================================================
// Bootstrap Commands (Phase 6: bootstrap-only behavior)
// ============================================================================

/// Bootstrap mrd-service if not already running via IPC
/// Phase 6: This is the ONLY start method. Returns true if bootstrap was performed.
#[tauri::command]
async fn service_bootstrap_if_needed(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let manager = state.service_manager.clone();

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            manager
                .bootstrap_if_needed()
                .await
                .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Wait for service to be healthy (with timeout)
#[tauri::command]
async fn service_wait_for_healthy(
    state: tauri::State<'_, AppState>,
    timeout_secs: u64,
) -> Result<bool, String> {
    let manager = state.service_manager.clone();

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            manager
                .wait_for_healthy(timeout_secs)
                .await
                .map_err(|e| e.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Check if this instance bootstrapped the service
#[tauri::command]
async fn service_did_bootstrap(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let manager = state.service_manager.clone();

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { Ok(manager.did_bootstrap().await) })
    })
    .await
    .map_err(|e| e.to_string())?
}

// ============================================================================
// Shell / Lifecycle Commands (Phase 2)
// ============================================================================

/// Register UI presence with mrd-service
#[tauri::command]
async fn shell_ui_attached() -> Result<(), String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::UiAttached {
            pid: std::process::id(),
            executable_path: std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(String::from)),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::Ack => Ok(()),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Notify mrd-service that UI is detaching
#[tauri::command]
async fn shell_ui_detached(reason: String) -> Result<(), String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let detach_reason = match reason.as_str() {
        "user_close" => mrd_ipc::UiDetachReason::UserClose,
        "user_quit" => mrd_ipc::UiDetachReason::UserQuit,
        "crash" => mrd_ipc::UiDetachReason::Crash,
        "connection_lost" => mrd_ipc::UiDetachReason::ConnectionLost,
        _ => return Err(format!("Unknown detach reason: {}", reason)),
    };

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::UiDetached {
            pid: std::process::id(),
            reason: detach_reason,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::Ack => Ok(()),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get shell/service status
#[tauri::command]
async fn shell_get_status() -> Result<mrd_ipc::ShellStatusSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::GetShellStatus)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::ShellStatus { status } => Ok(status),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Request service shutdown (Phase 2: returns error until fully implemented)
#[tauri::command]
async fn shell_shutdown_service(mode: String) -> Result<(), String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let shutdown_mode = match mode.as_str() {
        "graceful" => mrd_ipc::ShutdownMode::Graceful,
        "force" => mrd_ipc::ShutdownMode::Force,
        "after_sessions" => mrd_ipc::ShutdownMode::AfterSessions,
        _ => return Err(format!("Unknown shutdown mode: {}", mode)),
    };

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ShutdownService {
            mode: shutdown_mode,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::Ack => Ok(()),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Quit UI and stop service (explicit user action)
///
/// Phase 6: This now uses IPC ShutdownService instead of directly stopping
/// the service process. Rdesk no longer owns service lifecycle.
#[tauri::command]
async fn shell_quit_ui_and_stop_service(app_handle: tauri::AppHandle) -> Result<(), String> {
    // Notify service that UI is detaching
    let _ = shell_ui_detached("user_quit".to_string()).await;

    // Stop all active sessions via IPC
    use mrd_ipc::{IpcRequest, IpcResponse};
    let mut client = mrd_ipc::client::IpcClient::new();
    if let Ok(IpcResponse::SessionList { sessions }) =
        client.send_request(IpcRequest::ListSessions).await
    {
        for session_info in sessions {
            let _ = client
                .send_request(IpcRequest::StopSession {
                    session_id: session_info.session_id,
                })
                .await;
        }
    }

    // Request service shutdown via IPC (Phase 6: service owns lifecycle)
    let _ = client
        .send_request(IpcRequest::ShutdownService {
            mode: mrd_ipc::ShutdownMode::Graceful,
        })
        .await;

    // Exit the UI application
    request_app_exit(&app_handle, "user_quit");
    Ok(())
}

// ============================================================================
// IPC-based commands (migrated to use mrd-service)
// ============================================================================

/// Register device via IPC (migrated version)
#[tauri::command]
async fn ipc_register_device(device_id: String, device_name: String) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::DeviceId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::RegisterDevice {
            device_id: DeviceId(device_id),
            device_name,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DeviceRegistered { device_id } => Ok(device_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List devices via IPC (migrated version)
#[tauri::command]
async fn ipc_list_devices() -> Result<Vec<mrd_ipc::DeviceInfo>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListDevices)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DeviceList { devices } => Ok(devices),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List service-owned device preferences via IPC.
#[tauri::command]
async fn ipc_get_device_preferences() -> Result<Vec<mrd_ipc::DevicePreference>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::GetDevicePreferences)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DevicePreferences { preferences } => Ok(preferences),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Update service-owned device preferences via IPC.
#[tauri::command]
async fn ipc_update_device_preference(
    device_id: String,
    update: mrd_ipc::DevicePreferenceUpdate,
) -> Result<mrd_ipc::DevicePreference, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::DeviceId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::UpdateDevicePreference {
            device_id: DeviceId(device_id),
            update,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DevicePreferenceUpdated { preference } => Ok(preference),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get LAN peer discovery snapshot via IPC.
#[tauri::command]
async fn ipc_lan_discovery_snapshot() -> Result<mrd_ipc::LanDiscoverySnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::LanDiscoverySnapshot)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::LanDiscoverySnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Trigger a LAN discovery probe via IPC.
#[tauri::command]
async fn ipc_refresh_lan_discovery() -> Result<mrd_ipc::LanDiscoverySnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::RefreshLanDiscovery)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::LanDiscoverySnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List a local directory through mrd-service IPC.
#[tauri::command]
async fn ipc_list_directory(path: Option<String>) -> Result<mrd_ipc::DirectoryList, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListDirectory { path })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DirectoryList { listing } => Ok(listing),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Start a service-owned file transfer through mrd-service IPC.
#[tauri::command]
async fn ipc_start_file_transfer(
    request: mrd_ipc::FileTransferStartRequest,
) -> Result<mrd_ipc::FileTransferTaskSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::StartFileTransfer { request })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::FileTransferStarted { transfer } => Ok(transfer),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List service-owned file transfer tasks through mrd-service IPC.
#[tauri::command]
async fn ipc_list_file_transfers() -> Result<Vec<mrd_ipc::FileTransferTaskSnapshot>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListFileTransfers)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::FileTransferList { transfers } => Ok(transfers),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List available and reserved file transfer providers through mrd-service IPC.
#[tauri::command]
async fn ipc_list_file_transfer_providers(
) -> Result<Vec<mrd_ipc::FileTransferProviderDescriptor>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListFileTransferProviders)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::FileTransferProviderList { providers } => Ok(providers),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Cancel a service-owned file transfer task through mrd-service IPC.
#[tauri::command]
async fn ipc_cancel_file_transfer(
    transfer_id: String,
) -> Result<mrd_ipc::FileTransferTaskSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::CancelFileTransfer { transfer_id })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::FileTransferCancelled { transfer } => Ok(transfer),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Send a Wake-on-LAN magic packet via mrd-service IPC.
#[tauri::command]
async fn ipc_wake_on_lan(
    device_id: String,
    mac_address: String,
    broadcast_addr: Option<String>,
) -> Result<WakeOnLanSentDto, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::DeviceId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::WakeOnLan {
            device_id: DeviceId(device_id),
            mac_address,
            broadcast_addr,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::WakeOnLanSent {
            device_id,
            mac_address,
            broadcast_addr,
            packet_bytes,
        } => Ok(WakeOnLanSentDto {
            device_id: device_id.0,
            mac_address,
            broadcast_addr,
            packet_bytes,
        }),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Request a remote device restart/shutdown through mrd-service IPC.
#[tauri::command]
async fn ipc_request_remote_device_power_action(
    device_id: String,
    action: mrd_ipc::RemoteDevicePowerAction,
) -> Result<RemoteDevicePowerActionAcceptedDto, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::DeviceId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::RequestRemoteDevicePowerAction {
            device_id: DeviceId(device_id),
            action,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::RemoteDevicePowerActionAccepted { device_id, action } => {
            Ok(RemoteDevicePowerActionAcceptedDto {
                device_id: device_id.0,
                action,
            })
        }
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Start session via IPC (migrated version)
#[tauri::command]
async fn ipc_start_session(
    session_id: String,
    target_device_id: String,
    transport_kind: String,
) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::{DeviceId, SessionId};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::StartSession {
            session_id: SessionId(session_id),
            target_device_id: DeviceId(target_device_id),
            transport_kind,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionStarted { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Start LAN P2P session via IPC and ask the peer to auto-accept it.
#[tauri::command]
async fn ipc_start_lan_remote_session(
    session_id: String,
    target_device_id: String,
    transport_kind: String,
    requested_profile: Option<mrd_ipc::MediaProfile>,
) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::{DeviceId, SessionId};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::StartLanRemoteSession {
            session_id: SessionId(session_id),
            target_device_id: DeviceId(target_device_id),
            transport_kind,
            requested_profile,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionStarted { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Request runtime media profile switch via IPC.
#[tauri::command]
async fn ipc_update_media_profile(
    session_id: String,
    requested_profile: mrd_ipc::MediaProfile,
) -> Result<mrd_ipc::MediaProfileNegotiation, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::UpdateMediaProfile {
            session_id: SessionId(session_id),
            requested_profile,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::MediaProfileUpdated { negotiation, .. } => Ok(negotiation),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Configure LAN media adaptation via IPC.
#[tauri::command]
async fn ipc_configure_media_adaptation(
    session_id: String,
    config: mrd_ipc::AdaptiveMediaConfig,
) -> Result<mrd_ipc::MediaAdaptationSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ConfigureMediaAdaptation {
            session_id: SessionId(session_id),
            config,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::MediaAdaptationConfigured { snapshot, .. } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Send keyboard/mouse control input via mrd-service IPC.
#[tauri::command]
async fn ipc_send_control_input(
    session_id: String,
    event: mrd_ipc::ControlInputEvent,
) -> Result<ControlInputAcceptedDto, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::SendControlInput {
            session_id: SessionId(session_id),
            event,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::ControlInputAccepted {
            session_id,
            lane,
            event_count,
        } => Ok(ControlInputAcceptedDto {
            session_id: session_id.0,
            lane,
            event_count,
        }),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Inject a test-only cross-device E2E fault via mrd-service IPC.
#[tauri::command]
async fn cross_e2e_inject_fault(
    session_id: String,
    fault_type: String,
    duration_ms: Option<u64>,
) -> Result<mrd_ipc::CrossE2EFaultInjectionResult, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::CrossE2EInjectFault {
            session_id: SessionId(session_id),
            fault_type,
            duration_ms,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::CrossE2EFaultInjected { result } => Ok(result),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List remote capture sources through mrd-service IPC.
#[tauri::command]
async fn ipc_list_remote_capture_sources(
    session_id: String,
    include_previews: bool,
    limit: Option<u32>,
) -> Result<Vec<mrd_ipc::CaptureSource>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListRemoteCaptureSources {
            session_id: SessionId(session_id),
            include_previews,
            limit,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::CaptureSourceList { sources, .. } => Ok(sources),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List local capture sources through mrd-service IPC.
#[tauri::command]
async fn ipc_list_local_capture_sources(
    include_previews: bool,
    limit: Option<u32>,
) -> Result<Vec<mrd_ipc::CaptureSource>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListLocalCaptureSources {
            include_previews,
            limit,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::LocalCaptureSourceList { sources } => Ok(sources),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Select a remote capture source through mrd-service IPC.
#[tauri::command]
async fn ipc_select_remote_capture_source(
    session_id: String,
    source_id: String,
) -> Result<mrd_ipc::CaptureSourceSelection, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::SelectRemoteCaptureSource {
            session_id: SessionId(session_id),
            source_id,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::CaptureSourceSelected { selection, .. } => Ok(selection),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List remote display modes through mrd-service IPC.
#[tauri::command]
async fn ipc_list_remote_display_modes(
    session_id: String,
) -> Result<Vec<mrd_ipc::DisplayMode>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListRemoteDisplayModes {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DisplayModeList { modes, .. } => Ok(modes),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Set remote display mode through mrd-service IPC.
#[tauri::command]
async fn ipc_set_remote_display_mode(
    session_id: String,
    mode: mrd_ipc::DisplayMode,
    restore_after_session: bool,
) -> Result<mrd_ipc::DisplayModeChange, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::SetRemoteDisplayMode {
            session_id: SessionId(session_id),
            mode,
            restore_after_session,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DisplayModeChanged { change, .. } => Ok(change),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Restore remote display mode through mrd-service IPC.
#[tauri::command]
async fn ipc_restore_remote_display_mode(
    session_id: String,
) -> Result<mrd_ipc::DisplayModeChange, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::RestoreRemoteDisplayMode {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::DisplayModeChanged { change, .. } => Ok(change),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Accept session via IPC (migrated version)
#[tauri::command]
async fn ipc_accept_session(
    session_id: String,
    source_device_id: String,
) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::{DeviceId, SessionId};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::AcceptSession {
            session_id: SessionId(session_id),
            source_device_id: DeviceId(source_device_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionAccepted { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Stop session via IPC (migrated version)
#[tauri::command]
async fn ipc_stop_session(session_id: String) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::StopSession {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionStopped { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Mark a session failed via IPC.
#[tauri::command]
async fn ipc_fail_session(session_id: String, reason: String) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::FailSession {
            session_id: SessionId(session_id),
            reason,
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionFailed { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Recover a failed or closed session via IPC.
#[tauri::command]
async fn ipc_recover_session(session_id: String) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::RecoverSession {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionRecovered { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get session snapshot via IPC (migrated version)
#[tauri::command]
async fn ipc_session_snapshot(
    session_id: String,
) -> Result<mrd_ipc::SessionRuntimeSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::SessionRuntimeSnapshot {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionSnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Start sender via IPC (migrated version)
#[tauri::command]
async fn ipc_start_sender(session_id: String) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::StartSender {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SenderStarted { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Start receiver via IPC (migrated version)
#[tauri::command]
async fn ipc_start_receiver(session_id: String) -> Result<String, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::StartReceiver {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::ReceiverStarted { session_id } => Ok(session_id.0),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// List sessions via IPC (migrated version)
#[tauri::command]
async fn ipc_list_sessions() -> Result<Vec<mrd_ipc::SessionInfo>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListSessions)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::SessionList { sessions } => Ok(sessions),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Reject requests outside the narrow secure remote-session passthrough surface.
fn ensure_secure_remote_request(request: &mrd_ipc::IpcRequest) -> Result<(), String> {
    if request.is_secure_remote() {
        Ok(())
    } else {
        Err(
            "E_SECURE_REMOTE_REQUEST_REQUIRED: ipc_secure_remote only accepts secure remote-session requests"
                .to_string(),
        )
    }
}

/// Forward an allowlisted secure remote-session contract to the local service.
#[tauri::command]
async fn ipc_secure_remote(request: mrd_ipc::IpcRequest) -> Result<mrd_ipc::IpcResponse, String> {
    ensure_secure_remote_request(&request)?;
    let mut client = mrd_ipc::client::IpcClient::new();
    client
        .send_request(request)
        .await
        .map_err(|error| error.to_string())
}

/// Get runtime snapshot via IPC (migrated version)
#[tauri::command]
async fn ipc_runtime_snapshot() -> Result<mrd_ipc::RuntimeSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::RuntimeSnapshot)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::RuntimeSnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Query service-owned audit events via IPC.
#[tauri::command]
async fn ipc_audit_log(query: mrd_ipc::AuditLogQuery) -> Result<Vec<mrd_ipc::AuditEvent>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::AuditLog { query })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::AuditLog { events } => Ok(events),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get structured local capability snapshot via IPC.
#[tauri::command]
async fn ipc_capability_snapshot() -> Result<mrd_ipc::CapabilitySnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::CapabilitySnapshot)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::CapabilitySnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get a discovered LAN peer capability snapshot via IPC.
#[tauri::command]
async fn ipc_peer_capability_snapshot(
    peer_device_id: String,
) -> Result<Option<mrd_ipc::CapabilitySnapshot>, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::DeviceId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::GetPeerCapabilitySnapshot {
            peer_device_id: DeviceId(peer_device_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::PeerCapabilitySnapshot { snapshot, .. } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Service health check via IPC (migrated version)
#[tauri::command]
async fn ipc_service_health() -> Result<mrd_ipc::ServiceStatus, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ServiceHealth)
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::ServiceHealth { status } => Ok(status),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get probe snapshot via IPC (migrated version)
#[tauri::command]
async fn ipc_probe_snapshot(session_id: String) -> Result<mrd_ipc::ProbeSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ProbeSnapshot {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::ProbeSnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

/// Get receiver media pipeline snapshot via IPC.
#[tauri::command]
async fn ipc_media_pipeline_snapshot(
    session_id: String,
) -> Result<mrd_ipc::MediaPipelineSnapshot, String> {
    use mrd_ipc::{IpcRequest, IpcResponse};
    use mrd_proto::SessionId;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::MediaPipelineSnapshot {
            session_id: SessionId(session_id),
        })
        .await
        .map_err(|e| e.to_string())?;

    match response {
        IpcResponse::MediaPipelineSnapshot { snapshot } => Ok(snapshot),
        IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

// Legacy Tauri commands removed - use rdesk-legacy-harness package for testing

// Example of migrated WebRTC command using IPC
#[tauri::command]
async fn webrtc_session_list_via_ipc() -> Result<Vec<String>, String> {
    use mrd_ipc::IpcRequest;

    let mut client = mrd_ipc::client::IpcClient::new();
    let response = client
        .send_request(IpcRequest::ListDevices)
        .await
        .map_err(|e| format!("IPC error: {}", e))?;

    match response {
        mrd_ipc::IpcResponse::DeviceList { devices } => {
            Ok(devices.into_iter().map(|d| d.device_id.0).collect())
        }
        mrd_ipc::IpcResponse::Error { code, message } => Err(format!("{}: {}", code, message)),
        _ => Err("Unexpected response".to_string()),
    }
}

// Legacy Tauri commands removed - use rdesk-legacy-harness package for testing

/// Tauri 命令：设备注册
///
/// 调用后端 API 进行设备注册，后端根据主板序列号生成设备ID
#[tauri::command]
async fn register_device(
    motherboard_serial: String,
    hostname: String,
    os_version: String,
    device_name: Option<String>,
) -> Result<DeviceRegistrationResponse, String> {
    // 构建注册请求
    let client = reqwest::Client::new();
    let mut payload = HashMap::new();
    payload.insert("motherboard_serial", motherboard_serial);
    payload.insert("hostname", hostname);
    payload.insert("os_version", os_version);

    if let Some(name) = device_name {
        payload.insert("device_name", name);
    }

    // 调用后端 API
    let response = client
        .post("http://127.0.0.1:9530/api/v1/devices/register")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("连接服务器失败: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "未知错误".to_string());
        return Err(format!("注册失败 ({}): {}", status, error_text));
    }

    response
        .json::<DeviceRegistrationResponse>()
        .await
        .map_err(|e| format!("解析响应失败: {}", e))
}

/// Tauri 命令：检查设备是否已注册
#[tauri::command]
async fn check_device_registration(motherboard_serial: String) -> Result<bool, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://127.0.0.1:9530/api/v1/devices/check/{}",
            motherboard_serial
        ))
        .send()
        .await
        .map_err(|e| format!("连接服务器失败: {}", e))?;

    Ok(response.status().is_success())
}

fn parse_decode_policy(value: &str) -> Result<DecodePolicy, String> {
    match value {
        "auto" => Ok(DecodePolicy::Auto),
        "software" => Ok(DecodePolicy::Software),
        "d3d11va" => Ok(DecodePolicy::D3d11va),
        "nvdec" => Ok(DecodePolicy::Nvdec),
        other => Err(format!("未知 decode policy: {other}")),
    }
}

async fn set_decode_policy_with(
    settings_path: &std::path::Path,
    decode_policy: DecodePolicy,
) -> Result<DecodePolicyResponse, String> {
    // Save policy to settings - actual decode policy application now happens in mrd-service
    let mut settings = load_settings(settings_path)?;
    settings.decode_policy = decode_policy;
    save_settings(settings_path, &settings)?;
    Ok(DecodePolicyResponse {
        decode_policy: decode_policy.as_str().to_string(),
    })
}

fn ffmpeg_probe_at_path(
    settings_path: &std::path::Path,
) -> Result<mrd_ffmpeg::FfmpegProbeResult, String> {
    let settings = load_settings(settings_path)?;
    Ok(mrd_ffmpeg::probe_ffmpeg(&settings.ffmpeg))
}

async fn ffmpeg_download_at_path(
    settings_path: &std::path::Path,
) -> Result<mrd_ffmpeg::FfmpegInstallResult, String> {
    let settings = load_settings(settings_path)?;
    mrd_ffmpeg::download_ffmpeg(&settings.ffmpeg)
        .await
        .map_err(|error| error.to_string())
}

fn reset_ffmpeg_settings_at_path(settings_path: &std::path::Path) -> Result<AppSettings, String> {
    let mut settings = load_settings(settings_path)?;
    settings.ffmpeg = mrd_ffmpeg::golden_settings();
    save_settings(settings_path, &settings)?;
    Ok(settings)
}

// ============================================================================
// Test harness commands - end-to-end pipeline visualization
// ============================================================================

#[tauri::command]
async fn test_harness_start(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let test_harness = state.test_harness.clone();
    tokio::task::spawn_blocking(move || {
        test_harness
            .lock()
            .unwrap()
            .start_replacing_existing()
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_harness_stop(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let test_harness = state.test_harness.clone();
    tokio::task::spawn_blocking(move || {
        test_harness
            .lock()
            .unwrap()
            .stop()
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn test_harness_set_chain(state: tauri::State<'_, AppState>, chain: String) -> Result<(), String> {
    use test_harness::TestChain;
    let parsed = match chain.as_str() {
        "capture_only" => TestChain::CaptureOnly,
        "nvenc_nvdec" => TestChain::NvencNvdec,
        "nvenc_only" => TestChain::NvencOnly,
        "openh264" => TestChain::OpenH264,
        _ => return Err(format!("未知的测试链路: {}", chain)),
    };
    state.test_harness.lock().unwrap().set_chain(parsed);
    Ok(())
}

#[tauri::command]
fn test_harness_set_custom(
    state: tauri::State<'_, AppState>,
    capture: String,
    encoder: String,
    decoder: String,
) -> Result<(), String> {
    use test_harness::{CaptureType, DecoderType, EncoderType, TestChain};

    let capture = match capture.as_str() {
        "dxgi" => CaptureType::Dxgi,
        "winrt" => CaptureType::Winrt,
        "macos" => CaptureType::Macos,
        #[cfg(target_os = "linux")]
        "linux" => CaptureType::Linux,
        "synthetic" => CaptureType::Synthetic,
        _ => return Err(format!("Unsupported capture type: {}", capture)),
    };
    let encoder = match encoder.as_str() {
        "none" => EncoderType::None,
        "nvenc_h264" => EncoderType::NvencH264,
        "nvenc_av1" => EncoderType::NvencAv1,
        "nvenc_hevc" | "hevc" => EncoderType::NvencHevc,
        "nvenc_hevc_main10" | "hevc_main10" | "hevc-main10" => EncoderType::NvencHevcMain10,
        "openh264" | "software_h264" | "h264_software" | "software-h264" | "h264-software"
        | "sw_h264" => EncoderType::OpenH264,
        "videotoolbox_h264" | "videotoolbox" => EncoderType::VideoToolboxH264,
        "videotoolbox_hevc" => EncoderType::VideoToolboxHevc,
        _ => return Err(format!("Unsupported encoder type: {}", encoder)),
    };
    let decoder = match decoder.as_str() {
        "none" => DecoderType::None,
        "nvdec" => DecoderType::Nvdec,
        "software" | "software_h264" | "h264_software" | "software-h264" | "h264-software"
        | "openh264" => DecoderType::Software,
        "ffmpeg_vvc" | "vvc_ffmpeg" | "ffmpeg_h266" | "h266_ffmpeg" => DecoderType::FfmpegVvc,
        "linux_h264" | "gstreamer_h264" | "vaapi_h264" => DecoderType::LinuxH264,
        "linux_hevc" | "gstreamer_hevc" | "vaapi_hevc" => DecoderType::LinuxHevc,
        "linux_hevc_main10" | "gstreamer_hevc_main10" | "vaapi_hevc_main10" => {
            DecoderType::LinuxHevcMain10
        }
        "videotoolbox" => DecoderType::VideoToolbox,
        _ => return Err(format!("Unsupported decoder type: {}", decoder)),
    };

    state
        .test_harness
        .lock()
        .unwrap()
        .set_chain(TestChain::Custom {
            capture,
            encoder,
            decoder,
        });
    Ok(())
}

#[tauri::command]
fn test_harness_get_chain(state: tauri::State<'_, AppState>) -> String {
    use test_harness::TestChain;
    match state.test_harness.lock().unwrap().get_chain() {
        TestChain::CaptureOnly => "capture_only".to_string(),
        TestChain::NvencNvdec => "nvenc_nvdec".to_string(),
        TestChain::NvencOnly => "nvenc_only".to_string(),
        TestChain::OpenH264 => "openh264".to_string(),
        #[cfg(target_os = "linux")]
        TestChain::LinuxOpenh264 => "linux_openh264".to_string(),
        TestChain::Custom { .. } => "custom".to_string(),
    }
}

#[tauri::command]
async fn test_harness_get_metrics(
    state: tauri::State<'_, AppState>,
) -> Result<test_harness::HarnessMetrics, String> {
    let test_harness = state.test_harness.clone();
    tokio::task::spawn_blocking(move || Ok(test_harness.lock().unwrap().get_metrics()))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_harness_get_comparison_result(
    state: tauri::State<'_, AppState>,
) -> Result<mrd_observability::PipelineComparisonResult, String> {
    let test_harness = state.test_harness.clone();
    tokio::task::spawn_blocking(move || {
        Ok(test_harness
            .lock()
            .unwrap()
            .get_pipeline_comparison_result())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod frame_encoding_tests {
    use super::*;

    #[test]
    fn native_probe_frame_is_bgra_and_non_empty() {
        let frame = build_native_probe_frame(64, 48);

        assert_eq!(frame.width, 64);
        assert_eq!(frame.height, 48);
        assert_eq!(frame.pixel_format, mrd_render::RenderPixelFormat::Bgra32);
        assert_eq!(frame.as_bgra32().unwrap().len(), 64 * 48 * 4);
    }
}

// ============================================================================
// Test Workbench Commands (New Unified Test API)
// ============================================================================

/// List all available test scenarios
#[tauri::command]
fn test_list_scenarios(state: tauri::State<'_, AppState>) -> Vec<test_orchestrator::TestScenario> {
    state.test_orchestrator.list_scenarios()
}

/// Get environment capabilities
#[tauri::command]
async fn test_get_capabilities(
    state: tauri::State<'_, AppState>,
) -> Result<test_orchestrator::EnvironmentSnapshot, String> {
    let orchestrator = state.test_orchestrator.clone();
    tokio::task::spawn_blocking(move || orchestrator.get_capabilities().map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}

/// List visible top-level windows that can be used as platform capture targets.
#[tauri::command]
fn test_list_window_capture_targets() -> Result<Vec<test_orchestrator::WindowCaptureTarget>, String>
{
    test_orchestrator::list_window_capture_targets().map_err(|e| e.to_string())
}

/// Legacy preview command. Image payloads are disabled; returns target metadata only.
#[tauri::command]
fn test_list_window_capture_targets_with_previews(
    limit: Option<usize>,
) -> Result<Vec<test_orchestrator::WindowCaptureTarget>, String> {
    test_orchestrator::list_window_capture_targets_with_previews(limit).map_err(|e| e.to_string())
}

/// List cross-platform screen sharing sources.
#[tauri::command]
fn test_list_capture_share_sources(
) -> Result<Vec<test_orchestrator::CaptureShareSourceTarget>, String> {
    test_orchestrator::list_capture_share_sources().map_err(|e| e.to_string())
}

/// List cross-platform screen sharing sources and attach best-effort window previews.
#[tauri::command]
fn test_list_capture_share_sources_with_previews(
    limit: Option<usize>,
) -> Result<Vec<test_orchestrator::CaptureShareSourceTarget>, String> {
    test_orchestrator::list_capture_share_sources_with_previews(limit).map_err(|e| e.to_string())
}

/// Start a test run
#[tauri::command]
async fn test_start_run(
    state: tauri::State<'_, AppState>,
    scenario_id: String,
    config: test_orchestrator::TestConfigData,
) -> Result<String, String> {
    let orchestrator = state.test_orchestrator.clone();
    tokio::task::spawn_blocking(move || {
        orchestrator
            .start_run(scenario_id, config)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn test_record_external_run(
    state: tauri::State<'_, AppState>,
    record: test_orchestrator::ExternalTestRunRecord,
) -> Result<String, String> {
    let orchestrator = state.test_orchestrator.clone();
    tokio::task::spawn_blocking(move || {
        orchestrator
            .record_external_run(record)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Stop a test run
#[tauri::command]
async fn test_stop_run(state: tauri::State<'_, AppState>, run_id: String) -> Result<(), String> {
    let orchestrator = state.test_orchestrator.clone();
    tokio::task::spawn_blocking(move || orchestrator.stop_run(&run_id).map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}

/// List test runs
#[tauri::command]
fn test_list_runs(
    state: tauri::State<'_, AppState>,
    scenario_id: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
) -> Vec<test_orchestrator::TestRun> {
    state
        .test_orchestrator
        .list_runs(scenario_id, status, limit)
}

/// Get a test run
#[tauri::command]
fn test_get_run(
    state: tauri::State<'_, AppState>,
    run_id: String,
) -> Option<test_orchestrator::TestRun> {
    state.test_orchestrator.get_run(&run_id)
}

/// Get run events
#[tauri::command]
fn test_get_run_events(
    state: tauri::State<'_, AppState>,
    run_id: String,
) -> Vec<test_orchestrator::TestStageEvent> {
    state.test_orchestrator.get_run_events(&run_id)
}

/// Get run metrics
#[tauri::command]
fn test_get_run_metrics(
    state: tauri::State<'_, AppState>,
    run_id: String,
) -> std::collections::HashMap<String, test_orchestrator::MetricSeries> {
    state.test_orchestrator.get_run_metrics(&run_id)
}

/// Get run artifacts
#[tauri::command]
fn test_get_run_artifacts(
    state: tauri::State<'_, AppState>,
    run_id: String,
) -> Vec<test_orchestrator::Artifact> {
    state.test_orchestrator.get_run_artifacts(&run_id)
}

/// Get a test run with persisted telemetry.
#[tauri::command]
fn test_get_run_telemetry(
    state: tauri::State<'_, AppState>,
    run_id: String,
    query: Option<mrd_test_telemetry::TelemetryQuery>,
) -> Result<mrd_test_telemetry::TelemetryBundle, String> {
    state
        .test_orchestrator
        .get_run_telemetry(&run_id, query.unwrap_or_default())
        .map_err(|error| error.to_string())
}

/// List test presets
#[tauri::command]
fn test_list_presets(state: tauri::State<'_, AppState>) -> Vec<test_orchestrator::TestPreset> {
    state.test_orchestrator.list_presets()
}

/// Save a test preset
#[tauri::command]
fn test_save_preset(
    state: tauri::State<'_, AppState>,
    name: String,
    description: String,
    scenario_id: String,
    config: test_orchestrator::TestConfigData,
) -> String {
    state
        .test_orchestrator
        .save_preset(name, description, scenario_id, config)
}

/// Delete a test preset
#[tauri::command]
fn test_delete_preset(state: tauri::State<'_, AppState>, preset_id: String) -> Result<(), String> {
    state
        .test_orchestrator
        .delete_preset(&preset_id)
        .map_err(|e| e.to_string())
}

fn main_window(app: &AppHandle) -> Result<WebviewWindow, String> {
    app.get_webview_window("main")
        .ok_or_else(|| "main window not found".to_string())
}

fn show_main_window(app: &AppHandle) -> Result<(), String> {
    let window = main_window(app)?;
    let _ = window.unminimize();
    window.show().map_err(|err| err.to_string())?;
    window.set_focus().map_err(|err| err.to_string())?;
    Ok(())
}

fn hide_main_window(app: &AppHandle) -> Result<(), String> {
    main_window(app)?.hide().map_err(|err| err.to_string())
}

fn detach_ui_async(reason: &'static str) {
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Runtime::new() else {
            return;
        };
        rt.block_on(async move {
            let _ = shell_ui_detached(reason.to_string()).await;
        });
    });
}

fn claim_single_instance() -> Option<TcpListener> {
    let addr = single_instance_addr();
    match TcpListener::bind(&addr) {
        Ok(listener) => Some(listener),
        Err(_) => {
            if let Ok(mut stream) = TcpStream::connect(&addr) {
                let _ = stream.write_all(b"show\n");
            }
            None
        }
    }
}

fn single_instance_addr() -> String {
    single_instance_addr_from_env_value(
        std::env::var(RDESK_SINGLE_INSTANCE_ADDR_ENV)
            .ok()
            .as_deref(),
    )
}

fn single_instance_addr_from_env_value(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(SINGLE_INSTANCE_ADDR)
        .to_string()
}

fn spawn_single_instance_listener(listener: TcpListener, app: AppHandle) {
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            if incoming.is_err() {
                continue;
            }
            if APP_IS_QUITTING.load(Ordering::SeqCst) {
                break;
            }
            if let Err(error) = show_main_window(&app) {
                eprintln!("failed to show existing Rdesk instance: {error}");
            }
        }
    });
}

fn request_app_exit(app: &AppHandle, reason: &'static str) {
    if APP_IS_QUITTING.swap(true, Ordering::SeqCst) {
        return;
    }

    detach_ui_async(reason);
    for window in app.webview_windows().into_values() {
        let _ = window.close();
    }
    app.exit(0);

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(750));
        std::process::exit(0);
    });
}

fn setup_system_tray(app: &AppHandle) -> tauri::Result<()> {
    let show_item = MenuItem::with_id(app, TRAY_MENU_SHOW_ID, "显示主窗口", true, None::<&str>)?;
    let hide_item = MenuItem::with_id(app, TRAY_MENU_HIDE_ID, "隐藏到托盘", true, None::<&str>)?;
    let center_item = MenuItem::with_id(app, TRAY_MENU_CENTER_ID, "居中窗口", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, TRAY_MENU_QUIT_ID, "退出 Rdesk", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[&show_item, &hide_item, &center_item, &separator, &quit_item],
    )?;
    let icon = app.default_window_icon().cloned().unwrap_or_else(|| {
        let image = image::load_from_memory(include_bytes!("../icons/tray-icon.png"))
            .expect("embedded tray icon should be a valid PNG")
            .into_rgba8();
        let (width, height) = image.dimensions();
        tauri::image::Image::new_owned(image.into_raw(), width, height)
    });

    TrayIconBuilder::with_id(TRAY_ICON_ID)
        .icon(icon)
        .tooltip("Rdesk")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .build(app)?;

    Ok(())
}

fn tray_action_from_menu_id(id: &str) -> Option<TrayAction> {
    match id {
        TRAY_MENU_SHOW_ID => Some(TrayAction::ShowWindow),
        TRAY_MENU_HIDE_ID => Some(TrayAction::HideWindow),
        TRAY_MENU_CENTER_ID => Some(TrayAction::CenterWindow),
        TRAY_MENU_QUIT_ID => Some(TrayAction::QuitUi),
        _ => None,
    }
}

fn tray_action_from_icon_event(event: &TrayIconEvent) -> Option<TrayAction> {
    match event {
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }
        | TrayIconEvent::DoubleClick {
            button: MouseButton::Left,
            ..
        } => Some(TrayAction::ShowWindow),
        _ => None,
    }
}

fn apply_tray_action(app: &AppHandle, action: TrayAction) -> Result<(), String> {
    match action {
        TrayAction::ShowWindow => show_main_window(app),
        TrayAction::HideWindow => hide_main_window(app),
        TrayAction::CenterWindow => main_window(app)?.center().map_err(|err| err.to_string()),
        TrayAction::QuitUi => {
            request_app_exit(app, "user_quit");
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LanE2eAutorunLaunchConfig {
    scenario_id: Option<String>,
    target_device_id: Option<String>,
    transport: Option<String>,
    timeout_ms: Option<String>,
    min_sample_duration_ms: Option<String>,
    min_decoded_frames: Option<String>,
    min_fps: Option<String>,
    min_render_fps: Option<String>,
    stop_on_complete: Option<String>,
    profile_width: Option<String>,
    profile_height: Option<String>,
    profile_fps: Option<String>,
    profile_bitrate_mbps: Option<String>,
    profile_codec: Option<String>,
    profile_codec_profile: Option<String>,
    profile_bit_depth: Option<String>,
    profile_chroma_subsampling: Option<String>,
    profile_pixel_format: Option<String>,
    profile_hdr_enabled: Option<String>,
    profile_color_mode: Option<String>,
    profile_color_pipeline: Option<String>,
    display_mode_policy: Option<String>,
    capture_source_id: Option<String>,
    capture_source_kind: Option<String>,
    render_display_source_id: Option<String>,
    expected_peer_build_id: Option<String>,
    render_profile_cap: Option<String>,
    render_display: Option<String>,
    adaptive: Option<String>,
}

fn lan_e2e_autorun_config_from_env() -> Option<LanE2eAutorunLaunchConfig> {
    lan_e2e_autorun_config_from_env_lookup(|key| std::env::var(key).ok())
}

fn lan_e2e_autorun_config_from_env_lookup<F>(env: F) -> Option<LanE2eAutorunLaunchConfig>
where
    F: Fn(&str) -> Option<String>,
{
    let enabled = env(LAN_E2E_AUTORUN_ENV)?;
    if !is_truthy_env_value(&enabled) {
        return None;
    }

    Some(LanE2eAutorunLaunchConfig {
        scenario_id: non_empty_env(env(LAN_E2E_SCENARIO_ENV)),
        target_device_id: non_empty_env(env(LAN_E2E_TARGET_DEVICE_ID_ENV)),
        transport: non_empty_env(env(LAN_E2E_TRANSPORT_ENV)),
        timeout_ms: non_empty_env(env(LAN_E2E_TIMEOUT_MS_ENV)),
        min_sample_duration_ms: non_empty_env(env(LAN_E2E_MIN_SAMPLE_DURATION_MS_ENV)),
        min_decoded_frames: non_empty_env(env(LAN_E2E_MIN_DECODED_FRAMES_ENV)),
        min_fps: non_empty_env(env(LAN_E2E_MIN_FPS_ENV)),
        min_render_fps: non_empty_env(env(LAN_E2E_MIN_RENDER_FPS_ENV)),
        stop_on_complete: non_empty_env(env(LAN_E2E_STOP_ON_COMPLETE_ENV)),
        profile_width: non_empty_env(env(LAN_E2E_PROFILE_WIDTH_ENV)),
        profile_height: non_empty_env(env(LAN_E2E_PROFILE_HEIGHT_ENV)),
        profile_fps: non_empty_env(env(LAN_E2E_PROFILE_FPS_ENV)),
        profile_bitrate_mbps: non_empty_env(env(LAN_E2E_PROFILE_BITRATE_MBPS_ENV)),
        profile_codec: non_empty_env(env(LAN_E2E_PROFILE_CODEC_ENV)),
        profile_codec_profile: non_empty_env(env(LAN_E2E_PROFILE_CODEC_PROFILE_ENV)),
        profile_bit_depth: non_empty_env(env(LAN_E2E_PROFILE_BIT_DEPTH_ENV)),
        profile_chroma_subsampling: non_empty_env(env(LAN_E2E_PROFILE_CHROMA_SUBSAMPLING_ENV)),
        profile_pixel_format: non_empty_env(env(LAN_E2E_PROFILE_PIXEL_FORMAT_ENV)),
        profile_hdr_enabled: non_empty_env(env(LAN_E2E_PROFILE_HDR_ENABLED_ENV)),
        profile_color_mode: non_empty_env(env(LAN_E2E_PROFILE_COLOR_MODE_ENV)),
        profile_color_pipeline: non_empty_env(env(LAN_E2E_PROFILE_COLOR_PIPELINE_ENV)),
        display_mode_policy: non_empty_env(env(LAN_E2E_DISPLAY_MODE_POLICY_ENV)),
        capture_source_id: non_empty_env(env(LAN_E2E_CAPTURE_SOURCE_ID_ENV)),
        capture_source_kind: non_empty_env(env(LAN_E2E_CAPTURE_SOURCE_KIND_ENV)),
        render_display_source_id: non_empty_env(env(LAN_E2E_RENDER_DISPLAY_SOURCE_ID_ENV)),
        expected_peer_build_id: non_empty_env(env(LAN_E2E_EXPECTED_PEER_BUILD_ID_ENV)),
        render_profile_cap: non_empty_env(env(LAN_E2E_RENDER_PROFILE_CAP_ENV)),
        render_display: non_empty_env(env(LAN_E2E_RENDER_DISPLAY_ENV)),
        adaptive: non_empty_env(env(LAN_E2E_ADAPTIVE_ENV)),
    })
}

fn build_lan_e2e_autorun_route(config: LanE2eAutorunLaunchConfig) -> String {
    let mut params = vec![("autorun".to_string(), "lan-e2e".to_string())];

    push_query_param(&mut params, "scenario", config.scenario_id);
    push_query_param(&mut params, "targetDeviceId", config.target_device_id);
    push_query_param(&mut params, "transport", config.transport);
    push_query_param(&mut params, "timeoutMs", config.timeout_ms);
    push_query_param(
        &mut params,
        "minSampleDurationMs",
        config.min_sample_duration_ms,
    );
    push_query_param(&mut params, "minDecodedFrames", config.min_decoded_frames);
    push_query_param(&mut params, "minFps", config.min_fps);
    push_query_param(&mut params, "minRenderFps", config.min_render_fps);
    push_query_param(&mut params, "stopOnComplete", config.stop_on_complete);
    push_query_param(&mut params, "width", config.profile_width);
    push_query_param(&mut params, "height", config.profile_height);
    push_query_param(&mut params, "fps", config.profile_fps);
    push_query_param(&mut params, "bitrateMbps", config.profile_bitrate_mbps);
    push_query_param(&mut params, "codec", config.profile_codec);
    push_query_param(&mut params, "codecProfile", config.profile_codec_profile);
    push_query_param(&mut params, "bitDepth", config.profile_bit_depth);
    push_query_param(
        &mut params,
        "chromaSubsampling",
        config.profile_chroma_subsampling,
    );
    push_query_param(&mut params, "pixelFormat", config.profile_pixel_format);
    push_query_param(&mut params, "hdrEnabled", config.profile_hdr_enabled);
    push_query_param(&mut params, "colorMode", config.profile_color_mode);
    push_query_param(&mut params, "colorPipeline", config.profile_color_pipeline);
    push_query_param(&mut params, "displayModePolicy", config.display_mode_policy);
    push_query_param(&mut params, "captureSourceId", config.capture_source_id);
    push_query_param(&mut params, "captureSourceKind", config.capture_source_kind);
    push_query_param(
        &mut params,
        "renderDisplaySourceId",
        config.render_display_source_id,
    );
    push_query_param(
        &mut params,
        "expectedPeerBuildId",
        config.expected_peer_build_id,
    );
    push_query_param(&mut params, "renderProfileCap", config.render_profile_cap);
    push_query_param(&mut params, "renderDisplay", config.render_display);
    push_query_param(&mut params, "adaptive", config.adaptive);

    let query = params
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, url_query_escape(&value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("/test/e2e?{query}")
}

fn navigate_webview_to_route(webview: &tauri::Webview, route: &str) -> Result<(), String> {
    let script = build_main_window_route_navigation_script(route)?;
    webview.eval(&script).map_err(|error| error.to_string())
}

fn build_main_window_route_navigation_script(route: &str) -> Result<String, String> {
    let route_json = serde_json::to_string(route).map_err(|error| error.to_string())?;
    Ok(format!("window.location.replace({route_json});"))
}

fn is_truthy_env_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn non_empty_env(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn push_query_param(params: &mut Vec<(String, String)>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        params.push((key.to_string(), value));
    }
}

fn url_query_escape(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

#[cfg(test)]
mod tray_tests {
    use super::*;

    #[test]
    fn tray_menu_ids_map_to_actions() {
        assert_eq!(
            tray_action_from_menu_id(TRAY_MENU_SHOW_ID),
            Some(TrayAction::ShowWindow)
        );
        assert_eq!(
            tray_action_from_menu_id(TRAY_MENU_HIDE_ID),
            Some(TrayAction::HideWindow)
        );
        assert_eq!(
            tray_action_from_menu_id(TRAY_MENU_CENTER_ID),
            Some(TrayAction::CenterWindow)
        );
        assert_eq!(
            tray_action_from_menu_id(TRAY_MENU_QUIT_ID),
            Some(TrayAction::QuitUi)
        );
        assert_eq!(tray_action_from_menu_id("unknown"), None);
    }

    #[test]
    fn lan_e2e_autorun_route_uses_env_configuration() {
        let route = build_lan_e2e_autorun_route(LanE2eAutorunLaunchConfig {
            scenario_id: Some("cross.fault.recovery".to_string()),
            target_device_id: Some("agent device/1".to_string()),
            transport: Some("quic".to_string()),
            timeout_ms: Some("2500".to_string()),
            min_sample_duration_ms: Some("1500".to_string()),
            min_decoded_frames: Some("2".to_string()),
            min_fps: Some("5".to_string()),
            min_render_fps: Some("4".to_string()),
            stop_on_complete: Some("false".to_string()),
            profile_width: Some("1920".to_string()),
            profile_height: Some("1080".to_string()),
            profile_fps: Some("180".to_string()),
            profile_bitrate_mbps: Some("20".to_string()),
            profile_codec: Some("hevc".to_string()),
            profile_codec_profile: Some("main".to_string()),
            profile_bit_depth: Some("8".to_string()),
            profile_chroma_subsampling: Some("4:2:0".to_string()),
            profile_pixel_format: Some("nv12".to_string()),
            profile_hdr_enabled: Some("false".to_string()),
            profile_color_mode: Some("monochrome".to_string()),
            profile_color_pipeline: Some("hdr_main10".to_string()),
            display_mode_policy: Some("temporary".to_string()),
            capture_source_id: Some("windows:display-shared:1".to_string()),
            capture_source_kind: Some("display".to_string()),
            render_display_source_id: Some("windows:display-shared:0".to_string()),
            expected_peer_build_id: Some("abc123def456".to_string()),
            render_profile_cap: Some("false".to_string()),
            render_display: Some("false".to_string()),
            adaptive: Some("true".to_string()),
        });

        assert_eq!(
            route,
            "/test/e2e?autorun=lan-e2e&scenario=cross.fault.recovery&targetDeviceId=agent%20device%2F1&transport=quic&timeoutMs=2500&minSampleDurationMs=1500&minDecodedFrames=2&minFps=5&minRenderFps=4&stopOnComplete=false&width=1920&height=1080&fps=180&bitrateMbps=20&codec=hevc&codecProfile=main&bitDepth=8&chromaSubsampling=4%3A2%3A0&pixelFormat=nv12&hdrEnabled=false&colorMode=monochrome&colorPipeline=hdr_main10&displayModePolicy=temporary&captureSourceId=windows%3Adisplay-shared%3A1&captureSourceKind=display&renderDisplaySourceId=windows%3Adisplay-shared%3A0&expectedPeerBuildId=abc123def456&renderProfileCap=false&renderDisplay=false&adaptive=true"
        );
    }

    #[test]
    fn lan_e2e_autorun_requires_enabled_flag() {
        let disabled = lan_e2e_autorun_config_from_env_lookup(|_| None);
        assert!(disabled.is_none());

        let enabled = lan_e2e_autorun_config_from_env_lookup(|key| {
            if key == LAN_E2E_AUTORUN_ENV {
                Some("true".to_string())
            } else {
                None
            }
        });
        assert!(enabled.is_some());
    }

    #[tokio::test]
    async fn set_decode_policy_preserves_ffmpeg_settings() {
        let path = unique_settings_path("decode-policy-preserves-ffmpeg");
        let mut settings = AppSettings::default();
        settings.ffmpeg.enabled = false;
        settings.ffmpeg.channel = "custom".to_string();
        save_settings(&path, &settings).expect("save initial settings");

        let response = set_decode_policy_with(&path, DecodePolicy::Nvdec)
            .await
            .expect("set decode policy");

        let loaded = load_settings(&path).expect("load settings");
        assert_eq!(response.decode_policy, "nvdec");
        assert_eq!(loaded.decode_policy, DecodePolicy::Nvdec);
        assert!(!loaded.ffmpeg.enabled);
        assert_eq!(loaded.ffmpeg.channel, "custom");

        std::fs::remove_file(&path).expect("cleanup temp settings");
    }

    #[test]
    fn reset_ffmpeg_settings_uses_golden_defaults() {
        let path = unique_settings_path("ffmpeg-reset");
        let mut settings = AppSettings::default();
        settings.ffmpeg.enabled = false;
        settings.ffmpeg.channel = "custom".to_string();
        save_settings(&path, &settings).expect("save custom settings");

        let settings = reset_ffmpeg_settings_at_path(&path).expect("reset ffmpeg");

        assert!(settings.ffmpeg.enabled);
        assert_eq!(settings.ffmpeg, mrd_ffmpeg::golden_settings());

        std::fs::remove_file(&path).expect("cleanup temp settings");
    }

    #[test]
    fn ffmpeg_probe_at_path_uses_saved_settings() {
        let path = unique_settings_path("ffmpeg-probe-disabled");
        let mut settings = AppSettings::default();
        settings.ffmpeg.enabled = false;
        save_settings(&path, &settings).expect("save disabled ffmpeg settings");

        let result = ffmpeg_probe_at_path(&path).expect("probe ffmpeg");

        assert!(!result.available);
        assert!(result.reason.unwrap().contains("disabled"));

        std::fs::remove_file(&path).expect("cleanup temp settings");
    }

    #[test]
    fn lan_e2e_autorun_navigation_forces_route_load() {
        let script = build_main_window_route_navigation_script(
            "/test/e2e?autorun=lan-e2e&displayModePolicy=temporary",
        )
        .expect("script should be valid");

        assert_eq!(
            script,
            "window.location.replace(\"/test/e2e?autorun=lan-e2e&displayModePolicy=temporary\");"
        );
    }

    #[test]
    fn display_source_id_maps_to_windows_display_name() {
        assert_eq!(
            display_name_for_capture_source_id("windows:display-shared:1").as_deref(),
            None
        );
        assert_eq!(
            display_name_for_capture_source_id("windows:display:1").as_deref(),
            None
        );
        assert_eq!(
            display_name_for_capture_source_id("DXGIShared:\\\\.\\DISPLAY1").as_deref(),
            Some("\\\\.\\DISPLAY1")
        );
        assert_eq!(
            display_name_for_capture_source_id("\\\\.\\DISPLAY3").as_deref(),
            Some("\\\\.\\DISPLAY3")
        );
    }

    #[test]
    fn remote_display_window_avoids_captured_display_when_possible() {
        let monitors = vec![
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY2".to_string()),
                primary: false,
                position_x: 0,
                position_y: 0,
                width: 2560,
                height: 1440,
            },
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY1".to_string()),
                primary: false,
                position_x: 3840,
                position_y: 0,
                width: 3840,
                height: 2160,
            },
        ];

        let selected = choose_remote_display_window_placement(
            &monitors,
            None,
            Some("DXGIShared:\\\\.\\DISPLAY2"),
        )
        .expect("secondary display should be selected");

        assert_eq!(selected.name.as_deref(), Some("\\\\.\\DISPLAY1"));
    }

    #[test]
    fn remote_display_window_prefers_requested_display_source() {
        let monitors = vec![
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY1".to_string()),
                primary: false,
                position_x: -2560,
                position_y: 0,
                width: 2560,
                height: 1440,
            },
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY2".to_string()),
                primary: false,
                position_x: 2560,
                position_y: -2385,
                width: 1440,
                height: 2560,
            },
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY3".to_string()),
                primary: true,
                position_x: 0,
                position_y: 0,
                width: 2560,
                height: 1440,
            },
        ];

        let selected = choose_remote_display_window_placement(
            &monitors,
            Some("DXGIShared:\\\\.\\DISPLAY2"),
            Some("DXGIShared:\\\\.\\DISPLAY3"),
        )
        .expect("explicit render display should be selected");

        assert_eq!(selected.name.as_deref(), Some("\\\\.\\DISPLAY2"));
    }

    #[test]
    fn remote_display_window_maps_display_source_id_by_monitor_topology() {
        let monitors = vec![
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY2".to_string()),
                primary: true,
                position_x: 0,
                position_y: 0,
                width: 2560,
                height: 1440,
            },
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY1".to_string()),
                primary: false,
                position_x: -3840,
                position_y: 0,
                width: 3840,
                height: 2160,
            },
            RemoteDisplayMonitorPlacement {
                name: Some("\\\\.\\DISPLAY3".to_string()),
                primary: false,
                position_x: 2560,
                position_y: 0,
                width: 2560,
                height: 1440,
            },
        ];

        let selected = choose_remote_display_window_placement(
            &monitors,
            Some("windows:display-shared:1"),
            Some("windows:display-shared:0"),
        )
        .expect("topology display source should be selected");

        assert_eq!(selected.name.as_deref(), Some("\\\\.\\DISPLAY1"));
    }

    #[test]
    fn remote_display_window_placement_error_does_not_abort_creation() {
        assert!(remote_display_window_placement_result(Err("position failed".to_string())).is_ok());
    }

    #[test]
    fn single_instance_addr_can_be_overridden_for_test_instances() {
        assert_eq!(
            single_instance_addr_from_env_value(None),
            SINGLE_INSTANCE_ADDR.to_string()
        );
        assert_eq!(
            single_instance_addr_from_env_value(Some(" 127.0.0.1:48765 ")),
            "127.0.0.1:48765".to_string()
        );
        assert_eq!(
            single_instance_addr_from_env_value(Some(" ")),
            SINGLE_INSTANCE_ADDR.to_string()
        );
    }

    fn unique_settings_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join("mini-remote-desktop-tests")
            .join(format!(
                "{prefix}-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time")
                    .as_nanos()
            ))
    }
}

#[cfg(target_os = "linux")]
fn prefer_x11_backend_for_linux_native_render() {
    if std::env::var_os("GDK_BACKEND").is_none() && std::env::var_os("DISPLAY").is_some() {
        std::env::set_var("GDK_BACKEND", "x11,wayland");
    }
}

#[cfg(windows)]
fn spawn_native_surface_control_input_forwarder() {
    let (forwarder, receiver) = remote_display_surface::native_surface_control_input_channel();
    if !remote_display_surface::install_control_input_forwarder(forwarder) {
        return;
    }

    let endpoint = mrd_ipc::transport::IpcEndpoint::service_from_env_or_default();
    let _ = spawn_native_surface_control_input_forwarder_for_receiver(receiver, endpoint);
}

#[cfg(windows)]
fn spawn_native_surface_control_input_forwarder_for_receiver(
    receiver: remote_display_surface::NativeSurfaceControlInputReceiver,
    endpoint: mrd_ipc::transport::IpcEndpoint,
) -> std::thread::JoinHandle<()> {
    spawn_native_surface_control_input_forwarder_for_receiver_with_reporter(
        receiver, endpoint, None,
    )
}

#[cfg(windows)]
fn spawn_native_surface_control_input_forwarder_for_receiver_with_reporter(
    receiver: remote_display_surface::NativeSurfaceControlInputReceiver,
    endpoint: mrd_ipc::transport::IpcEndpoint,
    reporter: Option<std::sync::mpsc::Sender<(String, Result<mrd_ipc::IpcResponse, String>)>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("native surface input forwarder runtime failed: {error}");
                return;
            }
        };

        while let Some(input) = receiver.recv() {
            let endpoint = endpoint.clone();
            let reporter = reporter.clone();
            runtime.block_on(async move {
                let mut client = mrd_ipc::client::IpcClient::with_endpoint(endpoint);
                let response = client
                    .send_request(mrd_ipc::IpcRequest::SendControlInput {
                        session_id: SessionId(input.session_id.clone()),
                        event: input.event,
                    })
                    .await;
                match response {
                    Ok(response) => {
                        if let mrd_ipc::IpcResponse::Error { code, message } = &response {
                            eprintln!(
                                "native surface input forward rejected session_id={} code={} message={}",
                                input.session_id, code, message
                            );
                        }
                        if let Some(reporter) = reporter {
                            let _ = reporter.send((input.session_id, Ok(response)));
                        }
                    }
                    Err(error) => {
                        let message = error.to_string();
                        eprintln!(
                            "native surface input forward failed session_id={} error={message}",
                            input.session_id
                        );
                        if let Some(reporter) = reporter {
                            let _ = reporter.send((input.session_id, Err(message)));
                        }
                    }
                }
            });
        }
    })
}

#[cfg(all(test, windows))]
mod native_surface_control_forwarder_tests {
    use super::*;
    use mrd_ipc::transport::IpcEndpoint;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn test_endpoint(name: &str) -> IpcEndpoint {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        IpcEndpoint::named_pipe(format!(
            r"\\.\pipe\rdesk-native-input-forwarder-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn native_surface_control_forwarder_sends_input_to_service_ipc() {
        let endpoint = test_endpoint("send-input");
        let server = mrd_ipc::transport::IpcServer::bind_with_endpoint(endpoint.clone())
            .await
            .expect("bind ipc capture server");
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut stream = server.accept().await.expect("accept ipc client");
            let request = stream.recv_request().await.expect("receive ipc request");
            stream
                .send_response(&mrd_ipc::IpcResponse::ControlInputAccepted {
                    session_id: SessionId("native-forward-ipc-session".to_string()),
                    lane: mrd_ipc::ControlInputLane::Realtime,
                    event_count: 1,
                })
                .await
                .expect("send ipc response");
            request_sender.send(request).expect("publish request");
        });

        let (input_forwarder, input_receiver) =
            remote_display_surface::native_surface_control_input_channel();
        let worker =
            spawn_native_surface_control_input_forwarder_for_receiver(input_receiver, endpoint);
        let authorization = remote_display_surface::NativeSurfaceControlAuthorization::new(
            "native-forward-ipc-session".to_string(),
            true,
            true,
        );
        input_forwarder.submit(
            1,
            authorization,
            mrd_ipc::ControlInputEvent::MouseMove { x: 7, y: 9 },
        );

        let request = tokio::time::timeout(Duration::from_secs(2), request_receiver)
            .await
            .expect("forwarded request timeout")
            .expect("forwarded request");
        drop(input_forwarder);
        worker.join().expect("forwarder worker exits");
        server_task.await.expect("ipc capture task exits");

        assert_eq!(
            request,
            mrd_ipc::IpcRequest::SendControlInput {
                session_id: SessionId("native-forward-ipc-session".to_string()),
                event: mrd_ipc::ControlInputEvent::MouseMove { x: 7, y: 9 },
            }
        );
    }
}

#[cfg(test)]
mod secure_remote_ipc_contract_tests {
    use super::ensure_secure_remote_request;
    use mrd_ipc::{IpcRequest, ShutdownMode};
    use mrd_proto::SessionId;

    #[test]
    fn secure_remote_passthrough_is_declared_and_registered() {
        let source = include_str!("main.rs");
        let declaration = ["async fn ipc_", "secure_remote("].concat();
        let registration = ["            ipc_", "secure_remote,"].concat();

        assert!(source.contains(&declaration));
        assert!(source.contains(&registration));
    }

    #[test]
    fn secure_remote_passthrough_rejects_requests_outside_its_allowlist() {
        assert!(ensure_secure_remote_request(&IpcRequest::GetRemoteSession {
            session_id: SessionId("secure-session".to_string()),
        })
        .is_ok());
        assert!(ensure_secure_remote_request(&IpcRequest::ShutdownService {
            mode: ShutdownMode::Graceful,
        })
        .is_err());
        assert!(
            ensure_secure_remote_request(&IpcRequest::CrossE2EInjectFault {
                session_id: SessionId("secure-session".to_string()),
                fault_type: "disconnect".to_string(),
                duration_ms: None,
            })
            .is_err()
        );
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    prefer_x11_backend_for_linux_native_render();
    #[cfg(windows)]
    spawn_native_surface_control_input_forwarder();

    let settings_path = default_settings_path();
    let _settings = load_settings(&settings_path).unwrap_or_else(|error| {
        eprintln!("failed to load app settings: {error}");
        AppSettings::default()
    });

    // Create shared service manager (bootstrap-only in Phase 6)
    let service_manager = std::sync::Arc::new(
        service_manager::ServiceManager::new().expect("failed to create ServiceManager"),
    );

    // Create test harness for end-to-end pipeline visualization
    let test_harness = std::sync::Arc::new(std::sync::Mutex::new(
        test_harness::TestHarness::new().expect("failed to create TestHarness"),
    ));

    // Create test orchestrator
    let telemetry_root = settings_path
        .parent()
        .map(|path| path.join("test-telemetry"))
        .unwrap_or_else(|| {
            std::env::temp_dir()
                .join("mini-remote-desktop")
                .join("test-telemetry")
        });
    let test_orchestrator = std::sync::Arc::new(
        test_orchestrator::TestOrchestrator::new_with_telemetry_store(
            test_harness.clone(),
            mrd_test_telemetry::TelemetryStore::from_env_or_dir(telemetry_root),
        ),
    );
    let resource_monitor = std::sync::Arc::new(std::sync::Mutex::new(ResourceMonitor::new()));
    let render_window_registry =
        std::sync::Arc::new(std::sync::Mutex::new(RenderWindowRegistry::default()));
    let remote_display_surfaces =
        std::sync::Arc::new(std::sync::Mutex::new(RemoteDisplaySurfaceManager::default()));
    let render_proxy = std::sync::Arc::new(render_proxy::RenderProxyRegistry::default());
    let webrtc_host =
        std::sync::Arc::new(tokio::sync::Mutex::new(webrtc_host::WebrtcHost::default()));

    let Some(single_instance_listener) = claim_single_instance() else {
        return;
    };

    let lan_e2e_autorun_route = lan_e2e_autorun_config_from_env().map(build_lan_e2e_autorun_route);
    let lan_e2e_autorun_pending =
        std::sync::Arc::new(AtomicBool::new(lan_e2e_autorun_route.is_some()));
    let lan_e2e_autorun_route_for_load = lan_e2e_autorun_route.clone();
    let lan_e2e_autorun_pending_for_load = lan_e2e_autorun_pending.clone();

    // Build the app
    tauri::Builder::default()
        .manage(AppState {
            settings_path,
            service_manager,
            test_harness,
            test_orchestrator,
            resource_monitor,
            render_window_registry,
            remote_display_surfaces,
            render_proxy,
            webrtc_host,
        })
        .on_menu_event(|app, event| {
            if let Some(action) = tray_action_from_menu_id(event.id().as_ref()) {
                if let Err(error) = apply_tray_action(app, action) {
                    eprintln!("tray menu action failed: {error}");
                }
            }
        })
        .on_tray_icon_event(|app, event| {
            if event.id().as_ref() != TRAY_ICON_ID {
                return;
            }

            if let Some(action) = tray_action_from_icon_event(&event) {
                if let Err(error) = apply_tray_action(app, action) {
                    eprintln!("tray icon action failed: {error}");
                }
            }
        })
        .on_page_load(move |webview, payload| {
            if payload.event() != PageLoadEvent::Finished || webview.label() != "main" {
                return;
            }
            if !lan_e2e_autorun_pending_for_load.swap(false, Ordering::SeqCst) {
                return;
            }
            let Some(route) = lan_e2e_autorun_route_for_load.as_deref() else {
                return;
            };
            if let Err(error) = navigate_webview_to_route(webview, route) {
                eprintln!("failed to navigate to LAN E2E autorun route after page load: {error}");
            }
        })
        .setup(move |app| {
            spawn_single_instance_listener(single_instance_listener, app.handle().clone());
            setup_system_tray(app.handle())?;

            if let Some(main_window) = app.get_webview_window("main") {
                let backdrop_status = platform::configure_main_window(&main_window);
                if !backdrop_status.applied {
                    eprintln!(
                        "failed to apply native backdrop: {}",
                        backdrop_status.detail
                    );
                }

                let app_handle_for_close = app.handle().clone();
                main_window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        if APP_IS_QUITTING.load(Ordering::SeqCst) {
                            return;
                        }
                        api.prevent_close();
                        if let Err(error) = hide_main_window(&app_handle_for_close) {
                            eprintln!("failed to hide Rdesk window: {error}");
                        }
                    }
                });
            }

            // Step 1: Bootstrap mrd-service if not already running
            let service_mgr = app.state::<AppState>().service_manager.clone();

            // Spawn a blocking task for service bootstrap
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    // Bootstrap mrd-service only if not reachable via IPC
                    let bootstrapped = match service_mgr.bootstrap_if_needed().await {
                        Ok(did_bootstrap) => did_bootstrap,
                        Err(e) => {
                            eprintln!("Failed to bootstrap mrd-service: {}", e);
                            return;
                        }
                    };

                    if bootstrapped {
                        println!("Bootstrapped mrd-service");
                    } else {
                        println!("mrd-service already running");
                    }

                    // Wait for service to be healthy (max 30 seconds)
                    if let Err(e) = service_mgr.wait_for_healthy(30).await {
                        eprintln!("mrd-service health check failed: {}", e);
                    } else {
                        println!("mrd-service is ready");

                        // Register UI presence with service
                        if let Err(e) = shell_ui_attached().await {
                            eprintln!("Failed to register UI presence: {}", e);
                        }
                    }
                });
            });

            Ok(())
        })
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            // Hardware and decode policy (local-only)
            get_hardware_info,
            get_system_resource_snapshot,
            start_drag_window,
            minimize_window,
            toggle_maximize_window,
            hide_to_tray,
            show_window,
            center_window,
            close_window,
            set_window_decorations,
            apply_native_chrome,
            open_remote_display_window,
            list_remote_display_windows,
            current_remote_display_window_context,
            close_remote_display_window,
            browser_webrtc_preview_start,
            browser_webrtc_preview_stop,
            configure_remote_display_native_surface,
            present_test_harness_frame_on_native_surface,
            get_client_diagnostics,
            open_diagnostics_folder,
            automation_write_report,
            nvdec_runtime_probe,
            decode_policy,
            set_decode_policy,
            ffmpeg_probe,
            ffmpeg_download,
            ffmpeg_reset_golden_settings,
            // Bootstrap commands (Phase 6: bootstrap-only behavior)
            service_bootstrap_if_needed,
            service_wait_for_healthy,
            service_did_bootstrap,
            // IPC-based commands (all session control goes through mrd-service)
            ipc_register_device,
            ipc_list_devices,
            ipc_get_device_preferences,
            ipc_update_device_preference,
            ipc_lan_discovery_snapshot,
            ipc_refresh_lan_discovery,
            ipc_list_directory,
            ipc_start_file_transfer,
            ipc_list_file_transfers,
            ipc_list_file_transfer_providers,
            ipc_cancel_file_transfer,
            ipc_wake_on_lan,
            ipc_request_remote_device_power_action,
            ipc_list_sessions,
            ipc_secure_remote,
            ipc_start_session,
            ipc_start_lan_remote_session,
            ipc_update_media_profile,
            ipc_configure_media_adaptation,
            ipc_send_control_input,
            cross_e2e_inject_fault,
            ipc_list_local_capture_sources,
            ipc_list_remote_capture_sources,
            ipc_select_remote_capture_source,
            ipc_list_remote_display_modes,
            ipc_set_remote_display_mode,
            ipc_restore_remote_display_mode,
            ipc_accept_session,
            ipc_stop_session,
            ipc_fail_session,
            ipc_recover_session,
            ipc_session_snapshot,
            ipc_runtime_snapshot,
            ipc_audit_log,
            ipc_capability_snapshot,
            ipc_peer_capability_snapshot,
            ipc_service_health,
            ipc_probe_snapshot,
            ipc_media_pipeline_snapshot,
            ipc_start_sender,
            ipc_start_receiver,
            // Legacy commands
            register_device,
            check_device_registration,
            webrtc_session_list_via_ipc,
            // Shell / Lifecycle commands (Phase 2-6: service owns lifecycle)
            shell_ui_attached,
            shell_ui_detached,
            shell_get_status,
            shell_shutdown_service,
            shell_quit_ui_and_stop_service,
            // Test harness commands
            test_harness_start,
            test_harness_stop,
            test_harness_set_chain,
            test_harness_set_custom,
            test_harness_get_chain,
            test_harness_get_metrics,
            test_harness_get_comparison_result,
            // Test Workbench commands (new unified test API)
            test_list_scenarios,
            test_get_capabilities,
            test_list_window_capture_targets,
            test_list_window_capture_targets_with_previews,
            test_list_capture_share_sources,
            test_list_capture_share_sources_with_previews,
            test_start_run,
            test_record_external_run,
            test_stop_run,
            test_list_runs,
            test_get_run,
            test_get_run_events,
            test_get_run_metrics,
            test_get_run_artifacts,
            test_get_run_telemetry,
            test_list_presets,
            test_save_preset,
            test_delete_preset,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
