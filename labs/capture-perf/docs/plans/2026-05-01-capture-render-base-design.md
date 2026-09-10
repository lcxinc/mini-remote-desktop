# Capture Render Base Design

**Date:** 2026-05-01
**Status:** Approved

## Goal

Build `CapTest` into the base project for live Windows capture plus rendering. The first milestone is a normalized C++ D3D11 pipeline that captures the desktop, renders the captured texture, and reports capture/render/end-to-end metrics from one executable.

## Project Decision

`CapTest` remains the canonical project. `ShowTest` is treated as a working rendering benchmark reference, not copied wholesale. The merge brings its useful practices into `CapTest`: simple renderer/profiler separation, compact JSON metrics, and a buildable D3D11 baseline.

## Recommended Approach

Start with C++ D3D11 because it is the shortest path to a reliable base:

- Desktop Duplication already returns `ID3D11Texture2D`.
- `CapTest/cpp/viewer` already has a D3D11 texture renderer and overlay.
- `ShowTest/cpp_dx11` proves the render benchmark path compiles on this machine.

Rust and DX12 remain second-stage targets after the D3D11 base has a stable interface and metrics schema.

## Architecture

The base executable owns one D3D11 device for both capture and render. This avoids cross-device texture use and makes the captured `ID3D11Texture2D` directly usable by the renderer as a shader resource.

Core components:

- `Window`: Win32 message loop and resize callbacks.
- `CaptureSource`: normalized capture interface for Desktop Duplication, Windows Graphics Capture, and the shared-memory bridge.
- `D3D11Renderer`: swap chain, full-window textured quad, overlay, present.
- `CaptureRenderMetrics`: normalized frame records and JSON/CSV summaries.

## Data Flow

1. Create the window.
2. Create one D3D11 device/context/swap chain through the renderer.
3. Initialize the selected capture source using the renderer's D3D11 device.
4. For each frame:
   - Acquire a frame from Desktop Duplication, Windows Graphics Capture, or the shared-memory bridge.
   - Render the acquired texture to the swap chain.
   - Render overlay stats.
   - Present.
   - Record capture time, render time, present time, end-to-end frame time, FPS, memory, and frame status.
5. On exit, save normalized metrics under `results/`.

## Metrics Schema

Frame CSV fields:

```csv
timestamp,api,language,renderer,frame_number,status,capture_time_ms,render_time_ms,present_time_ms,total_time_ms,fps,memory_mb,width,height
```

Summary JSON shape:

```json
{
  "test_config": {
    "api": "DesktopDuplication",
    "language": "C++",
    "renderer": "D3D11",
    "duration_sec": 0,
    "width": 2560,
    "height": 1440,
    "total_frames": 1000
  },
  "statistics": {
    "avg_capture_time_ms": 1.2,
    "avg_render_time_ms": 0.4,
    "avg_present_time_ms": 6.9,
    "avg_total_time_ms": 8.5,
    "avg_fps": 120.0,
    "avg_memory_mb": 64.0
  }
}
```

## Error Handling

- Treat `DXGI_ERROR_WAIT_TIMEOUT` as a no-frame status, not a fatal error.
- On `DXGI_ERROR_ACCESS_LOST`, release duplication and attempt reinitialization.
- On renderer resize, recreate render targets and reset overlay resources that reference the old back buffer.
- If metrics cannot be written, keep the viewer running and report the failure on stderr.

## Testing And Verification

The first implementation should be verified by:

- C++ unit-style checks for metrics calculations where feasible.
- CMake or batch build for the viewer target.
- A short smoke run of each source when a desktop session is available:
  - `viewer.exe --source desktop --duration 5`
  - `viewer.exe --source shared-memory --duration 5`
  - `viewer.exe --source wgc --duration 5`
  - `viewer_d3d12.exe --source desktop --duration 5`
  - `viewer_d3d12.exe --source shared-memory --duration 5`
  - `viewer_d3d12.exe --source wgc --duration 5`
- JSON/CSV file inspection to confirm normalized output.
