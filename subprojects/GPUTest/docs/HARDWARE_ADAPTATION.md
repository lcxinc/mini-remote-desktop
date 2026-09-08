# Hardware Adaptation Matrix

Last update: 2026-03-06
Scope: `J:/ProjectTest/GPUTest`

## 1) Dimensions

- system
- capture
- encoder
- transport
- decoder
- resolution
- fps

## 2) Current Platform Baseline (this machine)

- system: Windows 11 Pro for Workstations Insider Preview (10.0.26300, x64)
- CPU: Intel Core i5-14600KF (14C/20T)
- GPU: NVIDIA GeForce RTX 5060 Ti
- ffmpeg hwaccels (runtime probe source): cuda, dxva2, d3d11va, d3d12va, qsv, amf (availability depends on actual device/runtime)

## 3) Support by Dimension

### 3.1 system

| system | status | note |
|---|---|---|
| windows | implemented | primary target in current code |
| linux | planned | not implemented in this repo path |
| macos | planned | WGC/DXGI unavailable, needs native stack |

### 3.2 capture

| capture | status | note |
|---|---|---|
| desktop_dup | implemented | DXGI Desktop Duplication path |
| windows_graphics_capture | config-ready | in matrix config, not wired in runtime executor yet |

### 3.3 encoder

| encoder | status | note |
|---|---|---|
| gpu_proto | implemented | current executable path |
| software | config-ready | matrix generated but executor marks `path_not_implemented_yet` |
| nvenc | config-ready | same as above |
| amf | config-ready | same as above + may be backend unavailable |
| qsv | config-ready | same as above + may be backend unavailable |

### 3.4 transport

| transport | status | note |
|---|---|---|
| udp | implemented | fully runnable |
| quic | implemented | fully runnable |
| srt | config-ready | matrix includes, executor currently `transport_not_supported` |

### 3.5 decoder

| decoder | status | note |
|---|---|---|
| gpu_proto | implemented | current executable path |
| software | config-ready | path not wired in executor |
| d3d11va | config-ready | path not wired in executor |
| dxva2 | config-ready | path not wired in executor |
| cuda | config-ready | path not wired in executor |
| qsv | config-ready | path not wired in executor |

### 3.6 resolution / fps

| dimension | values in matrix | execution status |
|---|---|---|
| resolution | 1280x720, 1920x1080 | both runnable on implemented path |
| fps | 30, 60 | both runnable on implemented path |

## 4) Implemented Full-Path Cartesian Subset

Current fully implemented and executed subset:

- capture: `desktop_dup` + `windows_graphics_capture`
- encoder: `gpu_proto`
- transport: `udp` + `quic`
- decoder: `gpu_proto`
- resolution: `1280x720`, `1920x1080`
- fps: `30`, `60`

Total executed subset size: `2 x 1 x 2 x 1 x 2 x 2 = 16`.

## 5) Matrix Config & Outputs

- matrix config: `config/matrix.windows.json`
- 5s full cartesian run output: `artifacts/core_matrix_5s.csv`
- status summary from that run: total=720, pass=16, fail=0, skip=704

## 6) 10s Visible Capture/Render Check

A visible window test was run using `desktop-zero-copy-poc`:

- command: `POC_DURATION_SEC=10 cargo run --bin desktop-zero-copy-poc`
- log: `artifacts/desktop_zero_copy_poc.10s.display.log`
- final line:
  - duration_s=10
  - fps=5691.65
  - copy_hit=3.1%
  - avg_copy_ms=0.083
  - avg_present_ms=0.047

This validates a visible desktop capture->present chain in this project scope.
