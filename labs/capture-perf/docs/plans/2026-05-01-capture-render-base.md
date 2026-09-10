# Capture Render Base Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the first C++ D3D11 capture-render base inside `CapTest`.

**Architecture:** Keep `CapTest` as the canonical project. Refactor `cpp/viewer` so one D3D11 device is shared by Desktop Duplication capture and rendering, then emit normalized frame and summary metrics.

**Tech Stack:** C++20, Win32, D3D11, DXGI Desktop Duplication, CMake/MSVC.

---

### Task 1: Metrics Foundation

**Files:**
- Create: `cpp/viewer/include/capture_render_metrics.h`
- Create: `cpp/viewer/src/capture_render_metrics.cpp`
- Modify: `cpp/viewer/CMakeLists.txt`

**Step 1: Add metrics structs and collector**

Define frame records for capture, render, present, total time, status, FPS, memory, width, and height.

**Step 2: Add statistics calculation**

Calculate averages and save JSON/CSV using the normalized schema in the design document.

**Step 3: Build check**

Run: `cmake --build cpp/build --config Release --target viewer`

Expected: compile errors only from integration still pending are acceptable after this task; metrics files should compile once wired into the target.

### Task 2: Shared D3D11 Device Boundary

**Files:**
- Modify: `cpp/viewer/include/d3d11_renderer.h`
- Modify: `cpp/viewer/src/d3d11_renderer.cpp`
- Create: `cpp/viewer/include/desktop_duplication_capture.h`
- Create: `cpp/viewer/src/desktop_duplication_capture.cpp`

**Step 1: Expose renderer device/context**

Add safe accessors for `ID3D11Device` and `ID3D11DeviceContext`.

**Step 2: Move capture code behind a capture source**

Create `DesktopDuplicationCapture` that initializes from the renderer's device and returns acquired frame texture plus timing/status.

**Step 3: Handle access lost**

Release and reinitialize duplication on `DXGI_ERROR_ACCESS_LOST`.

### Task 3: Viewer Loop Integration

**Files:**
- Modify: `cpp/viewer/src/viewer_main.cpp`
- Modify: `cpp/viewer/include/overlay_renderer.h`
- Modify: `cpp/viewer/src/overlay_renderer.cpp`

**Step 1: Replace inline capture class**

Use `DesktopDuplicationCapture` in `viewer_main.cpp`.

**Step 2: Measure render and present separately**

Call render and present from the main loop with timers around each phase.

**Step 3: Update overlay**

Show API, renderer, FPS, resolution, capture time, render time, and present time.

### Task 4: Build And Smoke Verification

**Files:**
- Modify if needed: `cpp/build_viewer_d3d11.bat`
- Modify if needed: `cpp/run_viewer.bat`

**Step 1: Configure/build**

Run: `cmake -S cpp -B cpp/build -G "Visual Studio 17 2022" -A x64`
Run: `cmake --build cpp/build --config Release --target viewer`

**Step 2: Inspect outputs**

Run the viewer briefly when possible and confirm normalized JSON/CSV files appear under `results/`.

**Step 3: Final status**

Report exact build/run results and any remaining manual smoke-test gap.

