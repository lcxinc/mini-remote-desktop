use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderProbeConfig {
    pub backend: String,
    pub width: usize,
    pub height: usize,
    pub frames: usize,
    pub show_window: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderProbeResult {
    pub backend: String,
    pub width: usize,
    pub height: usize,
    pub frames_presented: usize,
    pub fps: f64,
    pub avg_frame_time_ms: f64,
    pub p50_frame_time_ms: f64,
    pub p95_frame_time_ms: f64,
    pub draw_calls: u64,
    pub triangles: u64,
    pub textures: u64,
    pub adapter_name: Option<String>,
    pub notes: Vec<String>,
}

pub fn render_backend_supported(backend: &str) -> bool {
    matches!(backend, "d3d12" | "opengl") && cfg!(windows)
}

pub fn run_render_probe(config: RenderProbeConfig) -> Result<RenderProbeResult> {
    if config.width == 0 || config.height == 0 {
        anyhow::bail!("render probe resolution must be non-zero");
    }

    match config.backend.as_str() {
        "d3d12" => run_d3d12_probe(config),
        "opengl" => run_opengl_probe(config),
        other => anyhow::bail!("Unsupported render probe backend: {}", other),
    }
}

#[cfg(windows)]
fn frame_count(config: &RenderProbeConfig) -> usize {
    config.frames.clamp(1, 600)
}

#[cfg(any(windows, test))]
fn summarize_probe(
    config: RenderProbeConfig,
    mut frame_times_ms: Vec<f64>,
    notes: Vec<String>,
) -> RenderProbeResult {
    let frames_presented = frame_times_ms.len();
    let total_ms: f64 = frame_times_ms.iter().sum();
    frame_times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let last = frame_times_ms.len().saturating_sub(1);
    let p50 = frame_times_ms
        .get(frame_times_ms.len() / 2)
        .copied()
        .unwrap_or(0.0);
    let p95 = frame_times_ms
        .get(((frame_times_ms.len() * 95) / 100).min(last))
        .copied()
        .unwrap_or(0.0);
    let avg = if frames_presented > 0 {
        total_ms / frames_presented as f64
    } else {
        0.0
    };
    let fps = if total_ms > 0.0 {
        frames_presented as f64 * 1000.0 / total_ms
    } else {
        0.0
    };

    RenderProbeResult {
        backend: config.backend,
        width: config.width,
        height: config.height,
        frames_presented,
        fps,
        avg_frame_time_ms: avg,
        p50_frame_time_ms: p50,
        p95_frame_time_ms: p95,
        draw_calls: frames_presented as u64,
        triangles: 0,
        textures: 1,
        adapter_name: None,
        notes,
    }
}

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
unsafe extern "system" fn probe_wnd_proc(
    hwnd: windows::Win32::Foundation::HWND,
    message: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, message, wparam, lparam)
}

#[cfg(windows)]
struct ProbeWindow {
    hwnd: windows::Win32::Foundation::HWND,
}

#[cfg(windows)]
impl Drop for ProbeWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(self.hwnd);
        }
    }
}

#[cfg(windows)]
fn create_probe_window(
    class_name: &str,
    title: &str,
    width: usize,
    height: usize,
    show: bool,
) -> Result<ProbeWindow> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, RegisterClassW, ShowWindow, CS_OWNDC, CW_USEDEFAULT, HMENU, SW_SHOW,
        WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    unsafe {
        let class_name = wide(class_name);
        let title = wide(title);
        let hmodule = GetModuleHandleW(None)
            .map_err(|error| anyhow::anyhow!("get module handle failed: {error}"))?;
        let hinstance = HINSTANCE(hmodule.0);
        let window_class = WNDCLASSW {
            style: CS_OWNDC,
            lpfnWndProc: Some(probe_wnd_proc),
            hInstance: hinstance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        RegisterClassW(&window_class);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            width.clamp(64, 4096) as i32,
            height.clamp(64, 4096) as i32,
            HWND(0),
            HMENU(0),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            anyhow::bail!("create render probe window failed");
        }
        if show {
            ShowWindow(hwnd, SW_SHOW);
        }

        Ok(ProbeWindow { hwnd })
    }
}

#[cfg(windows)]
fn pump_window_messages() {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };

    unsafe {
        let mut message = MSG::default();
        while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

#[cfg(windows)]
fn run_d3d12_probe(config: RenderProbeConfig) -> Result<RenderProbeResult> {
    if config.show_window {
        return run_d3d12_window_probe(config);
    }

    use windows::core::ComInterface;
    use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL_11_0;
    use windows::Win32::Graphics::Direct3D12::{
        D3D12CreateDevice, ID3D12CommandAllocator, ID3D12CommandList, ID3D12CommandQueue,
        ID3D12DescriptorHeap, ID3D12Device, ID3D12Fence, ID3D12GraphicsCommandList, ID3D12Resource,
        D3D12_CLEAR_VALUE, D3D12_CLEAR_VALUE_0, D3D12_COMMAND_LIST_TYPE_DIRECT,
        D3D12_COMMAND_QUEUE_DESC, D3D12_COMMAND_QUEUE_FLAG_NONE, D3D12_CPU_DESCRIPTOR_HANDLE,
        D3D12_CPU_PAGE_PROPERTY_UNKNOWN, D3D12_DESCRIPTOR_HEAP_DESC,
        D3D12_DESCRIPTOR_HEAP_FLAG_NONE, D3D12_DESCRIPTOR_HEAP_TYPE_RTV, D3D12_FENCE_FLAG_NONE,
        D3D12_HEAP_FLAG_NONE, D3D12_HEAP_PROPERTIES, D3D12_HEAP_TYPE_DEFAULT,
        D3D12_MEMORY_POOL_UNKNOWN, D3D12_RESOURCE_DESC, D3D12_RESOURCE_DIMENSION_TEXTURE2D,
        D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET, D3D12_RESOURCE_STATE_RENDER_TARGET,
        D3D12_TEXTURE_LAYOUT_UNKNOWN,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SAMPLE_DESC};

    unsafe {
        let mut device = None::<ID3D12Device>;
        D3D12CreateDevice(None, D3D_FEATURE_LEVEL_11_0, &mut device)
            .map_err(|error| anyhow::anyhow!("create D3D12 device failed: {error}"))?;
        let device = device.ok_or_else(|| anyhow::anyhow!("missing D3D12 device"))?;

        let queue_desc = D3D12_COMMAND_QUEUE_DESC {
            Type: D3D12_COMMAND_LIST_TYPE_DIRECT,
            Priority: 0,
            Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
            NodeMask: 0,
        };
        let queue: ID3D12CommandQueue = device
            .CreateCommandQueue(&queue_desc)
            .map_err(|error| anyhow::anyhow!("create D3D12 command queue failed: {error}"))?;
        let allocator: ID3D12CommandAllocator = device
            .CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT)
            .map_err(|error| anyhow::anyhow!("create D3D12 command allocator failed: {error}"))?;
        let command_list: ID3D12GraphicsCommandList = device
            .CreateCommandList(
                0,
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                &allocator,
                None::<&windows::Win32::Graphics::Direct3D12::ID3D12PipelineState>,
            )
            .map_err(|error| anyhow::anyhow!("create D3D12 command list failed: {error}"))?;
        command_list.Close().ok();

        let heap_desc = D3D12_DESCRIPTOR_HEAP_DESC {
            Type: D3D12_DESCRIPTOR_HEAP_TYPE_RTV,
            NumDescriptors: 1,
            Flags: D3D12_DESCRIPTOR_HEAP_FLAG_NONE,
            NodeMask: 0,
        };
        let rtv_heap: ID3D12DescriptorHeap = device
            .CreateDescriptorHeap(&heap_desc)
            .map_err(|error| anyhow::anyhow!("create D3D12 RTV heap failed: {error}"))?;
        let rtv_handle: D3D12_CPU_DESCRIPTOR_HANDLE = rtv_heap.GetCPUDescriptorHandleForHeapStart();

        let clear_color = [0.02, 0.08, 0.18, 1.0];
        let clear_value = D3D12_CLEAR_VALUE {
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            Anonymous: D3D12_CLEAR_VALUE_0 { Color: clear_color },
        };
        let heap_properties = D3D12_HEAP_PROPERTIES {
            Type: D3D12_HEAP_TYPE_DEFAULT,
            CPUPageProperty: D3D12_CPU_PAGE_PROPERTY_UNKNOWN,
            MemoryPoolPreference: D3D12_MEMORY_POOL_UNKNOWN,
            CreationNodeMask: 1,
            VisibleNodeMask: 1,
        };
        let resource_desc = D3D12_RESOURCE_DESC {
            Dimension: D3D12_RESOURCE_DIMENSION_TEXTURE2D,
            Alignment: 0,
            Width: config.width as u64,
            Height: config.height as u32,
            DepthOrArraySize: 1,
            MipLevels: 1,
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Layout: D3D12_TEXTURE_LAYOUT_UNKNOWN,
            Flags: D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET,
        };
        let mut render_target = None::<ID3D12Resource>;
        device
            .CreateCommittedResource(
                &heap_properties,
                D3D12_HEAP_FLAG_NONE,
                &resource_desc,
                D3D12_RESOURCE_STATE_RENDER_TARGET,
                Some(&clear_value),
                &mut render_target,
            )
            .map_err(|error| anyhow::anyhow!("create D3D12 render target failed: {error}"))?;
        let render_target =
            render_target.ok_or_else(|| anyhow::anyhow!("missing D3D12 render target"))?;
        device.CreateRenderTargetView(&render_target, None, rtv_handle);

        let fence: ID3D12Fence = device
            .CreateFence(0, D3D12_FENCE_FLAG_NONE)
            .map_err(|error| anyhow::anyhow!("create D3D12 fence failed: {error}"))?;
        let command_list_base: ID3D12CommandList = command_list.cast()?;
        let mut frame_times_ms = Vec::with_capacity(frame_count(&config));
        let mut fence_value = 0_u64;

        for frame_index in 0..frame_count(&config) {
            let started = Instant::now();
            allocator
                .Reset()
                .map_err(|error| anyhow::anyhow!("reset D3D12 allocator failed: {error}"))?;
            command_list
                .Reset(
                    &allocator,
                    None::<&windows::Win32::Graphics::Direct3D12::ID3D12PipelineState>,
                )
                .map_err(|error| anyhow::anyhow!("reset D3D12 command list failed: {error}"))?;

            let shade = (frame_index % 255) as f32 / 255.0;
            let color = [0.02 + shade * 0.1, 0.08, 0.18 + shade * 0.2, 1.0];
            command_list.OMSetRenderTargets(1, Some(&rtv_handle), false, None);
            command_list.ClearRenderTargetView(rtv_handle, &color, None);
            command_list
                .Close()
                .map_err(|error| anyhow::anyhow!("close D3D12 command list failed: {error}"))?;
            queue.ExecuteCommandLists(&[Some(command_list_base.clone())]);

            fence_value += 1;
            queue
                .Signal(&fence, fence_value)
                .map_err(|error| anyhow::anyhow!("signal D3D12 fence failed: {error}"))?;
            let wait_started = Instant::now();
            while fence.GetCompletedValue() < fence_value {
                if wait_started.elapsed() > Duration::from_secs(2) {
                    anyhow::bail!("D3D12 fence wait timed out");
                }
                std::thread::yield_now();
            }
            frame_times_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        }

        let mut result = summarize_probe(
            config,
            frame_times_ms,
            vec!["d3d12_clear_render_target_offscreen".to_string()],
        );
        result.textures = 1;
        Ok(result)
    }
}

#[cfg(windows)]
fn run_d3d12_window_probe(config: RenderProbeConfig) -> Result<RenderProbeResult> {
    use std::mem::ManuallyDrop;
    use windows::core::ComInterface;
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL_11_0;
    use windows::Win32::Graphics::Direct3D12::{
        D3D12CreateDevice, ID3D12CommandAllocator, ID3D12CommandList, ID3D12CommandQueue,
        ID3D12DescriptorHeap, ID3D12Device, ID3D12Fence, ID3D12GraphicsCommandList, ID3D12Resource,
        D3D12_COMMAND_LIST_TYPE_DIRECT, D3D12_COMMAND_QUEUE_DESC, D3D12_COMMAND_QUEUE_FLAG_NONE,
        D3D12_CPU_DESCRIPTOR_HANDLE, D3D12_DESCRIPTOR_HEAP_DESC, D3D12_DESCRIPTOR_HEAP_FLAG_NONE,
        D3D12_DESCRIPTOR_HEAP_TYPE_RTV, D3D12_FENCE_FLAG_NONE, D3D12_RESOURCE_BARRIER,
        D3D12_RESOURCE_BARRIER_0, D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
        D3D12_RESOURCE_BARRIER_FLAG_NONE, D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
        D3D12_RESOURCE_STATES, D3D12_RESOURCE_STATE_PRESENT, D3D12_RESOURCE_STATE_RENDER_TARGET,
        D3D12_RESOURCE_TRANSITION_BARRIER,
    };
    use windows::Win32::Graphics::Dxgi::Common::{
        DXGI_ALPHA_MODE_IGNORE, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SAMPLE_DESC,
    };
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory2, IDXGIFactory2, IDXGIOutput, IDXGISwapChain1, IDXGISwapChain3,
        DXGI_SCALING_STRETCH, DXGI_SWAP_CHAIN_DESC1, DXGI_SWAP_EFFECT_FLIP_DISCARD,
        DXGI_USAGE_RENDER_TARGET_OUTPUT,
    };

    fn transition_barrier(
        resource: &ID3D12Resource,
        before: D3D12_RESOURCE_STATES,
        after: D3D12_RESOURCE_STATES,
    ) -> D3D12_RESOURCE_BARRIER {
        D3D12_RESOURCE_BARRIER {
            Type: D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
            Flags: D3D12_RESOURCE_BARRIER_FLAG_NONE,
            Anonymous: D3D12_RESOURCE_BARRIER_0 {
                Transition: ManuallyDrop::new(D3D12_RESOURCE_TRANSITION_BARRIER {
                    pResource: ManuallyDrop::new(Some(resource.clone())),
                    Subresource: D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
                    StateBefore: before,
                    StateAfter: after,
                }),
            },
        }
    }

    unsafe {
        let surface_width = config.width.clamp(320, 4096);
        let surface_height = config.height.clamp(180, 4096);
        let window = create_probe_window(
            "RdeskD3d12RenderProbeWindow",
            "Rdesk D3D12 Render Probe",
            surface_width,
            surface_height,
            true,
        )?;

        let mut device = None::<ID3D12Device>;
        D3D12CreateDevice(None, D3D_FEATURE_LEVEL_11_0, &mut device)
            .map_err(|error| anyhow::anyhow!("create D3D12 device failed: {error}"))?;
        let device = device.ok_or_else(|| anyhow::anyhow!("missing D3D12 device"))?;

        let queue_desc = D3D12_COMMAND_QUEUE_DESC {
            Type: D3D12_COMMAND_LIST_TYPE_DIRECT,
            Priority: 0,
            Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
            NodeMask: 0,
        };
        let queue: ID3D12CommandQueue = device
            .CreateCommandQueue(&queue_desc)
            .map_err(|error| anyhow::anyhow!("create D3D12 command queue failed: {error}"))?;
        let allocator: ID3D12CommandAllocator = device
            .CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT)
            .map_err(|error| anyhow::anyhow!("create D3D12 command allocator failed: {error}"))?;
        let command_list: ID3D12GraphicsCommandList = device
            .CreateCommandList(
                0,
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                &allocator,
                None::<&windows::Win32::Graphics::Direct3D12::ID3D12PipelineState>,
            )
            .map_err(|error| anyhow::anyhow!("create D3D12 command list failed: {error}"))?;
        command_list.Close().ok();

        let factory: IDXGIFactory2 = CreateDXGIFactory2(0)
            .map_err(|error| anyhow::anyhow!("create DXGI factory failed: {error}"))?;
        let swap_chain_desc = DXGI_SWAP_CHAIN_DESC1 {
            Width: surface_width as u32,
            Height: surface_height as u32,
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            Stereo: BOOL(0),
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            BufferCount: 2,
            Scaling: DXGI_SCALING_STRETCH,
            SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
            AlphaMode: DXGI_ALPHA_MODE_IGNORE,
            Flags: 0,
        };
        let swap_chain1: IDXGISwapChain1 = factory
            .CreateSwapChainForHwnd(
                &queue,
                window.hwnd,
                &swap_chain_desc,
                None,
                None::<&IDXGIOutput>,
            )
            .map_err(|error| anyhow::anyhow!("create D3D12 swapchain failed: {error}"))?;
        let swap_chain: IDXGISwapChain3 = swap_chain1.cast()?;

        let heap_desc = D3D12_DESCRIPTOR_HEAP_DESC {
            Type: D3D12_DESCRIPTOR_HEAP_TYPE_RTV,
            NumDescriptors: 2,
            Flags: D3D12_DESCRIPTOR_HEAP_FLAG_NONE,
            NodeMask: 0,
        };
        let rtv_heap: ID3D12DescriptorHeap = device
            .CreateDescriptorHeap(&heap_desc)
            .map_err(|error| anyhow::anyhow!("create D3D12 RTV heap failed: {error}"))?;
        let descriptor_size =
            device.GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV) as usize;
        let heap_start = rtv_heap.GetCPUDescriptorHandleForHeapStart();

        let mut render_targets = Vec::with_capacity(2);
        let mut rtv_handles = Vec::with_capacity(2);
        for index in 0..2 {
            let render_target: ID3D12Resource = swap_chain
                .GetBuffer(index)
                .map_err(|error| anyhow::anyhow!("get D3D12 back buffer failed: {error}"))?;
            let handle = D3D12_CPU_DESCRIPTOR_HANDLE {
                ptr: heap_start.ptr + index as usize * descriptor_size,
            };
            device.CreateRenderTargetView(&render_target, None, handle);
            render_targets.push(render_target);
            rtv_handles.push(handle);
        }

        let fence: ID3D12Fence = device
            .CreateFence(0, D3D12_FENCE_FLAG_NONE)
            .map_err(|error| anyhow::anyhow!("create D3D12 fence failed: {error}"))?;
        let command_list_base: ID3D12CommandList = command_list.cast()?;
        let mut frame_times_ms = Vec::with_capacity(frame_count(&config));
        let mut fence_value = 0_u64;

        for frame_index in 0..frame_count(&config) {
            pump_window_messages();
            let started = Instant::now();
            let back_buffer_index = swap_chain.GetCurrentBackBufferIndex() as usize;
            let target = &render_targets[back_buffer_index];
            let target_handle = rtv_handles[back_buffer_index];

            allocator
                .Reset()
                .map_err(|error| anyhow::anyhow!("reset D3D12 allocator failed: {error}"))?;
            command_list
                .Reset(
                    &allocator,
                    None::<&windows::Win32::Graphics::Direct3D12::ID3D12PipelineState>,
                )
                .map_err(|error| anyhow::anyhow!("reset D3D12 command list failed: {error}"))?;

            let to_render_target = transition_barrier(
                target,
                D3D12_RESOURCE_STATE_PRESENT,
                D3D12_RESOURCE_STATE_RENDER_TARGET,
            );
            command_list.ResourceBarrier(&[to_render_target]);
            let shade = (frame_index % 255) as f32 / 255.0;
            let color = [
                0.02 + shade * 0.12,
                0.1 + shade * 0.05,
                0.24 + shade * 0.25,
                1.0,
            ];
            command_list.OMSetRenderTargets(1, Some(&target_handle), false, None);
            command_list.ClearRenderTargetView(target_handle, &color, None);
            let to_present = transition_barrier(
                target,
                D3D12_RESOURCE_STATE_RENDER_TARGET,
                D3D12_RESOURCE_STATE_PRESENT,
            );
            command_list.ResourceBarrier(&[to_present]);
            command_list
                .Close()
                .map_err(|error| anyhow::anyhow!("close D3D12 command list failed: {error}"))?;
            queue.ExecuteCommandLists(&[Some(command_list_base.clone())]);
            swap_chain
                .Present(0, 0)
                .ok()
                .map_err(|error| anyhow::anyhow!("D3D12 swapchain present failed: {error}"))?;

            fence_value += 1;
            queue
                .Signal(&fence, fence_value)
                .map_err(|error| anyhow::anyhow!("signal D3D12 fence failed: {error}"))?;
            let wait_started = Instant::now();
            while fence.GetCompletedValue() < fence_value {
                if wait_started.elapsed() > Duration::from_secs(2) {
                    anyhow::bail!("D3D12 fence wait timed out");
                }
                std::thread::yield_now();
            }
            frame_times_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        }

        let mut result = summarize_probe(
            config,
            frame_times_ms,
            vec!["d3d12_visible_window_swapchain_present".to_string()],
        );
        result.textures = 2;
        Ok(result)
    }
}

#[cfg(not(windows))]
fn run_d3d12_probe(_config: RenderProbeConfig) -> Result<RenderProbeResult> {
    anyhow::bail!("D3D12 render probe is only supported on Windows")
}

#[cfg(windows)]
fn run_opengl_probe(config: RenderProbeConfig) -> Result<RenderProbeResult> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::Graphics::Gdi::{GetDC, ReleaseDC, HDC};
    use windows::Win32::Graphics::OpenGL::{
        glClear, glClearColor, wglCreateContext, wglDeleteContext, wglMakeCurrent,
        ChoosePixelFormat, SetPixelFormat, SwapBuffers, GL_COLOR_BUFFER_BIT, HGLRC,
        PFD_DOUBLEBUFFER, PFD_DRAW_TO_WINDOW, PFD_FLAGS, PFD_MAIN_PLANE, PFD_SUPPORT_OPENGL,
        PFD_TYPE_RGBA, PIXELFORMATDESCRIPTOR,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassW, ShowWindow, CS_OWNDC,
        CW_USEDEFAULT, HMENU, SW_SHOW, WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        DefWindowProcW(hwnd, message, wparam, lparam)
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    struct GlWindow {
        hwnd: HWND,
        hdc: HDC,
        context: HGLRC,
    }

    impl Drop for GlWindow {
        fn drop(&mut self) {
            unsafe {
                let _ = wglMakeCurrent(HDC(0), HGLRC(0));
                let _ = wglDeleteContext(self.context);
                let _ = ReleaseDC(self.hwnd, self.hdc);
                let _ = DestroyWindow(self.hwnd);
            }
        }
    }

    unsafe {
        let class_name = wide("RdeskOpenGlRenderProbeWindow");
        let title = wide("Rdesk OpenGL Render Probe");
        let hmodule = GetModuleHandleW(None)
            .map_err(|error| anyhow::anyhow!("get module handle failed: {error}"))?;
        let hinstance = HINSTANCE(hmodule.0);
        let window_class = WNDCLASSW {
            style: CS_OWNDC,
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        RegisterClassW(&window_class);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            config.width.clamp(64, 4096) as i32,
            config.height.clamp(64, 4096) as i32,
            HWND(0),
            HMENU(0),
            hinstance,
            None,
        );
        if hwnd.0 == 0 {
            anyhow::bail!("create OpenGL probe window failed");
        }
        if config.show_window {
            ShowWindow(hwnd, SW_SHOW);
        }

        let hdc = GetDC(hwnd);
        if hdc.0 == 0 {
            let _ = DestroyWindow(hwnd);
            anyhow::bail!("get OpenGL probe device context failed");
        }

        let pfd = PIXELFORMATDESCRIPTOR {
            nSize: std::mem::size_of::<PIXELFORMATDESCRIPTOR>() as u16,
            nVersion: 1,
            dwFlags: PFD_FLAGS(PFD_DRAW_TO_WINDOW.0 | PFD_SUPPORT_OPENGL.0 | PFD_DOUBLEBUFFER.0),
            iPixelType: PFD_TYPE_RGBA,
            cColorBits: 32,
            cDepthBits: 24,
            cStencilBits: 8,
            iLayerType: PFD_MAIN_PLANE.0 as u8,
            ..Default::default()
        };
        let pixel_format = ChoosePixelFormat(hdc, &pfd);
        if pixel_format == 0 {
            let _ = ReleaseDC(hwnd, hdc);
            let _ = DestroyWindow(hwnd);
            anyhow::bail!("choose OpenGL pixel format failed");
        }
        SetPixelFormat(hdc, pixel_format, &pfd)
            .map_err(|error| anyhow::anyhow!("set OpenGL pixel format failed: {error}"))?;
        let context = wglCreateContext(hdc)
            .map_err(|error| anyhow::anyhow!("create OpenGL context failed: {error}"))?;
        wglMakeCurrent(hdc, context)
            .map_err(|error| anyhow::anyhow!("make OpenGL context current failed: {error}"))?;
        let _window = GlWindow { hwnd, hdc, context };

        let mut frame_times_ms = Vec::with_capacity(frame_count(&config));
        for frame_index in 0..frame_count(&config) {
            pump_window_messages();
            let started = Instant::now();
            let shade = (frame_index % 255) as f32 / 255.0;
            glClearColor(0.02 + shade * 0.1, 0.08, 0.18 + shade * 0.2, 1.0);
            glClear(GL_COLOR_BUFFER_BIT);
            SwapBuffers(hdc)
                .map_err(|error| anyhow::anyhow!("OpenGL SwapBuffers failed: {error}"))?;
            frame_times_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        }

        Ok(summarize_probe(
            config,
            frame_times_ms,
            vec!["opengl_visible_window_clear_swapbuffers".to_string()],
        ))
    }
}

#[cfg(not(windows))]
fn run_opengl_probe(_config: RenderProbeConfig) -> Result<RenderProbeResult> {
    anyhow::bail!("OpenGL render probe is only supported on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_probe_reports_percentiles_and_fps() {
        let result = summarize_probe(
            RenderProbeConfig {
                backend: "opengl".to_string(),
                width: 64,
                height: 64,
                frames: 3,
                show_window: false,
            },
            vec![1.0, 2.0, 3.0],
            vec!["test".to_string()],
        );

        assert_eq!(result.frames_presented, 3);
        assert_eq!(result.avg_frame_time_ms, 2.0);
        assert_eq!(result.p50_frame_time_ms, 2.0);
        assert_eq!(result.p95_frame_time_ms, 3.0);
        assert!(result.fps > 0.0);
    }

    #[test]
    #[ignore]
    fn d3d12_probe_smoke() {
        let result = run_render_probe(RenderProbeConfig {
            backend: "d3d12".to_string(),
            width: 64,
            height: 64,
            frames: 3,
            show_window: true,
        })
        .expect("D3D12 probe should run on Windows hosts with a D3D12 device");

        assert_eq!(result.backend, "d3d12");
        assert_eq!(result.frames_presented, 3);
        assert!(result.fps > 0.0);
    }

    #[test]
    #[ignore]
    fn opengl_probe_smoke() {
        let result = run_render_probe(RenderProbeConfig {
            backend: "opengl".to_string(),
            width: 64,
            height: 64,
            frames: 3,
            show_window: true,
        })
        .expect("OpenGL probe should run on Windows hosts with a WGL context");

        assert_eq!(result.backend, "opengl");
        assert_eq!(result.frames_presented, 3);
        assert!(result.fps > 0.0);
    }
}
