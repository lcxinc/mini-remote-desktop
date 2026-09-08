#![windows_subsystem = "windows"]

use std::ptr;
use std::time::{Duration, Instant};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D12::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::WindowsAndMessaging::*;

const WINDOW_WIDTH: u32 = 1280;
const WINDOW_HEIGHT: u32 = 720;
const FRAME_COUNT: u32 = 2;

/// 生成动态帧数据 - CPU 端渲染
fn generate_frame_data(width: u32, height: u32, time_sec: f32) -> Vec<u8> {
    let mut data = Vec::with_capacity((width * height * 4) as usize);

    let t = time_sec;
    let offset_x = ((t * 100.0).sin() * 200.0) as i32;
    let offset_y = ((t * 80.0).cos() * 150.0) as i32;

    for y in 0..height {
        for x in 0..width {
            // 渐变背景
            let bg_r = (x as f32 / width as f32 * 100.0) as u8;
            let bg_g = (y as f32 / height as f32 * 150.0) as u8;
            let bg_b = (100.0 + (t * 50.0).sin() * 50.0) as u8;

            let mut r = bg_r;
            let mut g = bg_g;
            let mut b = bg_b;

            // 移动的方块
            let square_x = (width as i32 / 2 - 100 + offset_x) as u32;
            let square_y = (height as i32 / 2 - 75 + offset_y) as u32;

            if x >= square_x && x < square_x + 200 && y >= square_y && y < square_y + 150 {
                // 方块内：彩虹色
                let local_x = x - square_x;
                let local_y = y - square_y;
                r = ((local_x as f32 / 200.0) * 255.0) as u8;
                g = ((local_y as f32 / 150.0) * 255.0) as u8;
                b = ((t * 100.0).sin() * 127.0 + 128.0) as u8;
            }

            // 添加一些动态圆圈
            let cx = width as i32 / 2 + ((t * 60.0).cos() * 300.0) as i32;
            let cy = height as i32 / 2 + ((t * 50.0).sin() * 200.0) as i32;
            let dx = x as i32 - cx;
            let dy = y as i32 - cy;
            let dist = (dx * dx + dy * dy) as f32;
            if dist < 10000.0 {
                let blend = (1.0 - dist / 10000.0) * 0.5;
                r = (r as f32 * (1.0 - blend) + 255.0 * blend) as u8;
                g = (g as f32 * (1.0 - blend) + 100.0 * blend) as u8;
                b = (b as f32 * (1.0 - blend) + 200.0 * blend) as u8;
            }

            data.push(r);
            data.push(g);
            data.push(b);
            data.push(255);
        }
    }
    data
}

/// D3D12 渲染上下文
struct D3D12Context {
    device: ID3D12Device,
    command_queue: ID3D12CommandQueue,
    swap_chain: IDXGISwapChain3,
    command_allocator: ID3D12CommandAllocator,
    command_list: ID3D12GraphicsCommandList,
    render_targets: [Option<ID3D12Resource>; FRAME_COUNT as usize],
    upload_resources: [Option<ID3D12Resource>; FRAME_COUNT as usize],
    fence: ID3D12Fence,
    fence_value: u64,
    fence_event: HANDLE,
}

impl D3D12Context {
    fn new(hwnd: HWND) -> Result<Self> {
        unsafe {
            // 创建 D3D12 设备
            let mut device: Option<ID3D12Device> = None;
            D3D12CreateDevice(None, D3D_FEATURE_LEVEL_11_0, &mut device)?;
            let device = device.unwrap();

            // 创建命令队列
            let queue_desc = D3D12_COMMAND_QUEUE_DESC {
                Type: D3D12_COMMAND_LIST_TYPE_DIRECT,
                Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
                ..Default::default()
            };
            let command_queue = device.CreateCommandQueue(&queue_desc)?;

            // 创建交换链
            let dxgi_factory: IDXGIFactory4 = CreateDXGIFactory1()?;
            let swap_chain_desc = DXGI_SWAP_CHAIN_DESC1 {
                Width: WINDOW_WIDTH,
                Height: WINDOW_HEIGHT,
                Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    ..Default::default()
                },
                BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
                BufferCount: FRAME_COUNT,
                SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
                ..Default::default()
            };
            let swap_chain: IDXGISwapChain1 = dxgi_factory.CreateSwapChainForHwnd(
                &command_queue,
                hwnd,
                &swap_chain_desc,
                None,
                None,
            )?;
            let _ = dxgi_factory.MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
            let swap_chain: IDXGISwapChain3 = swap_chain.cast()?;

            // 创建命令分配器和命令列表
            let command_allocator =
                device.CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT)?;
            let command_list: ID3D12GraphicsCommandList = device.CreateCommandList(
                0,
                D3D12_COMMAND_LIST_TYPE_DIRECT,
                &command_allocator,
                None,
            )?;
            command_list.Close()?;

            // 创建 RTV 描述符堆
            let rtv_heap_desc = D3D12_DESCRIPTOR_HEAP_DESC {
                Type: D3D12_DESCRIPTOR_HEAP_TYPE_RTV,
                NumDescriptors: FRAME_COUNT,
                Flags: D3D12_DESCRIPTOR_HEAP_FLAG_NONE,
                NodeMask: 0,
            };
            let rtv_heap: ID3D12DescriptorHeap = device.CreateDescriptorHeap(&rtv_heap_desc)?;
            let rtv_descriptor_size =
                device.GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

            // 创建渲染目标视图和上传资源
            let mut render_targets: [Option<ID3D12Resource>; FRAME_COUNT as usize] =
                Default::default();
            let mut upload_resources: [Option<ID3D12Resource>; FRAME_COUNT as usize] =
                Default::default();
            let mut rtv_handle = rtv_heap.GetCPUDescriptorHandleForHeapStart();

            for i in 0..FRAME_COUNT {
                let resource = swap_chain.GetBuffer(i)?;
                device.CreateRenderTargetView(&resource, None, rtv_handle);
                render_targets[i as usize] = Some(resource);
                rtv_handle.ptr += rtv_descriptor_size as usize;

                // 创建上传堆资源
                let upload_heap = D3D12_HEAP_PROPERTIES {
                    Type: D3D12_HEAP_TYPE_UPLOAD,
                    ..Default::default()
                };
                let upload_resource_desc = D3D12_RESOURCE_DESC {
                    Dimension: D3D12_RESOURCE_DIMENSION_BUFFER,
                    Alignment: 0,
                    Width: (WINDOW_WIDTH * WINDOW_HEIGHT * 4) as u64,
                    Height: 1,
                    DepthOrArraySize: 1,
                    MipLevels: 1,
                    Format: DXGI_FORMAT_UNKNOWN,
                    SampleDesc: DXGI_SAMPLE_DESC {
                        Count: 1,
                        ..Default::default()
                    },
                    Layout: D3D12_TEXTURE_LAYOUT_ROW_MAJOR,
                    Flags: D3D12_RESOURCE_FLAG_NONE,
                };
                let mut upload_resource: Option<ID3D12Resource> = None;
                device.CreateCommittedResource(
                    &upload_heap,
                    D3D12_HEAP_FLAG_NONE,
                    &upload_resource_desc,
                    D3D12_RESOURCE_STATE_GENERIC_READ,
                    None,
                    &mut upload_resource,
                )?;
                upload_resources[i as usize] = upload_resource;
            }

            // 创建围栏和事件
            let fence = device.CreateFence(0, D3D12_FENCE_FLAG_NONE)?;
            let fence_value = 0u64;
            let fence_event =
                windows::Win32::System::Threading::CreateEventW(None, false, false, None)?;

            Ok(Self {
                device,
                command_queue,
                swap_chain,
                command_allocator,
                command_list,
                render_targets,
                upload_resources,
                fence,
                fence_value,
                fence_event,
            })
        }
    }

    /// 渲染一帧
    fn render(&mut self, frame_data: &[u8]) -> Result<()> {
        unsafe {
            // 重置命令分配器和命令列表
            self.command_allocator.Reset()?;
            self.command_list.Reset(&self.command_allocator, None)?;

            // 获取当前渲染目标索引
            let frame_index = self.swap_chain.GetCurrentBackBufferIndex() as usize;
            let current_render_target = self.render_targets[frame_index].as_ref().unwrap();
            let upload_resource = self.upload_resources[frame_index].as_ref().unwrap();

            // 资源屏障：Present -> CopyDest
            let barrier = D3D12_RESOURCE_BARRIER {
                Type: D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
                Flags: D3D12_RESOURCE_BARRIER_FLAG_NONE,
                Anonymous: D3D12_RESOURCE_BARRIER_0 {
                    Transition: std::mem::ManuallyDrop::new(D3D12_RESOURCE_TRANSITION_BARRIER {
                        pResource: std::mem::ManuallyDrop::new(Some(current_render_target.clone())),
                        Subresource: D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
                        StateBefore: D3D12_RESOURCE_STATE_PRESENT,
                        StateAfter: D3D12_RESOURCE_STATE_COPY_DEST,
                    }),
                },
            };
            self.command_list.ResourceBarrier(&[barrier]);

            // 上传纹理数据并复制到渲染目标
            self.upload_and_copy(upload_resource, current_render_target, frame_data)?;

            // 资源屏障：CopyDest -> Present
            let barrier = D3D12_RESOURCE_BARRIER {
                Type: D3D12_RESOURCE_BARRIER_TYPE_TRANSITION,
                Flags: D3D12_RESOURCE_BARRIER_FLAG_NONE,
                Anonymous: D3D12_RESOURCE_BARRIER_0 {
                    Transition: std::mem::ManuallyDrop::new(D3D12_RESOURCE_TRANSITION_BARRIER {
                        pResource: std::mem::ManuallyDrop::new(Some(current_render_target.clone())),
                        Subresource: D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES,
                        StateBefore: D3D12_RESOURCE_STATE_COPY_DEST,
                        StateAfter: D3D12_RESOURCE_STATE_PRESENT,
                    }),
                },
            };
            self.command_list.ResourceBarrier(&[barrier]);

            // 关闭并执行命令列表
            self.command_list.Close()?;
            let command_lists = [Some(self.command_list.cast::<ID3D12CommandList>()?)];
            self.command_queue.ExecuteCommandLists(&command_lists);

            // 等待 GPU 完成
            self.wait_for_gpu()?;

            // 呈现
            let _ = self.swap_chain.Present(1, DXGI_PRESENT(0));

            Ok(())
        }
    }

    /// 上传纹理数据到渲染目标
    fn upload_and_copy(
        &self,
        upload_resource: &ID3D12Resource,
        render_target: &ID3D12Resource,
        data: &[u8],
    ) -> Result<()> {
        unsafe {
            let row_pitch = (WINDOW_WIDTH * 4) as usize;

            // 映射上传堆并复制数据
            let mut data_ptr: *mut u8 = ptr::null_mut();
            upload_resource.Map(0, None, Some(&mut data_ptr as *mut _ as *mut *mut _))?;
            ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
            upload_resource.Unmap(0, None);

            // 设置源位置（上传堆）
            let src_location = D3D12_TEXTURE_COPY_LOCATION {
                pResource: std::mem::ManuallyDrop::new(Some(upload_resource.clone())),
                Type: D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT,
                Anonymous: D3D12_TEXTURE_COPY_LOCATION_0 {
                    PlacedFootprint: D3D12_PLACED_SUBRESOURCE_FOOTPRINT {
                        Offset: 0,
                        Footprint: D3D12_SUBRESOURCE_FOOTPRINT {
                            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                            Width: WINDOW_WIDTH,
                            Height: WINDOW_HEIGHT,
                            Depth: 1,
                            RowPitch: row_pitch as u32,
                        },
                    },
                },
            };

            // 设置目标位置（渲染目标）
            let dst_location = D3D12_TEXTURE_COPY_LOCATION {
                pResource: std::mem::ManuallyDrop::new(Some(render_target.clone())),
                Type: D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX,
                Anonymous: D3D12_TEXTURE_COPY_LOCATION_0 {
                    SubresourceIndex: 0,
                },
            };

            // 复制纹理区域
            let box_ = D3D12_BOX {
                left: 0,
                top: 0,
                front: 0,
                right: WINDOW_WIDTH,
                bottom: WINDOW_HEIGHT,
                back: 1,
            };
            self.command_list
                .CopyTextureRegion(&dst_location, 0, 0, 0, &src_location, Some(&box_));

            Ok(())
        }
    }

    /// 等待 GPU 完成
    fn wait_for_gpu(&mut self) -> Result<()> {
        unsafe {
            self.fence_value += 1;
            self.command_queue.Signal(&self.fence, self.fence_value)?;

            if self.fence.GetCompletedValue() < self.fence_value {
                self.fence
                    .SetEventOnCompletion(self.fence_value, self.fence_event)?;
                WaitForSingleObject(self.fence_event, INFINITE);
            }

            Ok(())
        }
    }
}

impl Drop for D3D12Context {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.fence_event);
        }
    }
}

/// 获取窗口模块实例
fn create_window_instance() -> Result<HINSTANCE> {
    unsafe { Ok(GetModuleHandleW(PCWSTR::null())?.into()) }
}

/// 注册窗口类
fn register_window_class(hinstance: HINSTANCE) -> Result<()> {
    unsafe {
        let class_name = w!("D3D12WindowClass");

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: hinstance,
            hCursor: LoadCursorW(None, IDC_ARROW)
                .ok()
                .expect("Failed to load cursor"),
            lpszClassName: class_name,
            ..Default::default()
        };

        if RegisterClassExW(&wc) == 0 {
            let error = GetLastError();
            if error != ERROR_CLASS_ALREADY_EXISTS {
                return Err(Error::from_win32());
            }
        }

        Ok(())
    }
}

/// 窗口过程函数
extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                BeginPaint(hwnd, &mut ps);
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// 创建窗口
fn create_window(hinstance: HINSTANCE) -> Result<HWND> {
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("D3D12WindowClass"),
            w!("D3D12 Stream Test"),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH as i32,
            WINDOW_HEIGHT as i32,
            None,
            None,
            Some(hinstance),
            None,
        )
    }
}

/// 主函数
fn main() -> Result<()> {
    unsafe {
        // 创建窗口
        let hinstance = create_window_instance()?;
        register_window_class(hinstance)?;
        let hwnd = create_window(hinstance)?;

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);

        // 初始化 D3D12
        let mut d3d12 = D3D12Context::new(hwnd)?;

        // 主循环
        let mut msg = MSG::default();
        let start_time = Instant::now();

        loop {
            if PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).into() {
                if msg.message == WM_QUIT {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            } else {
                // 1. CPU 生成动态帧数据
                let elapsed = start_time.elapsed().as_secs_f32();
                let frame_data = generate_frame_data(WINDOW_WIDTH, WINDOW_HEIGHT, elapsed);

                // 2. 上传到 GPU 并渲染
                if let Err(e) = d3d12.render(&frame_data) {
                    eprintln!("Render error: {:?}", e);
                    break;
                }

                // 限制到约 60 FPS
                std::thread::sleep(Duration::from_millis(16));
            }
        }

        Ok(())
    }
}
