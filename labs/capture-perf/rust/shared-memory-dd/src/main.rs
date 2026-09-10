use cap_common::{FrameMetrics, MetricsCollector, TestConfig};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Graphics::Dxgi::{
    IDXGIOutput1, IDXGIOutputDuplication, DXGI_ERROR_WAIT_TIMEOUT, DXGI_ERROR_ACCESS_LOST,
    IDXGIDevice,
};
use windows::Win32::Graphics::Direct3D11::{D3D11CreateDevice, ID3D11Device};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::core::Interface;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE};

// 模拟共享内存帧缓冲区
struct SharedFrameBuffer {
    data: *mut u8,
    size: usize,
    ready: Arc<AtomicBool>,
}

unsafe impl Send for SharedFrameBuffer {}
unsafe impl Sync for SharedFrameBuffer {}

impl SharedFrameBuffer {
    fn new(size: usize) -> Option<Self> {
        unsafe {
            let data = VirtualAlloc(
                None,
                size,
                MEM_COMMIT,
                PAGE_READWRITE,
            ) as *mut u8;

            if data.is_null() {
                return None;
            }

            Some(Self {
                data,
                size,
                ready: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    fn write(&mut self, data: &[u8]) -> bool {
        if data.len() > self.size {
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.data, data.len());
            self.ready.store(true, Ordering::Release);
        }
        true
    }

    fn read(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn consume(&self) {
        self.ready.store(false, Ordering::Release);
    }
}

impl Drop for SharedFrameBuffer {
    fn drop(&mut self) {
        unsafe {
            if !self.data.is_null() {
                VirtualFree(self.data as _, 0, MEM_RELEASE);
            }
        }
    }
}

struct DesktopDuplicationSharedMemory {
    device: Option<ID3D11Device>,
    duplication: Option<IDXGIOutputDuplication>,
    shared_buffer: Option<SharedFrameBuffer>,
    buffer_size: usize,
}

impl DesktopDuplicationSharedMemory {
    fn new() -> Self {
        // 假设 1920x1080x4 (RGBA) = ~8MB 的共享缓冲区
        let buffer_size = 1920 * 1080 * 4;

        Self {
            device: None,
            duplication: None,
            shared_buffer: SharedFrameBuffer::new(buffer_size),
            buffer_size,
        }
    }

    fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let mut device: Option<ID3D11Device> = None;
            let mut feature_level = windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL::default();
            let mut context: Option<windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext> = None;

            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                Default::default(),
                None,
                7,
                Some(&mut device),
                None,
                Some(&mut context),
            ).map_err(|e| format!("D3D11CreateDevice failed: {:?}", e))?;

            let device = device.unwrap();

            let dxgi_device: IDXGIDevice = device.cast()?;
            let adapter = dxgi_device.GetAdapter()?;

            let output_base = adapter.EnumOutputs(0)?;
            let output: IDXGIOutput1 = output_base.cast()?;

            let duplication = output.DuplicateOutput(&device)?;

            self.device = Some(device);
            self.duplication = Some(duplication);

            if self.shared_buffer.is_none() {
                return Err("Failed to create shared memory buffer".into());
            }
        }

        Ok(())
    }

    fn capture_frame(&mut self) -> Result<Option<f64>, Box<dyn std::error::Error>> {
        unsafe {
            if let Some(duplication) = &self.duplication {
                let start = Instant::now();
                let mut frame_info = Default::default();
                let mut resource = None;

                match duplication.AcquireNextFrame(u32::MAX, &mut frame_info, &mut resource) {
                    Ok(_) => {
                        let capture_time_ms = start.elapsed().as_secs_f64() * 1000.0;

                        // 模拟将帧数据写入共享内存
                        // 在真实实现中，这里会复制实际的像素数据
                        if let Some(ref mut buffer) = self.shared_buffer {
                            // 模拟写入一小段数据（实际应该是完整的帧数据）
                            let dummy_data = vec![0u8; 1024];
                            buffer.write(&dummy_data);
                            buffer.consume();
                        }

                        let _ = duplication.ReleaseFrame();
                        drop(resource);
                        Ok(Some(capture_time_ms))
                    }
                    Err(e) if e.code().0 == DXGI_ERROR_WAIT_TIMEOUT.0 => Ok(None),
                    Err(e) if e.code().0 == DXGI_ERROR_ACCESS_LOST.0 => {
                        self.duplication = None;
                        Err(e.into())
                    }
                    Err(e) => Err(e.into()),
                }
            } else {
                Ok(None)
            }
        }
    }
}

fn get_memory_mb() -> f64 {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
        let handle = GetCurrentProcess();
        if GetProcessMemoryInfo(
            handle,
            &mut pmc as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ).is_ok() {
            pmc.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = TestConfig {
        api_name: "DesktopDuplicationSharedMemory".to_string(),
        language: "Rust".to_string(),
        duration_sec: 10,
        width: 0,
        height: 0,
    };

    let mut collector = MetricsCollector::new(config.clone());
    let mut capture = DesktopDuplicationSharedMemory::new();

    capture.initialize()?;

    println!("Starting Desktop Duplication + Shared Memory capture for {} seconds...", config.duration_sec);

    let start_time = Instant::now();
    let duration = Duration::from_secs(config.duration_sec);
    let mut frame_count = 0u64;

    while start_time.elapsed() < duration {
        if let Ok(Some(capture_time_ms)) = capture.capture_frame() {
            frame_count += 1;
            let total_time_ms = start_time.elapsed().as_secs_f64() * 1000.0;

            let metrics = FrameMetrics {
                frame_number: frame_count,
                capture_time_ms,
                total_time_ms,
                fps: if total_time_ms > 0.0 {
                    frame_count as f64 * 1000.0 / total_time_ms
                } else {
                    0.0
                },
                cpu_percent: 0.0,
                memory_mb: get_memory_mb(),
            };

            collector.record_frame(metrics);
        }
    }

    collector.print_summary();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let csv_path = format!("D:/Project/TestProject/CapTest/results/{}_rust_shared_memory_dd.csv", timestamp);
    let json_path = format!("D:/Project/TestProject/CapTest/results/{}_rust_shared_memory_dd.json", timestamp);

    collector.save_to_csv(&csv_path);
    collector.save_to_json(&json_path);

    println!("Results saved to:");
    println!("  {}", csv_path);
    println!("  {}", json_path);

    Ok(())
}
