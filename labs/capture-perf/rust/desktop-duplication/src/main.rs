use cap_common::{FrameMetrics, MetricsCollector, TestConfig};
use std::time::{Duration, Instant};
use windows::Win32::Graphics::Dxgi::{
    IDXGIOutput1, IDXGIOutputDuplication, DXGI_ERROR_WAIT_TIMEOUT, DXGI_ERROR_ACCESS_LOST,
    IDXGIDevice,
};
use windows::Win32::Graphics::Direct3D11::{D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, D3D11_CREATE_DEVICE_FLAG};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL};
use windows::core::Interface;
use windows::Win32::Foundation::HMODULE;

struct DesktopDuplicationCapture {
    device: Option<ID3D11Device>,
    duplication: Option<IDXGIOutputDuplication>,
    acquired_frame: bool,
}

impl DesktopDuplicationCapture {
    fn new() -> Self {
        Self {
            device: None,
            duplication: None,
            acquired_frame: false,
        }
    }

    fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let mut device: Option<ID3D11Device> = None;
            let mut feature_level = D3D_FEATURE_LEVEL::default();
            let mut context: Option<ID3D11DeviceContext> = None;

            D3D11CreateDevice(
                None,                                    // adapter
                D3D_DRIVER_TYPE_HARDWARE,                // driver type
                HMODULE::default(),                      // software
                D3D11_CREATE_DEVICE_FLAG(0),             // flags
                None,                                    // feature levels
                7,                                       // SDK version
                Some(&mut device),                       // ppDevice
                Some(&mut feature_level),                // pFeatureLevel
                Some(&mut context),                      // ppImmediateContext
            ).map_err(|e| format!("D3D11CreateDevice failed: {:?}", e))?;

            let device = device.ok_or("Device not created")?;

            let dxgi_device: IDXGIDevice = device.cast()?;
            let adapter = dxgi_device.GetAdapter()?;

            let output_base = adapter.EnumOutputs(0)?;
            let output: IDXGIOutput1 = output_base.cast()?;

            let duplication = output.DuplicateOutput(&device)?;

            self.device = Some(device);
            self.duplication = Some(duplication);
        }

        Ok(())
    }

    fn capture_frame(&mut self) -> Result<Option<i64>, Box<dyn std::error::Error>> {
        unsafe {
            if let Some(duplication) = &self.duplication {
                let mut frame_info = Default::default();
                let mut resource = None;

                // 使用 INFINITE 等待，与 C++ 版本保持一致
                match duplication.AcquireNextFrame(u32::MAX, &mut frame_info, &mut resource) {
                    Ok(_) => {
                        self.acquired_frame = true;
                        let last_present_time = frame_info.LastPresentTime;
                        drop(resource);
                        Ok(Some(last_present_time))
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

    fn release_frame(&mut self) {
        if self.acquired_frame {
            if let Some(duplication) = &self.duplication {
                unsafe {
                    let _ = duplication.ReleaseFrame();
                }
            }
            self.acquired_frame = false;
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
        api_name: "DesktopDuplication".to_string(),
        language: "Rust".to_string(),
        duration_sec: 10,
        width: 0,
        height: 0,
    };

    let mut collector = MetricsCollector::new(config.clone());
    let mut capture = DesktopDuplicationCapture::new();

    capture.initialize()?;

    println!("Starting Desktop Duplication capture for {} seconds...", config.duration_sec);

    let start_time = Instant::now();
    let duration = Duration::from_secs(config.duration_sec);
    let mut frame_count = 0u64;

    let mut last_present_time: i64 = 0;

    while start_time.elapsed() < duration {
        let frame_start = Instant::now();

        if let Ok(Some(present_time)) = capture.capture_frame() {
            let after_acquire = Instant::now();
            let acquire_time = after_acquire.duration_since(frame_start).as_secs_f64() * 1000.0;

            // 跳过 PresentTime 非递增的帧（这些是重复或过时的帧）
            if present_time <= last_present_time && last_present_time != 0 {
                capture.release_frame();
                continue;
            }
            last_present_time = present_time;

            frame_count += 1;
            let total_time_ms = start_time.elapsed().as_secs_f64() * 1000.0;

            let metrics = FrameMetrics {
                frame_number: frame_count,
                capture_time_ms: acquire_time,
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
            capture.release_frame();
        }
    }

    collector.print_summary();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 使用绝对路径保存到项目结果目录
    let csv_path = format!("D:/Project/TestProject/CapTest/results/{}_rust_desktop_duplication.csv", timestamp);
    let json_path = format!("D:/Project/TestProject/CapTest/results/{}_rust_desktop_duplication.json", timestamp);

    collector.save_to_csv(&csv_path);
    collector.save_to_json(&json_path);

    println!("Results saved to:");
    println!("  {}", csv_path);
    println!("  {}", json_path);

    Ok(())
}
