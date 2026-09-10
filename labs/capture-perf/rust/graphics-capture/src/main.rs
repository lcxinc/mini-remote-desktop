use cap_common::{FrameMetrics, MetricsCollector, TestConfig};
use std::time::{Duration, Instant};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use windows_capture::capture::{Context, GraphicsCaptureApiHandler};
use windows_capture::frame::Frame;
use windows_capture::graphics_capture_api::InternalCaptureControl;
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
    MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
};

// 全局通道用于传递帧时间
static mut FRAME_SENDER: Option<mpsc::Sender<f64>> = None;
static mut FRAME_COUNT: Option<Arc<Mutex<u64>>> = None;

// 捕获处理器
struct CaptureHandler;

impl GraphicsCaptureApiHandler for CaptureHandler {
    type Flags = ();
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn new(_ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
        Ok(Self)
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut Frame,
        _capture_control: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        let start = Instant::now();
        
        // 访问帧数据以触发实际捕获
        let _ = frame.buffer();
        
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        
        unsafe {
            if let Some(ref sender) = FRAME_SENDER {
                let _ = sender.send(elapsed);
            }
            if let Some(ref count) = FRAME_COUNT {
                let mut c = count.lock().unwrap();
                *c += 1;
            }
        }
        
        Ok(())
    }

    fn on_closed(&mut self) -> Result<(), Self::Error> {
        println!("Capture session ended");
        Ok(())
    }
}

struct GraphicsCaptureCapture {
    receiver: mpsc::Receiver<f64>,
    frame_count: Arc<Mutex<u64>>,
}

impl GraphicsCaptureCapture {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel::<f64>();
        let frame_count = Arc::new(Mutex::new(0u64));
        
        unsafe {
            FRAME_SENDER = Some(sender);
            FRAME_COUNT = Some(frame_count.clone());
        }
        
        Self {
            receiver,
            frame_count,
        }
    }

    fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 获取主显示器
        let primary_monitor = Monitor::primary()?;
        println!("Capturing monitor: {:?}", primary_monitor.name());

        // 设置最小更新间隔为 1/144 秒（约 6.94ms）以支持 144Hz
        // 注意：这是最小间隔，实际帧率取决于系统
        let min_interval = Duration::from_micros(6_944); // ~144 FPS

        let settings = Settings::new(
            primary_monitor,
            CursorCaptureSettings::Default,
            DrawBorderSettings::Default,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Custom(min_interval),
            DirtyRegionSettings::Default,
            ColorFormat::Rgba8,
            (), // 空的 flags
        );

        // 在新线程中启动捕获
        std::thread::spawn(move || {
            CaptureHandler::start(settings).expect("Screen capture failed");
        });

        // 等待一下让捕获初始化
        std::thread::sleep(Duration::from_millis(500));

        Ok(())
    }

    fn capture_frame(&mut self) -> Result<Option<f64>, Box<dyn std::error::Error>> {
        match self.receiver.try_recv() {
            Ok(time) => Ok(Some(time)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err("Channel disconnected".into()),
        }
    }

    fn get_frame_count(&self) -> u64 {
        *self.frame_count.lock().unwrap()
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
        api_name: "GraphicsCapture".to_string(),
        language: "Rust".to_string(),
        duration_sec: 10,
        width: 0,
        height: 0,
    };

    let mut collector = MetricsCollector::new(config.clone());
    let mut capture = GraphicsCaptureCapture::new();

    println!("Starting Graphics Capture test...");
    println!("Note: Windows will show a permission dialog for screen capture.");
    println!("      Please click 'Yes' to allow capture.");

    capture.initialize()?;

    println!("Capture initialized successfully!");

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
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    collector.print_summary();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let csv_path = format!("D:/Project/TestProject/CapTest/results/{}_rust_graphics_capture.csv", timestamp);
    let json_path = format!("D:/Project/TestProject/CapTest/results/{}_rust_graphics_capture.json", timestamp);

    collector.save_to_csv(&csv_path);
    collector.save_to_json(&json_path);

    println!("Results saved to:");
    println!("  {}", csv_path);
    println!("  {}", json_path);

    Ok(())
}
