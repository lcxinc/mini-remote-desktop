use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameMetrics {
    pub frame_number: u64,
    pub capture_time_ms: f64,
    pub total_time_ms: f64,
    pub fps: f64,
    pub cpu_percent: f64,
    pub memory_mb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStatistics {
    pub avg_capture_time_ms: f64,
    pub min_capture_time_ms: f64,
    pub max_capture_time_ms: f64,
    pub p95_capture_time_ms: f64,
    pub p99_capture_time_ms: f64,
    pub avg_fps: f64,
    pub avg_cpu_percent: f64,
    pub avg_memory_mb: f64,
}

#[derive(Debug, Clone)]
pub struct TestConfig {
    pub api_name: String,
    pub language: String,
    pub duration_sec: u64,
    pub width: u32,
    pub height: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            api_name: String::new(),
            language: "Rust".to_string(),
            duration_sec: 60,
            width: 0,
            height: 0,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonResult<'a> {
    test_config: JsonTestConfig<'a>,
    statistics: TestStatistics,
}

#[derive(Debug, Serialize)]
struct JsonTestConfig<'a> {
    api: &'a str,
    language: &'a str,
    duration_sec: u64,
    total_frames: usize,
}

pub struct MetricsCollector {
    pub config: TestConfig,
    frames: Vec<FrameMetrics>,
    start_time: std::time::Instant,
}

impl MetricsCollector {
    pub fn new(config: TestConfig) -> Self {
        Self {
            config,
            frames: Vec::new(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn record_frame(&mut self, metrics: FrameMetrics) {
        self.frames.push(metrics);
    }

    pub fn calculate_statistics(&self) -> TestStatistics {
        if self.frames.is_empty() {
            return TestStatistics {
                avg_capture_time_ms: 0.0,
                min_capture_time_ms: 0.0,
                max_capture_time_ms: 0.0,
                p95_capture_time_ms: 0.0,
                p99_capture_time_ms: 0.0,
                avg_fps: 0.0,
                avg_cpu_percent: 0.0,
                avg_memory_mb: 0.0,
            };
        }

        let mut capture_times: Vec<f64> = self.frames.iter()
            .map(|f| f.capture_time_ms)
            .collect();
        capture_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let sum_capture_time: f64 = capture_times.iter().sum();
        let sum_cpu: f64 = self.frames.iter().map(|f| f.cpu_percent).sum();
        let sum_memory: f64 = self.frames.iter().map(|f| f.memory_mb).sum();

        let avg_capture_time_ms = sum_capture_time / self.frames.len() as f64;
        let min_capture_time_ms = capture_times[0];
        let max_capture_time_ms = capture_times[capture_times.len() - 1];

        let p95_idx = (0.95 * capture_times.len() as f64).ceil() as usize - 1;
        let p99_idx = (0.99 * capture_times.len() as f64).ceil() as usize - 1;
        let p95_capture_time_ms = capture_times[p95_idx.min(capture_times.len() - 1)];
        let p99_capture_time_ms = capture_times[p99_idx.min(capture_times.len() - 1)];

        // 正确的 FPS 计算：总帧数 / 总时间（秒）
        let total_time_sec = self.frames.last().unwrap().total_time_ms / 1000.0;
        let avg_fps = if total_time_sec > 0.0 {
            self.frames.len() as f64 / total_time_sec
        } else {
            0.0
        };

        TestStatistics {
            avg_capture_time_ms,
            min_capture_time_ms,
            max_capture_time_ms,
            p95_capture_time_ms,
            p99_capture_time_ms,
            avg_fps,
            avg_cpu_percent: sum_cpu / self.frames.len() as f64,
            avg_memory_mb: sum_memory / self.frames.len() as f64,
        }
    }

    pub fn save_to_csv<P: AsRef<Path>>(&self, filepath: P) {
        if let Ok(file) = File::create(filepath) {
            let mut wtr = csv::Writer::from_writer(file);

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            for frame in &self.frames {
                let _ = wtr.write_record(&[
                    &timestamp.to_string(),
                    &self.config.api_name,
                    &self.config.language,
                    &frame.frame_number.to_string(),
                    &format!("{:.2}", frame.capture_time_ms),
                    &format!("{:.2}", frame.total_time_ms),
                    &format!("{:.2}", frame.fps),
                    &format!("{:.2}", frame.cpu_percent),
                    &format!("{:.2}", frame.memory_mb),
                ]);
            }

            let _ = wtr.flush();
        }
    }

    pub fn save_to_json<P: AsRef<Path>>(&self, filepath: P) {
        let stats = self.calculate_statistics();
        let result = JsonResult {
            test_config: JsonTestConfig {
                api: &self.config.api_name,
                language: &self.config.language,
                duration_sec: self.config.duration_sec,
                total_frames: self.frames.len(),
            },
            statistics: stats,
        };

        if let Ok(file) = File::create(filepath) {
            let _ = serde_json::to_writer_pretty(file, &result);
        }
    }

    pub fn print_summary(&self) {
        let stats = self.calculate_statistics();

        println!("\n=== {} ({}) ===", self.config.api_name, self.config.language);
        println!("Total frames captured: {}", self.frames.len());
        println!("Average capture time: {:.2} ms", stats.avg_capture_time_ms);
        println!("Min/Max capture time: {:.2} / {:.2} ms",
                 stats.min_capture_time_ms, stats.max_capture_time_ms);
        println!("P95/P99 capture time: {:.2} / {:.2} ms",
                 stats.p95_capture_time_ms, stats.p99_capture_time_ms);
        println!("Average FPS: {:.2}", stats.avg_fps);
        println!("Average CPU: {:.2}%", stats.avg_cpu_percent);
        println!("Average Memory: {:.2} MB", stats.avg_memory_mb);
        println!();
    }
}
