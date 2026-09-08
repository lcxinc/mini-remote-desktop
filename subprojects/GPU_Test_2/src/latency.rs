//! 全链路延迟测试
//!
//! 采集 -> 编码 -> 传输 -> 解码 -> 渲染
//! 测量每个阶段的 p50, p90, p95, p99 延迟

use anyhow::Result;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 延迟统计
#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub samples: Vec<Duration>,
    pub p50: Duration,
    pub p90: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
    pub mean: Duration,
    pub stddev: Duration,
}

impl LatencyStats {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            p50: Duration::ZERO,
            p90: Duration::ZERO,
            p95: Duration::ZERO,
            p99: Duration::ZERO,
            min: Duration::ZERO,
            max: Duration::ZERO,
            mean: Duration::ZERO,
            stddev: Duration::ZERO,
        }
    }

    pub fn add_sample(&mut self, latency: Duration) {
        self.samples.push(latency);
    }

    pub fn calculate(&mut self) {
        if self.samples.is_empty() {
            return;
        }

        self.samples.sort();

        let len = self.samples.len();
        self.min = self.samples[0];
        self.max = self.samples[len - 1];

        // 计算百分位数
        let p50_idx = (len as f64 * 0.50) as usize;
        let p90_idx = (len as f64 * 0.90) as usize;
        let p95_idx = (len as f64 * 0.95) as usize;
        let p99_idx = (len as f64 * 0.99) as usize;

        self.p50 = self.samples[p50_idx.min(len - 1)];
        self.p90 = self.samples[p90_idx.min(len - 1)];
        self.p95 = self.samples[p95_idx.min(len - 1)];
        self.p99 = self.samples[p99_idx.min(len - 1)];

        // 计算平均值
        let total: Duration = self.samples.iter().sum();
        self.mean = total / len as u32;

        // 计算标准差
        let mean_secs = self.mean.as_secs_f64();
        let variance: f64 = self
            .samples
            .iter()
            .map(|d| {
                let diff = d.as_secs_f64() - mean_secs;
                diff * diff
            })
            .sum::<f64>()
            / len as f64;
        self.stddev = Duration::from_secs_f64(variance.sqrt());
    }

    pub fn print(&self, name: &str) {
        println!("=== {} 延迟统计 ===", name);
        println!("  样本数: {}", self.samples.len());
        println!("  最小值: {:.3} ms", self.min.as_secs_f64() * 1000.0);
        println!("  最大值: {:.3} ms", self.max.as_secs_f64() * 1000.0);
        println!("  平均值: {:.3} ms", self.mean.as_secs_f64() * 1000.0);
        println!("  标准差: {:.3} ms", self.stddev.as_secs_f64() * 1000.0);
        println!("  P50:    {:.3} ms", self.p50.as_secs_f64() * 1000.0);
        println!("  P90:    {:.3} ms", self.p90.as_secs_f64() * 1000.0);
        println!("  P95:    {:.3} ms", self.p95.as_secs_f64() * 1000.0);
        println!("  P99:    {:.3} ms", self.p99.as_secs_f64() * 1000.0);
        println!();
    }
}

/// 延迟测量器
pub struct LatencyMeasurer {
    capture_stats: LatencyStats,
    encode_stats: LatencyStats,
    transfer_stats: LatencyStats,
    decode_stats: LatencyStats,
    render_stats: LatencyStats,
    e2e_stats: LatencyStats,
}

impl LatencyMeasurer {
    pub fn new() -> Self {
        Self {
            capture_stats: LatencyStats::new(),
            encode_stats: LatencyStats::new(),
            transfer_stats: LatencyStats::new(),
            decode_stats: LatencyStats::new(),
            render_stats: LatencyStats::new(),
            e2e_stats: LatencyStats::new(),
        }
    }

    pub fn add_capture(&mut self, latency: Duration) {
        self.capture_stats.add_sample(latency);
    }

    pub fn add_encode(&mut self, latency: Duration) {
        self.encode_stats.add_sample(latency);
    }

    pub fn add_transfer(&mut self, latency: Duration) {
        self.transfer_stats.add_sample(latency);
    }

    pub fn add_decode(&mut self, latency: Duration) {
        self.decode_stats.add_sample(latency);
    }

    pub fn add_render(&mut self, latency: Duration) {
        self.render_stats.add_sample(latency);
    }

    pub fn add_e2e(&mut self, latency: Duration) {
        self.e2e_stats.add_sample(latency);
    }

    pub fn calculate(&mut self) {
        self.capture_stats.calculate();
        self.encode_stats.calculate();
        self.transfer_stats.calculate();
        self.decode_stats.calculate();
        self.render_stats.calculate();
        self.e2e_stats.calculate();
    }

    pub fn print(&self) {
        println!("\n");
        println!(
            "╔══════════════════════════════════════════════════════════════════════════════╗"
        );
        println!("║                    全链路延迟测试报告                                       ║");
        println!(
            "╚══════════════════════════════════════════════════════════════════════════════╝"
        );
        println!();

        self.capture_stats.print("采集");
        self.encode_stats.print("编码");
        self.transfer_stats.print("传输");
        self.decode_stats.print("解码");
        self.render_stats.print("渲染");
        self.e2e_stats.print("端到端");

        println!("=== 延迟汇总 ===");
        println!("| 阶段   | P50 (ms) | P90 (ms) | P95 (ms) | P99 (ms) |");
        println!("|--------|----------|----------|----------|----------|");
        println!(
            "| 采集   | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            self.capture_stats.p50.as_secs_f64() * 1000.0,
            self.capture_stats.p90.as_secs_f64() * 1000.0,
            self.capture_stats.p95.as_secs_f64() * 1000.0,
            self.capture_stats.p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 编码   | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            self.encode_stats.p50.as_secs_f64() * 1000.0,
            self.encode_stats.p90.as_secs_f64() * 1000.0,
            self.encode_stats.p95.as_secs_f64() * 1000.0,
            self.encode_stats.p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 传输   | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            self.transfer_stats.p50.as_secs_f64() * 1000.0,
            self.transfer_stats.p90.as_secs_f64() * 1000.0,
            self.transfer_stats.p95.as_secs_f64() * 1000.0,
            self.transfer_stats.p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 解码   | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            self.decode_stats.p50.as_secs_f64() * 1000.0,
            self.decode_stats.p90.as_secs_f64() * 1000.0,
            self.decode_stats.p95.as_secs_f64() * 1000.0,
            self.decode_stats.p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 渲染   | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            self.render_stats.p50.as_secs_f64() * 1000.0,
            self.render_stats.p90.as_secs_f64() * 1000.0,
            self.render_stats.p95.as_secs_f64() * 1000.0,
            self.render_stats.p99.as_secs_f64() * 1000.0
        );
        println!(
            "| 端到端 | {:8.3} | {:8.3} | {:8.3} | {:8.3} |",
            self.e2e_stats.p50.as_secs_f64() * 1000.0,
            self.e2e_stats.p90.as_secs_f64() * 1000.0,
            self.e2e_stats.p95.as_secs_f64() * 1000.0,
            self.e2e_stats.p99.as_secs_f64() * 1000.0
        );
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_stats() {
        let mut stats = LatencyStats::new();
        stats.add_sample(Duration::from_millis(1));
        stats.add_sample(Duration::from_millis(2));
        stats.add_sample(Duration::from_millis(3));
        stats.add_sample(Duration::from_millis(4));
        stats.add_sample(Duration::from_millis(5));
        stats.calculate();

        assert_eq!(stats.min, Duration::from_millis(1));
        assert_eq!(stats.max, Duration::from_millis(5));
        assert_eq!(stats.p50, Duration::from_millis(3));
    }
}
