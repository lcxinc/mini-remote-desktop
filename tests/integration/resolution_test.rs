//! Resolution-specific capture and encoding test
//!
//! Tests performance at different resolutions and refresh rates.

#[cfg(not(windows))]
fn main() {
    println!("resolution_test is Windows-only (WinRT capture + NVENC)");
}

#[cfg(windows)]
fn main() {
    windows_resolution::run();
}

#[cfg(windows)]
mod windows_resolution {
    use mrd_capture_winrt::WinrtCapture;
    use mrd_encode_nvenc::NvencH264Encoder;
    use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoEncoder};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy)]
    enum EncoderMode {
        UltraLowLatency,
        HighRefreshRate,
        ExtremeLowLatency,
        MaxSpeed,
    }

    /// Common resolution configurations
    const RESOLUTIONS: &[(usize, usize, &str)] = &[
        (1280, 720, "720p"),
        (1920, 1080, "1080p"),
        (2560, 1440, "2K QHD"),
        (3840, 2160, "4K UHD"),
    ];

    /// Common refresh rates
    const REFRESH_RATES: &[u32] = &[60, 120, 144, 240];

    pub fn run() {
        println!("=== Resolution & Refresh Rate Performance Test ===\n");

        // First, show available monitors
        println!("--- Available Monitors ---");
        match mrd_capture_winrt::get_monitor_count() {
            Ok(count) => println!("Monitor count: {}", count),
            Err(e) => println!("Failed to get monitor count: {:?}", e),
        }

        // Get capture info
        match mrd_capture_winrt::get_capture_info() {
            Ok(info) => {
                println!(
                    "Monitor capture supported: {}",
                    info.monitor_capture_supported
                );
                println!(
                    "Window capture supported: {}",
                    info.window_capture_supported
                );
            }
            Err(e) => println!("Failed to get capture info: {:?}", e),
        }

        // Test each resolution
        for &(width, height, name) in RESOLUTIONS {
            println!("\n--- Testing {} ({}x{}) ---", name, width, height);

            // Test with different refresh rates
            for &fps in REFRESH_RATES {
                print!("  @ {}Hz: ", fps);

                // Test with both encoder modes
                let ull_result = test_encoding_at_resolution(
                    width,
                    height,
                    fps,
                    30,
                    EncoderMode::UltraLowLatency,
                );
                let hrr_result = test_encoding_at_resolution(
                    width,
                    height,
                    fps,
                    30,
                    EncoderMode::HighRefreshRate,
                );

                match (ull_result, hrr_result) {
                    (Ok(ull_stats), Ok(hrr_stats)) => {
                        let ull_p95 = ull_stats.encode_p95.as_nanos();
                        let hrr_p95 = hrr_stats.encode_p95.as_nanos();
                        let improvement = if ull_p95 > hrr_p95 {
                            ((ull_p95 - hrr_p95) as f64 / ull_p95 as f64) * 100.0
                        } else {
                            -((hrr_p95 - ull_p95) as f64 / hrr_p95 as f64) * 100.0
                        };
                        println!(
                            "ULL P50={:.2}ms/P95={:.2}ms | HRR P50={:.2}ms/P95={:.2}ms [Δ={:.1}%]",
                            ull_stats.encode_p50.as_secs_f64() * 1000.0,
                            ull_stats.encode_p95.as_secs_f64() * 1000.0,
                            hrr_stats.encode_p50.as_secs_f64() * 1000.0,
                            hrr_stats.encode_p95.as_secs_f64() * 1000.0,
                            improvement
                        );
                    }
                    (Ok(ull_stats), Err(_)) => {
                        println!(
                            "ULL P50={:.2}ms, P95={:.2}ms | HRR N/A",
                            ull_stats.encode_p50.as_secs_f64() * 1000.0,
                            ull_stats.encode_p95.as_secs_f64() * 1000.0
                        );
                    }
                    (Err(e1), Err(e2)) => {
                        println!("✗ ULL: {:?} | HRR: {:?}", e1, e2);
                    }
                    _ => {}
                }
            }
        }

        // Test WinRT monitor capture with actual resolution
        println!("\n--- Actual Monitor Resolution Test ---");
        if let Ok(capture) = WinrtCapture::from_monitor_index(0) {
            println!("Monitor 0: {}x{}", capture.width(), capture.height());
        }

        // 2K 144Hz detailed comparison
        println!("\n--- 2K 144Hz Detailed Comparison ---");
        test_2k_144hz_detailed();

        println!("\n=== Test Complete ===");
    }

    fn test_2k_144hz_detailed() {
        const WIDTH: usize = 2560;
        const HEIGHT: usize = 1440;
        const FPS: u32 = 144;
        const FRAME_COUNT: usize = 120; // Test more frames for accurate P95

        println!("Testing 2K@144Hz with {} frames...", FRAME_COUNT);
        let frame_budget_ms = 1000.0 / FPS as f64;

        // Ultra Low Latency mode
        print!("  ULL Mode: ");
        match test_encoding_at_resolution(
            WIDTH,
            HEIGHT,
            FPS,
            FRAME_COUNT,
            EncoderMode::UltraLowLatency,
        ) {
            Ok(stats) => {
                let p50_ms = stats.encode_p50.as_secs_f64() * 1000.0;
                let p95_ms = stats.encode_p95.as_secs_f64() * 1000.0;
                let p50_status = if p50_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                let p95_status = if p95_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                println!(
                    "P50={} {:.2}ms, P95={} {:.2}ms (Budget: {:.2}ms)",
                    p50_status, p50_ms, p95_status, p95_ms, frame_budget_ms
                );
            }
            Err(e) => println!("Failed: {:?}", e),
        }

        // High Refresh Rate mode
        print!("  HRR Mode: ");
        match test_encoding_at_resolution(
            WIDTH,
            HEIGHT,
            FPS,
            FRAME_COUNT,
            EncoderMode::HighRefreshRate,
        ) {
            Ok(stats) => {
                let p50_ms = stats.encode_p50.as_secs_f64() * 1000.0;
                let p95_ms = stats.encode_p95.as_secs_f64() * 1000.0;
                let p50_status = if p50_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                let p95_status = if p95_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                println!(
                    "P50={} {:.2}ms, P95={} {:.2}ms (Budget: {:.2}ms)",
                    p50_status, p50_ms, p95_status, p95_ms, frame_budget_ms
                );
            }
            Err(e) => println!("Failed: {:?}", e),
        }

        // Extreme Low Latency mode
        print!("  ELL Mode: ");
        match test_encoding_at_resolution(
            WIDTH,
            HEIGHT,
            FPS,
            FRAME_COUNT,
            EncoderMode::ExtremeLowLatency,
        ) {
            Ok(stats) => {
                let p50_ms = stats.encode_p50.as_secs_f64() * 1000.0;
                let p95_ms = stats.encode_p95.as_secs_f64() * 1000.0;
                let p50_status = if p50_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                let p95_status = if p95_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                println!(
                    "P50={} {:.2}ms, P95={} {:.2}ms (Budget: {:.2}ms)",
                    p50_status, p50_ms, p95_status, p95_ms, frame_budget_ms
                );
            }
            Err(e) => println!("Failed: {:?}", e),
        }

        // Max Speed mode
        print!("  MAX Mode: ");
        match test_encoding_at_resolution(WIDTH, HEIGHT, FPS, FRAME_COUNT, EncoderMode::MaxSpeed) {
            Ok(stats) => {
                let p50_ms = stats.encode_p50.as_secs_f64() * 1000.0;
                let p95_ms = stats.encode_p95.as_secs_f64() * 1000.0;
                let p50_status = if p50_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                let p95_status = if p95_ms <= frame_budget_ms {
                    "✓"
                } else {
                    "⚠"
                };
                println!(
                    "P50={} {:.2}ms, P95={} {:.2}ms (Budget: {:.2}ms)",
                    p50_status, p50_ms, p95_status, p95_ms, frame_budget_ms
                );
            }
            Err(e) => println!("Failed: {:?}", e),
        }
    }

    struct EncodingStats {
        encode_p50: Duration,
        encode_p95: Duration,
    }

    fn test_encoding_at_resolution(
        width: usize,
        height: usize,
        fps: u32,
        frame_count: usize,
        mode: EncoderMode,
    ) -> Result<EncodingStats, Box<dyn std::error::Error>> {
        // Create encoder based on mode
        let mut encoder = match mode {
            EncoderMode::UltraLowLatency => {
                NvencH264Encoder::new_ultra_low_latency(width, height, fps)?
            }
            EncoderMode::HighRefreshRate => {
                NvencH264Encoder::new_high_refresh_rate(width, height, fps)?
            }
            EncoderMode::ExtremeLowLatency => {
                NvencH264Encoder::new_extreme_low_latency(width, height, fps)?
            }
            EncoderMode::MaxSpeed => NvencH264Encoder::new_max_speed(width, height, fps)?,
        };

        let mut encode_latencies = Vec::with_capacity(frame_count);

        for frame_idx in 0..frame_count {
            let frame = CapturedFrame::from_cpu(
                width,
                height,
                FramePixelFormat::Bgra32,
                frame_idx as u64 * (1_000_000 / fps as u64),
                synthetic_frame_bytes(width, height, frame_idx as u8),
            );

            let encode_start = Instant::now();
            encoder.encode(&frame)?;
            let encode_latency = encode_start.elapsed();
            encode_latencies.push(encode_latency);
        }

        // Calculate statistics
        encode_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let encode_p50 = encode_latencies[encode_latencies.len() / 2];
        let encode_p95 = encode_latencies[(encode_latencies.len() * 95) / 100];

        Ok(EncodingStats {
            encode_p50,
            encode_p95,
        })
    }

    fn synthetic_frame_bytes(width: usize, height: usize, value: u8) -> Vec<u8> {
        let mut bytes = vec![0_u8; width * height * 4];
        for (index, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let x = (index % width) as u8;
            let y = (index / width) as u8;
            chunk[0] = x.wrapping_add(value);
            chunk[1] = y;
            chunk[2] = value.wrapping_add(x);
            chunk[3] = 255;
        }
        bytes
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[ignore]
        fn test_720p_60hz() {
            let result =
                test_encoding_at_resolution(1280, 720, 60, 60, EncoderMode::UltraLowLatency);
            assert!(result.is_ok(), "720p@60Hz encoding failed");
        }

        #[test]
        #[ignore]
        fn test_1080p_60hz() {
            let result =
                test_encoding_at_resolution(1920, 1080, 60, 60, EncoderMode::UltraLowLatency);
            assert!(result.is_ok(), "1080p@60Hz encoding failed");
        }

        #[test]
        #[ignore]
        fn test_2k_144hz() {
            let result =
                test_encoding_at_resolution(2560, 1440, 144, 120, EncoderMode::HighRefreshRate);
            assert!(result.is_ok(), "2K@144Hz encoding failed");

            if let Ok(stats) = result {
                println!(
                    "2K@144Hz - P50: {:.2}ms, P95: {:.2}ms",
                    stats.encode_p50.as_secs_f64() * 1000.0,
                    stats.encode_p95.as_secs_f64() * 1000.0
                );
            }
        }

        #[test]
        #[ignore]
        fn test_4k_60hz() {
            let result =
                test_encoding_at_resolution(3840, 2160, 60, 60, EncoderMode::UltraLowLatency);
            assert!(result.is_ok(), "4K@60Hz encoding failed");
        }

        #[test]
        #[ignore]
        fn test_2k_144hz_comparison() {
            println!("\n--- 2K 144Hz Mode Comparison ---");

            let ull_result =
                test_encoding_at_resolution(2560, 1440, 144, 120, EncoderMode::UltraLowLatency);
            let hrr_result =
                test_encoding_at_resolution(2560, 1440, 144, 120, EncoderMode::HighRefreshRate);

            if let (Ok(ull), Ok(hrr)) = (ull_result, hrr_result) {
                println!(
                    "ULL: P50={:.2}ms, P95={:.2}ms",
                    ull.encode_p50.as_secs_f64() * 1000.0,
                    ull.encode_p95.as_secs_f64() * 1000.0
                );
                println!(
                    "HRR: P50={:.2}ms, P95={:.2}ms",
                    hrr.encode_p50.as_secs_f64() * 1000.0,
                    hrr.encode_p95.as_secs_f64() * 1000.0
                );
                println!(
                    "Improvement: {:.1}%",
                    ((ull.encode_p95.as_nanos() - hrr.encode_p95.as_nanos()) as f64
                        / ull.encode_p95.as_nanos() as f64)
                        * 100.0
                );
            }
        }
    }
}
