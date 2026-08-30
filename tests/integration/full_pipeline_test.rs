//! Full pipeline integration test
//!
//! Tests the complete encoding → transport → decoding pipeline locally.

#[cfg(not(windows))]
fn main() {
    println!("full_pipeline_test is Windows-only (NVENC/NVDEC/AV1 hardware paths)");
}

#[cfg(windows)]
fn main() {
    windows_full_pipeline::run();
}

#[cfg(windows)]
mod windows_full_pipeline {
    use std::time::{Duration, Instant};

    use mrd_decode::NvdecVideoDecoder;
    use mrd_encode_nvenc::NvencH264Encoder;
    use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoDecoder, VideoEncoder};
    use mrd_transport_quic_quinn::{
        fragment_access_unit, QuicAuFragment, QuicAuReassembler, QuicAuReassemblerConfig,
    };

    pub fn run() {
        println!("=== Mini Remote Desktop - Full Pipeline Integration Test ===\n");

        // Run all tests
        test_full_pipeline_nvenc_to_nvdec();
        test_ultra_low_latency_pipeline();
        test_av1_pipeline();

        println!("\n=== All tests completed ===");
    }

    /// Test full pipeline: Encode → Fragment → Reassemble → Decode
    fn test_full_pipeline_nvenc_to_nvdec() {
        println!("--- Test 1: NVENC → Transport → NVDEC Pipeline ---");

        let width = 1280_usize;
        let height = 720_usize;
        let fps = 30_u32;
        let frame_count = 60;

        // Create encoder
        let encoder = match NvencH264Encoder::new(width, height, fps) {
            Ok(e) => e,
            Err(e) => {
                println!("NVENC not available: {}, skipping test", e);
                return;
            }
        };

        // Create decoder
        let decoder = match NvdecVideoDecoder::new() {
            Ok(d) => d,
            Err(e) => {
                println!("NVDEC not available: {}, skipping test", e);
                return;
            }
        };

        // Create reassembler
        let mut reassembler = QuicAuReassembler::new(QuicAuReassemblerConfig {
            frame_timeout: Duration::from_millis(250),
            max_pending_frames: 64,
        });

        let mut encode_latencies = Vec::new();
        let mut fragment_count = 0;
        let mut reassembled_count = 0;
        let mut decoded_frame_count = 0;
        let mut encoder = encoder;
        let mut decoder = decoder;

        println!("Running full pipeline test: {} frames", frame_count);

        for frame_idx in 0..frame_count {
            // 1. Create synthetic frame
            let frame = CapturedFrame::from_cpu(
                width,
                height,
                FramePixelFormat::Bgra32,
                frame_idx as u64 * 33_333,
                synthetic_frame_bytes(width, height, frame_idx as u8),
            );

            // 2. Encode
            let encode_start = Instant::now();
            let encoded_units = match encoder.encode(&frame) {
                Ok(units) => units,
                Err(e) => {
                    println!("Encode failed at frame {}: {}", frame_idx, e);
                    break;
                }
            };
            let encode_latency = encode_start.elapsed();
            encode_latencies.push(encode_latency);

            for unit in &encoded_units {
                // 3. Fragment for transport
                let fragments = match fragment_access_unit(
                    frame_idx as u32,
                    unit.timestamp_us,
                    unit.is_keyframe,
                    &unit.bytes,
                    1200, // Typical MTU
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        println!("Fragmentation failed: {}", e);
                        continue;
                    }
                };
                fragment_count += fragments.len();

                // 4. Reassemble
                for fragment in &fragments {
                    let _parsed = match QuicAuFragment::decode(fragment) {
                        Ok(f) => f,
                        Err(e) => {
                            println!("Fragment decode failed: {}", e);
                            continue;
                        }
                    };
                    if let Ok(Some(reassembled)) = reassembler.push_datagram(fragment) {
                        reassembled_count += 1;

                        // 5. Decode
                        if decoder.push_access_unit(&reassembled.payload).is_ok() {
                            let frames = decoder.drain_decoded_frames();
                            decoded_frame_count += frames.len();
                        }
                    }
                }
            }

            if frame_idx % 10 == 0 {
                println!(
                    "Frame {}: encode={:.2?}ms, total_fragments={}, reassembled={}, decoded={}",
                    frame_idx,
                    encode_latency.as_secs_f64() * 1000.0,
                    fragment_count,
                    reassembled_count,
                    decoded_frame_count
                );
            }
        }

        // Prune any remaining frames
        reassembler.prune_expired();

        // Statistics
        if encode_latencies.is_empty() {
            println!("No frames encoded successfully!");
            return;
        }

        encode_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let encode_p50 = encode_latencies[encode_latencies.len() / 2];
        let encode_p95 = encode_latencies[(encode_latencies.len() * 95) / 100];
        let encode_p99 = encode_latencies[(encode_latencies.len() * 99) / 100];

        println!("\n--- Results ---");
        println!("Frames processed: {}", frame_count);
        println!("Fragments created: {}", fragment_count);
        println!("Frames reassembled: {}", reassembled_count);
        println!("Frames decoded: {}", decoded_frame_count);
        println!("\nEncode latency:");
        println!("  P50: {:.2}ms", encode_p50.as_secs_f64() * 1000.0);
        println!("  P95: {:.2}ms", encode_p95.as_secs_f64() * 1000.0);
        println!("  P99: {:.2}ms", encode_p99.as_secs_f64() * 1000.0);

        // Basic sanity checks
        if decoded_frame_count <= frame_count / 2 {
            println!(
                "WARNING: Only decoded {} out of {} frames",
                decoded_frame_count, frame_count
            );
        }
        if encode_p95.as_millis() > 20 {
            println!(
                "WARNING: Encode P95 is {:.2}ms (target < 20ms)",
                encode_p95.as_secs_f64() * 1000.0
            );
        } else {
            println!("✓ Encode P95 meets target (< 20ms)");
        }
    }

    /// Test ultra-low latency encoder pipeline
    fn test_ultra_low_latency_pipeline() {
        println!("\n--- Test 2: Ultra-Low Latency NVENC Pipeline ---");

        let width = 1280_usize;
        let height = 720_usize;
        let fps = 30_u32;
        let frame_count = 60;

        // Create ultra-low latency encoder
        let encoder = match NvencH264Encoder::new_ultra_low_latency(width, height, fps) {
            Ok(e) => e,
            Err(e) => {
                println!(
                    "NVENC ultra-low latency not available: {}, skipping test",
                    e
                );
                return;
            }
        };

        let decoder = match NvdecVideoDecoder::new() {
            Ok(d) => d,
            Err(e) => {
                println!("NVDEC not available: {}, skipping test", e);
                return;
            }
        };

        let mut encode_latencies = Vec::new();
        let mut decoded_frame_count = 0;
        let mut encoder = encoder;
        let mut decoder = decoder;

        println!(
            "Running ultra-low latency pipeline test: {} frames",
            frame_count
        );

        for frame_idx in 0..frame_count {
            let frame = CapturedFrame::from_cpu(
                width,
                height,
                FramePixelFormat::Bgra32,
                frame_idx as u64 * 33_333,
                synthetic_frame_bytes(width, height, frame_idx as u8),
            );

            let encode_start = Instant::now();
            let encoded_units = match encoder.encode(&frame) {
                Ok(units) => units,
                Err(e) => {
                    println!("Encode failed at frame {}: {}", frame_idx, e);
                    break;
                }
            };
            let encode_latency = encode_start.elapsed();
            encode_latencies.push(encode_latency);

            for unit in &encoded_units {
                if decoder.push_access_unit(&unit.bytes).is_ok() {
                    let frames = decoder.drain_decoded_frames();
                    decoded_frame_count += frames.len();
                }
            }
        }

        if encode_latencies.is_empty() {
            println!("No frames encoded successfully!");
            return;
        }

        encode_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let encode_p50 = encode_latencies[encode_latencies.len() / 2];
        let encode_p95 = encode_latencies[(encode_latencies.len() * 95) / 100];
        let encode_p99 = encode_latencies[(encode_latencies.len() * 99) / 100];

        println!("\n--- Results ---");
        println!("Frames processed: {}", frame_count);
        println!("Frames decoded: {}", decoded_frame_count);
        println!("Encode P50: {:.2}ms", encode_p50.as_secs_f64() * 1000.0);
        println!("Encode P95: {:.2}ms", encode_p95.as_secs_f64() * 1000.0);
        println!("Encode P99: {:.2}ms", encode_p99.as_secs_f64() * 1000.0);

        // Ultra-low latency should be faster
        if encode_p95.as_millis() < 15 {
            println!("✓ Ultra-low latency encode P95 meets target (< 15ms)");
        } else {
            println!(
                "WARNING: Encode P95 is {:.2}ms (target < 15ms)",
                encode_p95.as_secs_f64() * 1000.0
            );
        }
    }

    /// Test AV1 full pipeline (if supported)
    fn test_av1_pipeline() {
        println!("\n--- Test 3: AV1 Pipeline ---");

        let width = 1280_usize;
        let height = 720_usize;
        let fps = 30_u32;
        let frame_count = 30;

        // Check AV1 encoder availability
        if mrd_encode_nvenc_av1::NvencAv1Encoder::probe_av1_available().is_err() {
            println!("AV1 encoder not available, skipping test");
            return;
        }

        let encoder = match mrd_encode_nvenc_av1::NvencAv1Encoder::new(width, height, fps) {
            Ok(e) => e,
            Err(e) => {
                println!("AV1 encoder creation failed: {}, skipping test", e);
                return;
            }
        };

        let mut encode_latencies = Vec::new();
        let mut encoded_bytes = 0;
        let mut encoder = encoder;

        println!("Running AV1 pipeline test: {} frames", frame_count);

        for frame_idx in 0..frame_count {
            let frame = CapturedFrame::from_cpu(
                width,
                height,
                FramePixelFormat::Bgra32,
                frame_idx as u64 * 33_333,
                synthetic_frame_bytes(width, height, frame_idx as u8),
            );

            let encode_start = Instant::now();
            let encoded_units = match encoder.encode(&frame) {
                Ok(units) => units,
                Err(e) => {
                    println!("Encode failed at frame {}: {}", frame_idx, e);
                    break;
                }
            };
            let encode_latency = encode_start.elapsed();
            encode_latencies.push(encode_latency);

            for unit in &encoded_units {
                encoded_bytes += unit.bytes.len();
            }
        }

        if encode_latencies.is_empty() {
            println!("No frames encoded successfully!");
            return;
        }

        encode_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let encode_p50 = encode_latencies[encode_latencies.len() / 2];
        let encode_p95 = encode_latencies[(encode_latencies.len() * 95) / 100];

        println!("\n--- Results ---");
        println!("Frames processed: {}", frame_count);
        println!("Total encoded bytes: {}", encoded_bytes);
        println!("Average bytes per frame: {}", encoded_bytes / frame_count);
        println!("Encode P50: {:.2}ms", encode_p50.as_secs_f64() * 1000.0);
        println!("Encode P95: {:.2}ms", encode_p95.as_secs_f64() * 1000.0);

        println!("✓ AV1 encoding completed successfully");
    }

    fn synthetic_frame_bytes(width: usize, height: usize, value: u8) -> Vec<u8> {
        let mut bytes = vec![0_u8; width * height * 4];
        for (index, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            // Create a gradient pattern based on position
            let x = (index % width) as u8;
            let y = (index / width) as u8;
            chunk[0] = x.wrapping_add(value); // B
            chunk[1] = y; // G
            chunk[2] = value.wrapping_add(x); // R
            chunk[3] = 255; // A
        }
        bytes
    }
}
