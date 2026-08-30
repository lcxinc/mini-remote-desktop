use std::{fs, path::Path, time::Instant};

use mrd_encode_openh264::OpenH264Encoder;
use mrd_observability::{ComponentKind, ComponentResult};
use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoEncoder};

#[test]
#[ignore]
fn perf_openh264_encode_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120);
    let case_name =
        std::env::var("MRD_COMPONENT_CASE_NAME").unwrap_or_else(|_| "encode.openh264".into());
    let width = 1280usize;
    let height = 720usize;
    let mut encoder = OpenH264Encoder::new(width, height, 30).expect("create openh264 encoder");
    let frame = CapturedFrame::from_cpu(
        width,
        height,
        FramePixelFormat::Bgra32,
        0,
        synthetic_bgra_frame(width, height),
    );

    let mut latencies_ms = Vec::with_capacity(sample_count as usize);
    let mut access_unit_sizes = Vec::with_capacity(sample_count as usize);
    let mut success_count = 0_u64;
    let mut failure_count = 0_u64;
    let mut keyframe_count = 0_u64;
    let started_at = Instant::now();

    for index in 0..sample_count {
        let mut frame = frame.clone();
        frame.timestamp_us = index * 33_000;
        let iter_started_at = Instant::now();
        match encoder.encode(&frame) {
            Ok(access_units) => {
                latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
                success_count += 1;
                for access_unit in access_units {
                    access_unit_sizes.push(access_unit.bytes.len());
                    if access_unit.is_keyframe {
                        keyframe_count += 1;
                    }
                }
            }
            Err(_) => {
                failure_count += 1;
            }
        }
    }

    let result = ComponentResult::new(
        ComponentKind::Encode,
        "openh264",
        case_name,
        started_at.elapsed().as_secs_f64(),
        success_count,
        failure_count,
        &latencies_ms,
        Some(width as u32),
        Some(height as u32),
        None,
        None,
        Some(&access_unit_sizes),
        None,
        None,
        if success_count > 0 {
            Some(keyframe_count as f64 / success_count as f64)
        } else {
            None
        },
        None,
    );

    if let Ok(result_path) = std::env::var("MRD_COMPONENT_RESULT_PATH") {
        fs::write(
            Path::new(&result_path),
            serde_json::to_string_pretty(&result).expect("serialize encode perf result"),
        )
        .expect("write encode perf result");
    }

    assert!(result.sample_count > 0);
    assert!(result.latency_ms.p50_ms.is_some());
    assert!(result.latency_ms.p95_ms.is_some());
    assert!(result.latency_ms.p99_ms.is_some());
    assert!(result.access_unit_bytes.is_some());
}

fn synthetic_bgra_frame(width: usize, height: usize) -> Vec<u8> {
    let mut data = vec![0_u8; width * height * 4];
    for (index, chunk) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        chunk[0] = (index % 255) as u8;
        chunk[1] = ((index / 2) % 255) as u8;
        chunk[2] = ((index / 3) % 255) as u8;
        chunk[3] = 255;
    }
    data
}
