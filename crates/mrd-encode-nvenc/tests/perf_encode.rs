use std::{fs, path::Path, time::Instant};

use mrd_encode_nvenc::NvencH264Encoder;
use mrd_observability::{ComponentKind, ComponentResult};
use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoEncoder};

#[test]
#[ignore]
fn perf_nvenc_encode_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120);
    let case_name =
        std::env::var("MRD_COMPONENT_CASE_NAME").unwrap_or_else(|_| "encode.nvenc".into());
    let width = env_u32("MRD_COMPONENT_WIDTH").unwrap_or(1280);
    let height = env_u32("MRD_COMPONENT_HEIGHT").unwrap_or(720);
    let fps = env_u32("MRD_COMPONENT_FPS").unwrap_or(30);
    let frame = CapturedFrame::from_cpu(
        width as usize,
        height as usize,
        FramePixelFormat::Bgra32,
        0,
        synthetic_frame_bytes(width as usize, height as usize),
    );

    let started_at = Instant::now();
    let Ok(mut encoder) = new_encoder_for_backend(
        &std::env::var("MRD_COMPONENT_BACKEND").unwrap_or_else(|_| "nvenc".into()),
        width as usize,
        height as usize,
        fps,
    ) else {
        let result = ComponentResult::new(
            ComponentKind::Encode,
            "nvenc",
            case_name,
            started_at.elapsed().as_secs_f64(),
            0,
            1,
            &[],
            Some(width),
            Some(height),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        write_result(&result);
        return;
    };

    let mut latencies_ms = Vec::with_capacity(sample_count as usize);
    let mut access_unit_sizes = Vec::with_capacity(sample_count as usize);
    let mut success_count = 0_u64;
    let mut failure_count = 0_u64;

    for index in 0..sample_count {
        let mut frame = frame.clone();
        frame.timestamp_us = index * 33_000;
        frame.data[0] = (index % 255) as u8;
        let iter_started_at = Instant::now();
        match encoder.encode(&frame) {
            Ok(access_units) if !access_units.is_empty() => {
                latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
                access_unit_sizes.push(access_units[0].bytes.len());
                success_count += 1;
            }
            _ => {
                failure_count += 1;
            }
        }
    }

    let result = ComponentResult::new(
        ComponentKind::Encode,
        "nvenc",
        case_name,
        started_at.elapsed().as_secs_f64(),
        success_count,
        failure_count,
        &latencies_ms,
        Some(width),
        Some(height),
        None,
        None,
        Some(&access_unit_sizes),
        Some(&access_unit_sizes),
        None,
        Some(success_count as f64 / sample_count.max(1) as f64),
        None,
    );
    write_result(&result);
}

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
}

fn new_encoder_for_backend(
    backend: &str,
    width: usize,
    height: usize,
    fps: u32,
) -> Result<NvencH264Encoder, mrd_pipeline_core::PipelineError> {
    match backend {
        "nvenc_max_speed" => NvencH264Encoder::new_max_speed(width, height, fps),
        "nvenc_ll_p1" => NvencH264Encoder::new_low_latency_p1(width, height, fps),
        "nvenc_hq_p5" => NvencH264Encoder::new_high_quality_p5(width, height, fps),
        _ => NvencH264Encoder::new(width, height, fps),
    }
}

fn synthetic_frame_bytes(width: usize, height: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; width * height * 4];
    for (index, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        chunk[0] = (index % 255) as u8;
        chunk[1] = 64;
        chunk[2] = 192;
        chunk[3] = 255;
    }
    bytes
}

fn write_result(result: &ComponentResult) {
    if let Ok(result_path) = std::env::var("MRD_COMPONENT_RESULT_PATH") {
        fs::write(
            Path::new(&result_path),
            serde_json::to_string_pretty(result).expect("serialize nvenc perf result"),
        )
        .expect("write nvenc perf result");
    }
}
