use std::{
    fs,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use mrd_decode::create_decoder;
use mrd_encode_nvenc::NvencH264Encoder;
use mrd_observability::{ComponentKind, ComponentResult};
use mrd_pipeline_core::{CapturedFrame, DecodedFrameData, FramePixelFormat, VideoEncoder};
use openh264::{
    encoder::Encoder,
    formats::{RgbSliceU8, YUVBuffer},
};

#[test]
#[ignore]
fn perf_h264_software_decode_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120);
    let case_name =
        std::env::var("MRD_COMPONENT_CASE_NAME").unwrap_or_else(|_| "decode.h264_software".into());
    run_h264_decode_perf(
        "h264_software",
        "h264_software",
        &case_name,
        sample_count,
        Duration::ZERO,
    );
}

#[test]
#[ignore]
fn perf_h264_ffmpeg_decode_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let case_name =
        std::env::var("MRD_COMPONENT_CASE_NAME").unwrap_or_else(|_| "decode.ffmpeg_h264".into());
    run_h264_decode_perf(
        "ffmpeg_h264",
        "ffmpeg_h264",
        &case_name,
        sample_count,
        Duration::from_millis(20),
    );
}

fn run_h264_decode_perf(
    decoder_id: &str,
    backend: &str,
    case_name: &str,
    sample_count: u64,
    wait_after_push: Duration,
) {
    let access_unit = encoded_access_unit();
    let mut decoder = create_decoder(decoder_id).expect("create h264 decoder");

    let mut latencies_ms = Vec::with_capacity(sample_count as usize);
    let mut success_count = 0_u64;
    let mut failure_count = 0_u64;
    let mut decoded_frame_bytes = None;
    let mut width = None;
    let mut height = None;
    let started_at = Instant::now();

    for _ in 0..sample_count {
        let iter_started_at = Instant::now();
        match decoder.push_access_unit(&access_unit) {
            Ok(()) => {
                let mut frames = decoder.drain_decoded_frames();
                if frames.is_empty() && !wait_after_push.is_zero() {
                    let deadline = Instant::now() + wait_after_push;
                    while frames.is_empty() && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(2));
                        frames = decoder.drain_decoded_frames();
                    }
                }
                if let Some(frame) = frames.first() {
                    decoded_frame_bytes = match &frame.data {
                        DecodedFrameData::CpuRgb24(data) => Some(data.len()),
                        DecodedFrameData::CpuI420 { data, .. } => Some(data.len()),
                        DecodedFrameData::CpuNv12 { data, .. } => Some(data.len()),
                        _ => Some(0),
                    };
                    width = Some(frame.width as u32);
                    height = Some(frame.height as u32);
                }
                latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
                success_count += 1;
            }
            Err(_) => {
                failure_count += 1;
            }
        }
    }

    let result = ComponentResult::new(
        ComponentKind::Decode,
        backend,
        case_name.to_string(),
        started_at.elapsed().as_secs_f64(),
        success_count,
        failure_count,
        &latencies_ms,
        width,
        height,
        None,
        None,
        None,
        None,
        None,
        None,
        decoded_frame_bytes,
    );

    if let Ok(result_path) = std::env::var("MRD_COMPONENT_RESULT_PATH") {
        fs::write(
            Path::new(&result_path),
            serde_json::to_string_pretty(&result).expect("serialize decode perf result"),
        )
        .expect("write decode perf result");
    }

    assert!(result.sample_count > 0);
    assert!(result.latency_ms.p50_ms.is_some());
    assert!(result.latency_ms.p95_ms.is_some());
    assert!(result.latency_ms.p99_ms.is_some());
    assert!(result.decoded_frame_bytes.is_some());
}

#[test]
#[ignore]
fn perf_nvenc_720p_decode_reports_latency_distribution() {
    let sample_count = std::env::var("MRD_COMPONENT_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);
    let case_name =
        std::env::var("MRD_COMPONENT_CASE_NAME").unwrap_or_else(|_| "decode.nvenc_720p".into());
    let access_units = nvenc_720p_access_units();
    let mut decoder = create_decoder("h264_software").expect("create h264 decoder");

    let mut latencies_ms = Vec::with_capacity(sample_count as usize);
    let mut success_count = 0_u64;
    let mut failure_count = 0_u64;
    let mut decoded_frame_bytes = None;
    let mut width = None;
    let mut height = None;
    let started_at = Instant::now();

    for access_unit in access_units.iter().cycle().take(sample_count as usize) {
        let iter_started_at = Instant::now();
        match decoder.push_access_unit(access_unit) {
            Ok(()) => {
                let frames = decoder.drain_decoded_frames();
                if let Some(frame) = frames.first() {
                    decoded_frame_bytes = match &frame.data {
                        DecodedFrameData::CpuRgb24(data) => Some(data.len()),
                        DecodedFrameData::CpuI420 { data, .. } => Some(data.len()),
                        _ => Some(0),
                    };
                    width = Some(frame.width as u32);
                    height = Some(frame.height as u32);
                }
                latencies_ms.push(iter_started_at.elapsed().as_secs_f64() * 1000.0);
                success_count += 1;
            }
            Err(_) => {
                failure_count += 1;
            }
        }
    }

    let result = ComponentResult::new(
        ComponentKind::Decode,
        "nvenc_720p",
        case_name,
        started_at.elapsed().as_secs_f64(),
        success_count,
        failure_count,
        &latencies_ms,
        width,
        height,
        None,
        None,
        None,
        None,
        None,
        None,
        decoded_frame_bytes,
    );

    if let Ok(result_path) = std::env::var("MRD_COMPONENT_RESULT_PATH") {
        fs::write(
            Path::new(&result_path),
            serde_json::to_string_pretty(&result).expect("serialize decode perf result"),
        )
        .expect("write decode perf result");
    }

    assert_eq!(result.width, Some(1280));
    assert_eq!(result.height, Some(720));
    assert!(result.sample_count > 0);
    assert!(result.latency_ms.p50_ms.is_some());
    assert!(result.latency_ms.p95_ms.is_some());
    assert!(result.latency_ms.p99_ms.is_some());
    assert!(result.decoded_frame_bytes.is_some());
}

fn encoded_access_unit() -> Vec<u8> {
    let mut rgb = Vec::with_capacity(16 * 16 * 3);
    for y in 0..16 {
        for x in 0..16 {
            rgb.push((x * 16) as u8);
            rgb.push((y * 16) as u8);
            rgb.push(96);
        }
    }
    let rgb_source = RgbSliceU8::new(&rgb, (16, 16));
    let yuv = YUVBuffer::from_rgb_source(rgb_source);
    let mut encoder = Encoder::new().expect("openh264 encoder");
    encoder.encode(&yuv).expect("encode access unit").to_vec()
}

fn nvenc_720p_access_units() -> Vec<Vec<u8>> {
    let Ok(mut encoder) = NvencH264Encoder::new_baseline(1280, 720, 30) else {
        return Vec::new();
    };

    let mut access_units = Vec::new();
    for frame_index in 0..3u64 {
        let mut data = vec![0u8; 1280 * 720 * 4];
        for (index, pixel) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let x = (index % 1280) as u8;
            let y = ((index / 1280) % 256) as u8;
            pixel[0] = x.wrapping_add(frame_index as u8);
            pixel[1] = y;
            pixel[2] = x ^ y ^ (frame_index as u8);
            pixel[3] = 255;
        }
        let frame = CapturedFrame::from_cpu(
            1280,
            720,
            FramePixelFormat::Bgra32,
            frame_index * 33_000,
            data,
        );
        if let Ok(encoded) = encoder.encode(&frame) {
            access_units.extend(
                encoded
                    .into_iter()
                    .filter(|access_unit| !access_unit.bytes.is_empty())
                    .map(|access_unit| access_unit.bytes),
            );
        }
    }

    access_units
}
