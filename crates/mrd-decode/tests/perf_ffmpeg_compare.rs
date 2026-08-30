use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use mrd_decode::create_decoder;
use mrd_encode_openh264::OpenH264Encoder;
use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoEncoder};
use serde_json::json;

#[test]
#[ignore]
fn perf_ffmpeg_decode_compare_reports_results() {
    let samples = env_usize("MRD_FFMPEG_PERF_SAMPLES").unwrap_or(120);
    let width = env_usize("MRD_FFMPEG_PERF_WIDTH").unwrap_or(1280);
    let height = env_usize("MRD_FFMPEG_PERF_HEIGHT").unwrap_or(720);
    let fps = env_u32("MRD_FFMPEG_PERF_FPS").unwrap_or(30);
    let ffmpeg = ffmpeg_path();
    let artifact_dir = artifact_dir();
    fs::create_dir_all(&artifact_dir).expect("create artifact dir");

    let access_units = generate_h264_access_units(width, height, fps, samples);
    let encoded_frame_count = access_units.len();
    assert!(encoded_frame_count > 0, "OpenH264 produced no access units");
    let warmup_frames = env_usize("MRD_FFMPEG_PERF_WARMUP_FRAMES")
        .unwrap_or(5)
        .min(encoded_frame_count.saturating_sub(1));
    let measured_frame_count = encoded_frame_count.saturating_sub(warmup_frames);
    let input_path = artifact_dir.join(format!(
        "openh264-{width}x{height}-requested{samples}-encoded{encoded_frame_count}.h264"
    ));
    write_h264_stream(&input_path, &access_units);
    let warmup_access_units = &access_units[..warmup_frames];
    let measured_access_units = &access_units[warmup_frames..];
    let measured_input_path = artifact_dir.join(format!(
        "openh264-{width}x{height}-measured{measured_frame_count}.h264"
    ));
    write_h264_stream(&measured_input_path, measured_access_units);

    let software = run_mrd_decoder("h264_software", warmup_access_units, measured_access_units);
    let nvdec = run_mrd_decoder("nvdec", warmup_access_units, measured_access_units);
    let ffmpeg_rgb24 = run_ffmpeg_decoder(
        "ffmpeg_cli_rgb24",
        &ffmpeg,
        &input_path,
        encoded_frame_count,
        warmup_frames,
        measured_frame_count,
        "rgb24",
    );
    let ffmpeg_nv12 = run_ffmpeg_decoder(
        "ffmpeg_cli_nv12",
        &ffmpeg,
        &input_path,
        encoded_frame_count,
        warmup_frames,
        measured_frame_count,
        "nv12",
    );

    let report = json!({
        "width": width,
        "height": height,
        "fps": fps,
        "requested_sample_count": samples,
        "sample_count": encoded_frame_count,
        "encoded_frame_count": encoded_frame_count,
        "warmup_frames": warmup_frames,
        "measured_frame_count": measured_frame_count,
        "input_path": input_path,
        "backends": [software, nvdec, ffmpeg_rgb24, ffmpeg_nv12],
    });
    for backend in report["backends"].as_array().expect("backend array") {
        assert!(
            backend.get("measured_throughput_fps").is_some(),
            "backend must expose measured_throughput_fps: {backend}"
        );
        assert_eq!(
            backend.get("warmup_frames"),
            Some(&json!(warmup_frames)),
            "backend must expose warmup_frames: {backend}"
        );
        assert_eq!(
            backend.get("measured_frames"),
            Some(&json!(measured_frame_count)),
            "backend must expose measured_frames: {backend}"
        );
    }
    let report_path = artifact_dir.join("ffmpeg-decode-compare.json");
    fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).expect("serialize report"),
    )
    .expect("write report");
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    println!("report_path={}", report_path.display());
}

fn generate_h264_access_units(
    width: usize,
    height: usize,
    fps: u32,
    samples: usize,
) -> Vec<Vec<u8>> {
    let mut encoder = OpenH264Encoder::new_with_bitrate(width, height, fps, 12_000_000)
        .expect("create OpenH264 encoder");
    let mut access_units = Vec::with_capacity(samples);
    for frame_index in 0..samples {
        let frame = synthetic_bgra_frame(width, height, frame_index as u64, fps);
        let encoded = encoder.encode(&frame).expect("encode synthetic frame");
        access_units.extend(
            encoded
                .into_iter()
                .filter(|access_unit| !access_unit.bytes.is_empty())
                .map(|access_unit| access_unit.bytes),
        );
    }
    access_units
}

fn synthetic_bgra_frame(width: usize, height: usize, frame_index: u64, fps: u32) -> CapturedFrame {
    let mut data = vec![0_u8; width * height * 4];
    for (index, pixel) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let x = (index % width) as u8;
        let y = ((index / width) % 256) as u8;
        let t = frame_index as u8;
        pixel[0] = x.wrapping_add(t);
        pixel[1] = y.wrapping_mul(2).wrapping_add(t);
        pixel[2] = x ^ y ^ t;
        pixel[3] = 255;
    }
    let timestamp_us = frame_index.saturating_mul(1_000_000 / u64::from(fps.max(1)));
    CapturedFrame::from_cpu(width, height, FramePixelFormat::Bgra32, timestamp_us, data)
}

fn write_h264_stream(path: &Path, access_units: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    for access_unit in access_units {
        bytes.extend_from_slice(access_unit);
    }
    fs::write(path, bytes).expect("write h264 stream");
}

fn run_mrd_decoder(
    id: &str,
    warmup_access_units: &[Vec<u8>],
    measured_access_units: &[Vec<u8>],
) -> serde_json::Value {
    let mut decoder = match create_decoder(id) {
        Ok(decoder) => decoder,
        Err(error) => {
            return json!({
                "backend": id,
                "available": false,
                "error": error.to_string(),
                "warmup_frames": warmup_access_units.len(),
                "measured_frames": 0,
                "measured_throughput_fps": 0.0,
            });
        }
    };

    let total_started = Instant::now();
    let warmup_started = Instant::now();
    let mut warmup_decoded_frames = 0_usize;
    let mut warmup_errors = 0_usize;
    for access_unit in warmup_access_units {
        match decoder.push_access_unit(access_unit) {
            Ok(()) => warmup_decoded_frames += decoder.drain_decoded_frames().len(),
            Err(_) => warmup_errors += 1,
        }
    }
    warmup_decoded_frames += decoder.drain_decoded_frames().len();
    let warmup_elapsed_s = warmup_started.elapsed().as_secs_f64();

    let measured_started = Instant::now();
    let mut measured_decoded_frames = 0_usize;
    let mut measured_errors = 0_usize;
    for access_unit in measured_access_units {
        match decoder.push_access_unit(access_unit) {
            Ok(()) => measured_decoded_frames += decoder.drain_decoded_frames().len(),
            Err(_) => measured_errors += 1,
        }
    }
    measured_decoded_frames += decoder.drain_decoded_frames().len();
    let measured_elapsed_s = measured_started.elapsed().as_secs_f64();
    let elapsed_s = total_started.elapsed().as_secs_f64();
    let decoded_frames = warmup_decoded_frames + measured_decoded_frames;
    let errors = warmup_errors + measured_errors;
    json!({
        "backend": id,
        "available": true,
        "decoded_frames": decoded_frames,
        "errors": errors,
        "elapsed_s": elapsed_s,
        "throughput_fps": decoded_frames as f64 / elapsed_s.max(f64::EPSILON),
        "warmup_frames": warmup_access_units.len(),
        "warmup_decoded_frames": warmup_decoded_frames,
        "warmup_errors": warmup_errors,
        "warmup_elapsed_s": warmup_elapsed_s,
        "measured_frames": measured_access_units.len(),
        "measured_decoded_frames": measured_decoded_frames,
        "measured_errors": measured_errors,
        "measured_elapsed_s": measured_elapsed_s,
        "measured_throughput_fps": measured_decoded_frames as f64 / measured_elapsed_s.max(f64::EPSILON),
    })
}

fn run_ffmpeg_decoder(
    backend: &str,
    ffmpeg: &Path,
    input_path: &Path,
    expected_frames: usize,
    warmup_frames: usize,
    measured_frames: usize,
    pixel_format: &str,
) -> serde_json::Value {
    if !ffmpeg.is_file() {
        return json!({
            "backend": backend,
            "available": false,
            "error": format!("ffmpeg executable not found: {}", ffmpeg.display()),
            "warmup_frames": warmup_frames,
            "measured_frames": 0,
            "measured_throughput_fps": 0.0,
        });
    }

    let output_path = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let started = Instant::now();
    let output = Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-f", "h264", "-i"])
        .arg(input_path)
        .args([
            "-f",
            "rawvideo",
            "-pix_fmt",
            pixel_format,
            "-y",
            output_path,
        ])
        .output()
        .expect("run ffmpeg decode");
    let elapsed_s = started.elapsed().as_secs_f64();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    json!({
        "backend": backend,
        "available": output.status.success(),
        "decoded_frames": if output.status.success() { expected_frames } else { 0 },
        "errors": if output.status.success() { 0 } else { 1 },
        "elapsed_s": elapsed_s,
        "pixel_format": pixel_format,
        "throughput_fps": if output.status.success() { expected_frames as f64 / elapsed_s.max(f64::EPSILON) } else { 0.0 },
        "warmup_frames": warmup_frames,
        "warmup_elapsed_s": serde_json::Value::Null,
        "measured_frames": if output.status.success() { measured_frames } else { 0 },
        "measured_elapsed_s": elapsed_s,
        "measured_throughput_fps": if output.status.success() { measured_frames as f64 / elapsed_s.max(f64::EPSILON) } else { 0.0 },
        "error": if output.status.success() { serde_json::Value::Null } else { json!(stderr) },
        "path": ffmpeg,
    })
}

fn ffmpeg_path() -> PathBuf {
    if let Ok(path) = std::env::var("MRD_FFMPEG_BIN") {
        return PathBuf::from(path);
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata)
            .join("mini-remote-desktop")
            .join("tools")
            .join("ffmpeg")
            .join("release-essentials")
            .join("bin")
            .join(if cfg!(windows) {
                "ffmpeg.exe"
            } else {
                "ffmpeg"
            });
    }
    PathBuf::from("ffmpeg")
}

fn artifact_dir() -> PathBuf {
    let dir = std::env::var("MRD_FFMPEG_PERF_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("ffmpeg-perf")
                .join(timestamp())
        });
    if dir.is_absolute() {
        dir
    } else {
        workspace_root().join(dir)
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("mrd-decode crate should live under workspace crates directory")
        .to_path_buf()
}

fn timestamp() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time");
    duration.as_secs().to_string()
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.parse().ok()
}

fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.parse().ok()
}
