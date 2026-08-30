use mrd_pipeline_core::{
    CapturedFrame, EncodedAccessUnit, FramePixelFormat, PipelineError, VideoCodec, VideoEncoder,
};
use openh264::{
    encoder::{
        BitRate, Complexity, Encoder, EncoderConfig, FrameRate, IntraFramePeriod, RateControlMode,
        UsageType,
    },
    formats::YUVSlices,
    OpenH264API,
};

pub struct OpenH264Encoder {
    encoder: Encoder,
    width: usize,
    height: usize,
    fps: u32,
    frame_index: u64,
    last_forced_intra_timestamp_us: Option<u64>,
    i420: Vec<u8>,
}

const RECOVERY_KEYFRAME_INTERVAL_US: u64 = 1_000_000;

impl OpenH264Encoder {
    pub fn new(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_internal(width, height, fps, None)
    }

    pub fn new_with_bitrate(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        Self::new_internal(width, height, fps, Some(bitrate.max(1)))
    }

    fn new_internal(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: Option<u32>,
    ) -> Result<Self, PipelineError> {
        validate_even_dimensions(width, height)?;

        let rate_control_mode = if bitrate.is_some() {
            RateControlMode::Bitrate
        } else {
            RateControlMode::Off
        };

        let mut config = EncoderConfig::new()
            .usage_type(openh264_usage_type())
            .max_frame_rate(FrameRate::from_hz(fps.max(1) as f32))
            .intra_frame_period(IntraFramePeriod::from_num_frames(fps.max(1)))
            .rate_control_mode(rate_control_mode)
            .complexity(Complexity::Low)
            .num_threads(openh264_thread_count())
            .max_slice_len(openh264_max_slice_len())
            .scene_change_detect(openh264_scene_change_detection())
            .adaptive_quantization(false)
            .background_detection(false)
            .skip_frames(bitrate.is_some());

        if let Some(bitrate) = bitrate {
            config = config.bitrate(BitRate::from_bps(bitrate));
        }

        let api = OpenH264API::from_source();
        let encoder = Encoder::with_api_config(api, config).map_err(|error| {
            PipelineError::message(format!("create openh264 encoder failed: {error}"))
        })?;

        Ok(Self {
            encoder,
            width,
            height,
            fps: fps.max(1),
            frame_index: 0,
            last_forced_intra_timestamp_us: None,
            i420: vec![0; i420_len(width, height)?],
        })
    }

    pub fn new_speed(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new(width, height, fps)
    }
}

impl VideoEncoder for OpenH264Encoder {
    fn encode(&mut self, frame: &CapturedFrame) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
        validate_even_dimensions(frame.width, frame.height)?;

        if frame.width != self.width || frame.height != self.height {
            return Err(PipelineError::message(format!(
                "frame size mismatch: expected {}x{}, got {}x{}",
                self.width, self.height, frame.width, frame.height
            )));
        }

        let force_intra = self.should_force_intra(frame.timestamp_us);
        if force_intra {
            self.encoder.force_intra_frame();
        }

        write_i420(frame, &mut self.i420)?;
        let y_size = frame.width * frame.height;
        let uv_size = y_size / 4;
        let yuv = YUVSlices::new(
            (
                &self.i420[..y_size],
                &self.i420[y_size..y_size + uv_size],
                &self.i420[y_size + uv_size..],
            ),
            (frame.width, frame.height),
            (frame.width, frame.width / 2, frame.width / 2),
        );
        let bitstream = self
            .encoder
            .encode(&yuv)
            .map_err(|error| PipelineError::message(format!("openh264 encode failed: {error}")))?;
        self.frame_index += 1;

        let bytes = normalize_h264_bitstream(bitstream.to_vec());
        Ok(encoded_access_units_from_bytes(
            VideoCodec::H264,
            frame.timestamp_us,
            bytes,
        ))
    }
}

impl OpenH264Encoder {
    fn should_force_intra(&mut self, timestamp_us: u64) -> bool {
        let frame_interval_due =
            self.frame_index == 0 || self.frame_index.is_multiple_of(self.fps as u64);
        let recovery_interval_due = self
            .last_forced_intra_timestamp_us
            .is_some_and(|last| timestamp_us.saturating_sub(last) >= RECOVERY_KEYFRAME_INTERVAL_US);

        if frame_interval_due || recovery_interval_due {
            self.last_forced_intra_timestamp_us = Some(timestamp_us);
            true
        } else {
            false
        }
    }
}

fn validate_even_dimensions(width: usize, height: usize) -> Result<(), PipelineError> {
    if width == 0 || height == 0 {
        return Err(PipelineError::message(format!(
            "openh264 frame dimensions must be non-zero, got {width}x{height}"
        )));
    }

    if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(PipelineError::message(format!(
            "openh264 requires even frame dimensions, got {width}x{height}"
        )));
    }

    Ok(())
}

fn openh264_thread_count() -> u16 {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    resolve_openh264_thread_count(available)
}

fn resolve_openh264_thread_count(available: usize) -> u16 {
    available.clamp(1, 12) as u16
}

fn openh264_max_slice_len() -> u32 {
    65_536
}

fn openh264_usage_type() -> UsageType {
    UsageType::CameraVideoRealTime
}

fn openh264_scene_change_detection() -> bool {
    false
}

fn i420_len(width: usize, height: usize) -> Result<usize, PipelineError> {
    width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(3))
        .map(|bytes| bytes / 2)
        .ok_or_else(|| PipelineError::message("openh264 i420 buffer size overflow"))
}

fn normalize_h264_bitstream(bytes: Vec<u8>) -> Vec<u8> {
    if looks_like_annex_b(&bytes) {
        return bytes;
    }

    if let Some(converted) = avcc_to_annex_b(&bytes) {
        return converted;
    }

    bytes
}

fn encoded_access_units_from_bytes(
    codec: VideoCodec,
    timestamp_us: u64,
    bytes: Vec<u8>,
) -> Vec<EncodedAccessUnit> {
    if bytes.is_empty() {
        return Vec::new();
    }

    vec![EncodedAccessUnit {
        codec,
        timestamp_us,
        is_keyframe: codec == VideoCodec::H264 && annex_b_contains_h264_idr(&bytes),
        bytes,
    }]
}

fn looks_like_annex_b(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|window| window == [0, 0, 0, 1])
        || bytes.windows(3).any(|window| window == [0, 0, 1])
}

fn avcc_to_annex_b(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    let mut annex_b = Vec::with_capacity(bytes.len() + 16);

    while offset + 4 <= bytes.len() {
        let nal_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if nal_len == 0 || offset + nal_len > bytes.len() {
            return None;
        }

        annex_b.extend_from_slice(&[0, 0, 0, 1]);
        annex_b.extend_from_slice(&bytes[offset..offset + nal_len]);
        offset += nal_len;
    }

    if offset == bytes.len() && !annex_b.is_empty() {
        Some(annex_b)
    } else {
        None
    }
}

fn annex_b_contains_h264_idr(access_unit: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < access_unit.len() {
        let Some((nal_offset, start_code_len)) = find_annex_b_start_code(access_unit, offset)
        else {
            break;
        };
        let nal_header_offset = nal_offset + start_code_len;
        if nal_header_offset >= access_unit.len() {
            break;
        }
        if access_unit[nal_header_offset] & 0x1f == 5 {
            return true;
        }
        offset = nal_header_offset + 1;
    }
    false
}

fn find_annex_b_start_code(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut index = from;
    while index + 3 <= bytes.len() {
        if bytes[index..].starts_with(&[0, 0, 1]) {
            return Some((index, 3));
        }
        if index + 4 <= bytes.len() && bytes[index..].starts_with(&[0, 0, 0, 1]) {
            return Some((index, 4));
        }
        index += 1;
    }
    None
}

fn write_i420(frame: &CapturedFrame, out: &mut [u8]) -> Result<(), PipelineError> {
    let expected_len = frame
        .width
        .checked_mul(frame.height)
        .and_then(|pixels| match frame.pixel_format {
            FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => pixels.checked_mul(4),
            FramePixelFormat::Rgb24 => pixels.checked_mul(3),
            FramePixelFormat::Nv12 => i420_len(frame.width, frame.height).ok(),
        })
        .ok_or_else(|| PipelineError::message("frame buffer size overflow"))?;

    if frame.data.len() != expected_len {
        return Err(PipelineError::message(format!(
            "frame bytes mismatch: expected {expected_len}, got {}",
            frame.data.len()
        )));
    }

    let expected_i420 = i420_len(frame.width, frame.height)?;
    if out.len() != expected_i420 {
        return Err(PipelineError::message(format!(
            "openh264 i420 scratch mismatch: expected {expected_i420}, got {}",
            out.len()
        )));
    }

    if frame.pixel_format == FramePixelFormat::Bgra32 {
        write_bgra_to_i420(&frame.data, frame.width, frame.height, out);
        return Ok(());
    }

    let y_size = frame.width * frame.height;
    let uv_size = y_size / 4;
    let (y_plane, uv_planes) = out.split_at_mut(y_size);
    let (u_plane, v_plane) = uv_planes.split_at_mut(uv_size);

    if frame.pixel_format == FramePixelFormat::Nv12 {
        y_plane.copy_from_slice(&frame.data[..y_size]);
        let uv_plane = &frame.data[y_size..expected_len];
        let chroma_width = frame.width / 2;
        for row in 0..frame.height / 2 {
            for col in 0..chroma_width {
                let nv12_index = row * frame.width + col * 2;
                let i420_index = row * chroma_width + col;
                u_plane[i420_index] = uv_plane[nv12_index];
                v_plane[i420_index] = uv_plane[nv12_index + 1];
            }
        }
        return Ok(());
    }

    let bytes_per_pixel = match frame.pixel_format {
        FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => 4,
        FramePixelFormat::Rgb24 => 3,
        FramePixelFormat::Nv12 => unreachable!("NV12 was copied above"),
    };

    for block_y in (0..frame.height).step_by(2) {
        for block_x in (0..frame.width).step_by(2) {
            let p00 = read_rgb(frame, block_x, block_y, bytes_per_pixel);
            let p10 = read_rgb(frame, block_x + 1, block_y, bytes_per_pixel);
            let p01 = read_rgb(frame, block_x, block_y + 1, bytes_per_pixel);
            let p11 = read_rgb(frame, block_x + 1, block_y + 1, bytes_per_pixel);

            y_plane[block_y * frame.width + block_x] = rgb_to_y(p00);
            y_plane[block_y * frame.width + block_x + 1] = rgb_to_y(p10);
            y_plane[(block_y + 1) * frame.width + block_x] = rgb_to_y(p01);
            y_plane[(block_y + 1) * frame.width + block_x + 1] = rgb_to_y(p11);

            let avg = average_rgb([p00, p10, p01, p11]);
            let uv_index = (block_y / 2) * (frame.width / 2) + (block_x / 2);
            u_plane[uv_index] = rgb_to_u(avg);
            v_plane[uv_index] = rgb_to_v(avg);
        }
    }

    Ok(())
}

fn write_bgra_to_i420(data: &[u8], width: usize, height: usize, out: &mut [u8]) {
    let y_size = width * height;
    let uv_size = y_size / 4;
    let (y_plane, uv_planes) = out.split_at_mut(y_size);
    let (u_plane, v_plane) = uv_planes.split_at_mut(uv_size);

    for block_y in (0..height).step_by(2) {
        let top = &data[block_y * width * 4..(block_y + 1) * width * 4];
        let bottom = &data[(block_y + 1) * width * 4..(block_y + 2) * width * 4];
        let y_rows = &mut y_plane[block_y * width..(block_y + 2) * width];
        let (top_y, bottom_y) = y_rows.split_at_mut(width);
        let chroma_row = (block_y / 2) * (width / 2);

        for (pair_x, (top_pair, bottom_pair)) in top
            .as_chunks::<8>()
            .0
            .iter()
            .zip(bottom.as_chunks::<8>().0.iter())
            .enumerate()
        {
            let p00 = (top_pair[2], top_pair[1], top_pair[0]);
            let p10 = (top_pair[6], top_pair[5], top_pair[4]);
            let p01 = (bottom_pair[2], bottom_pair[1], bottom_pair[0]);
            let p11 = (bottom_pair[6], bottom_pair[5], bottom_pair[4]);
            let pixel_x = pair_x * 2;

            top_y[pixel_x] = rgb_to_y(p00);
            top_y[pixel_x + 1] = rgb_to_y(p10);
            bottom_y[pixel_x] = rgb_to_y(p01);
            bottom_y[pixel_x + 1] = rgb_to_y(p11);

            let avg = average_rgb([p00, p10, p01, p11]);
            let uv_index = chroma_row + pair_x;
            u_plane[uv_index] = rgb_to_u(avg);
            v_plane[uv_index] = rgb_to_v(avg);
        }
    }
}

fn read_rgb(frame: &CapturedFrame, x: usize, y: usize, bytes_per_pixel: usize) -> (u8, u8, u8) {
    let index = (y * frame.width + x) * bytes_per_pixel;
    match frame.pixel_format {
        FramePixelFormat::Bgra32 => (
            frame.data[index + 2],
            frame.data[index + 1],
            frame.data[index],
        ),
        FramePixelFormat::Rgba32 | FramePixelFormat::Rgb24 => (
            frame.data[index],
            frame.data[index + 1],
            frame.data[index + 2],
        ),
        FramePixelFormat::Nv12 => unreachable!("NV12 is not read as packed RGB"),
    }
}

fn average_rgb(pixels: [(u8, u8, u8); 4]) -> (u8, u8, u8) {
    let (mut r, mut g, mut b) = (0_u32, 0_u32, 0_u32);
    for (pr, pg, pb) in pixels {
        r += u32::from(pr);
        g += u32::from(pg);
        b += u32::from(pb);
    }

    ((r / 4) as u8, (g / 4) as u8, (b / 4) as u8)
}

fn rgb_to_y((r, g, b): (u8, u8, u8)) -> u8 {
    clamp_u8(((66 * i32::from(r) + 129 * i32::from(g) + 25 * i32::from(b) + 128) >> 8) + 16)
}

fn rgb_to_u((r, g, b): (u8, u8, u8)) -> u8 {
    clamp_u8(((-38 * i32::from(r) - 74 * i32::from(g) + 112 * i32::from(b) + 128) >> 8) + 128)
}

fn rgb_to_v((r, g, b): (u8, u8, u8)) -> u8 {
    clamp_u8(((112 * i32::from(r) - 94 * i32::from(g) - 18 * i32::from(b) + 128) >> 8) + 128)
}

fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

#[allow(dead_code)]
fn to_rgba(frame: &CapturedFrame) -> Result<Vec<u8>, PipelineError> {
    let expected_len = frame
        .width
        .checked_mul(frame.height)
        .and_then(|pixels| match frame.pixel_format {
            FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => pixels.checked_mul(4),
            FramePixelFormat::Rgb24 => pixels.checked_mul(3),
            FramePixelFormat::Nv12 => i420_len(frame.width, frame.height).ok(),
        })
        .ok_or_else(|| PipelineError::message("frame buffer size overflow"))?;

    if frame.data.len() != expected_len {
        return Err(PipelineError::message(format!(
            "frame bytes mismatch: expected {expected_len}, got {}",
            frame.data.len()
        )));
    }

    match frame.pixel_format {
        FramePixelFormat::Rgba32 => Ok(frame.data.clone()),
        FramePixelFormat::Bgra32 => {
            // Optimized BGRA→RGBA conversion using swap_words
            // BGRA = [B, G, R, A], RGBA = [R, G, B, A]
            // We need to swap B and R in each 4-byte pixel
            let mut rgba = Vec::with_capacity(frame.data.len());
            for chunk in frame.data.as_chunks::<4>().0 {
                // Swap R and B channels
                rgba.extend_from_slice(&[chunk[2], chunk[1], chunk[0], chunk[3]]);
            }
            Ok(rgba)
        }
        FramePixelFormat::Rgb24 => {
            let mut rgba = Vec::with_capacity(frame.width * frame.height * 4);
            for chunk in frame.data.as_chunks::<3>().0 {
                rgba.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }
            Ok(rgba)
        }
        FramePixelFormat::Nv12 => nv12_to_rgba(frame),
    }
}

fn nv12_to_rgba(frame: &CapturedFrame) -> Result<Vec<u8>, PipelineError> {
    let y_size = frame
        .width
        .checked_mul(frame.height)
        .ok_or_else(|| PipelineError::message("NV12 luma byte size overflow"))?;
    let mut rgba = Vec::with_capacity(frame.width * frame.height * 4);
    for y in 0..frame.height {
        let y_row = y * frame.width;
        let uv_row = y_size + (y / 2) * frame.width;
        for x in 0..frame.width {
            let luma = frame.data[y_row + x] as i32;
            let uv_x = (x / 2) * 2;
            let u = frame.data[uv_row + uv_x] as i32;
            let v = frame.data[uv_row + uv_x + 1] as i32;
            let c = (luma - 16).max(0);
            let d = u - 128;
            let e = v - 128;
            rgba.push(clamp_u8((298 * c + 409 * e + 128) >> 8));
            rgba.push(clamp_u8((298 * c - 100 * d - 208 * e + 128) >> 8));
            rgba.push(clamp_u8((298 * c + 516 * d + 128) >> 8));
            rgba.push(255);
        }
    }
    Ok(rgba)
}

#[cfg(test)]
mod conversion_tests {
    use super::*;

    #[test]
    #[ignore]
    fn perf_openh264_2k_configuration_matrix() {
        struct Variant {
            name: &'static str,
            encoder: Encoder,
            samples_ms: Vec<f64>,
        }

        let width = 2560;
        let height = 1440;
        let definitions = [
            ("single-auto", 0, None),
            ("slice-1200-t4", 4, Some(1_200)),
            ("slice-1200-t8", 8, Some(1_200)),
            ("slice-1200-auto", 0, Some(1_200)),
            ("slice-16k-t4", 4, Some(16_384)),
            ("slice-64k-t4", 4, Some(65_536)),
            ("slice-64k-t8", 8, Some(65_536)),
            ("slice-64k-t12", 12, Some(65_536)),
            ("slice-256k-t8", 8, Some(262_144)),
        ];
        let mut variants = definitions
            .into_iter()
            .map(|(name, threads, max_slice_len)| {
                let mut config = EncoderConfig::new()
                    .usage_type(UsageType::CameraVideoRealTime)
                    .max_frame_rate(FrameRate::from_hz(30.0))
                    .intra_frame_period(IntraFramePeriod::from_num_frames(30))
                    .rate_control_mode(RateControlMode::Off)
                    .complexity(Complexity::Low)
                    .num_threads(threads)
                    .scene_change_detect(false)
                    .adaptive_quantization(false)
                    .background_detection(false)
                    .skip_frames(false);
                if let Some(max_slice_len) = max_slice_len {
                    config = config.max_slice_len(max_slice_len);
                }
                Variant {
                    name,
                    encoder: Encoder::with_api_config(OpenH264API::from_source(), config)
                        .expect("create matrix encoder"),
                    samples_ms: Vec::with_capacity(48),
                }
            })
            .collect::<Vec<_>>();
        let mut bgra = vec![0_u8; width * height * 4];
        let mut i420 = vec![0_u8; i420_len(width, height).expect("i420 size")];

        for frame_index in 0..48_usize {
            for pixel in bgra.as_chunks_mut::<4>().0 {
                pixel.copy_from_slice(&[frame_index as u8, 64, 192, 255]);
            }
            write_bgra_to_i420(&bgra, width, height, &mut i420);
            let y_size = width * height;
            let uv_size = y_size / 4;
            let yuv = YUVSlices::new(
                (
                    &i420[..y_size],
                    &i420[y_size..y_size + uv_size],
                    &i420[y_size + uv_size..],
                ),
                (width, height),
                (width, width / 2, width / 2),
            );
            let start_variant = frame_index % variants.len();
            for offset in 0..variants.len() {
                let variant_index = (start_variant + offset) % variants.len();
                let variant = &mut variants[variant_index];
                if frame_index == 0 || frame_index == 30 {
                    variant.encoder.force_intra_frame();
                }
                let started = std::time::Instant::now();
                let bitstream = variant.encoder.encode(&yuv).expect("matrix encode");
                let _bytes = bitstream.to_vec();
                variant
                    .samples_ms
                    .push(started.elapsed().as_secs_f64() * 1000.0);
            }
        }

        for variant in &mut variants {
            variant.samples_ms.sort_by(f64::total_cmp);
            let p50 = variant.samples_ms[variant.samples_ms.len() / 2];
            let p95 = variant.samples_ms
                [(variant.samples_ms.len() * 95 / 100).min(variant.samples_ms.len() - 1)];
            eprintln!("{} p50={p50:.3}ms p95={p95:.3}ms", variant.name);
        }
    }

    #[test]
    #[ignore]
    fn perf_bgra_to_i420_reports_2k_latency_distribution() {
        let width = 2560;
        let height = 1440;
        let data = vec![127_u8; width * height * 4];
        let mut out = vec![0_u8; i420_len(width, height).expect("i420 size")];
        let mut samples = Vec::with_capacity(120);

        for _ in 0..120 {
            let started = std::time::Instant::now();
            write_bgra_to_i420(&data, width, height, &mut out);
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        samples.sort_by(f64::total_cmp);
        let p50 = samples[samples.len() / 2];
        let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];

        eprintln!("2K BGRA->I420 p50={p50:.3}ms p95={p95:.3}ms");
    }

    #[test]
    fn optimized_bgra_conversion_matches_reference_planes() {
        let pixels = [
            [0, 0, 255, 255],
            [0, 255, 0, 255],
            [255, 0, 0, 255],
            [255, 255, 255, 255],
            [16, 32, 64, 255],
            [64, 32, 16, 255],
            [10, 20, 30, 255],
            [30, 20, 10, 255],
            [90, 80, 70, 255],
            [70, 80, 90, 255],
            [1, 2, 3, 255],
            [253, 252, 251, 255],
            [40, 100, 200, 255],
            [200, 100, 40, 255],
            [128, 128, 128, 255],
            [0, 0, 0, 255],
        ];
        let data = pixels.into_iter().flatten().collect::<Vec<_>>();
        let frame = CapturedFrame::from_cpu(4, 4, FramePixelFormat::Bgra32, 0, data.clone());
        let mut expected = vec![0; i420_len(4, 4).expect("i420 size")];
        write_i420_reference(&frame, &mut expected);
        let mut actual = vec![0; expected.len()];

        write_bgra_to_i420(&data, 4, 4, &mut actual);

        assert_eq!(actual, expected);
    }

    fn write_i420_reference(frame: &CapturedFrame, out: &mut [u8]) {
        let y_size = frame.width * frame.height;
        let uv_size = y_size / 4;
        let (y_plane, uv_planes) = out.split_at_mut(y_size);
        let (u_plane, v_plane) = uv_planes.split_at_mut(uv_size);
        for block_y in (0..frame.height).step_by(2) {
            for block_x in (0..frame.width).step_by(2) {
                let p00 = read_rgb(frame, block_x, block_y, 4);
                let p10 = read_rgb(frame, block_x + 1, block_y, 4);
                let p01 = read_rgb(frame, block_x, block_y + 1, 4);
                let p11 = read_rgb(frame, block_x + 1, block_y + 1, 4);
                y_plane[block_y * frame.width + block_x] = rgb_to_y(p00);
                y_plane[block_y * frame.width + block_x + 1] = rgb_to_y(p10);
                y_plane[(block_y + 1) * frame.width + block_x] = rgb_to_y(p01);
                y_plane[(block_y + 1) * frame.width + block_x + 1] = rgb_to_y(p11);
                let avg = average_rgb([p00, p10, p01, p11]);
                let uv_index = (block_y / 2) * (frame.width / 2) + block_x / 2;
                u_plane[uv_index] = rgb_to_u(avg);
                v_plane[uv_index] = rgb_to_v(avg);
            }
        }
    }

    #[test]
    fn bgra_to_i420_writes_expected_limited_range_planes() {
        let frame = CapturedFrame::from_cpu(
            2,
            2,
            FramePixelFormat::Bgra32,
            0,
            [0, 0, 255, 255]
                .into_iter()
                .cycle()
                .take(2 * 2 * 4)
                .collect(),
        );
        let mut i420 = vec![0; i420_len(2, 2).expect("i420 size")];

        write_i420(&frame, &mut i420).expect("convert bgra to i420");

        assert_eq!(&i420[..4], &[82, 82, 82, 82]);
        assert_eq!(&i420[4..5], &[90]);
        assert_eq!(&i420[5..], &[240]);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        avcc_to_annex_b, encoded_access_units_from_bytes, looks_like_annex_b,
        normalize_h264_bitstream, openh264_max_slice_len, openh264_scene_change_detection,
        openh264_usage_type, resolve_openh264_thread_count,
    };
    use mrd_pipeline_core::VideoCodec;
    use openh264::encoder::UsageType;

    #[test]
    fn avcc_bitstream_is_converted_to_annex_b() {
        let avcc = vec![0, 0, 0, 2, 0x67, 0x42, 0, 0, 0, 3, 0x68, 0xce, 0x06];
        let annex_b = avcc_to_annex_b(&avcc).expect("convert avcc");

        assert_eq!(
            annex_b,
            vec![0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x68, 0xce, 0x06]
        );
        assert!(looks_like_annex_b(&annex_b));
        assert_eq!(normalize_h264_bitstream(avcc), annex_b);
    }

    #[test]
    fn empty_bitstream_produces_no_access_units() {
        let access_units = encoded_access_units_from_bytes(VideoCodec::H264, 123, Vec::new());

        assert!(access_units.is_empty());
    }

    #[test]
    fn desktop_encoder_uses_low_latency_camera_mode() {
        assert!(matches!(
            openh264_usage_type(),
            UsageType::CameraVideoRealTime
        ));
    }

    #[test]
    fn desktop_encoder_caps_slice_workers_for_hybrid_cpus() {
        assert_eq!(resolve_openh264_thread_count(20), 12);
        assert_eq!(resolve_openh264_thread_count(4), 4);
        assert_eq!(resolve_openh264_thread_count(1), 1);
    }

    #[test]
    fn desktop_encoder_uses_parallel_64k_slices() {
        assert_eq!(openh264_max_slice_len(), 65_536);
    }

    #[test]
    fn desktop_encoder_skips_redundant_scene_scanning() {
        assert!(!openh264_scene_change_detection());
    }
}
