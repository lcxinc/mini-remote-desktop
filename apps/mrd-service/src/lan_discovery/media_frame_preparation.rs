use anyhow::Result;
use mrd_ipc::MediaProfile;
use mrd_pipeline_core::{CapturedFrame, DecodedFrame, DecodedFrameData, FramePixelFormat};
#[cfg(any(windows, target_os = "macos"))]
use mrd_render::RenderFrame;

pub(super) fn captured_frame_memory_path(_frame: &CapturedFrame) -> &'static str {
    #[cfg(target_os = "macos")]
    {
        if _frame.macos_cv_pixel_buffer().is_some() {
            return "macos_cv_pixel_buffer";
        }
    }

    #[cfg(windows)]
    {
        if _frame.d3d11_shared_bgra().is_some() {
            return "d3d11_shared_bgra";
        }
    }

    "cpu"
}

pub(crate) fn prepare_frame_for_h264(
    frame: CapturedFrame,
    profile: &MediaProfile,
) -> Result<CapturedFrame> {
    if frame.width < 2 || frame.height < 2 {
        anyhow::bail!(
            "captured frame is too small: {}x{}",
            frame.width,
            frame.height
        );
    }

    let (target_width, target_height) = h264_target_dimensions(frame.width, frame.height, profile);

    #[cfg(target_os = "macos")]
    if frame.macos_cv_pixel_buffer().is_some() {
        if target_width == frame.width && target_height == frame.height {
            return Ok(frame);
        }
        anyhow::bail!(
            "macOS CVPixelBuffer capture requires exact selected profile dimensions: source {}x{}, selected {}x{}",
            frame.width,
            frame.height,
            target_width,
            target_height
        );
    }

    #[cfg(windows)]
    if frame.d3d11_shared_bgra().is_some() {
        if target_width == frame.width && target_height == frame.height {
            return Ok(frame);
        }
        anyhow::bail!(
            "D3D11 shared capture requires exact selected profile dimensions: source {}x{}, selected {}x{}",
            frame.width,
            frame.height,
            target_width,
            target_height
        );
    }

    if frame.pixel_format == FramePixelFormat::Nv12 {
        let required_len = nv12_cpu_frame_len(frame.width, frame.height)
            .ok_or_else(|| anyhow::anyhow!("captured NV12 byte size overflow"))?;
        if frame.data.len() < required_len {
            anyhow::bail!(
                "captured NV12 frame is truncated: {} < {}",
                frame.data.len(),
                required_len
            );
        }

        if target_width == frame.width && target_height == frame.height {
            return Ok(frame);
        }

        let mut rgb = Vec::with_capacity(target_width * target_height * 3);
        for y in 0..target_height {
            let source_y = y * frame.height / target_height;
            for x in 0..target_width {
                let source_x = x * frame.width / target_width;
                let (r, g, b) =
                    read_nv12_rgb(&frame.data, frame.width, frame.height, source_x, source_y);
                rgb.extend_from_slice(&[r, g, b]);
            }
        }

        return Ok(CapturedFrame::from_cpu(
            target_width,
            target_height,
            FramePixelFormat::Rgb24,
            frame.timestamp_us,
            rgb,
        ));
    }

    let bytes_per_pixel = frame_bytes_per_pixel(frame.pixel_format);
    let source_stride = frame
        .width
        .checked_mul(bytes_per_pixel)
        .ok_or_else(|| anyhow::anyhow!("captured frame stride overflow"))?;
    let required_len = source_stride
        .checked_mul(frame.height)
        .ok_or_else(|| anyhow::anyhow!("captured frame byte size overflow"))?;
    if frame.data.len() < required_len {
        anyhow::bail!(
            "captured frame is truncated: {} < {}",
            frame.data.len(),
            required_len
        );
    }

    if target_width == frame.width && target_height == frame.height {
        return Ok(frame);
    }

    let mut rgb = Vec::with_capacity(target_width * target_height * 3);
    for y in 0..target_height {
        let source_y = y * frame.height / target_height;
        for x in 0..target_width {
            let source_x = x * frame.width / target_width;
            let (r, g, b) = read_captured_rgb(&frame, source_x, source_y, source_stride);
            rgb.extend_from_slice(&[r, g, b]);
        }
    }

    Ok(CapturedFrame::from_cpu(
        target_width,
        target_height,
        FramePixelFormat::Rgb24,
        frame.timestamp_us,
        rgb,
    ))
}

pub(super) fn h264_target_dimensions(
    width: usize,
    height: usize,
    profile: &MediaProfile,
) -> (usize, usize) {
    let max_width = profile.width.max(2) as f64;
    let max_height = profile.height.max(2) as f64;
    let scale = (max_width / width as f64)
        .min(max_height / height as f64)
        .min(1.0);
    let target_width = even_dimension(((width as f64 * scale).round() as usize).max(2));
    let target_height = even_dimension(((height as f64 * scale).round() as usize).max(2));
    (target_width.max(2), target_height.max(2))
}

#[cfg(any(windows, test))]
pub(super) fn window_h264_capture_dimensions(width: usize, height: usize) -> (usize, usize) {
    (even_dimension(width).max(2), even_dimension(height).max(2))
}

pub(super) fn even_dimension(value: usize) -> usize {
    value & !1
}

fn frame_bytes_per_pixel(pixel_format: FramePixelFormat) -> usize {
    match pixel_format {
        FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => 4,
        FramePixelFormat::Rgb24 => 3,
        FramePixelFormat::Nv12 => 1,
    }
}

fn nv12_cpu_frame_len(width: usize, height: usize) -> Option<usize> {
    width.checked_mul(height).and_then(|y_size| {
        width
            .checked_mul(height.div_ceil(2))
            .and_then(|uv_size| y_size.checked_add(uv_size))
    })
}

#[cfg(any(windows, target_os = "macos", test))]
pub(super) fn nv12_to_rgb24(
    data: &[u8],
    pitch: usize,
    width: usize,
    height: usize,
) -> Result<Vec<u8>> {
    if pitch < width {
        anyhow::bail!("NV12 pitch is smaller than frame width");
    }
    let y_bytes = pitch
        .checked_mul(height)
        .ok_or_else(|| anyhow::anyhow!("NV12 luma byte size overflow"))?;
    let uv_height = height.div_ceil(2);
    let uv_bytes = pitch
        .checked_mul(uv_height)
        .ok_or_else(|| anyhow::anyhow!("NV12 chroma byte size overflow"))?;
    let expected_len = y_bytes
        .checked_add(uv_bytes)
        .ok_or_else(|| anyhow::anyhow!("NV12 byte size overflow"))?;
    if data.len() < expected_len {
        anyhow::bail!("NV12 frame has invalid byte length");
    }

    let mut rgb = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        let y_row = y * pitch;
        let uv_row = y_bytes + (y / 2) * pitch;
        for x in 0..width {
            let luma = data[y_row + x] as i32;
            let uv_x = (x / 2) * 2;
            let u = data[uv_row + uv_x] as i32;
            let v = data[uv_row + uv_x + 1] as i32;
            let c = (luma - 16).max(0);
            let d = u - 128;
            let e = v - 128;
            rgb.push(clamp_yuv_to_u8((298 * c + 409 * e + 128) >> 8));
            rgb.push(clamp_yuv_to_u8((298 * c - 100 * d - 208 * e + 128) >> 8));
            rgb.push(clamp_yuv_to_u8((298 * c + 516 * d + 128) >> 8));
        }
    }
    Ok(rgb)
}

#[cfg(any(windows, target_os = "macos", test))]
pub(super) fn i420_to_rgb24(
    data: &[u8],
    y_pitch: usize,
    uv_pitch: usize,
    width: usize,
    height: usize,
) -> Result<Vec<u8>> {
    if y_pitch < width {
        anyhow::bail!("I420 Y pitch is smaller than frame width");
    }
    let chroma_width = width.div_ceil(2);
    if uv_pitch < chroma_width {
        anyhow::bail!("I420 UV pitch is smaller than chroma width");
    }
    let chroma_height = height.div_ceil(2);
    let y_bytes = y_pitch
        .checked_mul(height)
        .ok_or_else(|| anyhow::anyhow!("I420 luma byte size overflow"))?;
    let uv_bytes = uv_pitch
        .checked_mul(chroma_height)
        .ok_or_else(|| anyhow::anyhow!("I420 chroma byte size overflow"))?;
    let expected_len = y_bytes
        .checked_add(uv_bytes)
        .and_then(|bytes| bytes.checked_add(uv_bytes))
        .ok_or_else(|| anyhow::anyhow!("I420 byte size overflow"))?;
    if data.len() < expected_len {
        anyhow::bail!("I420 frame has invalid byte length");
    }

    let u_base = y_bytes;
    let v_base = y_bytes + uv_bytes;
    let mut rgb = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        let y_row = y * y_pitch;
        let uv_row = (y / 2) * uv_pitch;
        for x in 0..width {
            let luma = data[y_row + x] as i32;
            let u = data[u_base + uv_row + x / 2] as i32;
            let v = data[v_base + uv_row + x / 2] as i32;
            let c = (luma - 16).max(0);
            let d = u - 128;
            let e = v - 128;
            rgb.push(clamp_yuv_to_u8((298 * c + 409 * e + 128) >> 8));
            rgb.push(clamp_yuv_to_u8((298 * c - 100 * d - 208 * e + 128) >> 8));
            rgb.push(clamp_yuv_to_u8((298 * c + 516 * d + 128) >> 8));
        }
    }
    Ok(rgb)
}

#[cfg(any(windows, target_os = "macos", test))]
pub(super) fn decoded_frame_to_rgb24(frame: DecodedFrame) -> Result<(u32, u32, Vec<u8>)> {
    let expected_pixels = frame
        .width
        .checked_mul(frame.height)
        .ok_or_else(|| anyhow::anyhow!("decoded frame dimensions overflow"))?;
    let rgb = match frame.data {
        DecodedFrameData::CpuRgb24(data) => {
            let expected_len = expected_pixels
                .checked_mul(3)
                .ok_or_else(|| anyhow::anyhow!("decoded RGB frame byte size overflow"))?;
            if data.len() != expected_len {
                anyhow::bail!("decoded RGB frame has invalid byte length");
            }
            data
        }
        DecodedFrameData::CpuBgra32(data) => {
            let expected_len = expected_pixels
                .checked_mul(4)
                .ok_or_else(|| anyhow::anyhow!("decoded BGRA frame byte size overflow"))?;
            if data.len() != expected_len {
                anyhow::bail!("decoded BGRA frame has invalid byte length");
            }
            let mut rgb = Vec::with_capacity(expected_pixels * 3);
            for pixel in data.as_chunks::<4>().0 {
                rgb.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
            }
            rgb
        }
        DecodedFrameData::CpuNv12 { data, pitch } => {
            nv12_to_rgb24(&data, pitch, frame.width, frame.height)?
        }
        DecodedFrameData::CpuI420 {
            data,
            y_pitch,
            uv_pitch,
        } => i420_to_rgb24(&data, y_pitch, uv_pitch, frame.width, frame.height)?,
        _ => anyhow::bail!("decoded frame is not CPU RGB/BGRA/NV12/I420 backed"),
    };

    Ok((frame.width as u32, frame.height as u32, rgb))
}

pub(crate) fn decoded_frame_pixel_format(frame: &DecodedFrame) -> &'static str {
    match &frame.data {
        DecodedFrameData::CpuRgb24(_) => "cpu_rgb24",
        DecodedFrameData::CpuBgra32(_) => "cpu_bgra32",
        DecodedFrameData::CpuI420 { .. } => "cpu_i420",
        DecodedFrameData::CpuNv12 { .. } => "cpu_nv12",
        DecodedFrameData::CpuP010 { .. } => "cpu_p010",
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedNv12 { .. } => "d3d11_shared_nv12",
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedP010 { .. } => "d3d11_shared_p010",
    }
}

pub(crate) fn decoded_frame_format_stage(frame: &DecodedFrame) -> &'static str {
    match &frame.data {
        DecodedFrameData::CpuRgb24(_) => "receiver.format.cpu_rgb24",
        DecodedFrameData::CpuBgra32(_) => "receiver.format.cpu_bgra32",
        DecodedFrameData::CpuI420 { .. } => "receiver.format.cpu_i420",
        DecodedFrameData::CpuNv12 { .. } => "receiver.format.cpu_nv12",
        DecodedFrameData::CpuP010 { .. } => "receiver.format.cpu_p010",
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedNv12 { .. } => "receiver.format.d3d11_shared_nv12",
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedP010 { .. } => "receiver.format.d3d11_shared_p010",
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(super) fn decoded_frame_to_render_frame(frame: DecodedFrame) -> Result<RenderFrame> {
    match frame.data {
        DecodedFrameData::CpuRgb24(data) => {
            let expected_len = frame
                .width
                .checked_mul(frame.height)
                .and_then(|pixels| pixels.checked_mul(3))
                .ok_or_else(|| anyhow::anyhow!("decoded RGB render frame byte size overflow"))?;
            if data.len() != expected_len {
                anyhow::bail!("decoded RGB render frame has invalid byte length");
            }
            Ok(RenderFrame::from_rgb24(frame.width, frame.height, data))
        }
        DecodedFrameData::CpuBgra32(data) => {
            let expected_len = frame
                .width
                .checked_mul(frame.height)
                .and_then(|pixels| pixels.checked_mul(4))
                .ok_or_else(|| anyhow::anyhow!("decoded BGRA render frame byte size overflow"))?;
            if data.len() != expected_len {
                anyhow::bail!("decoded BGRA render frame has invalid byte length");
            }
            Ok(RenderFrame::from_bgra32(frame.width, frame.height, data))
        }
        DecodedFrameData::CpuNv12 { data, pitch } => {
            if pitch < frame.width {
                anyhow::bail!("decoded NV12 render frame pitch is smaller than width");
            }
            let y_bytes = pitch
                .checked_mul(frame.height)
                .ok_or_else(|| anyhow::anyhow!("decoded NV12 luma byte size overflow"))?;
            let uv_bytes = pitch
                .checked_mul(frame.height.div_ceil(2))
                .ok_or_else(|| anyhow::anyhow!("decoded NV12 chroma byte size overflow"))?;
            let expected_len = y_bytes
                .checked_add(uv_bytes)
                .ok_or_else(|| anyhow::anyhow!("decoded NV12 byte size overflow"))?;
            if data.len() < expected_len {
                anyhow::bail!("decoded NV12 render frame has invalid byte length");
            }
            Ok(RenderFrame::from_nv12(
                frame.width,
                frame.height,
                data,
                pitch,
            ))
        }
        DecodedFrameData::CpuI420 { .. } => {
            let (width, height, rgb24) = decoded_frame_to_rgb24(frame)?;
            Ok(RenderFrame::from_rgb24(
                width as usize,
                height as usize,
                rgb24,
            ))
        }
        DecodedFrameData::CpuP010 { .. } => {
            anyhow::bail!("CPU P010 decoded frames are not supported by the native renderer yet")
        }
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedNv12 {
            shared_handle_y,
            shared_handle_uv,
            ..
        } => Ok(RenderFrame::from_d3d11_shared_nv12(
            frame.width,
            frame.height,
            shared_handle_y,
            shared_handle_uv,
        )),
        #[cfg(windows)]
        DecodedFrameData::D3D11SharedP010 {
            shared_handle_y,
            shared_handle_uv,
            ..
        } => Ok(RenderFrame::from_d3d11_shared_p010(
            frame.width,
            frame.height,
            shared_handle_y,
            shared_handle_uv,
        )),
    }
}

fn clamp_yuv_to_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

fn read_nv12_rgb(data: &[u8], pitch: usize, height: usize, x: usize, y: usize) -> (u8, u8, u8) {
    let y_offset = y * pitch;
    let uv_offset = pitch * height + (y / 2) * pitch;
    let luma = data[y_offset + x] as i32;
    let uv_x = (x / 2) * 2;
    let u = data[uv_offset + uv_x] as i32;
    let v = data[uv_offset + uv_x + 1] as i32;
    let c = (luma - 16).max(0);
    let d = u - 128;
    let e = v - 128;
    (
        clamp_yuv_to_u8((298 * c + 409 * e + 128) >> 8),
        clamp_yuv_to_u8((298 * c - 100 * d - 208 * e + 128) >> 8),
        clamp_yuv_to_u8((298 * c + 516 * d + 128) >> 8),
    )
}

fn read_captured_rgb(
    frame: &CapturedFrame,
    x: usize,
    y: usize,
    source_stride: usize,
) -> (u8, u8, u8) {
    let bytes_per_pixel = frame_bytes_per_pixel(frame.pixel_format);
    let index = y * source_stride + x * bytes_per_pixel;
    match frame.pixel_format {
        FramePixelFormat::Bgra32 => (
            frame.data[index + 2],
            frame.data[index + 1],
            frame.data[index],
        ),
        FramePixelFormat::Rgba32 => (
            frame.data[index],
            frame.data[index + 1],
            frame.data[index + 2],
        ),
        FramePixelFormat::Rgb24 => (
            frame.data[index],
            frame.data[index + 1],
            frame.data[index + 2],
        ),
        FramePixelFormat::Nv12 => unreachable!("NV12 is handled before packed RGB scaling"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i420_to_rgb24_converts_decoder_planes_to_rgb_pixels() {
        let width = 2;
        let height = 2;
        let y_pitch = 2;
        let uv_pitch = 1;
        let data = vec![
            16, 235, 81, 145, // Y plane
            90,  // U plane
            240, // V plane
        ];

        let rgb = i420_to_rgb24(&data, y_pitch, uv_pitch, width, height).unwrap();

        assert_eq!(rgb.len(), width * height * 3);
        assert_eq!(&rgb[0..3], &[179, 0, 0]);
    }

    #[test]
    fn decoded_frame_to_rgb24_converts_bgra_decoder_output() {
        let frame = DecodedFrame {
            width: 2,
            height: 1,
            timestamp_us: 42,
            data: DecodedFrameData::CpuBgra32(vec![1, 2, 3, 255, 4, 5, 6, 255]),
        };

        let (width, height, rgb) = decoded_frame_to_rgb24(frame).unwrap();

        assert_eq!((width, height), (2, 1));
        assert_eq!(rgb, vec![3, 2, 1, 6, 5, 4]);
    }

    #[test]
    fn decoded_frame_pixel_format_names_cpu_nv12_decoder_output() {
        let frame = DecodedFrame {
            width: 2,
            height: 2,
            timestamp_us: 42,
            data: DecodedFrameData::CpuNv12 {
                data: vec![16, 235, 16, 235, 128, 128],
                pitch: 2,
            },
        };

        assert_eq!(decoded_frame_pixel_format(&frame), "cpu_nv12");
    }

    #[test]
    fn prepare_frame_for_h264_scales_nv12_without_changing_sampled_colors() {
        let width = 4;
        let height = 4;
        let data = vec![
            16, 48, 80, 112, 32, 64, 96, 128, 48, 80, 112, 144, 64, 96, 128, 160, // Y
            90, 240, 100, 230, 110, 220, 120, 210, // UV
        ];
        let source_rgb = nv12_to_rgb24(&data, width, width, height).unwrap();
        let profile = MediaProfile {
            width: 2,
            height: 2,
            ..MediaProfile::default()
        };

        let prepared = prepare_frame_for_h264(
            CapturedFrame::from_cpu(width, height, FramePixelFormat::Nv12, 42, data),
            &profile,
        )
        .unwrap();

        let expected = [0, 2, 8, 10]
            .into_iter()
            .flat_map(|pixel_index| {
                source_rgb[pixel_index * 3..pixel_index * 3 + 3]
                    .iter()
                    .copied()
            })
            .collect::<Vec<_>>();
        assert_eq!((prepared.width, prepared.height), (2, 2));
        assert_eq!(prepared.pixel_format, FramePixelFormat::Rgb24);
        assert_eq!(prepared.data, expected);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn decoded_frame_to_render_frame_preserves_nv12_pitch() {
        let frame = DecodedFrame {
            width: 2,
            height: 2,
            timestamp_us: 42,
            data: DecodedFrameData::CpuNv12 {
                data: vec![16, 235, 16, 235, 128, 128],
                pitch: 2,
            },
        };

        let render_frame = decoded_frame_to_render_frame(frame).unwrap();

        assert_eq!(render_frame.width, 2);
        assert_eq!(render_frame.height, 2);
        assert_eq!(
            render_frame.pixel_format,
            mrd_render::RenderPixelFormat::Nv12
        );
        assert_eq!(
            render_frame.data,
            mrd_render::RenderFrameData::Nv12 {
                data: vec![16, 235, 16, 235, 128, 128],
                pitch: 2
            }
        );
    }
}
