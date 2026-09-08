use anyhow::{anyhow, bail, ensure, Result};
use nvenc::encoder::{Encoder, RegisteredResource};
use nvenc::session::{InitParams, Session};
use nvenc::sys::enums::{NVencBufferFormat, NVencParamsRcMode, NVencPicStruct, NVencPicType, NVencTuningInfo};
use nvenc::sys::guids::{NV_ENC_CODEC_H264_GUID, NV_ENC_PRESET_P3_GUID};
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_BIND_SHADER_RESOURCE, D3D11_SUBRESOURCE_DATA,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SAMPLE_DESC};

use crate::capture::{CapturedFrame, PixelFormat};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncoderConfig {
    pub width: u32,
    pub height: u32,
}

impl EncoderConfig {
    pub fn new(width: u32, height: u32) -> Result<Self> {
        ensure!(width > 0, "width must be greater than 0");
        ensure!(height > 0, "height must be greater than 0");
        Ok(Self { width, height })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFrame {
    pub width: u32,
    pub height: u32,
    pub pts: u64,
    pub bitstream: Vec<u8>,
}

impl EncodedFrame {
    pub fn new(width: u32, height: u32, pts: u64, bitstream: Vec<u8>) -> Self {
        Self {
            width,
            height,
            pts,
            bitstream,
        }
    }
}

pub trait NvencEncoder {
    fn encode_frame(&mut self, frame: &CapturedFrame, pts: u64) -> Result<EncodedFrame>;
}

pub struct UnconfiguredNvencEncoder;

impl NvencEncoder for UnconfiguredNvencEncoder {
    fn encode_frame(&mut self, _frame: &CapturedFrame, _pts: u64) -> Result<EncodedFrame> {
        bail!("NVENC encoder is not configured")
    }
}

/// A persistent NVENC encoder that maintains session and all reusable resources across frames.
///
/// This encoder reuses:
/// - Input texture (updated via UpdateSubresource each frame)
/// - Registered NVENC resource
/// - Output bitstream buffer (locked/unlocked each frame)
pub struct PersistentNvencEncoder {
    _device: ID3D11Device,
    device_context: ID3D11DeviceContext,
    encoder: Encoder,
    config: EncoderConfig,
    frame_count: u64,

    // Reusable resources (created once, reused every frame)
    input_texture: ID3D11Texture2D,
    registered_resource: RegisteredResource,
    bitstream: nvenc::bitstream::BitStream,
}

impl PersistentNvencEncoder {
    /// Create a new persistent NVENC encoder with the given configuration.
    ///
    /// This creates and initializes all reusable resources (texture, registered resource,
    /// bitstream buffer) that will be reused for every frame encoded.
    pub fn new(config: EncoderConfig) -> Result<Self> {
        let device = create_nvenc_device()?;
        let device_context = unsafe { device.GetImmediateContext() }
            .map_err(|err| anyhow!("failed to get D3D11 device context: {err:?}"))?;

        let session: Session<nvenc::session::NeedsConfig> =
            Session::open_dx(&device).map_err(|err| anyhow!("failed to open NVENC session: {err:?}"))?;

        let codecs = session
            .get_encode_codecs()
            .map_err(|err| anyhow!("failed to enumerate NVENC codecs: {err:?}"))?;
        ensure!(codecs.contains(&NV_ENC_CODEC_H264_GUID), "GPU does not support H.264 NVENC");

        let presets = session
            .get_encode_presets(NV_ENC_CODEC_H264_GUID)
            .map_err(|err| anyhow!("failed to enumerate NVENC presets: {err:?}"))?;
        ensure!(presets.contains(&NV_ENC_PRESET_P3_GUID), "GPU does not support NVENC preset P3");

        let (session, mut enc_config) = session
            .get_encode_preset_config_ex(
                NV_ENC_CODEC_H264_GUID,
                NV_ENC_PRESET_P3_GUID,
                NVencTuningInfo::LowLatency,
            )
            .map_err(|err| anyhow!("failed to get NVENC preset config: {err:?}"))?;

        enc_config.preset_cfg.rc_params.rate_control_mode = NVencParamsRcMode::VBR;
        enc_config.preset_cfg.rc_params.average_bit_rate = 8_000_000;
        enc_config.preset_cfg.gop_len = 30; // Use 30-frame GOP for efficient P-frames
        enc_config.preset_cfg.frame_interval_p = 1;

        let init_params = InitParams {
            encode_guid: NV_ENC_CODEC_H264_GUID,
            preset_guid: NV_ENC_PRESET_P3_GUID,
            aspect_ratio: [config.width, config.height],
            encode_config: &mut enc_config.preset_cfg,
            tuning_info: NVencTuningInfo::LowLatency,
            buffer_format: NVencBufferFormat::ARGB,
            frame_rate: [60, 1],
            resolution: [config.width, config.height],
            enable_ptd: true,
            max_encoder_resolution: [0, 0],
        };

        let encoder = session
            .init_encoder(init_params)
            .map_err(|err| anyhow!("failed to initialize NVENC encoder: {err:?}"))?;

        // Create reusable input texture (DEFAULT usage, updated via UpdateSubresource)
        let input_texture = create_persistent_rgba_texture(&device, config.width, config.height)?;

        // Register the texture with NVENC (this mapping will persist)
        let registered_resource = encoder
            .register_resource_dx11(&input_texture, NVencBufferFormat::ARGB, 0)
            .map_err(|err| anyhow!("failed to register NVENC texture: {err:?}"))?;

        // Create reusable bitstream buffer
        let bitstream = encoder
            .create_bitstream_buffer()
            .map_err(|err| anyhow!("failed to create NVENC bitstream buffer: {err:?}"))?;

        Ok(Self {
            _device: device,
            device_context,
            encoder,
            config,
            frame_count: 0,
            input_texture,
            registered_resource,
            bitstream,
        })
    }

    /// Encode a single frame using the persistent NVENC session and reusable resources.
    /// First frame is IDR, subsequent frames are P-frames for efficiency.
    ///
    /// This reuses:
    /// - The same D3D11 input texture (content updated via UpdateSubresource)
    /// - The same NVENC registered resource
    /// - The same output bitstream buffer (locked/unlocked each frame)
    pub fn encode_frame(&mut self, frame: &CapturedFrame, pts: u64) -> Result<EncodedFrame> {
        ensure!(
            frame.width == self.config.width && frame.height == self.config.height,
            "frame dimensions ({}, {}) do not match encoder config ({}, {})",
            frame.width,
            frame.height,
            self.config.width,
            self.config.height
        );

        // Convert BGRA to RGBA in-place
        let rgba = bgra_to_rgba_bytes(frame)?;

        // Update the persistent texture via UpdateSubresource
        update_persistent_texture(&self.device_context, &self.input_texture, frame.width, frame.height, &rgba)?;

        // First frame is IDR (keyframe), subsequent frames are P-frames
        let pic_type = if self.frame_count == 0 {
            NVencPicType::IDR
        } else {
            NVencPicType::P
        };

        // Encode using the persistent registered resource and bitstream buffer
        self.encoder
            .encode_picture(
                &self.registered_resource,
                &self.bitstream,
                0,
                pts,
                NVencBufferFormat::ARGB,
                NVencPicStruct::Frame,
                pic_type,
                None,
            )
            .map_err(|err| anyhow!("failed to encode frame: {err:?}"))?;

        // Lock the persistent bitstream buffer to read the encoded data
        let lock = self
            .bitstream
            .try_lock(true)
            .map_err(|err| anyhow!("failed to lock NVENC bitstream: {err:?}"))?;
        let bitstream = lock.as_slice().to_vec();
        drop(lock); // Unlock so the buffer can be reused for next frame

        self.frame_count += 1;
        ensure!(!bitstream.is_empty(), "NVENC produced an empty bitstream");
        Ok(EncodedFrame::new(frame.width, frame.height, pts, bitstream))
    }
}

pub fn bgra_to_rgba_bytes(frame: &CapturedFrame) -> Result<Vec<u8>> {
    ensure!(frame.format == PixelFormat::Bgra8, "unsupported pixel format");
    let mut rgba = frame.data.clone();
    for pixel in rgba.chunks_exact_mut(4) {
        pixel.swap(0, 2);
    }
    Ok(rgba)
}

pub fn encode_bgra_frame_nvenc(frame: &CapturedFrame, pts: u64) -> Result<EncodedFrame> {
    let rgba = bgra_to_rgba_bytes(frame)?;
    let device = create_nvenc_device()?;
    let session: Session<nvenc::session::NeedsConfig> =
        Session::open_dx(&device).map_err(|err| anyhow!("failed to open NVENC session: {err:?}"))?;

    let codecs = session
        .get_encode_codecs()
        .map_err(|err| anyhow!("failed to enumerate NVENC codecs: {err:?}"))?;
    ensure!(codecs.contains(&NV_ENC_CODEC_H264_GUID), "GPU does not support H.264 NVENC");

    let presets = session
        .get_encode_presets(NV_ENC_CODEC_H264_GUID)
        .map_err(|err| anyhow!("failed to enumerate NVENC presets: {err:?}"))?;
    ensure!(presets.contains(&NV_ENC_PRESET_P3_GUID), "GPU does not support NVENC preset P3");

    let (session, mut config) = session
        .get_encode_preset_config_ex(
            NV_ENC_CODEC_H264_GUID,
            NV_ENC_PRESET_P3_GUID,
            NVencTuningInfo::LowLatency,
        )
        .map_err(|err| anyhow!("failed to get NVENC preset config: {err:?}"))?;

    config.preset_cfg.rc_params.rate_control_mode = NVencParamsRcMode::VBR;
    config.preset_cfg.rc_params.average_bit_rate = 8_000_000;
    config.preset_cfg.gop_len = 1;
    config.preset_cfg.frame_interval_p = 1;

    let init_params = InitParams {
        encode_guid: NV_ENC_CODEC_H264_GUID,
        preset_guid: NV_ENC_PRESET_P3_GUID,
        aspect_ratio: [frame.width, frame.height],
        encode_config: &mut config.preset_cfg,
        tuning_info: NVencTuningInfo::LowLatency,
        buffer_format: NVencBufferFormat::ARGB,
        frame_rate: [60, 1],
        resolution: [frame.width, frame.height],
        enable_ptd: true,
        max_encoder_resolution: [0, 0],
    };

    let encoder = session
        .init_encoder(init_params)
        .map_err(|err| anyhow!("failed to initialize NVENC encoder: {err:?}"))?;
    let texture = create_rgba_texture(&device, frame.width, frame.height, &rgba)?;
    let registered = encoder
        .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
        .map_err(|err| anyhow!("failed to register NVENC texture: {err:?}"))?;
    let output = encoder
        .create_bitstream_buffer()
        .map_err(|err| anyhow!("failed to create NVENC bitstream buffer: {err:?}"))?;

    encoder
        .encode_picture(
            &registered,
            &output,
            0,
            pts,
            NVencBufferFormat::ARGB,
            NVencPicStruct::Frame,
            NVencPicType::IDR,
            None,
        )
        .map_err(|err| anyhow!("failed to encode frame: {err:?}"))?;

    let lock = output
        .try_lock(true)
        .map_err(|err| anyhow!("failed to lock NVENC bitstream: {err:?}"))?;
    let bitstream = lock.as_slice().to_vec();
    drop(lock);

    ensure!(!bitstream.is_empty(), "NVENC produced an empty bitstream");
    Ok(EncodedFrame::new(frame.width, frame.height, pts, bitstream))
}

fn create_nvenc_device() -> Result<ID3D11Device> {
    let dxgi_factory: windows::Win32::Graphics::Dxgi::IDXGIFactory =
        unsafe { windows::Win32::Graphics::Dxgi::CreateDXGIFactory() }?;
    let dxgi_adapter = unsafe { dxgi_factory.EnumAdapters(0)? };

    let mut device = None;
    let mut device_context = None;
    unsafe {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0};
        use windows::Win32::Graphics::Direct3D11::{
            D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION, D3D11CreateDevice,
        };

        D3D11CreateDevice(
            &dxgi_adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE(std::ptr::null_mut()),
            D3D11_CREATE_DEVICE_FLAG(0),
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&raw mut device),
            None,
            Some(&raw mut device_context),
        )?;
    }

    device.ok_or_else(|| anyhow!("failed to create NVENC D3D11 device"))
}

fn create_rgba_texture(device: &ID3D11Device, width: u32, height: u32, rgba: &[u8]) -> Result<ID3D11Texture2D> {
    let mut texture = None;
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
        CPUAccessFlags: 0, // No CPU access needed for DEFAULT usage
        MiscFlags: 0,
    };
    let data = D3D11_SUBRESOURCE_DATA {
        pSysMem: rgba.as_ptr() as _,
        SysMemPitch: width * 4,
        SysMemSlicePitch: 0,
    };
    unsafe {
        device.CreateTexture2D(&raw const desc, Some(&raw const data), Some(&raw mut texture))?;
    }
    texture.ok_or_else(|| anyhow!("failed to create NVENC upload texture"))
}

/// Create a D3D11 texture for persistent NVENC input.
///
/// This creates a DEFAULT usage texture (required by NVENC) that can be
/// updated each frame via UpdateSubresource.
fn create_persistent_rgba_texture(device: &ID3D11Device, width: u32, height: u32) -> Result<ID3D11Texture2D> {
    let mut texture = None;
    let desc = D3D11_TEXTURE2D_DESC {
        Width: width,
        Height: height,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };
    // Create with no initial data - will be updated via UpdateSubresource
    unsafe {
        device.CreateTexture2D(&raw const desc, None, Some(&raw mut texture))?;
    }
    texture.ok_or_else(|| anyhow!("failed to create persistent D3D11 texture"))
}

/// Update a persistent texture with new frame data via UpdateSubresource.
///
/// This is more efficient than creating a new texture each frame because:
/// 1. No new D3D11 resource allocation
/// 2. No new NVENC resource registration
/// 3. UpdateSubresource is efficient for small-to-medium uploads
fn update_persistent_texture(
    device_context: &ID3D11DeviceContext,
    texture: &ID3D11Texture2D,
    width: u32,
    height: u32,
    rgba: &[u8],
) -> Result<()> {
    unsafe {
        // Calculate row pitch (width * 4 bytes per pixel)
        let row_pitch = width * 4;
        let total_size = row_pitch * height;

        // Use rgba as the source data pointer
        device_context.UpdateSubresource(
            texture,
            0,
            None,
            rgba.as_ptr() as _,
            row_pitch,
            total_size,
        );
    }

    Ok(())
}
