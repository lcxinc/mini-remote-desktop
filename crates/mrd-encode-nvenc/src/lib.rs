#[cfg(not(windows))]
use mrd_pipeline_core::{CapturedFrame, ColorMode, EncodedAccessUnit, PipelineError, VideoEncoder};
#[cfg(not(windows))]
use mrd_pipeline_core::{FramePixelFormat, VideoCodec};
#[cfg(not(windows))]
use std::io::{Read, Write};
#[cfg(not(windows))]
use std::process::{Child, ChildStdin};
#[cfg(not(windows))]
use std::sync::{mpsc, Arc, Mutex};
#[cfg(not(windows))]
use std::time::{Duration, Instant};

#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Context};
    use mrd_pipeline_core::{
        CapturedFrame, ColorMode, D3D11SharedBgraFrame, EncodedAccessUnit, FrameMemoryKind,
        FramePixelFormat, PipelineError, VideoCodec, VideoEncoder,
    };
    use nvenc::bitstream::BitStream;
    use nvenc::encoder::{Encoder, RegisteredResource};
    use nvenc::session::{InitParams, NeedsConfig, Session};
    use nvenc::sys::enums::{
        NVencBufferFormat, NVencPicFlags, NVencPicStruct, NVencPicType, NVencTuningInfo,
    };
    use nvenc::sys::guids::{
        NV_ENC_CODEC_H264_GUID, NV_ENC_CODEC_HEVC_GUID, NV_ENC_H264_PROFILE_BASELINE_GUID,
        NV_ENC_H264_PROFILE_HIGH_GUID, NV_ENC_HEVC_PROFILE_MAIN10_GUID,
        NV_ENC_HEVC_PROFILE_MAIN_GUID, NV_ENC_PRESET_P1_GUID, NV_ENC_PRESET_P3_GUID,
        NV_ENC_PRESET_P6_GUID,
    };
    use nvenc::sys::structs::Guid;
    use std::collections::VecDeque;
    use windows::core::Interface;
    use windows::Win32::Foundation::{HANDLE, HMODULE};
    use windows::Win32::Graphics::Direct3D::{
        D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0,
        D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
    };
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11ClassLinkage, ID3D11Device, ID3D11DeviceContext,
        ID3D11PixelShader, ID3D11RenderTargetView, ID3D11Resource, ID3D11SamplerState,
        ID3D11ShaderResourceView, ID3D11Texture2D, ID3D11VertexShader, D3D11_BIND_RENDER_TARGET,
        D3D11_BIND_SHADER_RESOURCE, D3D11_COMPARISON_NEVER, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_SAMPLER_DESC, D3D11_SDK_VERSION,
        D3D11_TEXTURE2D_DESC, D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_USAGE_DEFAULT, D3D11_VIEWPORT,
    };
    use windows::Win32::Graphics::Dxgi::Common::{
        DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_P010, DXGI_SAMPLE_DESC,
    };

    const H264_SHARED_ASYNC_SLOT_COUNT: usize = 2;
    const HEVC_SHARED_ASYNC_SLOT_COUNT: usize = 3;
    const SHARED_INPUT_CACHE_LIMIT: usize = 8;
    const H264_REMOTE_DESKTOP_MAX_KEYFRAME_INTERVAL_FRAMES: usize = 30;
    const HEVC_REMOTE_DESKTOP_MAX_KEYFRAME_INTERVAL_FRAMES: usize = 60;
    const COLOR_TRANSFORM_VERTEX_SHADER: &str = r#"
struct VSOut {
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD0;
};

VSOut main(uint vertex_id : SV_VertexID) {
    float2 positions[3] = {
        float2(-1.0, -1.0),
        float2(-1.0,  3.0),
        float2( 3.0, -1.0)
    };
    float2 pos = positions[vertex_id];
    VSOut output;
    output.position = float4(pos, 0.0, 1.0);
    output.uv = float2((pos.x + 1.0) * 0.5, (1.0 - pos.y) * 0.5);
    return output;
}
"#;
    const COLOR_TRANSFORM_GRAYSCALE_PIXEL_SHADER: &str = r#"
Texture2D source_tex : register(t0);
SamplerState source_sampler : register(s0);

float4 main(float4 position : SV_POSITION, float2 uv : TEXCOORD0) : SV_TARGET {
    float4 color = source_tex.Sample(source_sampler, uv);
    float luma = dot(color.rgb, float3(0.2126, 0.7152, 0.0722));
    return float4(luma, luma, luma, color.a);
}
"#;
    const COLOR_TRANSFORM_MONOCHROME_PIXEL_SHADER: &str = r#"
Texture2D source_tex : register(t0);
SamplerState source_sampler : register(s0);

float4 main(float4 position : SV_POSITION, float2 uv : TEXCOORD0) : SV_TARGET {
    float4 color = source_tex.Sample(source_sampler, uv);
    float luma = dot(color.rgb, float3(0.2126, 0.7152, 0.0722));
    float mono = luma >= 0.5 ? 1.0 : 0.0;
    return float4(mono, mono, mono, color.a);
}
"#;
    const COLOR_TRANSFORM_LOW_CHROMA_PIXEL_SHADER: &str = r#"
Texture2D source_tex : register(t0);
SamplerState source_sampler : register(s0);

float4 main(float4 position : SV_POSITION, float2 uv : TEXCOORD0) : SV_TARGET {
    float4 color = source_tex.Sample(source_sampler, uv);
    float luma = dot(color.rgb, float3(0.2126, 0.7152, 0.0722));
    float3 low_chroma = lerp(float3(luma, luma, luma), color.rgb, 0.25);
    return float4(low_chroma, color.a);
}
"#;

    pub struct NvencH264Encoder {
        // Rust drops fields in declaration order.  Keep the NVENC-owned
        // objects first so every bitstream is destroyed and every resource is
        // unregistered while the backing D3D11 textures/device are still live.
        pending_shared_encodes: VecDeque<PendingSharedEncode>,
        shared_encode_slots: Vec<SharedEncodeSlot>,
        bitstream: BitStream,
        registered: RegisteredResource,
        encoder: Encoder,
        shared_inputs: Vec<SharedInputResource>,
        color_transform_pipeline: Option<ColorTransformPipeline>,
        texture: ID3D11Texture2D,
        context: ID3D11DeviceContext,
        _device: ID3D11Device,
        width: usize,
        height: usize,
        fps: u32,
        frame_index: usize,
        force_next_keyframe: bool,
        color_mode: ColorMode,
    }

    unsafe impl Send for NvencH264Encoder {}

    pub struct NvencHevcEncoder {
        // See `NvencH264Encoder`: native encoder resources must be released
        // before the D3D11 resources backing their registrations.
        pending_shared_encodes: VecDeque<PendingSharedEncode>,
        shared_encode_slots: Vec<SharedEncodeSlot>,
        bitstream: BitStream,
        registered: RegisteredResource,
        encoder: Encoder,
        shared_inputs: Vec<SharedInputResource>,
        color_transform_pipeline: Option<ColorTransformPipeline>,
        texture: ID3D11Texture2D,
        context: ID3D11DeviceContext,
        _device: ID3D11Device,
        width: usize,
        height: usize,
        fps: u32,
        frame_index: usize,
        main10: bool,
        color_mode: ColorMode,
    }

    unsafe impl Send for NvencHevcEncoder {}

    fn h264_remote_desktop_keyframe_interval(fps: u32) -> usize {
        (fps.max(1) as usize).min(H264_REMOTE_DESKTOP_MAX_KEYFRAME_INTERVAL_FRAMES)
    }

    fn h264_should_force_keyframe(frame_index: usize, fps: u32, force_next: bool) -> bool {
        force_next
            || frame_index == 0
            || frame_index.is_multiple_of(h264_remote_desktop_keyframe_interval(fps))
    }

    fn hevc_remote_desktop_keyframe_interval(fps: u32) -> usize {
        (fps.max(1) as usize).min(HEVC_REMOTE_DESKTOP_MAX_KEYFRAME_INTERVAL_FRAMES)
    }

    struct SharedInputResource {
        shared_handle: isize,
        width: u32,
        height: u32,
        shader_resource_view: Option<ID3D11ShaderResourceView>,
        _texture: ID3D11Texture2D,
    }

    struct SharedEncodeSlot {
        bitstream: BitStream,
        registered: RegisteredResource,
        render_target_view: Option<ID3D11RenderTargetView>,
        texture: ID3D11Texture2D,
    }

    struct PendingSharedEncode {
        slot: SharedEncodeSlot,
        timestamp_us: u64,
        is_keyframe: bool,
    }

    struct SharedInputBinding {
        shader_resource_view: Option<ID3D11ShaderResourceView>,
        texture: ID3D11Texture2D,
    }

    struct ColorTransformPipeline {
        vertex_shader: ID3D11VertexShader,
        grayscale_pixel_shader: ID3D11PixelShader,
        monochrome_pixel_shader: ID3D11PixelShader,
        low_chroma_pixel_shader: ID3D11PixelShader,
        sampler: ID3D11SamplerState,
    }

    impl NvencH264Encoder {
        pub fn default_color_mode() -> ColorMode {
            ColorMode::Full
        }

        pub fn color_mode(&self) -> ColorMode {
            self.color_mode
        }

        pub fn with_color_mode(mut self, color_mode: ColorMode) -> Self {
            self.color_mode = color_mode;
            self.color_transform_pipeline = None;
            self.shared_inputs.clear();
            self.shared_encode_slots.clear();
            self.pending_shared_encodes.clear();
            self
        }

        pub fn preferred_input_memory_kind_for_color_mode(_mode: ColorMode) -> FrameMemoryKind {
            FrameMemoryKind::D3D11SharedBgra
        }

        pub fn new(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
            Self::new_with_profile(width, height, fps, NV_ENC_H264_PROFILE_HIGH_GUID)
        }

        pub fn new_with_bitrate(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_low_latency_internal(
                width,
                height,
                fps,
                NV_ENC_H264_PROFILE_HIGH_GUID,
                bitrate.max(1),
            )
        }

        pub fn new_baseline(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
            Self::new_with_profile(width, height, fps, NV_ENC_H264_PROFILE_BASELINE_GUID)
        }

        /// Ultra-low latency encoder for remote desktop scenarios
        /// Uses UltraLowLatency tuning and P6 preset for minimum latency
        pub fn new_ultra_low_latency(
            width: usize,
            height: usize,
            fps: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_ultra_low_latency_internal(width, height, fps, NV_ENC_H264_PROFILE_HIGH_GUID)
        }

        /// High refresh rate encoder (120Hz+) optimized for minimum latency
        /// Uses Baseline profile, lower bitrate, and shorter GOP for maximum speed
        /// Target: <7ms encode latency for 2K@144Hz
        pub fn new_high_refresh_rate(
            width: usize,
            height: usize,
            fps: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_high_refresh_rate_internal(width, height, fps, 8_000_000)
        }

        /// Extreme low latency encoder for 144Hz+ gaming scenarios
        /// Very aggressive settings for maximum speed at cost of quality
        /// Target: <7ms encode latency for 2K@144Hz
        pub fn new_extreme_low_latency(
            width: usize,
            height: usize,
            fps: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_high_refresh_rate_internal(width, height, fps, 5_000_000)
        }

        /// Maximum speed encoder using P1 preset (fastest preset)
        /// Lowest quality but maximum speed for 144Hz+ gaming
        pub fn new_max_speed(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
            Self::new_max_speed_with_bitrate(width, height, fps, 5_000_000)
        }

        pub fn new_max_speed_with_bitrate(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            let width = width.max(2);
            let height = height.max(2);
            let fps = fps.max(1);
            let bitrate = bitrate.max(1);
            let (device, context) = create_d3d11_device().map_err(|error| {
                PipelineError::message(format!("create d3d11 device failed: {error}"))
            })?;

            let session: Session<NeedsConfig> = Session::open_dx(&device).map_err(|error| {
                PipelineError::message(format!("nvenc open_dx failed: {error:?}"))
            })?;
            let (session, mut preset) = session
                .get_encode_preset_config_ex(
                    NV_ENC_CODEC_H264_GUID,
                    NV_ENC_PRESET_P1_GUID,
                    NVencTuningInfo::UltraLowLatency,
                )
                .map_err(|error| {
                    PipelineError::message(format!("nvenc preset config failed: {error:?}"))
                })?;

            // Maximum speed optimizations:
            preset.preset_cfg.profile_guid = NV_ENC_H264_PROFILE_BASELINE_GUID;
            preset.preset_cfg.rc_params.average_bit_rate = bitrate;
            preset.preset_cfg.gop_len = h264_remote_desktop_keyframe_interval(fps) as u32;
            preset.preset_cfg.frame_interval_p = 1;

            let init = InitParams {
                encode_guid: NV_ENC_CODEC_H264_GUID,
                preset_guid: NV_ENC_PRESET_P1_GUID,
                resolution: [width as u32, height as u32],
                aspect_ratio: [width as u32, height as u32],
                frame_rate: [fps, 1],
                tuning_info: NVencTuningInfo::UltraLowLatency,
                buffer_format: NVencBufferFormat::ARGB,
                encode_config: &mut preset.preset_cfg,
                enable_ptd: true,
                max_encoder_resolution: [width as u32, height as u32],
            };
            let encoder = session.init_encoder(init).map_err(|error| {
                PipelineError::message(format!("nvenc init encoder failed: {error:?}"))
            })?;
            let texture =
                create_encode_texture(&device, width as u32, height as u32).map_err(|error| {
                    PipelineError::message(format!("create nvenc texture failed: {error}"))
                })?;
            let registered = encoder
                .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                .map_err(|error| {
                    PipelineError::message(format!("nvenc register resource failed: {error:?}"))
                })?;
            let bitstream = encoder.create_bitstream_buffer().map_err(|error| {
                PipelineError::message(format!("nvenc bitstream buffer failed: {error:?}"))
            })?;

            Ok(Self {
                _device: device,
                context,
                texture,
                encoder,
                registered,
                shared_inputs: Vec::new(),
                shared_encode_slots: Vec::new(),
                pending_shared_encodes: VecDeque::new(),
                color_transform_pipeline: None,
                bitstream,
                width,
                height,
                fps,
                frame_index: 0,
                force_next_keyframe: false,
                color_mode: ColorMode::Full,
            })
        }

        fn new_high_refresh_rate_internal(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            let width = width.max(2);
            let height = height.max(2);
            let fps = fps.max(1);
            let (device, context) = create_d3d11_device().map_err(|error| {
                PipelineError::message(format!("create d3d11 device failed: {error}"))
            })?;

            let session: Session<NeedsConfig> = Session::open_dx(&device).map_err(|error| {
                PipelineError::message(format!("nvenc open_dx failed: {error:?}"))
            })?;
            let (session, mut preset) = session
                .get_encode_preset_config_ex(
                    NV_ENC_CODEC_H264_GUID,
                    NV_ENC_PRESET_P6_GUID,
                    NVencTuningInfo::UltraLowLatency,
                )
                .map_err(|error| {
                    PipelineError::message(format!("nvenc preset config failed: {error:?}"))
                })?;

            // High refresh rate optimizations:
            // - Use Baseline profile (faster than High/Main)
            preset.preset_cfg.profile_guid = NV_ENC_H264_PROFILE_BASELINE_GUID;
            // - Lower bitrate for faster encoding
            preset.preset_cfg.rc_params.average_bit_rate = bitrate;
            // - Very short GOP for minimal I-frame overhead
            preset.preset_cfg.gop_len = h264_remote_desktop_keyframe_interval(fps) as u32;
            // - Disable frame doubling
            preset.preset_cfg.frame_interval_p = 1;

            let init = InitParams {
                encode_guid: NV_ENC_CODEC_H264_GUID,
                preset_guid: NV_ENC_PRESET_P6_GUID,
                resolution: [width as u32, height as u32],
                aspect_ratio: [width as u32, height as u32],
                frame_rate: [fps, 1],
                tuning_info: NVencTuningInfo::UltraLowLatency,
                buffer_format: NVencBufferFormat::ARGB,
                encode_config: &mut preset.preset_cfg,
                enable_ptd: true,
                max_encoder_resolution: [width as u32, height as u32],
            };
            let encoder = session.init_encoder(init).map_err(|error| {
                PipelineError::message(format!("nvenc init encoder failed: {error:?}"))
            })?;
            let texture =
                create_encode_texture(&device, width as u32, height as u32).map_err(|error| {
                    PipelineError::message(format!("create nvenc texture failed: {error}"))
                })?;
            let registered = encoder
                .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                .map_err(|error| {
                    PipelineError::message(format!("nvenc register resource failed: {error:?}"))
                })?;
            let bitstream = encoder.create_bitstream_buffer().map_err(|error| {
                PipelineError::message(format!("nvenc bitstream buffer failed: {error:?}"))
            })?;

            Ok(Self {
                _device: device,
                context,
                texture,
                encoder,
                registered,
                shared_inputs: Vec::new(),
                shared_encode_slots: Vec::new(),
                pending_shared_encodes: VecDeque::new(),
                color_transform_pipeline: None,
                bitstream,
                width,
                height,
                fps,
                frame_index: 0,
                force_next_keyframe: false,
                color_mode: ColorMode::Full,
            })
        }

        /// Low latency encoder with balanced quality
        /// Uses LowLatency tuning and P3 preset
        pub fn new_low_latency_p1(
            width: usize,
            height: usize,
            fps: u32,
        ) -> Result<Self, PipelineError> {
            Self::new(width, height, fps)
        }

        /// High quality encoder (higher latency, better quality)
        /// Uses HighQuality tuning and P5 preset
        pub fn new_high_quality_p5(
            width: usize,
            height: usize,
            fps: u32,
        ) -> Result<Self, PipelineError> {
            Self::new(width, height, fps)
        }

        fn new_with_profile(
            width: usize,
            height: usize,
            fps: u32,
            profile_guid: Guid,
        ) -> Result<Self, PipelineError> {
            Self::new_low_latency_internal(width, height, fps, profile_guid, 12_000_000)
        }

        fn new_low_latency_internal(
            width: usize,
            height: usize,
            fps: u32,
            profile_guid: Guid,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            let width = width.max(2);
            let height = height.max(2);
            let fps = fps.max(1);
            let bitrate = bitrate.max(1);
            let (device, context) = create_d3d11_device().map_err(|error| {
                PipelineError::message(format!("create d3d11 device failed: {error}"))
            })?;

            let session: Session<NeedsConfig> = Session::open_dx(&device).map_err(|error| {
                PipelineError::message(format!("nvenc open_dx failed: {error:?}"))
            })?;
            let (session, mut preset) = session
                .get_encode_preset_config_ex(
                    NV_ENC_CODEC_H264_GUID,
                    NV_ENC_PRESET_P3_GUID,
                    NVencTuningInfo::LowLatency,
                )
                .map_err(|error| {
                    PipelineError::message(format!("nvenc preset config failed: {error:?}"))
                })?;
            preset.preset_cfg.profile_guid = profile_guid;
            preset.preset_cfg.rc_params.average_bit_rate = bitrate;
            preset.preset_cfg.frame_interval_p = 1;
            preset.preset_cfg.gop_len = h264_remote_desktop_keyframe_interval(fps) as u32;

            let init = InitParams {
                encode_guid: NV_ENC_CODEC_H264_GUID,
                preset_guid: NV_ENC_PRESET_P3_GUID,
                resolution: [width as u32, height as u32],
                aspect_ratio: [width as u32, height as u32],
                frame_rate: [fps, 1],
                tuning_info: NVencTuningInfo::LowLatency,
                buffer_format: NVencBufferFormat::ARGB,
                encode_config: &mut preset.preset_cfg,
                enable_ptd: true,
                max_encoder_resolution: [width as u32, height as u32],
            };
            let encoder = session.init_encoder(init).map_err(|error| {
                PipelineError::message(format!("nvenc init encoder failed: {error:?}"))
            })?;
            let texture =
                create_encode_texture(&device, width as u32, height as u32).map_err(|error| {
                    PipelineError::message(format!("create nvenc texture failed: {error}"))
                })?;
            let registered = encoder
                .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                .map_err(|error| {
                    PipelineError::message(format!("nvenc register resource failed: {error:?}"))
                })?;
            let bitstream = encoder.create_bitstream_buffer().map_err(|error| {
                PipelineError::message(format!("nvenc bitstream buffer failed: {error:?}"))
            })?;

            Ok(Self {
                _device: device,
                context,
                texture,
                encoder,
                registered,
                shared_inputs: Vec::new(),
                shared_encode_slots: Vec::new(),
                pending_shared_encodes: VecDeque::new(),
                color_transform_pipeline: None,
                bitstream,
                width,
                height,
                fps,
                frame_index: 0,
                force_next_keyframe: false,
                color_mode: ColorMode::Full,
            })
        }

        fn new_ultra_low_latency_internal(
            width: usize,
            height: usize,
            fps: u32,
            profile_guid: Guid,
        ) -> Result<Self, PipelineError> {
            let width = width.max(2);
            let height = height.max(2);
            let fps = fps.max(1);
            let (device, context) = create_d3d11_device().map_err(|error| {
                PipelineError::message(format!("create d3d11 device failed: {error}"))
            })?;

            let session: Session<NeedsConfig> = Session::open_dx(&device).map_err(|error| {
                PipelineError::message(format!("nvenc open_dx failed: {error:?}"))
            })?;
            let (session, mut preset) = session
                .get_encode_preset_config_ex(
                    NV_ENC_CODEC_H264_GUID,
                    NV_ENC_PRESET_P6_GUID,
                    NVencTuningInfo::UltraLowLatency,
                )
                .map_err(|error| {
                    PipelineError::message(format!("nvenc preset config failed: {error:?}"))
                })?;
            preset.preset_cfg.profile_guid = profile_guid;
            preset.preset_cfg.rc_params.average_bit_rate = 12_000_000;
            preset.preset_cfg.frame_interval_p = 1;
            preset.preset_cfg.gop_len = h264_remote_desktop_keyframe_interval(fps) as u32;

            let init = InitParams {
                encode_guid: NV_ENC_CODEC_H264_GUID,
                preset_guid: NV_ENC_PRESET_P6_GUID,
                resolution: [width as u32, height as u32],
                aspect_ratio: [width as u32, height as u32],
                frame_rate: [fps, 1],
                tuning_info: NVencTuningInfo::UltraLowLatency,
                buffer_format: NVencBufferFormat::ARGB,
                encode_config: &mut preset.preset_cfg,
                enable_ptd: true,
                max_encoder_resolution: [width as u32, height as u32],
            };
            let encoder = session.init_encoder(init).map_err(|error| {
                PipelineError::message(format!("nvenc init encoder failed: {error:?}"))
            })?;
            let texture =
                create_encode_texture(&device, width as u32, height as u32).map_err(|error| {
                    PipelineError::message(format!("create nvenc texture failed: {error}"))
                })?;
            let registered = encoder
                .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                .map_err(|error| {
                    PipelineError::message(format!("nvenc register resource failed: {error:?}"))
                })?;
            let bitstream = encoder.create_bitstream_buffer().map_err(|error| {
                PipelineError::message(format!("nvenc bitstream buffer failed: {error:?}"))
            })?;

            Ok(Self {
                _device: device,
                context,
                texture,
                encoder,
                registered,
                shared_inputs: Vec::new(),
                shared_encode_slots: Vec::new(),
                pending_shared_encodes: VecDeque::new(),
                color_transform_pipeline: None,
                bitstream,
                width,
                height,
                fps,
                frame_index: 0,
                force_next_keyframe: false,
                color_mode: ColorMode::Full,
            })
        }

        pub fn probe_h264_available() -> Result<(), PipelineError> {
            let _ = Self::new_max_speed_with_bitrate(1280, 720, 60, 20_000_000)?;
            Ok(())
        }

        pub fn request_keyframe(&mut self) {
            self.force_next_keyframe = true;
        }

        fn encode_shared_bgra(
            &mut self,
            frame: &CapturedFrame,
            shared: &D3D11SharedBgraFrame,
        ) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
            if shared.width as usize != self.width || shared.height as usize != self.height {
                return Err(PipelineError::message(format!(
                    "shared texture size mismatch: expected {}x{}, got {}x{}",
                    self.width, self.height, shared.width, shared.height
                )));
            }
            let source = self.ensure_shared_input(shared)?;
            self.ensure_shared_encode_slots()?;

            let mut output = Vec::new();
            if self.shared_encode_slots.is_empty() {
                if let Some(access_unit) = self.complete_oldest_shared_encode()? {
                    output.push(access_unit);
                }
            }

            let mut slot = self
                .shared_encode_slots
                .pop()
                .ok_or_else(|| PipelineError::message("missing shared NVENC encode slot"))?;
            self.copy_or_transform_shared_bgra_to_texture(&source, &slot)?;

            let force_idr =
                h264_should_force_keyframe(self.frame_index, self.fps, self.force_next_keyframe);
            submit_encode_picture(
                &mut self.encoder,
                &slot.bitstream,
                &mut slot.registered,
                self.frame_index,
                force_idr,
                NVencBufferFormat::ARGB,
            )
            .map_err(|error| PipelineError::message(error.to_string()))?;
            self.force_next_keyframe = false;
            self.frame_index += 1;
            self.pending_shared_encodes.push_back(PendingSharedEncode {
                slot,
                timestamp_us: frame.timestamp_us,
                is_keyframe: force_idr,
            });

            if self.pending_shared_encodes.len() >= H264_SHARED_ASYNC_SLOT_COUNT {
                if let Some(access_unit) = self.complete_oldest_shared_encode()? {
                    output.push(access_unit);
                }
            }

            Ok(output)
        }

        fn ensure_shared_encode_slots(&mut self) -> Result<(), PipelineError> {
            while self.shared_encode_slots.len() + self.pending_shared_encodes.len()
                < H264_SHARED_ASYNC_SLOT_COUNT
            {
                let texture =
                    create_encode_texture(&self._device, self.width as u32, self.height as u32)
                        .map_err(|error| {
                            PipelineError::message(format!(
                                "create shared NVENC slot texture failed: {error}"
                            ))
                        })?;
                let registered = self
                    .encoder
                    .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                    .map_err(|error| {
                        PipelineError::message(format!(
                            "nvenc register shared slot resource failed: {error:?}"
                        ))
                    })?;
                let bitstream = self.encoder.create_bitstream_buffer().map_err(|error| {
                    PipelineError::message(format!(
                        "nvenc shared slot bitstream buffer failed: {error:?}"
                    ))
                })?;
                let render_target_view = if self.color_mode == ColorMode::Full {
                    None
                } else {
                    Some(
                        create_render_target_view(&self._device, &texture).map_err(|error| {
                            PipelineError::message(format!(
                                "create shared NVENC slot RTV failed: {error}"
                            ))
                        })?,
                    )
                };
                self.shared_encode_slots.push(SharedEncodeSlot {
                    texture,
                    render_target_view,
                    registered,
                    bitstream,
                });
            }

            Ok(())
        }

        fn complete_oldest_shared_encode(
            &mut self,
        ) -> Result<Option<EncodedAccessUnit>, PipelineError> {
            let Some(mut pending) = self.pending_shared_encodes.pop_front() else {
                return Ok(None);
            };
            pending.slot.registered.unmap().map_err(|error| {
                PipelineError::message(format!("NVENC unmap input failed: {error:?}"))
            })?;
            let bytes = lock_bitstream_bytes(&pending.slot.bitstream)
                .map_err(|error| PipelineError::message(error.to_string()))?;
            let access_unit = EncodedAccessUnit {
                codec: VideoCodec::H264,
                timestamp_us: pending.timestamp_us,
                is_keyframe: pending.is_keyframe,
                bytes: normalize_annexb_au(bytes),
            };
            self.shared_encode_slots.push(pending.slot);
            Ok(Some(access_unit))
        }

        fn drain_pending_shared_encodes_for_shutdown(&mut self) {
            while !self.pending_shared_encodes.is_empty() {
                if self.complete_oldest_shared_encode().is_err() {
                    break;
                }
            }
        }

        fn unmap_registered_resources_for_shutdown(&mut self) {
            let _ = self.registered.unmap();
            for slot in &mut self.shared_encode_slots {
                let _ = slot.registered.unmap();
            }
        }

        fn copy_or_transform_shared_bgra_to_texture(
            &mut self,
            source: &SharedInputBinding,
            slot: &SharedEncodeSlot,
        ) -> Result<(), PipelineError> {
            if self.color_mode == ColorMode::Full {
                return self.copy_shared_bgra_to_texture(&source.texture, &slot.texture);
            }

            let source_srv = source.shader_resource_view.as_ref().ok_or_else(|| {
                PipelineError::message("missing shared BGRA shader resource view for color mode")
            })?;
            let target_rtv = slot.render_target_view.as_ref().ok_or_else(|| {
                PipelineError::message("missing NVENC render target view for color mode")
            })?;
            self.transform_shared_bgra_to_texture(source_srv, target_rtv)
        }

        fn copy_shared_bgra_to_texture(
            &self,
            source_texture: &ID3D11Texture2D,
            target_texture: &ID3D11Texture2D,
        ) -> Result<(), PipelineError> {
            let source_resource: ID3D11Resource = source_texture.cast().map_err(|error| {
                PipelineError::message(format!(
                    "cast shared texture to NVENC copy source failed: {error}"
                ))
            })?;
            let target_resource: ID3D11Resource = target_texture.cast().map_err(|error| {
                PipelineError::message(format!(
                    "cast registered NVENC texture to copy target failed: {error}"
                ))
            })?;

            unsafe {
                self.context
                    .CopyResource(&target_resource, &source_resource);
            }

            Ok(())
        }

        fn transform_shared_bgra_to_texture(
            &mut self,
            source_srv: &ID3D11ShaderResourceView,
            target_rtv: &ID3D11RenderTargetView,
        ) -> Result<(), PipelineError> {
            let context = self.context.clone();
            let width = self.width as u32;
            let height = self.height as u32;
            let color_mode = self.color_mode;
            let pipeline = self.ensure_color_transform_pipeline()?;
            draw_color_transform(
                &context, width, height, color_mode, pipeline, source_srv, target_rtv,
            )
        }

        fn ensure_color_transform_pipeline(
            &mut self,
        ) -> Result<&ColorTransformPipeline, PipelineError> {
            if self.color_transform_pipeline.is_none() {
                self.color_transform_pipeline = Some(
                    create_color_transform_pipeline(&self._device).map_err(|error| {
                        PipelineError::message(format!(
                            "create NVENC color transform pipeline failed: {error}"
                        ))
                    })?,
                );
            }
            Ok(self.color_transform_pipeline.as_ref().unwrap())
        }

        fn ensure_shared_input(
            &mut self,
            shared: &D3D11SharedBgraFrame,
        ) -> Result<SharedInputBinding, PipelineError> {
            if let Some(input) = self.shared_inputs.iter().find(|input| {
                input.shared_handle == shared.shared_handle
                    && input.width == shared.width
                    && input.height == shared.height
            }) {
                return Ok(SharedInputBinding {
                    texture: input._texture.clone(),
                    shader_resource_view: input.shader_resource_view.clone(),
                });
            }

            if shared.shared_handle == 0 {
                return Err(PipelineError::message("shared texture handle is zero"));
            }

            let mut texture = None::<ID3D11Texture2D>;
            unsafe {
                self._device.OpenSharedResource(
                    HANDLE(shared.shared_handle as *mut core::ffi::c_void),
                    &mut texture,
                )
            }
            .map_err(|error| {
                PipelineError::message(format!(
                    "open shared D3D11 texture for NVENC failed: {error}"
                ))
            })?;
            let texture =
                texture.ok_or_else(|| PipelineError::message("missing opened shared texture"))?;

            if self.shared_inputs.len() >= SHARED_INPUT_CACHE_LIMIT {
                self.shared_inputs.remove(0);
            }
            let shader_resource_view = if self.color_mode == ColorMode::Full {
                None
            } else {
                Some(
                    create_shader_resource_view(&self._device, &texture).map_err(|error| {
                        PipelineError::message(format!(
                            "create shared BGRA input SRV failed: {error}"
                        ))
                    })?,
                )
            };

            self.shared_inputs.push(SharedInputResource {
                shared_handle: shared.shared_handle,
                width: shared.width,
                height: shared.height,
                _texture: texture,
                shader_resource_view,
            });

            let input = self
                .shared_inputs
                .last()
                .expect("shared input resource was just inserted");
            Ok(SharedInputBinding {
                texture: input._texture.clone(),
                shader_resource_view: input.shader_resource_view.clone(),
            })
        }
    }

    impl NvencHevcEncoder {
        pub fn default_color_mode() -> ColorMode {
            ColorMode::Full
        }

        pub fn color_mode(&self) -> ColorMode {
            self.color_mode
        }

        pub fn with_color_mode(mut self, color_mode: ColorMode) -> Self {
            self.color_mode = color_mode;
            self.color_transform_pipeline = None;
            self.shared_inputs.clear();
            self.shared_encode_slots.clear();
            self.pending_shared_encodes.clear();
            self
        }

        pub fn preferred_input_memory_kind_for_color_mode(_mode: ColorMode) -> FrameMemoryKind {
            FrameMemoryKind::D3D11SharedBgra
        }

        pub fn preferred_input_memory_kind() -> FrameMemoryKind {
            FrameMemoryKind::D3D11SharedBgra
        }

        pub fn preferred_main10_input_memory_kind() -> FrameMemoryKind {
            FrameMemoryKind::D3D11SharedBgra
        }

        pub fn new(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
            Self::new_main(width, height, fps)
        }

        pub fn new_main(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
            Self::new_low_latency_internal(
                width,
                height,
                fps,
                8_000_000,
                NV_ENC_HEVC_PROFILE_MAIN_GUID,
            )
        }

        pub fn new_main10(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
            Self::new_low_latency_internal(
                width,
                height,
                fps,
                8_000_000,
                NV_ENC_HEVC_PROFILE_MAIN10_GUID,
            )
        }

        pub fn new_main_with_bitrate(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_low_latency_internal(
                width,
                height,
                fps,
                bitrate.max(1),
                NV_ENC_HEVC_PROFILE_MAIN_GUID,
            )
        }

        pub fn new_max_speed_with_bitrate(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_preset_internal(
                width,
                height,
                fps,
                bitrate.max(1),
                NV_ENC_HEVC_PROFILE_MAIN_GUID,
                NV_ENC_PRESET_P1_GUID,
                true,
            )
        }

        pub fn new_main10_with_bitrate(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
        ) -> Result<Self, PipelineError> {
            Self::new_low_latency_internal(
                width,
                height,
                fps,
                bitrate.max(1),
                NV_ENC_HEVC_PROFILE_MAIN10_GUID,
            )
        }

        pub fn probe_hevc_available() -> Result<(), PipelineError> {
            let _ = Self::new_max_speed_with_bitrate(1280, 720, 60, 20_000_000)?;
            Ok(())
        }

        pub fn probe_hevc_main10_available() -> Result<(), PipelineError> {
            let mut encoder = Self::new_main10_with_bitrate(1280, 720, 60, 20_000_000)?;
            let frame = CapturedFrame::from_cpu(
                1280,
                720,
                FramePixelFormat::Bgra32,
                0,
                vec![0x80; 1280 * 720 * 4],
            );
            let access_units = encoder.encode(&frame)?;
            if access_units
                .iter()
                .any(|unit| hevc_sps_luma_bit_depth(&unit.bytes) == Some(10))
            {
                return Ok(());
            }
            Err(PipelineError::message(
                "NVENC HEVC Main10 probe did not produce a 10-bit HEVC bitstream",
            ))
        }

        fn new_low_latency_internal(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
            profile_guid: Guid,
        ) -> Result<Self, PipelineError> {
            Self::new_preset_internal(
                width,
                height,
                fps,
                bitrate,
                profile_guid,
                NV_ENC_PRESET_P3_GUID,
                false,
            )
        }

        fn new_preset_internal(
            width: usize,
            height: usize,
            fps: u32,
            bitrate: u32,
            profile_guid: Guid,
            preset_guid: Guid,
            ultra_low_latency: bool,
        ) -> Result<Self, PipelineError> {
            let width = width.max(2);
            let height = height.max(2);
            let fps = fps.max(1);
            let bitrate = bitrate.max(1);
            let (device, context) = create_d3d11_device().map_err(|error| {
                PipelineError::message(format!("create d3d11 device failed: {error}"))
            })?;

            let session: Session<NeedsConfig> = Session::open_dx(&device).map_err(|error| {
                PipelineError::message(format!("nvenc open_dx failed: {error:?}"))
            })?;
            ensure_hevc_codec_supported(&session)?;
            ensure_hevc_preset_supported(&session, preset_guid.clone())?;
            let (session, mut preset) = session
                .get_encode_preset_config_ex(
                    NV_ENC_CODEC_HEVC_GUID,
                    preset_guid.clone(),
                    hevc_tuning_info(ultra_low_latency),
                )
                .map_err(|error| {
                    PipelineError::message(format!("nvenc HEVC preset config failed: {error:?}"))
                })?;
            let main10 = profile_guid == NV_ENC_HEVC_PROFILE_MAIN10_GUID;
            preset.preset_cfg.profile_guid = profile_guid;
            preset.preset_cfg.rc_params.average_bit_rate = bitrate;
            preset.preset_cfg.frame_interval_p = 1;
            preset.preset_cfg.gop_len = hevc_remote_desktop_keyframe_interval(fps) as u32;
            let texture_format = DXGI_FORMAT_B8G8R8A8_UNORM;
            if main10 {
                preset.preset_cfg.set_hevc_main10_8bit_input_bit_depths();
            }

            let init = InitParams {
                encode_guid: NV_ENC_CODEC_HEVC_GUID,
                preset_guid,
                resolution: [width as u32, height as u32],
                aspect_ratio: [width as u32, height as u32],
                frame_rate: [fps, 1],
                tuning_info: hevc_tuning_info(ultra_low_latency),
                buffer_format: NVencBufferFormat::ARGB,
                encode_config: &mut preset.preset_cfg,
                enable_ptd: true,
                max_encoder_resolution: [width as u32, height as u32],
            };
            let encoder = session.init_encoder(init).map_err(|error| {
                PipelineError::message(format!("nvenc HEVC init encoder failed: {error:?}"))
            })?;
            let texture = create_encode_texture_with_format(
                &device,
                width as u32,
                height as u32,
                texture_format,
            )
            .map_err(|error| {
                PipelineError::message(format!("create nvenc HEVC texture failed: {error}"))
            })?;
            let registered = encoder
                .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                .map_err(|error| {
                    PipelineError::message(format!(
                        "nvenc HEVC register resource failed: {error:?}"
                    ))
                })?;
            let bitstream = encoder.create_bitstream_buffer().map_err(|error| {
                PipelineError::message(format!("nvenc HEVC bitstream buffer failed: {error:?}"))
            })?;

            Ok(Self {
                _device: device,
                context,
                texture,
                encoder,
                registered,
                shared_inputs: Vec::new(),
                shared_encode_slots: Vec::new(),
                pending_shared_encodes: VecDeque::new(),
                color_transform_pipeline: None,
                bitstream,
                width,
                height,
                fps,
                frame_index: 0,
                main10,
                color_mode: ColorMode::Full,
            })
        }

        fn encode_shared_bgra(
            &mut self,
            frame: &CapturedFrame,
            shared: &D3D11SharedBgraFrame,
        ) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
            if shared.width as usize != self.width || shared.height as usize != self.height {
                return Err(PipelineError::message(format!(
                    "shared texture size mismatch: expected {}x{}, got {}x{}",
                    self.width, self.height, shared.width, shared.height
                )));
            }
            let source = self.ensure_shared_input(shared)?;
            self.ensure_shared_encode_slots()?;

            let mut output = Vec::new();
            if self.shared_encode_slots.is_empty() {
                if let Some(access_unit) = self.complete_oldest_shared_encode()? {
                    output.push(access_unit);
                }
            }

            let mut slot = self
                .shared_encode_slots
                .pop()
                .ok_or_else(|| PipelineError::message("missing shared NVENC HEVC encode slot"))?;
            self.copy_or_transform_shared_bgra_to_texture(&source, &slot)?;

            let keyframe_interval = hevc_remote_desktop_keyframe_interval(self.fps);
            let force_idr =
                self.frame_index == 0 || self.frame_index.is_multiple_of(keyframe_interval);
            submit_encode_picture(
                &mut self.encoder,
                &slot.bitstream,
                &mut slot.registered,
                self.frame_index,
                force_idr,
                NVencBufferFormat::ARGB,
            )
            .map_err(|error| PipelineError::message(error.to_string()))?;
            self.frame_index += 1;
            self.pending_shared_encodes.push_back(PendingSharedEncode {
                slot,
                timestamp_us: frame.timestamp_us,
                is_keyframe: force_idr,
            });

            if self.pending_shared_encodes.len() >= HEVC_SHARED_ASYNC_SLOT_COUNT {
                if let Some(access_unit) = self.complete_oldest_shared_encode()? {
                    output.push(access_unit);
                }
            }

            Ok(output)
        }

        fn ensure_shared_encode_slots(&mut self) -> Result<(), PipelineError> {
            while self.shared_encode_slots.len() + self.pending_shared_encodes.len()
                < HEVC_SHARED_ASYNC_SLOT_COUNT
            {
                let texture =
                    create_encode_texture(&self._device, self.width as u32, self.height as u32)
                        .map_err(|error| {
                            PipelineError::message(format!(
                                "create shared NVENC HEVC slot texture failed: {error}"
                            ))
                        })?;
                let registered = self
                    .encoder
                    .register_resource_dx11(&texture, NVencBufferFormat::ARGB, 0)
                    .map_err(|error| {
                        PipelineError::message(format!(
                            "nvenc HEVC register shared slot resource failed: {error:?}"
                        ))
                    })?;
                let bitstream = self.encoder.create_bitstream_buffer().map_err(|error| {
                    PipelineError::message(format!(
                        "nvenc HEVC shared slot bitstream buffer failed: {error:?}"
                    ))
                })?;
                let render_target_view = if self.color_mode == ColorMode::Full {
                    None
                } else {
                    Some(
                        create_render_target_view(&self._device, &texture).map_err(|error| {
                            PipelineError::message(format!(
                                "create shared NVENC HEVC slot RTV failed: {error}"
                            ))
                        })?,
                    )
                };
                self.shared_encode_slots.push(SharedEncodeSlot {
                    texture,
                    render_target_view,
                    registered,
                    bitstream,
                });
            }

            Ok(())
        }

        fn complete_oldest_shared_encode(
            &mut self,
        ) -> Result<Option<EncodedAccessUnit>, PipelineError> {
            let Some(mut pending) = self.pending_shared_encodes.pop_front() else {
                return Ok(None);
            };
            pending.slot.registered.unmap().map_err(|error| {
                PipelineError::message(format!("NVENC unmap input failed: {error:?}"))
            })?;
            let bytes = lock_bitstream_bytes(&pending.slot.bitstream)
                .map_err(|error| PipelineError::message(error.to_string()))?;
            if self.main10 {
                validate_hevc_main10_bitstream(&bytes)?;
            }
            let access_unit = EncodedAccessUnit {
                codec: VideoCodec::Hevc,
                timestamp_us: pending.timestamp_us,
                is_keyframe: pending.is_keyframe,
                bytes: normalize_annexb_au(bytes),
            };
            self.shared_encode_slots.push(pending.slot);
            Ok(Some(access_unit))
        }

        fn drain_pending_shared_encodes_for_shutdown(&mut self) {
            while !self.pending_shared_encodes.is_empty() {
                if self.complete_oldest_shared_encode().is_err() {
                    break;
                }
            }
        }

        fn unmap_registered_resources_for_shutdown(&mut self) {
            let _ = self.registered.unmap();
            for slot in &mut self.shared_encode_slots {
                let _ = slot.registered.unmap();
            }
        }

        fn copy_or_transform_shared_bgra_to_texture(
            &mut self,
            source: &SharedInputBinding,
            slot: &SharedEncodeSlot,
        ) -> Result<(), PipelineError> {
            if self.color_mode == ColorMode::Full {
                return self.copy_shared_bgra_to_texture(&source.texture, &slot.texture);
            }

            let source_srv = source.shader_resource_view.as_ref().ok_or_else(|| {
                PipelineError::message(
                    "missing shared BGRA shader resource view for HEVC color mode",
                )
            })?;
            let target_rtv = slot.render_target_view.as_ref().ok_or_else(|| {
                PipelineError::message("missing NVENC HEVC render target view for color mode")
            })?;
            self.transform_shared_bgra_to_texture(source_srv, target_rtv)
        }

        fn copy_shared_bgra_to_texture(
            &self,
            source_texture: &ID3D11Texture2D,
            target_texture: &ID3D11Texture2D,
        ) -> Result<(), PipelineError> {
            let source_resource: ID3D11Resource = source_texture.cast().map_err(|error| {
                PipelineError::message(format!(
                    "cast shared texture to NVENC HEVC copy source failed: {error}"
                ))
            })?;
            let target_resource: ID3D11Resource = target_texture.cast().map_err(|error| {
                PipelineError::message(format!(
                    "cast registered NVENC HEVC texture to copy target failed: {error}"
                ))
            })?;

            unsafe {
                self.context
                    .CopyResource(&target_resource, &source_resource);
            }

            Ok(())
        }

        fn transform_shared_bgra_to_texture(
            &mut self,
            source_srv: &ID3D11ShaderResourceView,
            target_rtv: &ID3D11RenderTargetView,
        ) -> Result<(), PipelineError> {
            let context = self.context.clone();
            let width = self.width as u32;
            let height = self.height as u32;
            let color_mode = self.color_mode;
            let pipeline = self.ensure_color_transform_pipeline()?;
            draw_color_transform(
                &context, width, height, color_mode, pipeline, source_srv, target_rtv,
            )
        }

        fn ensure_color_transform_pipeline(
            &mut self,
        ) -> Result<&ColorTransformPipeline, PipelineError> {
            if self.color_transform_pipeline.is_none() {
                self.color_transform_pipeline = Some(
                    create_color_transform_pipeline(&self._device).map_err(|error| {
                        PipelineError::message(format!(
                            "create NVENC HEVC color transform pipeline failed: {error}"
                        ))
                    })?,
                );
            }
            Ok(self.color_transform_pipeline.as_ref().unwrap())
        }

        fn ensure_shared_input(
            &mut self,
            shared: &D3D11SharedBgraFrame,
        ) -> Result<SharedInputBinding, PipelineError> {
            if let Some(input) = self.shared_inputs.iter().find(|input| {
                input.shared_handle == shared.shared_handle
                    && input.width == shared.width
                    && input.height == shared.height
            }) {
                return Ok(SharedInputBinding {
                    texture: input._texture.clone(),
                    shader_resource_view: input.shader_resource_view.clone(),
                });
            }

            if shared.shared_handle == 0 {
                return Err(PipelineError::message("shared texture handle is zero"));
            }

            let mut texture = None::<ID3D11Texture2D>;
            unsafe {
                self._device.OpenSharedResource(
                    HANDLE(shared.shared_handle as *mut core::ffi::c_void),
                    &mut texture,
                )
            }
            .map_err(|error| {
                PipelineError::message(format!(
                    "open shared D3D11 texture for NVENC HEVC failed: {error}"
                ))
            })?;
            let texture =
                texture.ok_or_else(|| PipelineError::message("missing opened shared texture"))?;

            if self.shared_inputs.len() >= SHARED_INPUT_CACHE_LIMIT {
                self.shared_inputs.remove(0);
            }
            let shader_resource_view = if self.color_mode == ColorMode::Full {
                None
            } else {
                Some(
                    create_shader_resource_view(&self._device, &texture).map_err(|error| {
                        PipelineError::message(format!(
                            "create shared BGRA HEVC input SRV failed: {error}"
                        ))
                    })?,
                )
            };

            self.shared_inputs.push(SharedInputResource {
                shared_handle: shared.shared_handle,
                width: shared.width,
                height: shared.height,
                _texture: texture,
                shader_resource_view,
            });

            let input = self
                .shared_inputs
                .last()
                .expect("shared HEVC input resource was just inserted");
            Ok(SharedInputBinding {
                texture: input._texture.clone(),
                shader_resource_view: input.shader_resource_view.clone(),
            })
        }
    }

    impl VideoEncoder for NvencH264Encoder {
        fn input_memory_kind(&self) -> FrameMemoryKind {
            FrameMemoryKind::D3D11SharedBgra
        }

        fn request_keyframe(&mut self) {
            NvencH264Encoder::request_keyframe(self);
        }

        fn encode(
            &mut self,
            frame: &CapturedFrame,
        ) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
            if frame.width != self.width || frame.height != self.height {
                return Err(PipelineError::message(format!(
                    "frame size mismatch: expected {}x{}, got {}x{}",
                    self.width, self.height, frame.width, frame.height
                )));
            }
            if let Some(shared) = frame.d3d11_shared_bgra() {
                return self.encode_shared_bgra(frame, shared);
            }
            if self.color_mode != ColorMode::Full {
                return Err(PipelineError::message(format!(
                    "NVENC H.264 color_mode={} requires D3D11 shared BGRA input",
                    self.color_mode.as_str()
                )));
            }

            let bgra = to_bgra(frame)?;
            let row_pitch = self
                .width
                .checked_mul(4)
                .ok_or_else(|| PipelineError::message("row pitch overflow"))?
                as u32;

            unsafe {
                self.context.UpdateSubresource(
                    &self.texture,
                    0,
                    None,
                    bgra.as_ptr() as *const core::ffi::c_void,
                    row_pitch,
                    0,
                );
            }

            let force_idr =
                h264_should_force_keyframe(self.frame_index, self.fps, self.force_next_keyframe);
            let bytes = encode_picture_with_sps_pps(
                &mut self.encoder,
                &self.bitstream,
                &mut self.registered,
                self.frame_index,
                force_idr,
                NVencBufferFormat::ARGB,
            )
            .map_err(|error| PipelineError::message(error.to_string()))?;
            self.force_next_keyframe = false;
            self.frame_index += 1;

            Ok(vec![EncodedAccessUnit {
                codec: VideoCodec::H264,
                timestamp_us: frame.timestamp_us,
                is_keyframe: force_idr,
                bytes: normalize_annexb_au(bytes),
            }])
        }
    }

    impl VideoEncoder for NvencHevcEncoder {
        fn input_memory_kind(&self) -> FrameMemoryKind {
            if self.main10 {
                Self::preferred_main10_input_memory_kind()
            } else {
                Self::preferred_input_memory_kind()
            }
        }

        fn encode(
            &mut self,
            frame: &CapturedFrame,
        ) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
            if frame.width != self.width || frame.height != self.height {
                return Err(PipelineError::message(format!(
                    "frame size mismatch: expected {}x{}, got {}x{}",
                    self.width, self.height, frame.width, frame.height
                )));
            }
            if let Some(shared) = frame.d3d11_shared_bgra() {
                return self.encode_shared_bgra(frame, shared);
            }
            if self.color_mode != ColorMode::Full {
                return Err(PipelineError::message(format!(
                    "NVENC HEVC color_mode={} requires D3D11 shared BGRA input",
                    self.color_mode.as_str()
                )));
            }

            let upload = to_bgra(frame)?;
            let (upload_data, row_pitch) = (upload.as_slice(), (self.width * 4) as u32);

            unsafe {
                self.context.UpdateSubresource(
                    &self.texture,
                    0,
                    None,
                    upload_data.as_ptr() as *const core::ffi::c_void,
                    row_pitch,
                    0,
                );
            }

            let keyframe_interval = hevc_remote_desktop_keyframe_interval(self.fps);
            let force_idr =
                self.frame_index == 0 || self.frame_index.is_multiple_of(keyframe_interval);
            let bytes = encode_picture_with_sps_pps(
                &mut self.encoder,
                &self.bitstream,
                &mut self.registered,
                self.frame_index,
                force_idr,
                NVencBufferFormat::ARGB,
            )
            .map_err(|error| PipelineError::message(error.to_string()))?;
            if self.main10 {
                validate_hevc_main10_bitstream(&bytes)?;
            }
            self.frame_index += 1;

            Ok(vec![EncodedAccessUnit {
                codec: VideoCodec::Hevc,
                timestamp_us: frame.timestamp_us,
                is_keyframe: force_idr,
                bytes: normalize_annexb_au(bytes),
            }])
        }
    }

    impl Drop for NvencH264Encoder {
        fn drop(&mut self) {
            // The shared path has asynchronous NVENC submissions.  Do not
            // unregister their D3D11 textures while a bitstream is still in
            // flight: flush D3D work, wait for every pending slot through the
            // NVENC lock, then close the encode stream before field teardown.
            unsafe { self.context.Flush() };
            self.drain_pending_shared_encodes_for_shutdown();
            self.unmap_registered_resources_for_shutdown();
            let _ = self.encoder.end_encode();
        }
    }

    impl Drop for NvencHevcEncoder {
        fn drop(&mut self) {
            unsafe { self.context.Flush() };
            self.drain_pending_shared_encodes_for_shutdown();
            self.unmap_registered_resources_for_shutdown();
            let _ = self.encoder.end_encode();
        }
    }

    fn ensure_hevc_codec_supported(session: &Session<NeedsConfig>) -> Result<(), PipelineError> {
        let codecs = session.get_encode_codecs().map_err(|error| {
            PipelineError::message(format!("NVENC codec capability query failed: {error:?}"))
        })?;

        if codecs.iter().any(|codec| codec == &NV_ENC_CODEC_HEVC_GUID) {
            return Ok(());
        }

        Err(PipelineError::message(
            "NVENC HEVC unavailable: current GPU/driver does not expose HEVC encode support",
        ))
    }

    fn ensure_hevc_preset_supported(
        session: &Session<NeedsConfig>,
        preset_guid: Guid,
    ) -> Result<(), PipelineError> {
        let presets = session
            .get_encode_presets(NV_ENC_CODEC_HEVC_GUID)
            .map_err(|error| {
                PipelineError::message(format!("NVENC HEVC preset query failed: {error:?}"))
            })?;

        if presets.iter().any(|preset| preset == &preset_guid) {
            return Ok(());
        }

        Err(PipelineError::message(
            "NVENC HEVC unavailable: required HEVC preset is not supported by this GPU/driver",
        ))
    }

    fn hevc_tuning_info(ultra_low_latency: bool) -> NVencTuningInfo {
        if ultra_low_latency {
            NVencTuningInfo::UltraLowLatency
        } else {
            NVencTuningInfo::LowLatency
        }
    }

    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod tests {
        use super::*;

        #[test]
        fn hevc_shared_encode_queue_has_tail_latency_headroom() {
            const {
                assert!(HEVC_SHARED_ASYNC_SLOT_COUNT >= 3);
                assert!(HEVC_SHARED_ASYNC_SLOT_COUNT <= 4);
            }
        }

        #[test]
        fn hevc_remote_desktop_keyframe_interval_caps_high_refresh_recovery() {
            assert_eq!(hevc_remote_desktop_keyframe_interval(30), 30);
            assert_eq!(hevc_remote_desktop_keyframe_interval(60), 60);
            assert_eq!(hevc_remote_desktop_keyframe_interval(144), 60);
            assert_eq!(hevc_remote_desktop_keyframe_interval(249), 60);
        }

        #[test]
        fn h264_remote_desktop_keyframe_interval_caps_browser_recovery() {
            assert_eq!(h264_remote_desktop_keyframe_interval(30), 30);
            assert_eq!(h264_remote_desktop_keyframe_interval(60), 30);
            assert_eq!(h264_remote_desktop_keyframe_interval(120), 30);
            assert_eq!(h264_remote_desktop_keyframe_interval(249), 30);
        }

        #[test]
        fn h264_requested_keyframe_overrides_interval() {
            assert!(!h264_should_force_keyframe(7, 120, false));
            assert!(h264_should_force_keyframe(7, 120, true));
            assert!(h264_should_force_keyframe(30, 120, false));
        }
    }

    fn compile_shader(source: &str, target: &'static core::ffi::CStr) -> anyhow::Result<Vec<u8>> {
        use windows::core::PCSTR;
        use windows::Win32::Graphics::Direct3D::{Fxc::D3DCompile, ID3DBlob, ID3DInclude};

        let mut code = None::<ID3DBlob>;
        let mut errors = None::<ID3DBlob>;
        let result = unsafe {
            D3DCompile(
                source.as_ptr() as *const core::ffi::c_void,
                source.len(),
                PCSTR::null(),
                None,
                None::<&ID3DInclude>,
                PCSTR(c"main".as_ptr().cast()),
                PCSTR(target.as_ptr().cast()),
                0,
                0,
                &mut code,
                Some(&mut errors),
            )
        };

        if let Err(error) = result {
            let details = errors
                .as_ref()
                .map(|blob| unsafe {
                    let bytes = core::slice::from_raw_parts(
                        blob.GetBufferPointer() as *const u8,
                        blob.GetBufferSize(),
                    );
                    String::from_utf8_lossy(bytes).trim().to_string()
                })
                .filter(|message| !message.is_empty())
                .unwrap_or_else(|| error.to_string());
            return Err(anyhow!(
                "compile NVENC color transform shader failed: {details}"
            ));
        }

        let code = code.ok_or_else(|| anyhow!("missing NVENC color transform shader bytecode"))?;
        let bytes = unsafe {
            core::slice::from_raw_parts(code.GetBufferPointer() as *const u8, code.GetBufferSize())
        };
        Ok(bytes.to_vec())
    }

    fn create_color_transform_pipeline(
        device: &ID3D11Device,
    ) -> anyhow::Result<ColorTransformPipeline> {
        let vertex_code = compile_shader(COLOR_TRANSFORM_VERTEX_SHADER, c"vs_5_0")?;
        let grayscale_pixel_code =
            compile_shader(COLOR_TRANSFORM_GRAYSCALE_PIXEL_SHADER, c"ps_5_0")?;
        let monochrome_pixel_code =
            compile_shader(COLOR_TRANSFORM_MONOCHROME_PIXEL_SHADER, c"ps_5_0")?;
        let low_chroma_pixel_code =
            compile_shader(COLOR_TRANSFORM_LOW_CHROMA_PIXEL_SHADER, c"ps_5_0")?;

        let mut vertex_shader = None::<ID3D11VertexShader>;
        let mut grayscale_pixel_shader = None::<ID3D11PixelShader>;
        let mut monochrome_pixel_shader = None::<ID3D11PixelShader>;
        let mut low_chroma_pixel_shader = None::<ID3D11PixelShader>;
        unsafe {
            device
                .CreateVertexShader(
                    &vertex_code,
                    None::<&ID3D11ClassLinkage>,
                    Some(&mut vertex_shader),
                )
                .context("create NVENC color transform vertex shader failed")?;
            device
                .CreatePixelShader(
                    &grayscale_pixel_code,
                    None::<&ID3D11ClassLinkage>,
                    Some(&mut grayscale_pixel_shader),
                )
                .context("create NVENC grayscale pixel shader failed")?;
            device
                .CreatePixelShader(
                    &monochrome_pixel_code,
                    None::<&ID3D11ClassLinkage>,
                    Some(&mut monochrome_pixel_shader),
                )
                .context("create NVENC monochrome pixel shader failed")?;
            device
                .CreatePixelShader(
                    &low_chroma_pixel_code,
                    None::<&ID3D11ClassLinkage>,
                    Some(&mut low_chroma_pixel_shader),
                )
                .context("create NVENC low-chroma pixel shader failed")?;
        }

        let sampler_desc = D3D11_SAMPLER_DESC {
            Filter: D3D11_FILTER_MIN_MAG_MIP_LINEAR,
            AddressU: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressV: D3D11_TEXTURE_ADDRESS_CLAMP,
            AddressW: D3D11_TEXTURE_ADDRESS_CLAMP,
            MipLODBias: 0.0,
            MaxAnisotropy: 1,
            ComparisonFunc: D3D11_COMPARISON_NEVER,
            BorderColor: [0.0, 0.0, 0.0, 0.0],
            MinLOD: 0.0,
            MaxLOD: f32::MAX,
        };
        let mut sampler = None::<ID3D11SamplerState>;
        unsafe {
            device
                .CreateSamplerState(&sampler_desc, Some(&mut sampler))
                .context("create NVENC color transform sampler failed")?;
        }

        Ok(ColorTransformPipeline {
            vertex_shader: vertex_shader.ok_or_else(|| anyhow!("missing vertex shader"))?,
            grayscale_pixel_shader: grayscale_pixel_shader
                .ok_or_else(|| anyhow!("missing grayscale pixel shader"))?,
            monochrome_pixel_shader: monochrome_pixel_shader
                .ok_or_else(|| anyhow!("missing monochrome pixel shader"))?,
            low_chroma_pixel_shader: low_chroma_pixel_shader
                .ok_or_else(|| anyhow!("missing low-chroma pixel shader"))?,
            sampler: sampler.ok_or_else(|| anyhow!("missing sampler"))?,
        })
    }

    fn create_shader_resource_view(
        device: &ID3D11Device,
        texture: &ID3D11Texture2D,
    ) -> anyhow::Result<ID3D11ShaderResourceView> {
        let resource: ID3D11Resource = texture.cast().context("cast texture to SRV resource")?;
        let mut view = None::<ID3D11ShaderResourceView>;
        unsafe {
            device
                .CreateShaderResourceView(&resource, None, Some(&mut view))
                .context("CreateShaderResourceView failed")?;
        }
        view.ok_or_else(|| anyhow!("CreateShaderResourceView returned none"))
    }

    fn create_render_target_view(
        device: &ID3D11Device,
        texture: &ID3D11Texture2D,
    ) -> anyhow::Result<ID3D11RenderTargetView> {
        let resource: ID3D11Resource = texture.cast().context("cast texture to RTV resource")?;
        let mut view = None::<ID3D11RenderTargetView>;
        unsafe {
            device
                .CreateRenderTargetView(&resource, None, Some(&mut view))
                .context("CreateRenderTargetView failed")?;
        }
        view.ok_or_else(|| anyhow!("CreateRenderTargetView returned none"))
    }

    fn draw_color_transform(
        context: &ID3D11DeviceContext,
        width: u32,
        height: u32,
        color_mode: ColorMode,
        pipeline: &ColorTransformPipeline,
        source_srv: &ID3D11ShaderResourceView,
        target_rtv: &ID3D11RenderTargetView,
    ) -> Result<(), PipelineError> {
        let pixel_shader = match color_mode {
            ColorMode::Full => {
                return Err(PipelineError::message(
                    "color transform draw called for full color mode",
                ))
            }
            ColorMode::Grayscale => pipeline.grayscale_pixel_shader.clone(),
            ColorMode::Monochrome => pipeline.monochrome_pixel_shader.clone(),
            ColorMode::LowChroma => pipeline.low_chroma_pixel_shader.clone(),
        };
        let vertex_shader = pipeline.vertex_shader.clone();
        let sampler = pipeline.sampler.clone();
        let viewport = D3D11_VIEWPORT {
            TopLeftX: 0.0,
            TopLeftY: 0.0,
            Width: width as f32,
            Height: height as f32,
            MinDepth: 0.0,
            MaxDepth: 1.0,
        };
        let srvs = [Some(source_srv.clone())];
        let empty_srvs: [Option<ID3D11ShaderResourceView>; 1] = [None];
        let samplers = [Some(sampler)];
        let empty_samplers: [Option<ID3D11SamplerState>; 1] = [None];

        unsafe {
            context.OMSetRenderTargets(Some(&[Some(target_rtv.clone())]), None);
            context.RSSetViewports(Some(&[viewport]));
            context.IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            context.VSSetShader(&vertex_shader, None);
            context.PSSetShader(&pixel_shader, None);
            context.PSSetSamplers(0, Some(&samplers));
            context.PSSetShaderResources(0, Some(&srvs));
            context.Draw(3, 0);
            context.PSSetShaderResources(0, Some(&empty_srvs));
            context.PSSetSamplers(0, Some(&empty_samplers));
            context.OMSetRenderTargets(Some(&[None]), None);
            context.Flush();
        }

        Ok(())
    }

    fn create_d3d11_device() -> anyhow::Result<(ID3D11Device, ID3D11DeviceContext)> {
        let mut device = None::<ID3D11Device>;
        let mut context = None::<ID3D11DeviceContext>;
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE(std::ptr::null_mut()),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .or_else(|_| unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE(std::ptr::null_mut()),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        })
        .context("D3D11CreateDevice failed")?;

        Ok((
            device.ok_or_else(|| anyhow!("missing d3d11 device"))?,
            context.ok_or_else(|| anyhow!("missing d3d11 context"))?,
        ))
    }

    fn create_encode_texture(
        device: &ID3D11Device,
        width: u32,
        height: u32,
    ) -> anyhow::Result<ID3D11Texture2D> {
        create_encode_texture_with_format(device, width, height, DXGI_FORMAT_B8G8R8A8_UNORM)
    }

    fn create_encode_texture_with_format(
        device: &ID3D11Device,
        width: u32,
        height: u32,
        format: DXGI_FORMAT,
    ) -> anyhow::Result<ID3D11Texture2D> {
        let mut texture = None;
        let bind_flags = if format == DXGI_FORMAT_P010 {
            D3D11_BIND_SHADER_RESOURCE.0
        } else {
            D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0
        };
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: bind_flags as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }
            .context("CreateTexture2D failed")?;
        texture.ok_or_else(|| anyhow!("CreateTexture2D returned none"))
    }

    fn encode_picture_with_sps_pps(
        encoder: &mut Encoder,
        bitstream: &BitStream,
        registered: &mut RegisteredResource,
        frame_index: usize,
        force_idr: bool,
        buffer_format: NVencBufferFormat,
    ) -> anyhow::Result<Vec<u8>> {
        submit_encode_picture(
            encoder,
            bitstream,
            registered,
            frame_index,
            force_idr,
            buffer_format,
        )?;
        registered
            .unmap()
            .map_err(|error| anyhow!("NVENC unmap input failed: {error:?}"))?;
        lock_bitstream_bytes(bitstream)
    }

    fn submit_encode_picture(
        encoder: &mut Encoder,
        bitstream: &BitStream,
        registered: &mut RegisteredResource,
        frame_index: usize,
        force_idr: bool,
        buffer_format: NVencBufferFormat,
    ) -> anyhow::Result<()> {
        registered
            .map()
            .map_err(|error| anyhow!("NVENC map input failed: {error:?}"))?;
        let flags = if force_idr {
            NVencPicFlags::ForceIDR as u32 | NVencPicFlags::OutputSpspps as u32
        } else {
            0
        };
        encoder
            .encode_picture_with_flags(
                registered,
                bitstream,
                frame_index,
                frame_index as u64,
                buffer_format,
                NVencPicStruct::Frame,
                if force_idr {
                    NVencPicType::IDR
                } else {
                    NVencPicType::P
                },
                flags,
                None,
            )
            .map_err(|error| anyhow!("NVENC encode_picture failed: {error:?}"))?;
        Ok(())
    }

    fn lock_bitstream_bytes(bitstream: &BitStream) -> anyhow::Result<Vec<u8>> {
        let lock = bitstream
            .try_lock(true)
            .map_err(|error| anyhow!("NVENC bitstream lock failed: {error:?}"))?;
        Ok(lock.as_slice().to_vec())
    }

    fn normalize_annexb_au(buf: Vec<u8>) -> Vec<u8> {
        if looks_like_annexb(&buf) {
            return buf;
        }
        if let Some(v) = avcc_to_annexb(&buf) {
            return v;
        }
        buf
    }

    fn validate_hevc_main10_bitstream(access_unit: &[u8]) -> Result<(), PipelineError> {
        match hevc_sps_luma_bit_depth(access_unit) {
            Some(10) => Ok(()),
            Some(bit_depth) => Err(PipelineError::message(format!(
                "NVENC HEVC Main10 produced a {bit_depth}-bit bitstream"
            ))),
            None => Ok(()),
        }
    }

    fn hevc_sps_luma_bit_depth(access_unit: &[u8]) -> Option<u8> {
        let mut offset = 0usize;
        while let Some((start, start_len)) = find_start_code(access_unit, offset) {
            let nal_start = start + start_len;
            let next = find_start_code(access_unit, nal_start)
                .map(|(next, _)| next)
                .unwrap_or(access_unit.len());
            let nal = access_unit.get(nal_start..next)?;
            if nal.len() >= 3 && ((nal[0] >> 1) & 0x3f) == 33 {
                return parse_hevc_sps_luma_bit_depth(&nal[2..]);
            }
            offset = nal_start.saturating_add(1);
        }
        None
    }

    fn find_start_code(buf: &[u8], from: usize) -> Option<(usize, usize)> {
        if from >= buf.len() {
            return None;
        }
        let mut i = from;
        while i + 3 <= buf.len() {
            if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
                return Some((i, 3));
            }
            if i + 4 <= buf.len()
                && buf[i] == 0
                && buf[i + 1] == 0
                && buf[i + 2] == 0
                && buf[i + 3] == 1
            {
                return Some((i, 4));
            }
            i += 1;
        }
        None
    }

    fn parse_hevc_sps_luma_bit_depth(bytes: &[u8]) -> Option<u8> {
        let rbsp = hevc_rbsp(bytes);
        let mut bits = BitReader::new(&rbsp);
        bits.read_bits(4)?;
        let max_sub_layers_minus1 = bits.read_bits(3)? as usize;
        bits.read_bit()?;
        skip_hevc_profile_tier_level(&mut bits, max_sub_layers_minus1)?;
        bits.read_ue()?;
        let chroma_format_idc = bits.read_ue()?;
        if chroma_format_idc == 3 {
            bits.read_bit()?;
        }
        bits.read_ue()?;
        bits.read_ue()?;
        if bits.read_bit()? != 0 {
            bits.read_ue()?;
            bits.read_ue()?;
            bits.read_ue()?;
            bits.read_ue()?;
        }
        Some(8 + bits.read_ue()? as u8)
    }

    fn skip_hevc_profile_tier_level(
        bits: &mut BitReader<'_>,
        max_sub_layers_minus1: usize,
    ) -> Option<()> {
        bits.read_bits(2)?;
        bits.read_bit()?;
        bits.read_bits(5)?;
        bits.read_bits(32)?;
        bits.read_bits(4)?;
        bits.read_bits(16)?;
        bits.read_bits(16)?;
        bits.read_bits(12)?;
        bits.read_bits(8)?;

        let mut profile_present = vec![false; max_sub_layers_minus1];
        let mut level_present = vec![false; max_sub_layers_minus1];
        for i in 0..max_sub_layers_minus1 {
            profile_present[i] = bits.read_bit()? != 0;
            level_present[i] = bits.read_bit()? != 0;
        }
        if max_sub_layers_minus1 > 0 {
            for _ in max_sub_layers_minus1..8 {
                bits.read_bits(2)?;
            }
        }
        for i in 0..max_sub_layers_minus1 {
            if profile_present[i] {
                bits.read_bits(2)?;
                bits.read_bit()?;
                bits.read_bits(5)?;
                bits.read_bits(32)?;
                bits.read_bits(4)?;
                bits.read_bits(16)?;
                bits.read_bits(16)?;
                bits.read_bits(12)?;
            }
            if level_present[i] {
                bits.read_bits(8)?;
            }
        }
        Some(())
    }

    fn hevc_rbsp(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut zeros = 0usize;
        for &byte in bytes {
            if zeros >= 2 && byte == 0x03 {
                zeros = 0;
                continue;
            }
            out.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        out
    }

    struct BitReader<'a> {
        bytes: &'a [u8],
        bit_offset: usize,
    }

    impl<'a> BitReader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self {
                bytes,
                bit_offset: 0,
            }
        }

        fn read_bit(&mut self) -> Option<u8> {
            let byte = *self.bytes.get(self.bit_offset / 8)?;
            let bit = (byte >> (7 - (self.bit_offset % 8))) & 1;
            self.bit_offset += 1;
            Some(bit)
        }

        fn read_bits(&mut self, count: usize) -> Option<u32> {
            let mut value = 0u32;
            for _ in 0..count {
                value = (value << 1) | self.read_bit()? as u32;
            }
            Some(value)
        }

        fn read_ue(&mut self) -> Option<u32> {
            let mut leading_zero_bits = 0u32;
            while self.read_bit()? == 0 {
                leading_zero_bits += 1;
                if leading_zero_bits > 31 {
                    return None;
                }
            }
            if leading_zero_bits == 0 {
                return Some(0);
            }
            let suffix = self.read_bits(leading_zero_bits as usize)?;
            Some((1u32 << leading_zero_bits) - 1 + suffix)
        }
    }

    fn looks_like_annexb(buf: &[u8]) -> bool {
        if buf.len() < 4 {
            return false;
        }
        (buf[0] == 0 && buf[1] == 0 && buf[2] == 1)
            || (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1)
    }

    fn avcc_to_annexb(buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 5 {
            return None;
        }
        let mut offset = 0usize;
        let mut out = Vec::with_capacity(buf.len() + 16);
        let mut nals = 0usize;
        while offset + 4 <= buf.len() {
            let nal_len = u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;
            offset += 4;
            if nal_len == 0 || offset + nal_len > buf.len() {
                return None;
            }
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(&buf[offset..offset + nal_len]);
            offset += nal_len;
            nals += 1;
        }
        if offset == buf.len() && nals > 0 {
            Some(out)
        } else {
            None
        }
    }

    fn to_bgra(frame: &CapturedFrame) -> Result<Vec<u8>, PipelineError> {
        let expected_len = frame
            .width
            .checked_mul(frame.height)
            .and_then(|pixels| match frame.pixel_format {
                FramePixelFormat::Bgra32 | FramePixelFormat::Rgba32 => pixels.checked_mul(4),
                FramePixelFormat::Rgb24 => pixels.checked_mul(3),
                FramePixelFormat::Nv12 => nv12_len(frame.width, frame.height),
            })
            .ok_or_else(|| PipelineError::message("frame buffer size overflow"))?;

        if frame.data.len() != expected_len {
            return Err(PipelineError::message(format!(
                "frame bytes mismatch: expected {expected_len}, got {}",
                frame.data.len()
            )));
        }

        match frame.pixel_format {
            FramePixelFormat::Bgra32 => Ok(frame.data.clone()),
            FramePixelFormat::Rgba32 => {
                let mut bgra = Vec::with_capacity(frame.data.len());
                for chunk in frame.data.chunks_exact(4) {
                    bgra.push(chunk[2]);
                    bgra.push(chunk[1]);
                    bgra.push(chunk[0]);
                    bgra.push(chunk[3]);
                }
                Ok(bgra)
            }
            FramePixelFormat::Rgb24 => {
                let mut bgra = Vec::with_capacity(frame.width * frame.height * 4);
                for chunk in frame.data.chunks_exact(3) {
                    bgra.push(chunk[2]);
                    bgra.push(chunk[1]);
                    bgra.push(chunk[0]);
                    bgra.push(255);
                }
                Ok(bgra)
            }
            FramePixelFormat::Nv12 => nv12_to_bgra(frame),
        }
    }

    fn nv12_len(width: usize, height: usize) -> Option<usize> {
        if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
            return None;
        }
        let y_size = width.checked_mul(height)?;
        y_size.checked_add(y_size / 2)
    }

    fn nv12_to_bgra(frame: &CapturedFrame) -> Result<Vec<u8>, PipelineError> {
        let y_size = frame
            .width
            .checked_mul(frame.height)
            .ok_or_else(|| PipelineError::message("NV12 luma byte size overflow"))?;
        let mut bgra = Vec::with_capacity(
            frame
                .width
                .checked_mul(frame.height)
                .and_then(|pixels| pixels.checked_mul(4))
                .ok_or_else(|| PipelineError::message("BGRA output byte size overflow"))?,
        );
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
                let r = ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u8;
                let g = ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u8;
                let b = ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u8;
                bgra.extend_from_slice(&[b, g, r, 255]);
            }
        }
        Ok(bgra)
    }
}

#[cfg(windows)]
pub use imp::{NvencH264Encoder, NvencHevcEncoder};

#[cfg(not(windows))]
pub struct NvencHevcEncoder {
    encoder: GstreamerNvencEncoder,
    main10: bool,
    color_mode: ColorMode,
}

#[cfg(not(windows))]
struct GstreamerNvencEncoder {
    codec: VideoCodec,
    element: &'static str,
    parser: &'static str,
    caps: &'static str,
    width: usize,
    height: usize,
    fps: u32,
    bitrate_kbps: u32,
    frame_index: usize,
    process: Option<GstreamerNvencProcess>,
}

#[cfg(not(windows))]
#[derive(Clone, Copy)]
struct GstreamerNvencProfile {
    codec: VideoCodec,
    element: &'static str,
    parser: &'static str,
    caps: &'static str,
}

#[cfg(not(windows))]
const GSTREAMER_H264_PROFILE: GstreamerNvencProfile = GstreamerNvencProfile {
    codec: VideoCodec::H264,
    element: "nvh264enc",
    parser: "h264parse",
    caps: "video/x-h264,stream-format=byte-stream,alignment=au",
};

#[cfg(not(windows))]
const GSTREAMER_HEVC_PROFILE: GstreamerNvencProfile = GstreamerNvencProfile {
    codec: VideoCodec::Hevc,
    element: "nvh265enc",
    parser: "h265parse",
    caps: "video/x-h265,stream-format=byte-stream,alignment=au",
};

#[cfg(not(windows))]
struct GstreamerNvencProcess {
    child: Child,
    stdin: ChildStdin,
    stdout_rx: mpsc::Receiver<GstreamerReadResult>,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
}

#[cfg(not(windows))]
type GstreamerReadResult = Result<Vec<u8>, String>;

#[cfg(not(windows))]
const GST_STDIO_CHUNK_SIZE: usize = 64 * 1024;
#[cfg(not(windows))]
const GST_STDERR_TAIL_LIMIT: usize = 16 * 1024;
#[cfg(not(windows))]
const GST_OUTPUT_TIMEOUT: Duration = Duration::from_millis(1_500);
#[cfg(not(windows))]
const GST_OUTPUT_IDLE: Duration = Duration::from_millis(8);

#[cfg(not(windows))]
impl GstreamerNvencEncoder {
    fn new(
        profile: GstreamerNvencProfile,
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        require_gst_element(profile.element)?;
        require_gst_element(profile.parser)?;
        require_gst_element("rawvideoparse")?;
        Ok(Self {
            codec: profile.codec,
            element: profile.element,
            parser: profile.parser,
            caps: profile.caps,
            width: width.max(2),
            height: height.max(2),
            fps: fps.max(1),
            bitrate_kbps: (bitrate / 1000).max(1),
            frame_index: 0,
            process: None,
        })
    }

    fn encode(&mut self, frame: &CapturedFrame) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
        if frame.pixel_format != FramePixelFormat::Bgra32 {
            return Err(PipelineError::message(format!(
                "Linux NVENC GStreamer path expects BGRA32 frames, got {:?}",
                frame.pixel_format
            )));
        }
        if frame.width != self.width || frame.height != self.height {
            return Err(PipelineError::message(format!(
                "Linux NVENC GStreamer path was initialized for {}x{}, got {}x{}",
                self.width, self.height, frame.width, frame.height
            )));
        }

        let force_idr = self.frame_index == 0 || self.frame_index.is_multiple_of(self.fps as usize);
        let timestamp_us = frame.timestamp_us;
        let codec = self.codec;
        let output = self.encode_with_process(&frame.data)?;
        self.frame_index += 1;
        Ok(vec![EncodedAccessUnit {
            codec,
            timestamp_us,
            is_keyframe: force_idr || annex_b_contains_keyframe(codec, &output),
            bytes: output,
        }])
    }

    fn encode_with_process(&mut self, frame_data: &[u8]) -> Result<Vec<u8>, PipelineError> {
        let label = "Linux GStreamer NVENC";
        let result = {
            let process = self.ensure_process()?;
            process.write_frame(frame_data, label)?;
            process.read_encoded_output(label)
        };
        if result.is_err() {
            self.process.take();
        }
        result
    }

    fn ensure_process(&mut self) -> Result<&mut GstreamerNvencProcess, PipelineError> {
        if let Some(process) = self.process.as_mut() {
            if let Some(status) = process.child.try_wait().map_err(|error| {
                PipelineError::message(format!(
                    "poll Linux GStreamer NVENC process failed: {error}"
                ))
            })? {
                let stderr = process.stderr_tail_text();
                self.process.take();
                return Err(PipelineError::message(format!(
                    "Linux GStreamer NVENC exited before encode with {status}; stderr: {stderr}"
                )));
            }
        }

        if self.process.is_none() {
            self.process = Some(GstreamerNvencProcess::spawn(
                self.gstreamer_command(),
                "Linux GStreamer NVENC",
            )?);
        }

        self.process
            .as_mut()
            .ok_or_else(|| PipelineError::message("Linux GStreamer NVENC process is unavailable"))
    }

    fn gstreamer_command(&self) -> std::process::Command {
        let mut command = std::process::Command::new("gst-launch-1.0");
        command
            .arg("-q")
            .arg("fdsrc")
            .arg("fd=0")
            .arg("blocksize=65536")
            .arg("!")
            .arg("rawvideoparse")
            .arg("format=bgra")
            .arg(format!("width={}", self.width))
            .arg(format!("height={}", self.height))
            .arg(format!("framerate={}/1", self.fps))
            .arg("!")
            .arg("videoconvert")
            .arg("!")
            .arg("video/x-raw,format=BGRA")
            .arg("!")
            .arg(self.element)
            .arg("preset=p1")
            .arg("tune=low-latency")
            .arg("zerolatency=true")
            .arg("bframes=0")
            .arg(format!("gop-size={}", self.fps.min(60)))
            .arg("repeat-sequence-header=true")
            .arg(format!("bitrate={}", self.bitrate_kbps))
            .arg("!")
            .arg(self.parser)
            .arg("config-interval=-1")
            .arg("!")
            .arg(self.caps)
            .arg("!")
            .arg("fdsink")
            .arg("fd=1")
            .arg("sync=false")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }
}

#[cfg(not(windows))]
pub struct NvencH264Encoder {
    encoder: GstreamerNvencEncoder,
    color_mode: ColorMode,
}

#[cfg(not(windows))]
impl GstreamerNvencProcess {
    fn spawn(mut command: std::process::Command, label: &str) -> Result<Self, PipelineError> {
        let mut child = command
            .spawn()
            .map_err(|error| PipelineError::message(format!("launch {label} failed: {error}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| PipelineError::message(format!("{label} stdin pipe is unavailable")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PipelineError::message(format!("{label} stdout pipe is unavailable")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| PipelineError::message(format!("{label} stderr pipe is unavailable")))?;
        let (stdout_tx, stdout_rx) = mpsc::channel();
        std::thread::spawn(move || read_gstreamer_stdout(stdout, stdout_tx));

        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let stderr_tail_reader = Arc::clone(&stderr_tail);
        std::thread::spawn(move || read_gstreamer_stderr(stderr, stderr_tail_reader));

        Ok(Self {
            child,
            stdin,
            stdout_rx,
            stderr_tail,
        })
    }

    fn write_frame(&mut self, frame_data: &[u8], label: &str) -> Result<(), PipelineError> {
        if let Err(error) = self.stdin.write_all(frame_data) {
            return Err(self.io_error(label, "writing raw frame input", error));
        }
        if let Err(error) = self.stdin.flush() {
            return Err(self.io_error(label, "flushing raw frame input", error));
        }
        Ok(())
    }

    fn read_encoded_output(&mut self, label: &str) -> Result<Vec<u8>, PipelineError> {
        let deadline = Instant::now() + GST_OUTPUT_TIMEOUT;
        let mut output = Vec::new();

        loop {
            let timeout = if output.is_empty() {
                deadline.saturating_duration_since(Instant::now())
            } else {
                GST_OUTPUT_IDLE
            };

            match self.stdout_rx.recv_timeout(timeout) {
                Ok(Ok(chunk)) => {
                    output.extend_from_slice(&chunk);
                    if let Some(done) = self.drain_ready_stdout(label, &mut output)? {
                        return Ok(done);
                    }
                }
                Ok(Err(error)) => {
                    if output.is_empty() {
                        return Err(PipelineError::message(format!(
                            "{label} stdout closed before encoded output: {error}; stderr: {}",
                            self.stderr_tail_text()
                        )));
                    }
                    return Ok(output);
                }
                Err(mpsc::RecvTimeoutError::Timeout) if output.is_empty() => {
                    if let Some(status) = self.child.try_wait().map_err(|error| {
                        PipelineError::message(format!("poll {label} process failed: {error}"))
                    })? {
                        return Err(PipelineError::message(format!(
                            "{label} exited with {status} before producing encoded output; stderr: {}",
                            self.stderr_tail_text()
                        )));
                    }
                    if Instant::now() >= deadline {
                        return Err(PipelineError::message(format!(
                            "{label} produced no encoded output within {} ms; stderr: {}",
                            GST_OUTPUT_TIMEOUT.as_millis(),
                            self.stderr_tail_text()
                        )));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return Ok(output),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if output.is_empty() {
                        return Err(PipelineError::message(format!(
                            "{label} stdout reader stopped before encoded output; stderr: {}",
                            self.stderr_tail_text()
                        )));
                    }
                    return Ok(output);
                }
            }
        }
    }

    fn drain_ready_stdout(
        &mut self,
        label: &str,
        output: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>, PipelineError> {
        loop {
            match self.stdout_rx.try_recv() {
                Ok(Ok(chunk)) => output.extend_from_slice(&chunk),
                Ok(Err(error)) => {
                    if output.is_empty() {
                        return Err(PipelineError::message(format!(
                            "{label} stdout closed before encoded output: {error}; stderr: {}",
                            self.stderr_tail_text()
                        )));
                    }
                    return Ok(Some(std::mem::take(output)));
                }
                Err(mpsc::TryRecvError::Empty) => return Ok(None),
                Err(mpsc::TryRecvError::Disconnected) => {
                    if output.is_empty() {
                        return Err(PipelineError::message(format!(
                            "{label} stdout reader stopped before encoded output; stderr: {}",
                            self.stderr_tail_text()
                        )));
                    }
                    return Ok(Some(std::mem::take(output)));
                }
            }
        }
    }

    fn io_error(&mut self, label: &str, operation: &str, error: std::io::Error) -> PipelineError {
        let exit = match self.child.try_wait() {
            Ok(Some(status)) => format!("; process exited with {status}"),
            Ok(None) => String::new(),
            Err(wait_error) => format!("; process status unavailable: {wait_error}"),
        };
        PipelineError::message(format!(
            "{label} failed while {operation}: {error}{exit}; stderr: {}",
            self.stderr_tail_text()
        ))
    }

    fn stderr_tail_text(&self) -> String {
        let bytes = self
            .stderr_tail
            .lock()
            .map(|tail| tail.clone())
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            "(empty)".to_string()
        } else {
            trimmed.to_string()
        }
    }
}

#[cfg(not(windows))]
impl Drop for GstreamerNvencProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(not(windows))]
fn read_gstreamer_stdout<R>(mut stdout: R, stdout_tx: mpsc::Sender<GstreamerReadResult>)
where
    R: Read,
{
    let mut buffer = vec![0; GST_STDIO_CHUNK_SIZE];
    loop {
        match stdout.read(&mut buffer) {
            Ok(0) => {
                let _ = stdout_tx.send(Err("stdout reached EOF".to_string()));
                break;
            }
            Ok(bytes_read) => {
                if stdout_tx.send(Ok(buffer[..bytes_read].to_vec())).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = stdout_tx.send(Err(error.to_string()));
                break;
            }
        }
    }
}

#[cfg(not(windows))]
fn read_gstreamer_stderr<R>(mut stderr: R, stderr_tail: Arc<Mutex<Vec<u8>>>)
where
    R: Read,
{
    let mut buffer = vec![0; GST_STDIO_CHUNK_SIZE];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => append_gstreamer_stderr_tail(&stderr_tail, &buffer[..bytes_read]),
            Err(_) => break,
        }
    }
}

#[cfg(not(windows))]
fn append_gstreamer_stderr_tail(stderr_tail: &Arc<Mutex<Vec<u8>>>, bytes: &[u8]) {
    if let Ok(mut tail) = stderr_tail.lock() {
        if bytes.len() >= GST_STDERR_TAIL_LIMIT {
            tail.clear();
            tail.extend_from_slice(&bytes[bytes.len() - GST_STDERR_TAIL_LIMIT..]);
            return;
        }
        let overflow = tail.len().saturating_add(bytes.len());
        if overflow > GST_STDERR_TAIL_LIMIT {
            tail.drain(..overflow - GST_STDERR_TAIL_LIMIT);
        }
        tail.extend_from_slice(bytes);
    }
}

#[cfg(not(windows))]
fn require_gst_element(element: &str) -> Result<(), PipelineError> {
    let status = std::process::Command::new("gst-inspect-1.0")
        .arg(element)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| {
            PipelineError::message(format!("gst-inspect-1.0 is not available: {error}"))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(PipelineError::message(format!(
            "GStreamer element `{element}` is not available"
        )))
    }
}

#[cfg(not(windows))]
fn probe_gstreamer_nvenc(
    profile: GstreamerNvencProfile,
    width: usize,
    height: usize,
) -> Result<(), PipelineError> {
    let mut encoder = GstreamerNvencEncoder::new(profile, width, height, 30, 1_000_000)?;
    let frame = CapturedFrame::from_cpu(
        width,
        height,
        FramePixelFormat::Bgra32,
        0,
        vec![0; width * height * 4],
    );
    let units = encoder.encode(&frame)?;
    if units.iter().any(|unit| !unit.bytes.is_empty()) {
        Ok(())
    } else {
        Err(PipelineError::message(format!(
            "Linux GStreamer NVENC probe for `{}` produced no encoded output",
            profile.element
        )))
    }
}

#[cfg(not(windows))]
fn annex_b_contains_keyframe(codec: VideoCodec, bytes: &[u8]) -> bool {
    let mut index = 0;
    while index + 5 < bytes.len() {
        let start_len = if bytes[index..].starts_with(&[0, 0, 1]) {
            3
        } else if bytes[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        let nal = bytes[index + start_len];
        match codec {
            VideoCodec::H264 => {
                let nal_type = nal & 0x1f;
                if nal_type == 5 || nal_type == 7 {
                    return true;
                }
            }
            VideoCodec::Hevc => {
                let nal_type = (nal >> 1) & 0x3f;
                if nal_type == 19 || nal_type == 20 || nal_type == 32 || nal_type == 33 {
                    return true;
                }
            }
            VideoCodec::Av1 | VideoCodec::Vvc => {}
        }
        index += start_len;
    }
    false
}

#[cfg(not(windows))]
impl NvencH264Encoder {
    pub fn default_color_mode() -> ColorMode {
        ColorMode::Full
    }

    pub fn color_mode(&self) -> ColorMode {
        self.color_mode
    }

    pub fn with_color_mode(mut self, color_mode: ColorMode) -> Self {
        self.color_mode = color_mode;
        self
    }

    pub fn preferred_input_memory_kind_for_color_mode(
        _mode: ColorMode,
    ) -> mrd_pipeline_core::FrameMemoryKind {
        mrd_pipeline_core::FrameMemoryKind::Cpu
    }

    pub fn new(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_with_bitrate(width, height, fps, 8_000_000)
    }

    pub fn new_with_bitrate(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        Self::new_max_speed_with_bitrate(width, height, fps, bitrate)
    }

    pub fn new_baseline(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_max_speed_with_bitrate(width, height, fps, 5_000_000)
    }

    pub fn new_max_speed(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_max_speed_with_bitrate(width, height, fps, 5_000_000)
    }

    pub fn new_max_speed_with_bitrate(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        Ok(Self {
            encoder: GstreamerNvencEncoder::new(
                GSTREAMER_H264_PROFILE,
                width,
                height,
                fps,
                bitrate,
            )?,
            color_mode: ColorMode::Full,
        })
    }

    pub fn new_low_latency_p1(
        width: usize,
        height: usize,
        fps: u32,
    ) -> Result<Self, PipelineError> {
        Self::new_max_speed(width, height, fps)
    }

    pub fn new_high_quality_p5(
        width: usize,
        height: usize,
        fps: u32,
    ) -> Result<Self, PipelineError> {
        Self::new_with_bitrate(width, height, fps, 12_000_000)
    }

    pub fn probe_h264_available() -> Result<(), PipelineError> {
        probe_gstreamer_nvenc(GSTREAMER_H264_PROFILE, 160, 64)
    }
}

#[cfg(not(windows))]
impl NvencHevcEncoder {
    pub fn default_color_mode() -> ColorMode {
        ColorMode::Full
    }

    pub fn color_mode(&self) -> ColorMode {
        self.color_mode
    }

    pub fn with_color_mode(mut self, color_mode: ColorMode) -> Self {
        self.color_mode = color_mode;
        self
    }

    pub fn preferred_input_memory_kind_for_color_mode(
        _mode: ColorMode,
    ) -> mrd_pipeline_core::FrameMemoryKind {
        mrd_pipeline_core::FrameMemoryKind::Cpu
    }

    pub fn preferred_input_memory_kind() -> mrd_pipeline_core::FrameMemoryKind {
        mrd_pipeline_core::FrameMemoryKind::Cpu
    }

    pub fn preferred_main10_input_memory_kind() -> mrd_pipeline_core::FrameMemoryKind {
        mrd_pipeline_core::FrameMemoryKind::Cpu
    }

    pub fn new(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_main_with_bitrate(width, height, fps, 8_000_000)
    }

    pub fn new_main(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_main_with_bitrate(width, height, fps, 8_000_000)
    }

    pub fn new_main10(width: usize, height: usize, fps: u32) -> Result<Self, PipelineError> {
        Self::new_main10_with_bitrate(width, height, fps, 10_000_000)
    }

    pub fn new_main_with_bitrate(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        Ok(Self {
            encoder: GstreamerNvencEncoder::new(
                GSTREAMER_HEVC_PROFILE,
                width,
                height,
                fps,
                bitrate,
            )?,
            main10: false,
            color_mode: ColorMode::Full,
        })
    }

    pub fn new_max_speed_with_bitrate(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        Self::new_main_with_bitrate(width, height, fps, bitrate)
    }

    pub fn new_main10_with_bitrate(
        width: usize,
        height: usize,
        fps: u32,
        bitrate: u32,
    ) -> Result<Self, PipelineError> {
        let mut encoder = Self::new_main_with_bitrate(width, height, fps, bitrate)?;
        encoder.main10 = true;
        Ok(encoder)
    }

    pub fn probe_hevc_available() -> Result<(), PipelineError> {
        probe_gstreamer_nvenc(GSTREAMER_HEVC_PROFILE, 160, 64)
    }

    pub fn probe_hevc_main10_available() -> Result<(), PipelineError> {
        Self::probe_hevc_available()
    }
}

#[cfg(not(windows))]
impl VideoEncoder for NvencH264Encoder {
    fn encode(&mut self, frame: &CapturedFrame) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
        if self.color_mode != ColorMode::Full {
            return Err(PipelineError::message(format!(
                "Linux NVENC H.264 color_mode={} requires a GPU color transform path",
                self.color_mode.as_str()
            )));
        }
        self.encoder.encode(frame)
    }
}

#[cfg(not(windows))]
impl VideoEncoder for NvencHevcEncoder {
    fn encode(&mut self, frame: &CapturedFrame) -> Result<Vec<EncodedAccessUnit>, PipelineError> {
        if self.color_mode != ColorMode::Full {
            return Err(PipelineError::message(format!(
                "Linux NVENC HEVC color_mode={} requires a GPU color transform path",
                self.color_mode.as_str()
            )));
        }
        self.encoder.encode(frame)
    }
}

#[cfg(all(test, not(windows)))]
mod linux_tests {
    use super::*;

    #[test]
    fn gstreamer_command_reassembles_large_raw_frames_before_nvenc() {
        let encoder = GstreamerNvencEncoder {
            codec: VideoCodec::H264,
            element: "nvh264enc",
            parser: "h264parse",
            caps: "video/x-h264,stream-format=byte-stream,alignment=au",
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 5_000,
            frame_index: 0,
            process: None,
        };

        let command = encoder.gstreamer_command();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(args.iter().any(|arg| arg == "rawvideoparse"));
        assert!(args.iter().any(|arg| arg == "format=bgra"));
        assert!(args.iter().any(|arg| arg == "width=1280"));
        assert!(args.iter().any(|arg| arg == "height=720"));
        assert!(args.iter().any(|arg| arg == "framerate=30/1"));
        assert!(args.iter().any(|arg| arg == "tune=low-latency"));
        assert!(!args.iter().any(|arg| arg == "num-buffers=1"));
    }
}
