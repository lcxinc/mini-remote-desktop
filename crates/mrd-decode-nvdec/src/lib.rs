#[cfg(windows)]
use std::ffi::{c_int, c_void};

/// Decoded frame data from NVDEC
///
/// Supports both CPU-accessible RGB data and D3D11 shared texture (zero-copy path)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvdecDecodedFrameData {
    /// CPU RGB24 data (standard path)
    CpuRgb24(Vec<u8>),
    /// CPU NV12 data with decoder pitch.
    CpuNv12 { data: Vec<u8>, pitch: usize },
    /// CPU P010/P016 data with decoder pitch.
    CpuP010 { data: Vec<u8>, pitch: usize },
    /// D3D11 shared texture handle (zero-copy path)
    #[cfg(windows)]
    D3D11SharedNv12 {
        shared_handle_y: isize,
        shared_handle_uv: isize,
        width: u32,
        height: u32,
    },
    /// D3D11 shared P010/P016 texture handles (zero-copy Main10 path)
    #[cfg(windows)]
    D3D11SharedP010 {
        shared_handle_y: isize,
        shared_handle_uv: isize,
        width: u32,
        height: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvdecDecodedFrame {
    pub width: usize,
    pub height: usize,
    pub data: NvdecDecodedFrameData,
}

impl NvdecDecodedFrame {
    /// Create a decoded frame from CPU RGB24 data
    pub fn from_cpu_rgb24(width: usize, height: usize, data: Vec<u8>) -> Self {
        Self {
            width,
            height,
            data: NvdecDecodedFrameData::CpuRgb24(data),
        }
    }

    /// Create a decoded frame from CPU NV12 data.
    pub fn from_cpu_nv12(width: usize, height: usize, pitch: usize, data: Vec<u8>) -> Self {
        Self {
            width,
            height,
            data: NvdecDecodedFrameData::CpuNv12 { data, pitch },
        }
    }

    /// Create a decoded frame from CPU P010/P016 data.
    pub fn from_cpu_p010(width: usize, height: usize, pitch: usize, data: Vec<u8>) -> Self {
        Self {
            width,
            height,
            data: NvdecDecodedFrameData::CpuP010 { data, pitch },
        }
    }

    /// Check if this frame uses shared texture (zero-copy)
    pub fn is_shared_texture(&self) -> bool {
        match &self.data {
            NvdecDecodedFrameData::CpuRgb24(_)
            | NvdecDecodedFrameData::CpuNv12 { .. }
            | NvdecDecodedFrameData::CpuP010 { .. } => false,
            #[cfg(windows)]
            NvdecDecodedFrameData::D3D11SharedNv12 { .. }
            | NvdecDecodedFrameData::D3D11SharedP010 { .. } => true,
        }
    }

    /// Get the CPU RGB24 data if available
    pub fn cpu_rgb24(&self) -> Option<&[u8]> {
        match &self.data {
            NvdecDecodedFrameData::CpuRgb24(data) => Some(data.as_slice()),
            NvdecDecodedFrameData::CpuNv12 { .. } | NvdecDecodedFrameData::CpuP010 { .. } => None,
            #[cfg(windows)]
            NvdecDecodedFrameData::D3D11SharedNv12 { .. }
            | NvdecDecodedFrameData::D3D11SharedP010 { .. } => None,
        }
    }

    /// Get the CPU NV12 data and pitch if available.
    pub fn cpu_nv12(&self) -> Option<(&[u8], usize)> {
        match &self.data {
            NvdecDecodedFrameData::CpuNv12 { data, pitch } => Some((data.as_slice(), *pitch)),
            NvdecDecodedFrameData::CpuRgb24(_) | NvdecDecodedFrameData::CpuP010 { .. } => None,
            #[cfg(windows)]
            NvdecDecodedFrameData::D3D11SharedNv12 { .. }
            | NvdecDecodedFrameData::D3D11SharedP010 { .. } => None,
        }
    }

    /// Get the CPU P010/P016 data and pitch if available.
    pub fn cpu_p010(&self) -> Option<(&[u8], usize)> {
        match &self.data {
            NvdecDecodedFrameData::CpuP010 { data, pitch } => Some((data.as_slice(), *pitch)),
            NvdecDecodedFrameData::CpuRgb24(_) | NvdecDecodedFrameData::CpuNv12 { .. } => None,
            #[cfg(windows)]
            NvdecDecodedFrameData::D3D11SharedNv12 { .. }
            | NvdecDecodedFrameData::D3D11SharedP010 { .. } => None,
        }
    }

    /// Get the shared texture handle if available
    #[cfg(windows)]
    pub fn d3d11_shared_handle(&self) -> Option<isize> {
        match &self.data {
            NvdecDecodedFrameData::CpuRgb24(_)
            | NvdecDecodedFrameData::CpuNv12 { .. }
            | NvdecDecodedFrameData::CpuP010 { .. } => None,
            NvdecDecodedFrameData::D3D11SharedNv12 {
                shared_handle_y, ..
            }
            | NvdecDecodedFrameData::D3D11SharedP010 {
                shared_handle_y, ..
            } => Some(*shared_handle_y),
        }
    }

    /// Get the shared Y and UV texture handles if available.
    #[cfg(windows)]
    pub fn d3d11_shared_handles(&self) -> Option<(isize, isize)> {
        match &self.data {
            NvdecDecodedFrameData::CpuRgb24(_)
            | NvdecDecodedFrameData::CpuNv12 { .. }
            | NvdecDecodedFrameData::CpuP010 { .. } => None,
            NvdecDecodedFrameData::D3D11SharedNv12 {
                shared_handle_y,
                shared_handle_uv,
                ..
            }
            | NvdecDecodedFrameData::D3D11SharedP010 {
                shared_handle_y,
                shared_handle_uv,
                ..
            } => Some((*shared_handle_y, *shared_handle_uv)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvdecOutputMode {
    CpuRgb24,
    CpuNv12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvdecCodecKind {
    H264,
    Hevc,
    HevcMain10,
    Av1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvdecRuntimeProbe {
    pub backend: &'static str,
    pub summary: String,
    pub checked_items: Vec<&'static str>,
    pub capability_probes: Vec<NvdecCapabilityProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvdecDiagnostics {
    pub last_stage: Option<String>,
    pub last_api: Option<String>,
    pub last_code: Option<i32>,
    pub last_error_name: Option<String>,
    pub last_error_description: Option<String>,
    pub last_picture_index: Option<i32>,
    pub decode_calls: usize,
    pub display_calls: usize,
    pub recreate_count: usize,
    pub last_recreate_reason: Option<String>,
    pub active_coded_width: Option<u32>,
    pub active_coded_height: Option<u32>,
    pub active_display_width: Option<u32>,
    pub active_display_height: Option<u32>,
    pub last_sequence_coded_width: Option<u32>,
    pub last_sequence_coded_height: Option<u32>,
    pub last_sequence_display_width: Option<u32>,
    pub last_sequence_display_height: Option<u32>,
    pub last_sequence_bit_depth_minus8: Option<u8>,
    pub last_sequence_chroma_format: Option<i32>,
    pub last_sequence_decision: Option<String>,
    pub last_recreate_from_coded_width: Option<u32>,
    pub last_recreate_from_coded_height: Option<u32>,
    pub last_recreate_to_coded_width: Option<u32>,
    pub last_recreate_to_coded_height: Option<u32>,
    pub last_decode_status_phase: Option<String>,
    pub last_decode_status_raw: Option<i32>,
    pub last_decode_status_description: Option<String>,
    pub last_reconfigure_attempted: bool,
    pub last_reconfigure_result: Option<String>,
    pub last_reconfigure_from_coded_width: Option<u32>,
    pub last_reconfigure_from_coded_height: Option<u32>,
    pub last_reconfigure_to_coded_width: Option<u32>,
    pub last_reconfigure_to_coded_height: Option<u32>,
    pub reconfigure_fallback_used: bool,
    pub last_support_codec: Option<String>,
    pub last_support_bit_depth_minus8: Option<u8>,
    pub last_support_chroma_format: Option<i32>,
    pub last_support_decision: Option<String>,
    pub last_support_reason: Option<String>,
    pub shared_copy_attempts: usize,
    pub shared_copy_successes: usize,
    pub shared_copy_failures: usize,
    pub last_shared_copy_stage: Option<String>,
    pub last_shared_copy_api: Option<String>,
    pub last_shared_copy_code: Option<i32>,
    pub last_shared_copy_error_name: Option<String>,
    pub last_shared_copy_error_description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvdecCapabilityProbe {
    pub codec: String,
    pub bit_depth_minus8: u8,
    pub chroma_format: i32,
    pub runtime_supported: bool,
    pub runtime_reason: String,
    pub wired_supported: bool,
    pub wired_reason: String,
}

#[cfg(any(windows, test))]
impl NvdecDiagnostics {
    fn record_shared_copy_attempt(&mut self) {
        self.shared_copy_attempts = self.shared_copy_attempts.saturating_add(1);
    }

    fn record_shared_copy_success(&mut self) {
        self.shared_copy_successes = self.shared_copy_successes.saturating_add(1);
    }

    fn record_shared_copy_failure(
        &mut self,
        stage: &'static str,
        api: &'static str,
        code: Option<i32>,
        error_name: Option<String>,
        description: Option<String>,
    ) {
        self.shared_copy_failures = self.shared_copy_failures.saturating_add(1);
        self.last_shared_copy_stage = Some(stage.to_string());
        self.last_shared_copy_api = Some(api.to_string());
        self.last_shared_copy_code = code;
        self.last_shared_copy_error_name = error_name;
        self.last_shared_copy_error_description = description;
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use super::NvdecDiagnostics;

    #[test]
    fn shared_copy_diagnostics_record_attempt_success_and_failure() {
        let mut diagnostics = NvdecDiagnostics::default();

        diagnostics.record_shared_copy_attempt();
        diagnostics.record_shared_copy_failure(
            "register",
            "cuGraphicsD3D11RegisterResource",
            Some(999),
            Some("CUDA_ERROR_UNKNOWN".to_string()),
            Some("unknown interop failure".to_string()),
        );
        diagnostics.record_shared_copy_attempt();
        diagnostics.record_shared_copy_success();

        assert_eq!(diagnostics.shared_copy_attempts, 2);
        assert_eq!(diagnostics.shared_copy_successes, 1);
        assert_eq!(diagnostics.shared_copy_failures, 1);
        assert_eq!(
            diagnostics.last_shared_copy_stage.as_deref(),
            Some("register")
        );
        assert_eq!(
            diagnostics.last_shared_copy_api.as_deref(),
            Some("cuGraphicsD3D11RegisterResource")
        );
        assert_eq!(diagnostics.last_shared_copy_code, Some(999));
        assert_eq!(
            diagnostics.last_shared_copy_error_name.as_deref(),
            Some("CUDA_ERROR_UNKNOWN")
        );
        assert_eq!(
            diagnostics.last_shared_copy_error_description.as_deref(),
            Some("unknown interop failure")
        );
    }
}

pub struct NvdecDecoder {
    runtime: NvdecRuntimeProbe,
    #[cfg(windows)]
    session: imp::NvdecSession,
    #[cfg(windows)]
    enable_shared_texture: bool,
}

unsafe impl Send for NvdecDecoder {}

impl NvdecDecoder {
    pub fn new() -> Result<Self, String> {
        Self::new_with_output_mode(NvdecOutputMode::CpuRgb24)
    }

    pub fn new_with_output_mode(output_mode: NvdecOutputMode) -> Result<Self, String> {
        Self::new_for_codec_with_output_mode(NvdecCodecKind::H264, output_mode)
    }

    pub fn new_av1_with_output_mode(output_mode: NvdecOutputMode) -> Result<Self, String> {
        Self::new_for_codec_with_output_mode(NvdecCodecKind::Av1, output_mode)
    }

    pub fn new_hevc_with_output_mode(output_mode: NvdecOutputMode) -> Result<Self, String> {
        Self::new_for_codec_with_output_mode(NvdecCodecKind::Hevc, output_mode)
    }

    pub fn new_hevc_main10_with_output_mode(output_mode: NvdecOutputMode) -> Result<Self, String> {
        Self::new_for_codec_with_output_mode(NvdecCodecKind::HevcMain10, output_mode)
    }

    pub fn new_for_codec_with_output_mode(
        codec: NvdecCodecKind,
        output_mode: NvdecOutputMode,
    ) -> Result<Self, String> {
        #[cfg(windows)]
        {
            let session = imp::NvdecSession::new_for_codec(codec, output_mode)?;
            let runtime = NvdecRuntimeProbe {
                backend: "windows-nvdec",
                summary: "nvdec runtime libraries and core exports are present".to_string(),
                checked_items: vec![
                    "nvcuda.dll",
                    "nvcuvid.dll",
                    "cuInit",
                    "cuDeviceGetCount",
                    "cuvidGetDecoderCaps",
                    "cuvidCreateDecoder",
                    "cuvidDestroyDecoder",
                    "cuvidCreateVideoParser",
                    "cuvidParseVideoData",
                ],
                capability_probes: Vec::new(),
            };
            Ok(Self {
                runtime,
                session,
                enable_shared_texture: false, // Disabled by default until fully implemented
            })
        }

        #[cfg(not(windows))]
        {
            let _ = (codec, output_mode);
            Err("Windows-only nvdec backend is unavailable on this platform".to_string())
        }
    }

    #[cfg(windows)]
    /// Creates an H.264 NVDEC decoder that can interoperate with the supplied D3D11 device.
    ///
    /// # Safety
    ///
    /// `d3d11_device_ptr` must be a valid, non-null `ID3D11Device` pointer that remains alive for
    /// the lifetime of the decoder. The pointer must be safe to use from the decoder's calling
    /// thread according to the D3D11 device's threading guarantees.
    pub unsafe fn new_with_output_mode_and_d3d11_device_ptr(
        output_mode: NvdecOutputMode,
        d3d11_device_ptr: *mut c_void,
    ) -> Result<Self, String> {
        unsafe {
            Self::new_for_codec_with_output_mode_and_d3d11_device_ptr(
                NvdecCodecKind::H264,
                output_mode,
                d3d11_device_ptr,
            )
        }
    }

    #[cfg(windows)]
    /// Creates an AV1 NVDEC decoder that can interoperate with the supplied D3D11 device.
    ///
    /// # Safety
    ///
    /// `d3d11_device_ptr` must be a valid, non-null `ID3D11Device` pointer that remains alive for
    /// the lifetime of the decoder. The pointer must be safe to use from the decoder's calling
    /// thread according to the D3D11 device's threading guarantees.
    pub unsafe fn new_av1_with_output_mode_and_d3d11_device_ptr(
        output_mode: NvdecOutputMode,
        d3d11_device_ptr: *mut c_void,
    ) -> Result<Self, String> {
        unsafe {
            Self::new_for_codec_with_output_mode_and_d3d11_device_ptr(
                NvdecCodecKind::Av1,
                output_mode,
                d3d11_device_ptr,
            )
        }
    }

    #[cfg(windows)]
    /// Creates an HEVC NVDEC decoder that can interoperate with the supplied D3D11 device.
    ///
    /// # Safety
    ///
    /// `d3d11_device_ptr` must be a valid, non-null `ID3D11Device` pointer that remains alive for
    /// the lifetime of the decoder. The pointer must be safe to use from the decoder's calling
    /// thread according to the D3D11 device's threading guarantees.
    pub unsafe fn new_hevc_with_output_mode_and_d3d11_device_ptr(
        output_mode: NvdecOutputMode,
        d3d11_device_ptr: *mut c_void,
    ) -> Result<Self, String> {
        unsafe {
            Self::new_for_codec_with_output_mode_and_d3d11_device_ptr(
                NvdecCodecKind::Hevc,
                output_mode,
                d3d11_device_ptr,
            )
        }
    }

    #[cfg(windows)]
    /// Creates an HEVC Main10 NVDEC decoder that can interoperate with the supplied D3D11 device.
    ///
    /// # Safety
    ///
    /// `d3d11_device_ptr` must be a valid, non-null `ID3D11Device` pointer that remains alive for
    /// the lifetime of the decoder. The pointer must be safe to use from the decoder's calling
    /// thread according to the D3D11 device's threading guarantees.
    pub unsafe fn new_hevc_main10_with_output_mode_and_d3d11_device_ptr(
        output_mode: NvdecOutputMode,
        d3d11_device_ptr: *mut c_void,
    ) -> Result<Self, String> {
        unsafe {
            Self::new_for_codec_with_output_mode_and_d3d11_device_ptr(
                NvdecCodecKind::HevcMain10,
                output_mode,
                d3d11_device_ptr,
            )
        }
    }

    #[cfg(windows)]
    /// Creates an NVDEC decoder for `codec` that can interoperate with the supplied D3D11 device.
    ///
    /// # Safety
    ///
    /// `d3d11_device_ptr` must be a valid, non-null `ID3D11Device` pointer that remains alive for
    /// the lifetime of the decoder. The pointer must be safe to use from the decoder's calling
    /// thread according to the D3D11 device's threading guarantees.
    pub unsafe fn new_for_codec_with_output_mode_and_d3d11_device_ptr(
        codec: NvdecCodecKind,
        output_mode: NvdecOutputMode,
        d3d11_device_ptr: *mut c_void,
    ) -> Result<Self, String> {
        if d3d11_device_ptr.is_null() {
            return Err("D3D11 device pointer is null".to_string());
        }

        let mut decoder = Self::new_for_codec_with_optional_d3d11_device_ptr(
            codec,
            output_mode,
            Some(d3d11_device_ptr),
        )?;
        decoder.enable_shared_texture(true);
        Ok(decoder)
    }

    #[cfg(windows)]
    fn new_for_codec_with_optional_d3d11_device_ptr(
        codec: NvdecCodecKind,
        output_mode: NvdecOutputMode,
        d3d11_device_ptr: Option<*mut c_void>,
    ) -> Result<Self, String> {
        let session = imp::NvdecSession::new_for_codec_with_d3d11_device_ptr(
            codec,
            output_mode,
            d3d11_device_ptr,
        )?;
        let runtime = NvdecRuntimeProbe {
            backend: "windows-nvdec",
            summary: "nvdec runtime libraries and core exports are present".to_string(),
            checked_items: vec![
                "nvcuda.dll",
                "nvcuvid.dll",
                "cuInit",
                "cuDeviceGetCount",
                "cuvidGetDecoderCaps",
                "cuvidCreateDecoder",
                "cuvidDestroyDecoder",
                "cuvidCreateVideoParser",
                "cuvidParseVideoData",
            ],
            capability_probes: Vec::new(),
        };
        Ok(Self {
            runtime,
            session,
            enable_shared_texture: false,
        })
    }

    /// Enable D3D11 shared texture output (zero-copy path)
    ///
    /// When enabled, the decoder will attempt to create D3D11 shared textures
    /// and copy decoded frames directly to them, avoiding GPU→CPU→GPU copies.
    #[cfg(windows)]
    pub fn enable_shared_texture(&mut self, enable: bool) {
        self.enable_shared_texture = enable;
        self.session.enable_shared_texture(enable);
    }

    pub fn runtime(&self) -> &NvdecRuntimeProbe {
        &self.runtime
    }

    pub fn diagnostics(&self) -> NvdecDiagnostics {
        #[cfg(windows)]
        {
            self.session.diagnostics()
        }

        #[cfg(not(windows))]
        {
            NvdecDiagnostics::default()
        }
    }

    pub fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), String> {
        #[cfg(windows)]
        {
            self.session.push_access_unit(access_unit)
        }

        #[cfg(not(windows))]
        {
            let _ = access_unit;
            Err("Windows-only nvdec backend is unavailable on this platform".to_string())
        }
    }

    pub fn drain_decoded_frames(&mut self) -> Vec<NvdecDecodedFrame> {
        #[cfg(windows)]
        {
            self.session.drain_decoded_frames()
        }

        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }
}

pub fn probe_h264_available() -> Result<(), String> {
    let probe = probe_capability("h264", 0, 1)?;
    if probe.runtime_supported && probe.wired_supported {
        Ok(())
    } else if !probe.runtime_supported {
        Err(probe.runtime_reason)
    } else {
        Err(probe.wired_reason)
    }
}

pub fn probe_hevc_available() -> Result<(), String> {
    let probe = probe_capability("hevc", 0, 1)?;
    if probe.runtime_supported && probe.wired_supported {
        Ok(())
    } else if !probe.runtime_supported {
        Err(probe.runtime_reason)
    } else {
        Err(probe.wired_reason)
    }
}

pub fn probe_hevc_main10_available() -> Result<(), String> {
    let probe = probe_capability("hevc", 2, 1)?;
    if probe.runtime_supported && probe.wired_supported {
        Ok(())
    } else if !probe.runtime_supported {
        Err(probe.runtime_reason)
    } else {
        Err(probe.wired_reason)
    }
}

pub fn probe_av1_available() -> Result<(), String> {
    let probe = probe_capability("av1", 0, 1)?;
    if probe.runtime_supported && probe.wired_supported {
        Ok(())
    } else if !probe.runtime_supported {
        Err(probe.runtime_reason)
    } else {
        Err(probe.wired_reason)
    }
}

pub fn probe_runtime() -> NvdecRuntimeProbe {
    let capability_probes = runtime_capability_probes();
    match NvdecDecoder::new() {
        Ok(mut decoder) => {
            decoder.runtime.capability_probes = capability_probes;
            decoder.runtime().clone()
        }
        Err(error) => NvdecRuntimeProbe {
            backend: "windows-nvdec",
            summary: error,
            checked_items: vec!["nvcuda.dll", "nvcuvid.dll"],
            capability_probes,
        },
    }
}

fn runtime_capability_probes() -> Vec<NvdecCapabilityProbe> {
    [
        ("h264", 0, 1, "H264 decode path wired"),
        ("hevc", 0, 1, "HEVC Main decode path wired"),
        ("hevc", 2, 1, "HEVC Main10 decode path wired"),
        (
            "av1",
            0,
            1,
            "AV1 decode path wired (requires Ada Lovelace or newer GPU)",
        ),
    ]
    .into_iter()
    .map(
        |(codec, bit_depth_minus8, chroma_format, fallback_wired_reason)| match probe_capability(
            codec,
            bit_depth_minus8,
            chroma_format,
        ) {
            Ok(probe) => probe,
            Err(error) => NvdecCapabilityProbe {
                codec: codec.to_string(),
                bit_depth_minus8,
                chroma_format,
                runtime_supported: false,
                runtime_reason: error,
                wired_supported: false,
                wired_reason: fallback_wired_reason.to_string(),
            },
        },
    )
    .collect()
}

fn probe_capability(
    codec: &'static str,
    bit_depth_minus8: u8,
    chroma_format: i32,
) -> Result<NvdecCapabilityProbe, String> {
    #[cfg(windows)]
    {
        imp::probe_capability(codec, bit_depth_minus8, chroma_format)
    }

    #[cfg(not(windows))]
    {
        let _ = (codec, bit_depth_minus8, chroma_format);
        Err("Windows-only nvdec backend is unavailable on this platform".to_string())
    }
}

#[cfg(windows)]
mod imp {
    #![allow(clippy::upper_case_acronyms, non_snake_case)]

    use super::{
        c_int, c_void, NvdecCapabilityProbe, NvdecDecodedFrame, NvdecDecodedFrameData,
        NvdecDiagnostics, NvdecOutputMode,
    };
    use std::{mem, ptr};
    use windows::core::{Interface, PCSTR};
    use windows::Win32::Foundation::{FreeLibrary, HMODULE};
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
        D3D11_BIND_SHADER_RESOURCE, D3D11_RESOURCE_MISC_SHARED, D3D11_SDK_VERSION,
        D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    };
    use windows::Win32::Graphics::Dxgi::Common::{
        DXGI_FORMAT_R16G16_UNORM, DXGI_FORMAT_R16_UNORM, DXGI_FORMAT_R8G8_UNORM,
        DXGI_FORMAT_R8_UNORM, DXGI_SAMPLE_DESC,
    };
    use windows::Win32::Graphics::Dxgi::IDXGIResource;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    type CUresult = i32;
    type CUdevice = c_int;
    type CUcontext = *mut c_void;
    type CUstream = *mut c_void;
    type CUvideodecoder = *mut c_void;
    type CUvideoparser = *mut c_void;
    type CUvideoctxlock = *mut c_void;
    type CUdeviceptr = u64;
    type CUarray = *mut c_void;
    type CUvideotimestamp = i64;
    type CUgraphicsResource = *mut c_void;

    const CUDA_SUCCESS: CUresult = 0;
    const CUDA_ERROR_NO_DEVICE: CUresult = 100;
    const CUDA_VIDEO_CODEC_H264: i32 = 4;
    const CUDA_VIDEO_CODEC_HEVC: i32 = 8;
    const CUDA_VIDEO_CODEC_AV1: i32 = 11; // AV1 decode support (requires Ada Lovelace or newer)
    const CUDA_VIDEO_CHROMA_420: i32 = 1;
    const CUDA_VIDEO_CREATE_PREFER_CUVID: u32 = 0x04;
    const CUDA_VIDEO_SURFACE_NV12: i32 = 0;
    const CUDA_VIDEO_SURFACE_P016: i32 = 1;
    const CUDA_VIDEO_DEINTERLACE_WEAVE: i32 = 0;
    const CUVID_PKT_ENDOFPICTURE: u32 = 0x08;
    const CUVID_PARSER_ANNEXB: u32 = 0x01;
    const CU_MEMORYTYPE_DEVICE: u32 = 2;
    const CU_MEMORYTYPE_ARRAY: u32 = 3;

    type CuInitFn = unsafe extern "system" fn(u32) -> CUresult;
    type CuDeviceGetCountFn = unsafe extern "system" fn(*mut c_int) -> CUresult;
    type CuDeviceGetFn = unsafe extern "system" fn(*mut CUdevice, c_int) -> CUresult;
    type CuCtxCreateFn = unsafe extern "system" fn(*mut CUcontext, u32, CUdevice) -> CUresult;
    type CuCtxDestroyFn = unsafe extern "system" fn(CUcontext) -> CUresult;
    type CuCtxPushCurrentFn = unsafe extern "system" fn(CUcontext) -> CUresult;
    type CuCtxPopCurrentFn = unsafe extern "system" fn(*mut CUcontext) -> CUresult;
    type CuGetErrorNameFn = unsafe extern "system" fn(CUresult, *mut *const i8) -> CUresult;
    type CuGetErrorStringFn = unsafe extern "system" fn(CUresult, *mut *const i8) -> CUresult;
    type CuMemcpyDtoHFn = unsafe extern "system" fn(*mut c_void, CUdeviceptr, usize) -> CUresult;
    type CuvidGetDecoderCapsFn = unsafe extern "system" fn(*mut CUVIDDECODECAPS) -> CUresult;
    type CuvidCreateDecoderFn =
        unsafe extern "system" fn(*mut CUvideodecoder, *mut CUVIDDECODECREATEINFO) -> CUresult;
    type CuvidDestroyDecoderFn = unsafe extern "system" fn(CUvideodecoder) -> CUresult;
    type CuvidDecodePictureFn =
        unsafe extern "system" fn(CUvideodecoder, *mut CUVIDPICPARAMS) -> CUresult;
    type CuvidGetDecodeStatusFn =
        unsafe extern "system" fn(CUvideodecoder, c_int, *mut CUVIDGETDECODESTATUS) -> CUresult;
    type CuvidReconfigureDecoderFn =
        unsafe extern "system" fn(CUvideodecoder, *mut CUVIDRECONFIGUREDECODERINFO) -> CUresult;
    type CuvidCreateVideoParserFn =
        unsafe extern "system" fn(*mut CUvideoparser, *mut CUVIDPARSERPARAMS) -> CUresult;
    type CuvidParseVideoDataFn =
        unsafe extern "system" fn(CUvideoparser, *mut CUVIDSOURCEDATAPACKET) -> CUresult;
    type CuvidDestroyVideoParserFn = unsafe extern "system" fn(CUvideoparser) -> CUresult;
    type CuvidMapVideoFrameFn = unsafe extern "system" fn(
        CUvideodecoder,
        c_int,
        *mut u64,
        *mut u32,
        *mut CUVIDPROCPARAMS,
    ) -> CUresult;
    type CuvidUnmapVideoFrameFn = unsafe extern "system" fn(CUvideodecoder, u64) -> CUresult;

    // CUDA-D3D11 interop functions
    type CuGraphicsD3D11RegisterResourceFn =
        unsafe extern "system" fn(*mut CUgraphicsResource, *mut c_void, u32) -> CUresult;
    type CuGraphicsUnregisterResourceFn = unsafe extern "system" fn(CUgraphicsResource) -> CUresult;
    type CuGraphicsMapResourcesFn =
        unsafe extern "system" fn(c_int, *mut CUgraphicsResource, CUstream) -> CUresult;
    type CuGraphicsUnmapResourcesFn =
        unsafe extern "system" fn(c_int, *mut CUgraphicsResource, CUstream) -> CUresult;
    type CuGraphicsSubResourceGetMappedArrayFn =
        unsafe extern "system" fn(*mut CUarray, CUgraphicsResource, u32, u32) -> CUresult;
    type CuMemcpy2DFn = unsafe extern "system" fn(*const CUDA_MEMCPY2D) -> CUresult;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUDA_MEMCPY2D {
        srcXInBytes: usize,
        srcY: usize,
        srcMemoryType: u32,
        srcHost: *const c_void,
        srcDevice: CUdeviceptr,
        srcArray: CUarray,
        srcPitch: usize,
        dstXInBytes: usize,
        dstY: usize,
        dstMemoryType: u32,
        dstHost: *mut c_void,
        dstDevice: CUdeviceptr,
        dstArray: CUarray,
        dstPitch: usize,
        WidthInBytes: usize,
        Height: usize,
    }

    // CUDA graphics register flags for D3D11
    const CU_GRAPHICS_REGISTER_FLAGS_NONE: u32 = 0x00;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DecodedSurfaceKind {
        Nv12,
        P010,
    }

    impl DecodedSurfaceKind {
        fn from_bit_depth(bit_depth_minus8: u8) -> Self {
            if bit_depth_minus8 > 0 {
                Self::P010
            } else {
                Self::Nv12
            }
        }

        fn bytes_per_sample(self) -> usize {
            match self {
                Self::Nv12 => 1,
                Self::P010 => 2,
            }
        }

        fn cuda_output_format(self) -> i32 {
            match self {
                Self::Nv12 => CUDA_VIDEO_SURFACE_NV12,
                Self::P010 => CUDA_VIDEO_SURFACE_P016,
            }
        }
    }

    // D3D11 shared texture for CUDA-D3D11 interop
    #[allow(dead_code)]
    struct D3D11SharedTexture {
        device: ID3D11Device,
        context: ID3D11DeviceContext,
        y_texture: ID3D11Texture2D,
        uv_texture: ID3D11Texture2D,
        shared_handle_y: isize,
        shared_handle_uv: isize,
        width: u32,
        height: u32,
        surface_kind: DecodedSurfaceKind,
    }

    impl D3D11SharedTexture {
        fn new(width: u32, height: u32, surface_kind: DecodedSurfaceKind) -> Result<Self, String> {
            unsafe {
                // Create D3D11 device
                let mut device = None::<ID3D11Device>;
                let mut context = None::<ID3D11DeviceContext>;
                D3D11CreateDevice(
                    None,
                    windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE,
                    HMODULE::default(),
                    windows::Win32::Graphics::Direct3D11::D3D11_CREATE_DEVICE_FLAG(0),
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )
                .map_err(|e| format!("创建 D3D11 设备失败: {}", e))?;

                let device = device.ok_or("缺少 D3D11 device")?;
                let context = context.ok_or("缺少 D3D11 context")?;
                Self::from_device(device, context, width, height, surface_kind)
            }
        }

        unsafe fn new_with_device_ptr(
            width: u32,
            height: u32,
            surface_kind: DecodedSurfaceKind,
            device_ptr: *mut c_void,
        ) -> Result<Self, String> {
            if device_ptr.is_null() {
                return Err("D3D11 device pointer is null".to_string());
            }

            let device = unsafe {
                ID3D11Device::from_raw_borrowed(&device_ptr)
                    .ok_or("D3D11 device pointer is invalid")?
                    .clone()
            };
            let context = unsafe { device.GetImmediateContext() }
                .map_err(|e| format!("获取外部 D3D11 immediate context 失败: {e}"))?;
            Self::from_device(device, context, width, height, surface_kind)
        }

        fn from_device(
            device: ID3D11Device,
            context: ID3D11DeviceContext,
            width: u32,
            height: u32,
            surface_kind: DecodedSurfaceKind,
        ) -> Result<Self, String> {
            let (y_format, uv_format) = match surface_kind {
                DecodedSurfaceKind::Nv12 => (DXGI_FORMAT_R8_UNORM, DXGI_FORMAT_R8G8_UNORM),
                DecodedSurfaceKind::P010 => (DXGI_FORMAT_R16_UNORM, DXGI_FORMAT_R16G16_UNORM),
            };
            // Create Y plane texture (R8, single channel, shared)
            let y_desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: y_format,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: D3D11_RESOURCE_MISC_SHARED.0 as u32,
            };

            let mut y_texture = None::<ID3D11Texture2D>;
            unsafe {
                device
                    .CreateTexture2D(&y_desc, None, Some(&mut y_texture))
                    .map_err(|e| format!("创建 Y 纹理失败: {}", e))?;
            }
            let y_texture = y_texture.ok_or("缺少 Y 纹理")?;

            // Create UV plane texture (R8G8, two channels, shared)
            let uv_desc = D3D11_TEXTURE2D_DESC {
                Width: width / 2,
                Height: height / 2,
                MipLevels: 1,
                ArraySize: 1,
                Format: uv_format,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                CPUAccessFlags: 0,
                MiscFlags: D3D11_RESOURCE_MISC_SHARED.0 as u32,
            };

            let mut uv_texture = None::<ID3D11Texture2D>;
            unsafe {
                device
                    .CreateTexture2D(&uv_desc, None, Some(&mut uv_texture))
                    .map_err(|e| format!("创建 UV 纹理失败: {}", e))?;
            }
            let uv_texture = uv_texture.ok_or("缺少 UV 纹理")?;

            // Get shared handles using IDXGIResource::GetSharedHandle
            let y_resource: IDXGIResource = y_texture
                .cast()
                .map_err(|e| format!("转换 Y 纹理到 IDXGIResource 失败: {}", e))?;
            let shared_handle_y = unsafe { y_resource.GetSharedHandle() }
                .map_err(|e| format!("获取 Y 共享句柄失败: {}", e))?;

            let uv_resource: IDXGIResource = uv_texture
                .cast()
                .map_err(|e| format!("转换 UV 纹理到 IDXGIResource 失败: {}", e))?;
            let shared_handle_uv = unsafe { uv_resource.GetSharedHandle() }
                .map_err(|e| format!("获取 UV 共享句柄失败: {}", e))?;

            Ok(Self {
                device,
                context,
                y_texture,
                uv_texture,
                shared_handle_y: shared_handle_y.0 as isize,
                shared_handle_uv: shared_handle_uv.0 as isize,
                width,
                height,
                surface_kind,
            })
        }

        /// Get raw pointer to Y texture for CUDA-D3D11 interop
        fn y_texture_ptr(&self) -> *mut c_void {
            self.y_texture.as_raw()
        }

        /// Get raw pointer to UV texture for CUDA-D3D11 interop
        fn uv_texture_ptr(&self) -> *mut c_void {
            self.uv_texture.as_raw()
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DisplayRect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AspectRatio {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VideoSignalDescription {
        flags: u8,
        color_primaries: u8,
        transfer_characteristics: u8,
        matrix_coefficients: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDEOFORMAT {
        codec: i32,
        frame_rate: FrameRate,
        progressive_sequence: u8,
        bit_depth_luma_minus8: u8,
        bit_depth_chroma_minus8: u8,
        min_num_decode_surfaces: u8,
        coded_width: u32,
        coded_height: u32,
        display_area: DisplayRect,
        chroma_format: i32,
        bitrate: u32,
        display_aspect_ratio: AspectRatio,
        video_signal_description: VideoSignalDescription,
        seqhdr_data_length: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FrameRate {
        numerator: u32,
        denominator: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ShortRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDDECODECREATEINFO {
        ulWidth: u32,
        ulHeight: u32,
        ulNumDecodeSurfaces: u32,
        CodecType: i32,
        ChromaFormat: i32,
        ulCreationFlags: u32,
        bitDepthMinus8: u32,
        ulIntraDecodeOnly: u32,
        ulMaxWidth: u32,
        ulMaxHeight: u32,
        Reserved1: u32,
        display_area: ShortRect,
        OutputFormat: i32,
        DeinterlaceMode: i32,
        ulTargetWidth: u32,
        ulTargetHeight: u32,
        ulNumOutputSurfaces: u32,
        vidLock: CUvideoctxlock,
        target_rect: ShortRect,
        enableHistogram: u32,
        Reserved2: [u32; 4],
    }

    #[repr(C)]
    struct CUVIDPICPARAMS {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDPARSERDISPINFO {
        picture_index: c_int,
        progressive_frame: c_int,
        top_field_first: c_int,
        repeat_first_field: c_int,
        timestamp: CUvideotimestamp,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDPARSERPARAMS {
        CodecType: i32,
        ulMaxNumDecodeSurfaces: u32,
        ulClockRate: u32,
        ulErrorThreshold: u32,
        ulMaxDisplayDelay: u32,
        bitfields: u32,
        uReserved1: [u32; 4],
        pUserData: *mut c_void,
        pfnSequenceCallback:
            Option<unsafe extern "system" fn(*mut c_void, *mut CUVIDEOFORMAT) -> c_int>,
        pfnDecodePicture:
            Option<unsafe extern "system" fn(*mut c_void, *mut CUVIDPICPARAMS) -> c_int>,
        pfnDisplayPicture:
            Option<unsafe extern "system" fn(*mut c_void, *mut CUVIDPARSERDISPINFO) -> c_int>,
        pfnGetOperatingPoint: Option<unsafe extern "system" fn(*mut c_void, *mut c_void) -> c_int>,
        pvReserved2: [*mut c_void; 6],
        pExtVideoInfo: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDSOURCEDATAPACKET {
        flags: u32,
        payload_size: u32,
        payload: *const u8,
        timestamp: CUvideotimestamp,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDPROCPARAMS {
        progressive_frame: c_int,
        second_field: c_int,
        top_field_first: c_int,
        unpaired_field: c_int,
        reserved_flags: u32,
        reserved_zero: u32,
        raw_input_dptr: u64,
        raw_input_pitch: u32,
        raw_input_format: u32,
        raw_output_dptr: u64,
        raw_output_pitch: u32,
        raw_output_format: u32,
        raw_output_surface: u32,
        reserved1: u32,
        Reserved: [u32; 48],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CUVIDDECODECAPS {
        eCodecType: i32,
        eChromaFormat: i32,
        nBitDepthMinus8: u32,
        reserved1: [u32; 3],
        bIsSupported: u8,
        nNumNVDECs: u8,
        nOutputFormatMask: u16,
        nMaxWidth: u32,
        nMaxHeight: u32,
        nMaxMBCount: u32,
        nMinWidth: u16,
        nMinHeight: u16,
        bIsHistogramSupported: u8,
        nCounterBitDepth: u8,
        nMaxHistogramBins: u16,
        reserved3: [u32; 10],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CUVIDGETDECODESTATUS {
        decodeStatus: i32,
        reserved: [u32; 31],
        pReserved: [*mut c_void; 8],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CUVIDRECONFIGUREDECODERINFO {
        ulWidth: u32,
        ulHeight: u32,
        ulTargetWidth: u32,
        ulTargetHeight: u32,
        ulNumDecodeSurfaces: u32,
        display_area: ShortRect,
        target_rect: ShortRect,
        Reserved1: [u32; 8],
        Reserved2: [*mut c_void; 6],
    }

    struct LoadedModule(HMODULE);

    impl LoadedModule {
        fn load(name: &'static [u8]) -> Result<Self, String> {
            let module = unsafe { LoadLibraryA(PCSTR(name.as_ptr())) }.map_err(|_| {
                format!(
                    "failed to load {}",
                    String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
                )
            })?;
            Ok(Self(module))
        }

        fn load_symbol<T>(&self, name: &'static [u8]) -> Result<T, String>
        where
            T: Copy,
        {
            let proc =
                unsafe { GetProcAddress(self.0, PCSTR(name.as_ptr())) }.ok_or_else(|| {
                    format!(
                        "missing export {}",
                        String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
                    )
                })?;
            let ptr = proc as *const ();
            Ok(unsafe { mem::transmute_copy(&ptr) })
        }
    }

    impl Drop for LoadedModule {
        fn drop(&mut self) {
            unsafe {
                let _ = FreeLibrary(self.0);
            }
        }
    }

    struct CudaApi {
        _module: LoadedModule,
        cu_init: CuInitFn,
        cu_device_get_count: CuDeviceGetCountFn,
        cu_device_get: CuDeviceGetFn,
        cu_ctx_create: CuCtxCreateFn,
        cu_ctx_destroy: CuCtxDestroyFn,
        cu_ctx_push_current: CuCtxPushCurrentFn,
        cu_ctx_pop_current: CuCtxPopCurrentFn,
        cu_get_error_name: Option<CuGetErrorNameFn>,
        cu_get_error_string: Option<CuGetErrorStringFn>,
        cu_memcpy_dtoh: CuMemcpyDtoHFn,
        // CUDA-D3D11 interop functions
        cu_graphics_d3d11_register_resource: Option<CuGraphicsD3D11RegisterResourceFn>,
        cu_graphics_unregister_resource: Option<CuGraphicsUnregisterResourceFn>,
        cu_graphics_map_resources: Option<CuGraphicsMapResourcesFn>,
        cu_graphics_unmap_resources: Option<CuGraphicsUnmapResourcesFn>,
        cu_graphics_sub_resource_get_mapped_array: Option<CuGraphicsSubResourceGetMappedArrayFn>,
        cu_memcpy_2d: Option<CuMemcpy2DFn>,
    }

    impl CudaApi {
        fn load() -> Result<Self, String> {
            let module = LoadedModule::load(b"nvcuda.dll\0".as_ref())?;
            Ok(Self {
                cu_init: module.load_symbol(b"cuInit\0".as_ref())?,
                cu_device_get_count: module.load_symbol(b"cuDeviceGetCount\0".as_ref())?,
                cu_device_get: module.load_symbol(b"cuDeviceGet\0".as_ref())?,
                cu_ctx_create: module.load_symbol(b"cuCtxCreate_v2\0".as_ref())?,
                cu_ctx_destroy: module.load_symbol(b"cuCtxDestroy_v2\0".as_ref())?,
                cu_ctx_push_current: module.load_symbol(b"cuCtxPushCurrent_v2\0".as_ref())?,
                cu_ctx_pop_current: module.load_symbol(b"cuCtxPopCurrent_v2\0".as_ref())?,
                cu_get_error_name: module.load_symbol(b"cuGetErrorName\0".as_ref()).ok(),
                cu_get_error_string: module.load_symbol(b"cuGetErrorString\0".as_ref()).ok(),
                cu_memcpy_dtoh: module.load_symbol(b"cuMemcpyDtoH_v2\0".as_ref())?,
                // CUDA-D3D11 interop functions (may not be available in all CUDA versions)
                cu_graphics_d3d11_register_resource: module
                    .load_symbol(b"cuGraphicsD3D11RegisterResource\0".as_ref())
                    .ok(),
                cu_graphics_unregister_resource: module
                    .load_symbol(b"cuGraphicsUnregisterResource\0".as_ref())
                    .ok(),
                cu_graphics_map_resources: module
                    .load_symbol(b"cuGraphicsMapResources\0".as_ref())
                    .ok(),
                cu_graphics_unmap_resources: module
                    .load_symbol(b"cuGraphicsUnmapResources\0".as_ref())
                    .ok(),
                cu_graphics_sub_resource_get_mapped_array: module
                    .load_symbol(b"cuGraphicsSubResourceGetMappedArray\0".as_ref())
                    .ok(),
                cu_memcpy_2d: module.load_symbol(b"cuMemcpy2D_v2\0".as_ref()).ok(),
                _module: module,
            })
        }
    }

    struct CudaContextGuard<'a> {
        cuda: &'a CudaApi,
        active: bool,
    }

    impl<'a> CudaContextGuard<'a> {
        fn push(cuda: &'a CudaApi, context: CUcontext) -> Result<Self, String> {
            unsafe {
                cuda_ok(
                    cuda,
                    (cuda.cu_ctx_push_current)(context),
                    "context",
                    "cuCtxPushCurrent_v2",
                )?;
            }
            Ok(Self { cuda, active: true })
        }
    }

    impl Drop for CudaContextGuard<'_> {
        fn drop(&mut self) {
            if !self.active {
                return;
            }
            let mut previous = ptr::null_mut();
            unsafe {
                let _ = (self.cuda.cu_ctx_pop_current)(&mut previous);
            }
            self.active = false;
        }
    }

    struct CuvidApi {
        _module: LoadedModule,
        cuvid_get_decoder_caps: Option<CuvidGetDecoderCapsFn>,
        cuvid_create_decoder: CuvidCreateDecoderFn,
        cuvid_destroy_decoder: CuvidDestroyDecoderFn,
        cuvid_decode_picture: CuvidDecodePictureFn,
        cuvid_get_decode_status: Option<CuvidGetDecodeStatusFn>,
        cuvid_reconfigure_decoder: Option<CuvidReconfigureDecoderFn>,
        cuvid_create_video_parser: CuvidCreateVideoParserFn,
        cuvid_parse_video_data: CuvidParseVideoDataFn,
        cuvid_destroy_video_parser: CuvidDestroyVideoParserFn,
        cuvid_map_video_frame: CuvidMapVideoFrameFn,
        cuvid_unmap_video_frame: CuvidUnmapVideoFrameFn,
    }

    impl CuvidApi {
        fn load() -> Result<Self, String> {
            let module = LoadedModule::load(b"nvcuvid.dll\0".as_ref())?;
            Ok(Self {
                cuvid_get_decoder_caps: module.load_symbol(b"cuvidGetDecoderCaps\0".as_ref()).ok(),
                cuvid_create_decoder: module.load_symbol(b"cuvidCreateDecoder\0".as_ref())?,
                cuvid_destroy_decoder: module.load_symbol(b"cuvidDestroyDecoder\0".as_ref())?,
                cuvid_decode_picture: module.load_symbol(b"cuvidDecodePicture\0".as_ref())?,
                cuvid_get_decode_status: module
                    .load_symbol(b"cuvidGetDecodeStatus\0".as_ref())
                    .ok(),
                cuvid_reconfigure_decoder: module
                    .load_symbol(b"cuvidReconfigureDecoder\0".as_ref())
                    .ok(),
                cuvid_create_video_parser: module
                    .load_symbol(b"cuvidCreateVideoParser\0".as_ref())?,
                cuvid_parse_video_data: module.load_symbol(b"cuvidParseVideoData\0".as_ref())?,
                cuvid_destroy_video_parser: module
                    .load_symbol(b"cuvidDestroyVideoParser\0".as_ref())?,
                cuvid_map_video_frame: module.load_symbol(b"cuvidMapVideoFrame64\0".as_ref())?,
                cuvid_unmap_video_frame: module
                    .load_symbol(b"cuvidUnmapVideoFrame64\0".as_ref())?,
                _module: module,
            })
        }
    }

    pub struct NvdecSession {
        _cuda: CudaApi,
        _cuvid: CuvidApi,
        context: CUcontext,
        parser: CUvideoparser,
        parser_codec: i32,
        callback_state: Box<CallbackState>,
        shared_texture: Option<D3D11SharedTexture>,
        external_d3d11_device_ptr: Option<*mut c_void>,
        enable_shared_texture: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SequenceFormat {
        codec: i32,
        coded_width: u32,
        coded_height: u32,
        display_width: u32,
        display_height: u32,
        chroma_format: i32,
        bit_depth_minus8: u8,
        min_decode_surfaces: u8,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DecoderConfig {
        codec: i32,
        coded_width: u32,
        coded_height: u32,
        display_width: u32,
        display_height: u32,
        chroma_format: i32,
        bit_depth_minus8: u8,
        decode_surfaces: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SequenceChangeDecision {
        Reuse,
        Recreate(&'static str),
        Unsupported(&'static str),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ReconfigureDecision {
        Attempt,
        SkipUnsupported,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NvdecCodec {
        H264,
        Hevc,
        Av1,
        Unknown(i32),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct NvdecSupportRequest {
        codec: NvdecCodec,
        bit_depth_minus8: u8,
        chroma_format: i32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NvdecSupportDecision {
        Supported,
        Unsupported(&'static str),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct NvdecCapabilityRequest {
        codec: NvdecCodec,
        bit_depth_minus8: u8,
        chroma_format: i32,
    }

    struct CallbackState {
        cuvid_create_decoder: CuvidCreateDecoderFn,
        cuvid_destroy_decoder: CuvidDestroyDecoderFn,
        cuvid_decode_picture: CuvidDecodePictureFn,
        cuvid_get_decode_status: Option<CuvidGetDecodeStatusFn>,
        cuvid_reconfigure_decoder: Option<CuvidReconfigureDecoderFn>,
        cuvid_map_video_frame: CuvidMapVideoFrameFn,
        cuvid_unmap_video_frame: CuvidUnmapVideoFrameFn,
        cu_get_error_name: Option<CuGetErrorNameFn>,
        cu_get_error_string: Option<CuGetErrorStringFn>,
        cu_memcpy_dtoh: CuMemcpyDtoHFn,
        // CUDA-D3D11 interop functions for GPU zero-copy
        cu_graphics_d3d11_register_resource: Option<CuGraphicsD3D11RegisterResourceFn>,
        cu_graphics_unregister_resource: Option<CuGraphicsUnregisterResourceFn>,
        cu_graphics_map_resources: Option<CuGraphicsMapResourcesFn>,
        cu_graphics_unmap_resources: Option<CuGraphicsUnmapResourcesFn>,
        cu_graphics_sub_resource_get_mapped_array: Option<CuGraphicsSubResourceGetMappedArrayFn>,
        cu_memcpy_2d: Option<CuMemcpy2DFn>,
        // Registered CUDA graphics resources for D3D11 textures
        cuda_resource_y: Option<CUgraphicsResource>,
        cuda_resource_uv: Option<CUgraphicsResource>,
        // D3D11 texture pointers for CUDA registration (set when shared texture is enabled)
        d3d11_y_texture_ptr: Option<*mut c_void>,
        d3d11_uv_texture_ptr: Option<*mut c_void>,
        // CUDA context for GPU operations
        cuda_context: CUcontext,
        decoder: CUvideodecoder,
        decoder_config: Option<DecoderConfig>,
        sequence_width: u32,
        sequence_height: u32,
        diagnostics: NvdecDiagnostics,
        output_mode: NvdecOutputMode,
        last_error: Option<String>,
        frames: Vec<NvdecDecodedFrame>,
        // Shared texture support (when enabled, outputs D3D11SharedNv12 frames)
        use_shared_texture: bool,
        shared_texture_y: Option<isize>,
        shared_texture_uv: Option<isize>,
    }

    impl NvdecSession {
        pub fn new_for_codec(
            codec: super::NvdecCodecKind,
            output_mode: NvdecOutputMode,
        ) -> Result<Self, String> {
            Self::new_for_codec_with_d3d11_device_ptr(codec, output_mode, None)
        }

        pub fn new_for_codec_with_d3d11_device_ptr(
            codec: super::NvdecCodecKind,
            output_mode: NvdecOutputMode,
            external_d3d11_device_ptr: Option<*mut c_void>,
        ) -> Result<Self, String> {
            let parser_codec = match codec {
                super::NvdecCodecKind::H264 => CUDA_VIDEO_CODEC_H264,
                super::NvdecCodecKind::Hevc | super::NvdecCodecKind::HevcMain10 => {
                    CUDA_VIDEO_CODEC_HEVC
                }
                super::NvdecCodecKind::Av1 => CUDA_VIDEO_CODEC_AV1,
            };
            let initial_probe_bit_depth = match codec {
                super::NvdecCodecKind::HevcMain10 => 2,
                _ => 0,
            };

            let cuda = CudaApi::load()?;
            let cuvid = CuvidApi::load()?;

            unsafe {
                cuda_ok(&cuda, (cuda.cu_init)(0), "init", "cuInit")?;
            }

            let mut count = 0;
            unsafe {
                cuda_ok(
                    &cuda,
                    (cuda.cu_device_get_count)(&mut count),
                    "init",
                    "cuDeviceGetCount",
                )?;
            }
            if count <= 0 {
                return Err("cuDeviceGetCount reported no CUDA devices".to_string());
            }

            if let Some(get_caps) = cuvid.cuvid_get_decoder_caps {
                let mut caps = CUVIDDECODECAPS {
                    eCodecType: parser_codec,
                    eChromaFormat: CUDA_VIDEO_CHROMA_420,
                    nBitDepthMinus8: initial_probe_bit_depth,
                    ..Default::default()
                };
                let caps_result = unsafe { get_caps(&mut caps) };
                if caps_result == CUDA_SUCCESS && caps.bIsSupported == 0 {
                    return Err(format!(
                        "cuvidGetDecoderCaps reported {} NVDEC unsupported",
                        describe_codec(parser_codec)
                    ));
                }
            }

            let mut device = 0;
            unsafe {
                cuda_ok(
                    &cuda,
                    (cuda.cu_device_get)(&mut device, 0),
                    "init",
                    "cuDeviceGet",
                )?;
            }

            let mut context = ptr::null_mut();
            unsafe {
                cuda_ok(
                    &cuda,
                    (cuda.cu_ctx_create)(&mut context, 0, device),
                    "init",
                    "cuCtxCreate_v2",
                )?;
            }

            let mut callback_state = Box::new(CallbackState {
                cuvid_create_decoder: cuvid.cuvid_create_decoder,
                cuvid_destroy_decoder: cuvid.cuvid_destroy_decoder,
                cuvid_decode_picture: cuvid.cuvid_decode_picture,
                cuvid_get_decode_status: cuvid.cuvid_get_decode_status,
                cuvid_reconfigure_decoder: cuvid.cuvid_reconfigure_decoder,
                cuvid_map_video_frame: cuvid.cuvid_map_video_frame,
                cuvid_unmap_video_frame: cuvid.cuvid_unmap_video_frame,
                cu_get_error_name: cuda.cu_get_error_name,
                cu_get_error_string: cuda.cu_get_error_string,
                cu_memcpy_dtoh: cuda.cu_memcpy_dtoh,
                // CUDA-D3D11 interop functions
                cu_graphics_d3d11_register_resource: cuda.cu_graphics_d3d11_register_resource,
                cu_graphics_unregister_resource: cuda.cu_graphics_unregister_resource,
                cu_graphics_map_resources: cuda.cu_graphics_map_resources,
                cu_graphics_unmap_resources: cuda.cu_graphics_unmap_resources,
                cu_graphics_sub_resource_get_mapped_array: cuda
                    .cu_graphics_sub_resource_get_mapped_array,
                cu_memcpy_2d: cuda.cu_memcpy_2d,
                // Registered CUDA resources (initialized when shared texture is created)
                cuda_resource_y: None,
                cuda_resource_uv: None,
                // D3D11 texture pointers (set when shared texture is enabled)
                d3d11_y_texture_ptr: None,
                d3d11_uv_texture_ptr: None,
                // CUDA context for GPU operations
                cuda_context: context,
                decoder: ptr::null_mut(),
                decoder_config: None,
                sequence_width: 0,
                sequence_height: 0,
                diagnostics: NvdecDiagnostics::default(),
                output_mode,
                last_error: None,
                frames: Vec::new(),
                use_shared_texture: false,
                shared_texture_y: None,
                shared_texture_uv: None,
            });

            let mut parser = ptr::null_mut();
            let mut params = CUVIDPARSERPARAMS {
                CodecType: parser_codec,
                ulMaxNumDecodeSurfaces: 8,
                ulClockRate: 10_000_000,
                ulErrorThreshold: 0,
                ulMaxDisplayDelay: 0,
                bitfields: parser_flags(parser_codec),
                uReserved1: [0; 4],
                pUserData: callback_state.as_mut() as *mut CallbackState as *mut c_void,
                pfnSequenceCallback: Some(sequence_callback),
                pfnDecodePicture: Some(decode_callback),
                pfnDisplayPicture: Some(display_callback),
                pfnGetOperatingPoint: operating_point_callback_for(parser_codec),
                pvReserved2: [ptr::null_mut(); 6],
                pExtVideoInfo: ptr::null_mut(),
            };
            unsafe {
                cuda_ok(
                    &cuda,
                    (cuvid.cuvid_create_video_parser)(&mut parser, &mut params),
                    "init",
                    "cuvidCreateVideoParser",
                )?;
            }

            Ok(Self {
                _cuda: cuda,
                _cuvid: cuvid,
                context,
                parser,
                parser_codec,
                callback_state,
                shared_texture: None,
                external_d3d11_device_ptr,
                enable_shared_texture: false, // Disabled by default
            })
        }

        /// Enable or disable D3D11 shared texture output
        #[allow(dead_code)]
        pub fn enable_shared_texture(&mut self, enable: bool) {
            self.enable_shared_texture = enable;
            self.callback_state.use_shared_texture = enable;

            // If enabling and shared texture doesn't exist, create it
            if enable && self.shared_texture.is_none() {
                // Create shared texture when we know the video dimensions
                // This will happen during the first decode callback
            }
        }

        pub fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), String> {
            if access_unit.is_empty() {
                self.callback_state.clear_access_unit_state();
                let message = "nvdec input validation failed: empty access unit".to_string();
                self.callback_state.last_error = Some(message.clone());
                self.callback_state.diagnostics.last_stage = Some("input".to_string());
                self.callback_state.diagnostics.last_api = Some("push_access_unit".to_string());
                self.callback_state.diagnostics.last_error_description =
                    Some("empty access unit".to_string());
                return Err(message);
            }

            if matches!(
                self.parser_codec,
                CUDA_VIDEO_CODEC_H264 | CUDA_VIDEO_CODEC_HEVC
            ) && !looks_like_annexb(access_unit)
            {
                self.callback_state.clear_access_unit_state();
                let message = format!(
                    "nvdec input validation failed: expected {} Annex-B access unit",
                    describe_codec(self.parser_codec)
                );
                self.callback_state.last_error = Some(message.clone());
                self.callback_state.diagnostics.last_stage = Some("input".to_string());
                self.callback_state.diagnostics.last_api = Some("push_access_unit".to_string());
                self.callback_state.diagnostics.last_error_description = Some(format!(
                    "expected {} Annex-B start code",
                    describe_codec(self.parser_codec)
                ));
                return Err(message);
            }

            self.callback_state.clear_access_unit_state();

            let converted_access_unit = if self.parser_codec == CUDA_VIDEO_CODEC_AV1 {
                av1_low_overhead_obu_to_annexb(access_unit)
            } else {
                None
            };
            let packet_payload = converted_access_unit.as_deref().unwrap_or(access_unit);

            let payload_size = u32::try_from(packet_payload.len())
                .map_err(|_| "access unit too large for NVDEC packet".to_string())?;
            let mut packet = CUVIDSOURCEDATAPACKET {
                flags: CUVID_PKT_ENDOFPICTURE,
                payload_size,
                payload: packet_payload.as_ptr(),
                timestamp: 0,
            };

            let _context_guard = CudaContextGuard::push(&self._cuda, self.context)?;

            unsafe {
                cuda_ok(
                    &self._cuda,
                    (self._cuvid.cuvid_parse_video_data)(self.parser, &mut packet),
                    "parse",
                    "cuvidParseVideoData",
                )?;
            }

            if let Some(error) = self.callback_state.last_error.take() {
                return Err(error);
            }

            if self.callback_state.sequence_width == 0 || self.callback_state.sequence_height == 0 {
                return Err(
                    "nvdec parse failed at parser-state: parser did not report sequence information"
                        .to_string(),
                );
            }

            if self.callback_state.diagnostics.decode_calls == 0 {
                return Err(
                    "nvdec decode failed at callback-state: parser completed without decode activity"
                        .to_string(),
                );
            }

            // Create or recreate shared texture if needed. NVDEC can reconfigure
            // after a display-mode/profile change; stale shared textures force
            // the hot path back through CPU NV12.
            if self.enable_shared_texture {
                let (width, height) = self.callback_state.output_dimensions_u32();
                if width > 0 && height > 0 {
                    let surface_kind = self
                        .callback_state
                        .decoder_config
                        .as_ref()
                        .map(|config| DecodedSurfaceKind::from_bit_depth(config.bit_depth_minus8))
                        .unwrap_or(DecodedSurfaceKind::Nv12);
                    let needs_texture = self
                        .shared_texture
                        .as_ref()
                        .map(|texture| {
                            texture.width != width
                                || texture.height != height
                                || texture.surface_kind != surface_kind
                        })
                        .unwrap_or(true);
                    if !needs_texture {
                        return Ok(());
                    }

                    self.callback_state.clear_shared_texture_registration();
                    self.shared_texture = None;
                    let texture_result = if let Some(device_ptr) = self.external_d3d11_device_ptr {
                        unsafe {
                            D3D11SharedTexture::new_with_device_ptr(
                                width,
                                height,
                                surface_kind,
                                device_ptr,
                            )
                        }
                    } else {
                        D3D11SharedTexture::new(width, height, surface_kind)
                    };
                    match texture_result {
                        Ok(texture) => {
                            self.callback_state.shared_texture_y = Some(texture.shared_handle_y);
                            self.callback_state.shared_texture_uv = Some(texture.shared_handle_uv);
                            // Set D3D11 texture pointers for CUDA-D3D11 interop
                            self.callback_state.d3d11_y_texture_ptr = Some(texture.y_texture_ptr());
                            self.callback_state.d3d11_uv_texture_ptr =
                                Some(texture.uv_texture_ptr());
                            self.shared_texture = Some(texture);
                        }
                        Err(e) => {
                            // Fall back to CPU path if shared texture creation fails
                            eprintln!(
                                "Failed to create shared texture: {e}, falling back to CPU path"
                            );
                            self.enable_shared_texture = false;
                            self.callback_state.use_shared_texture = false;
                        }
                    }
                }
            }

            Ok(())
        }

        pub fn drain_decoded_frames(&mut self) -> Vec<NvdecDecodedFrame> {
            mem::take(&mut self.callback_state.frames)
        }

        pub fn diagnostics(&self) -> NvdecDiagnostics {
            self.callback_state.diagnostics.clone()
        }
    }

    impl Drop for NvdecSession {
        fn drop(&mut self) {
            unsafe {
                let context_guard = if !self.context.is_null() {
                    CudaContextGuard::push(&self._cuda, self.context).ok()
                } else {
                    None
                };
                self.callback_state.clear_shared_texture_registration();
                if !self.parser.is_null() {
                    let _ = (self._cuvid.cuvid_destroy_video_parser)(self.parser);
                }
                if !self.callback_state.decoder.is_null() {
                    let _ = (self._cuvid.cuvid_destroy_decoder)(self.callback_state.decoder);
                }
                drop(context_guard);
                if !self.context.is_null() {
                    let _ = (self._cuda.cu_ctx_destroy)(self.context);
                }
            }
        }
    }

    impl CallbackState {
        fn clear_access_unit_state(&mut self) {
            self.last_error = None;
            self.diagnostics.last_stage = None;
            self.diagnostics.last_api = None;
            self.diagnostics.last_code = None;
            self.diagnostics.last_error_name = None;
            self.diagnostics.last_error_description = None;
            self.diagnostics.last_picture_index = None;
            self.diagnostics.decode_calls = 0;
            self.diagnostics.display_calls = 0;
            self.diagnostics.last_decode_status_phase = None;
            self.diagnostics.last_decode_status_raw = None;
            self.diagnostics.last_decode_status_description = None;
            self.diagnostics.last_reconfigure_attempted = false;
            self.diagnostics.last_reconfigure_result = None;
            self.diagnostics.last_reconfigure_from_coded_width = None;
            self.diagnostics.last_reconfigure_from_coded_height = None;
            self.diagnostics.last_reconfigure_to_coded_width = None;
            self.diagnostics.last_reconfigure_to_coded_height = None;
            self.diagnostics.reconfigure_fallback_used = false;
        }

        fn clear_shared_texture_registration(&mut self) {
            if let Some(unregister) = self.cu_graphics_unregister_resource {
                if let Some(resource) = self.cuda_resource_y.take() {
                    let _ = unsafe { unregister(resource) };
                }
                if let Some(resource) = self.cuda_resource_uv.take() {
                    let _ = unsafe { unregister(resource) };
                }
            } else {
                self.cuda_resource_y = None;
                self.cuda_resource_uv = None;
            }
            self.d3d11_y_texture_ptr = None;
            self.d3d11_uv_texture_ptr = None;
            self.shared_texture_y = None;
            self.shared_texture_uv = None;
        }

        fn record_recreate(&mut self, reason: &'static str, config: &DecoderConfig) {
            self.diagnostics.recreate_count += 1;
            self.diagnostics.last_recreate_reason = Some(reason.to_string());
            self.diagnostics.last_sequence_decision = Some("recreate".to_string());
            self.diagnostics.last_recreate_to_coded_width = Some(config.coded_width);
            self.diagnostics.last_recreate_to_coded_height = Some(config.coded_height);
            self.diagnostics.active_coded_width = Some(config.coded_width);
            self.diagnostics.active_coded_height = Some(config.coded_height);
            self.diagnostics.active_display_width = Some(config.display_width);
            self.diagnostics.active_display_height = Some(config.display_height);
        }

        fn record_active_config(&mut self, config: &DecoderConfig) {
            self.diagnostics.active_coded_width = Some(config.coded_width);
            self.diagnostics.active_coded_height = Some(config.coded_height);
            self.diagnostics.active_display_width = Some(config.display_width);
            self.diagnostics.active_display_height = Some(config.display_height);
        }

        fn record_sequence(&mut self, sequence: &SequenceFormat) {
            self.diagnostics.last_sequence_coded_width = Some(sequence.coded_width);
            self.diagnostics.last_sequence_coded_height = Some(sequence.coded_height);
            self.diagnostics.last_sequence_display_width = Some(sequence.display_width);
            self.diagnostics.last_sequence_display_height = Some(sequence.display_height);
            self.diagnostics.last_sequence_bit_depth_minus8 = Some(sequence.bit_depth_minus8);
            self.diagnostics.last_sequence_chroma_format = Some(sequence.chroma_format);
            self.diagnostics.last_support_codec = Some(describe_codec(sequence.codec).to_string());
            self.diagnostics.last_support_bit_depth_minus8 = Some(sequence.bit_depth_minus8);
            self.diagnostics.last_support_chroma_format = Some(sequence.chroma_format);
        }

        fn record_sequence_decision(&mut self, decision: &str) {
            self.diagnostics.last_sequence_decision = Some(decision.to_string());
        }

        fn record_support_decision(&mut self, decision: &str, reason: Option<&str>) {
            self.diagnostics.last_support_decision = Some(decision.to_string());
            self.diagnostics.last_support_reason = reason.map(ToString::to_string);
        }

        fn record_recreate_from(&mut self, config: &DecoderConfig) {
            self.diagnostics.last_recreate_from_coded_width = Some(config.coded_width);
            self.diagnostics.last_recreate_from_coded_height = Some(config.coded_height);
        }

        fn record_reconfigure_attempt(&mut self, from: &DecoderConfig, to: &SequenceFormat) {
            self.diagnostics.last_reconfigure_attempted = true;
            self.diagnostics.last_reconfigure_from_coded_width = Some(from.coded_width);
            self.diagnostics.last_reconfigure_from_coded_height = Some(from.coded_height);
            self.diagnostics.last_reconfigure_to_coded_width = Some(to.coded_width);
            self.diagnostics.last_reconfigure_to_coded_height = Some(to.coded_height);
        }

        fn record_reconfigure_result(&mut self, result: String) {
            self.diagnostics.last_reconfigure_result = Some(result);
        }

        fn record_decode_status_snapshot(
            &mut self,
            phase: &'static str,
            raw: Option<i32>,
            description: String,
        ) {
            self.diagnostics.last_decode_status_phase = Some(phase.to_string());
            self.diagnostics.last_decode_status_raw = raw;
            self.diagnostics.last_decode_status_description = Some(description);
        }

        fn output_dimensions(&self) -> (usize, usize) {
            decoder_output_dimensions(
                self.decoder_config.as_ref(),
                self.sequence_width,
                self.sequence_height,
            )
        }

        fn output_dimensions_u32(&self) -> (u32, u32) {
            decoder_output_dimensions_u32(
                self.decoder_config.as_ref(),
                self.sequence_width,
                self.sequence_height,
            )
        }

        fn record_failure(
            &mut self,
            stage: &'static str,
            api: &'static str,
            code: CUresult,
            context: Option<String>,
        ) {
            let (name, description) =
                describe_cuda_error(self.cu_get_error_name, self.cu_get_error_string, code);
            self.diagnostics.last_stage = Some(stage.to_string());
            self.diagnostics.last_api = Some(api.to_string());
            self.diagnostics.last_code = Some(code);
            self.diagnostics.last_error_name = name.clone();
            self.diagnostics.last_error_description = description.clone().or(context.clone());
            self.last_error = Some(format_cuda_failure(
                stage,
                api,
                code,
                name.as_deref(),
                description.as_deref(),
                context.as_deref(),
            ));
        }

        fn record_shared_copy_failure_code(
            &mut self,
            stage: &'static str,
            api: &'static str,
            code: CUresult,
            context: Option<String>,
        ) {
            let (name, description) =
                describe_cuda_error(self.cu_get_error_name, self.cu_get_error_string, code);
            self.diagnostics.record_shared_copy_failure(
                stage,
                api,
                Some(code),
                name,
                description.or(context),
            );
        }

        fn record_shared_copy_failure_text(
            &mut self,
            stage: &'static str,
            api: &'static str,
            description: &'static str,
        ) {
            self.diagnostics.record_shared_copy_failure(
                stage,
                api,
                None,
                None,
                Some(description.to_string()),
            );
        }

        /// Attempt GPU zero-copy from CUDA decoded frame to D3D11 shared texture
        /// Returns true if successful, false if fallback to CPU path is needed
        #[allow(clippy::too_many_arguments)]
        fn try_gpu_zero_copy(
            &mut self,
            _cuda_context: CUcontext,
            d3d11_y_texture: *mut c_void,
            d3d11_uv_texture: *mut c_void,
            cuda_src_ptr: CUdeviceptr,
            y_pitch: u32,
            width: usize,
            height: usize,
            surface_kind: DecodedSurfaceKind,
        ) -> bool {
            // Check if all required CUDA-D3D11 interop functions are available
            let register_fn = match self.cu_graphics_d3d11_register_resource {
                Some(f) => f,
                None => {
                    self.record_shared_copy_failure_text(
                        "capability",
                        "cuGraphicsD3D11RegisterResource",
                        "CUDA-D3D11 interop register function unavailable",
                    );
                    return false;
                }
            };
            let unregister_fn = match self.cu_graphics_unregister_resource {
                Some(f) => f,
                None => {
                    self.record_shared_copy_failure_text(
                        "capability",
                        "cuGraphicsUnregisterResource",
                        "CUDA graphics unregister function unavailable",
                    );
                    return false;
                }
            };
            let map_fn = match self.cu_graphics_map_resources {
                Some(f) => f,
                None => {
                    self.record_shared_copy_failure_text(
                        "capability",
                        "cuGraphicsMapResources",
                        "CUDA graphics map function unavailable",
                    );
                    return false;
                }
            };
            let unmap_fn = match self.cu_graphics_unmap_resources {
                Some(f) => f,
                None => {
                    self.record_shared_copy_failure_text(
                        "capability",
                        "cuGraphicsUnmapResources",
                        "CUDA graphics unmap function unavailable",
                    );
                    return false;
                }
            };
            let get_array_fn = match self.cu_graphics_sub_resource_get_mapped_array {
                Some(f) => f,
                None => {
                    self.record_shared_copy_failure_text(
                        "capability",
                        "cuGraphicsSubResourceGetMappedArray",
                        "CUDA graphics mapped array function unavailable",
                    );
                    return false;
                }
            };
            let copy_fn = match self.cu_memcpy_2d {
                Some(f) => f,
                None => {
                    self.record_shared_copy_failure_text(
                        "capability",
                        "cuMemcpy2D_v2",
                        "CUDA 2D copy function unavailable",
                    );
                    return false;
                }
            };

            // Register D3D11 textures with CUDA if not already registered
            if self.cuda_resource_y.is_none() {
                let mut resource_y: CUgraphicsResource = ptr::null_mut();
                let result = unsafe {
                    register_fn(
                        &mut resource_y,
                        d3d11_y_texture,
                        CU_GRAPHICS_REGISTER_FLAGS_NONE,
                    )
                };
                if result != CUDA_SUCCESS {
                    self.record_shared_copy_failure_code(
                        "register",
                        "cuGraphicsD3D11RegisterResource:Y",
                        result,
                        None,
                    );
                    return false;
                }
                self.cuda_resource_y = Some(resource_y);
            }

            if self.cuda_resource_uv.is_none() {
                let mut resource_uv: CUgraphicsResource = ptr::null_mut();
                let result = unsafe {
                    register_fn(
                        &mut resource_uv,
                        d3d11_uv_texture,
                        CU_GRAPHICS_REGISTER_FLAGS_NONE,
                    )
                };
                if result != CUDA_SUCCESS {
                    // Cleanup Y resource on failure
                    if let Some(res) = self.cuda_resource_y.take() {
                        let _ = unsafe { unregister_fn(res) };
                    }
                    self.record_shared_copy_failure_code(
                        "register",
                        "cuGraphicsD3D11RegisterResource:UV",
                        result,
                        None,
                    );
                    return false;
                }
                self.cuda_resource_uv = Some(resource_uv);
            }

            let mut resources = [
                self.cuda_resource_y.unwrap(),
                self.cuda_resource_uv.unwrap(),
            ];

            // Map resources for CUDA access
            let map_result = unsafe { map_fn(2, resources.as_mut_ptr(), ptr::null_mut()) };
            if map_result != CUDA_SUCCESS {
                self.record_shared_copy_failure_code(
                    "map",
                    "cuGraphicsMapResources",
                    map_result,
                    None,
                );
                return false;
            }

            let mut y_array: CUarray = ptr::null_mut();
            let y_array_result =
                unsafe { get_array_fn(&mut y_array, self.cuda_resource_y.unwrap(), 0, 0) };
            if y_array_result != CUDA_SUCCESS {
                unsafe { unmap_fn(2, resources.as_mut_ptr(), ptr::null_mut()) };
                self.record_shared_copy_failure_code(
                    "array",
                    "cuGraphicsSubResourceGetMappedArray:Y",
                    y_array_result,
                    None,
                );
                return false;
            }

            let mut uv_array: CUarray = ptr::null_mut();
            let uv_array_result =
                unsafe { get_array_fn(&mut uv_array, self.cuda_resource_uv.unwrap(), 0, 0) };
            if uv_array_result != CUDA_SUCCESS {
                unsafe { unmap_fn(2, resources.as_mut_ptr(), ptr::null_mut()) };
                self.record_shared_copy_failure_code(
                    "array",
                    "cuGraphicsSubResourceGetMappedArray:UV",
                    uv_array_result,
                    None,
                );
                return false;
            }

            let copy_y = CUDA_MEMCPY2D {
                srcXInBytes: 0,
                srcY: 0,
                srcMemoryType: CU_MEMORYTYPE_DEVICE,
                srcHost: ptr::null(),
                srcDevice: cuda_src_ptr,
                srcArray: ptr::null_mut(),
                srcPitch: y_pitch as usize,
                dstXInBytes: 0,
                dstY: 0,
                dstMemoryType: CU_MEMORYTYPE_ARRAY,
                dstHost: ptr::null_mut(),
                dstDevice: 0,
                dstArray: y_array,
                dstPitch: 0,
                WidthInBytes: width * surface_kind.bytes_per_sample(),
                Height: height,
            };
            let copy_result = unsafe { copy_fn(&copy_y) };
            if copy_result != CUDA_SUCCESS {
                unsafe { unmap_fn(2, resources.as_mut_ptr(), ptr::null_mut()) };
                self.record_shared_copy_failure_code("copy", "cuMemcpy2D_v2:Y", copy_result, None);
                return false;
            }

            let copy_uv = CUDA_MEMCPY2D {
                srcXInBytes: 0,
                srcY: 0,
                srcMemoryType: CU_MEMORYTYPE_DEVICE,
                srcHost: ptr::null(),
                srcDevice: cuda_src_ptr + (y_pitch as CUdeviceptr * height as CUdeviceptr),
                srcArray: ptr::null_mut(),
                srcPitch: y_pitch as usize,
                dstXInBytes: 0,
                dstY: 0,
                dstMemoryType: CU_MEMORYTYPE_ARRAY,
                dstHost: ptr::null_mut(),
                dstDevice: 0,
                dstArray: uv_array,
                dstPitch: 0,
                WidthInBytes: width * surface_kind.bytes_per_sample(),
                Height: height / 2,
            };
            let copy_result_uv = unsafe { copy_fn(&copy_uv) };
            if copy_result_uv != CUDA_SUCCESS {
                unsafe { unmap_fn(2, resources.as_mut_ptr(), ptr::null_mut()) };
                self.record_shared_copy_failure_code(
                    "copy",
                    "cuMemcpy2D_v2:UV",
                    copy_result_uv,
                    None,
                );
                return false;
            }

            // Unmap resources
            let unmap_result = unsafe { unmap_fn(2, resources.as_mut_ptr(), ptr::null_mut()) };
            if unmap_result != CUDA_SUCCESS {
                self.record_shared_copy_failure_code(
                    "unmap",
                    "cuGraphicsUnmapResources",
                    unmap_result,
                    None,
                );
                return false;
            }

            self.diagnostics.record_shared_copy_success();
            true
        }
    }

    impl SequenceFormat {
        fn from_video_format(format: &CUVIDEOFORMAT) -> Self {
            Self {
                codec: format.codec,
                coded_width: format.coded_width,
                coded_height: format.coded_height,
                display_width: (format.display_area.right - format.display_area.left).max(1) as u32,
                display_height: (format.display_area.bottom - format.display_area.top).max(1)
                    as u32,
                chroma_format: format.chroma_format,
                bit_depth_minus8: format.bit_depth_luma_minus8,
                min_decode_surfaces: format.min_num_decode_surfaces.max(1),
            }
        }
    }

    impl DecoderConfig {
        fn from_sequence(sequence: &SequenceFormat) -> Self {
            Self {
                codec: sequence.codec,
                coded_width: sequence.coded_width,
                coded_height: sequence.coded_height,
                display_width: sequence.display_width,
                display_height: sequence.display_height,
                chroma_format: sequence.chroma_format,
                bit_depth_minus8: sequence.bit_depth_minus8,
                decode_surfaces: u32::from(sequence.min_decode_surfaces.max(1)),
            }
        }

        fn evaluate_sequence_change(&self, next: &SequenceFormat) -> SequenceChangeDecision {
            if next.chroma_format != CUDA_VIDEO_CHROMA_420 {
                return SequenceChangeDecision::Unsupported("chroma format change");
            }

            if self.bit_depth_minus8 != next.bit_depth_minus8 {
                return SequenceChangeDecision::Recreate("bit depth changed");
            }

            if self.coded_width != next.coded_width || self.coded_height != next.coded_height {
                return SequenceChangeDecision::Recreate("coded size changed");
            }

            if self.display_width != next.display_width
                || self.display_height != next.display_height
            {
                return SequenceChangeDecision::Recreate("display size changed");
            }

            if self.decode_surfaces != u32::from(next.min_decode_surfaces.max(1)) {
                return SequenceChangeDecision::Recreate("decode surface count changed");
            }

            SequenceChangeDecision::Reuse
        }

        fn evaluate_reconfigure(&self, next: &SequenceFormat) -> ReconfigureDecision {
            if next.chroma_format != CUDA_VIDEO_CHROMA_420
                || self.bit_depth_minus8 != next.bit_depth_minus8
            {
                return ReconfigureDecision::SkipUnsupported;
            }

            if self.coded_width != next.coded_width
                || self.coded_height != next.coded_height
                || self.display_width != next.display_width
                || self.display_height != next.display_height
                || self.decode_surfaces != u32::from(next.min_decode_surfaces.max(1))
            {
                return ReconfigureDecision::Attempt;
            }

            ReconfigureDecision::SkipUnsupported
        }
    }

    fn decoder_output_dimensions(
        config: Option<&DecoderConfig>,
        fallback_width: u32,
        fallback_height: u32,
    ) -> (usize, usize) {
        let (width, height) =
            decoder_output_dimensions_u32(config, fallback_width, fallback_height);
        (width as usize, height as usize)
    }

    fn decoder_output_dimensions_u32(
        config: Option<&DecoderConfig>,
        fallback_width: u32,
        fallback_height: u32,
    ) -> (u32, u32) {
        if let Some(config) = config {
            (config.display_width.max(1), config.display_height.max(1))
        } else {
            (fallback_width.max(1), fallback_height.max(1))
        }
    }

    unsafe extern "system" fn sequence_callback(
        user_data: *mut c_void,
        format: *mut CUVIDEOFORMAT,
    ) -> c_int {
        let state = unsafe { &mut *(user_data as *mut CallbackState) };
        let format = unsafe { &*format };
        let next_sequence = SequenceFormat::from_video_format(format);
        state.sequence_width = next_sequence.coded_width;
        state.sequence_height = next_sequence.coded_height;
        state.record_sequence(&next_sequence);
        let support_request = NvdecSupportRequest::from_sequence(&next_sequence);
        match evaluate_support(support_request) {
            NvdecSupportDecision::Supported => {
                state.record_support_decision("supported", None);
            }
            NvdecSupportDecision::Unsupported(reason) => {
                state.record_support_decision("unsupported", Some(reason));
                state.last_error = Some(format!("nvdec sequence unsupported: {reason}"));
                state.diagnostics.last_stage = Some("sequence".to_string());
                state.diagnostics.last_api = Some("support-matrix".to_string());
                state.diagnostics.last_error_description = Some(reason.to_string());
                return 0;
            }
        }

        match state.decoder_config.clone() {
            None => {
                state.record_sequence_decision("create");
                if let Err(error) = create_decoder_for_sequence(state, &next_sequence) {
                    state.last_error = Some(error);
                    return 0;
                }
            }
            Some(current) => match current.evaluate_sequence_change(&next_sequence) {
                SequenceChangeDecision::Reuse => {
                    state.record_sequence_decision("reuse");
                    state.record_active_config(&current);
                }
                SequenceChangeDecision::Recreate(reason) => {
                    match current.evaluate_reconfigure(&next_sequence) {
                        ReconfigureDecision::Attempt => {
                            match try_reconfigure_decoder(state, &current, &next_sequence, reason) {
                                Ok(true) => {
                                    state.record_sequence_decision("reconfigure");
                                }
                                Ok(false) => {
                                    state.diagnostics.reconfigure_fallback_used = true;
                                    state.record_recreate_from(&current);
                                    if let Err(error) =
                                        destroy_active_decoder(state, "recreate", reason)
                                    {
                                        state.last_error = Some(error);
                                        return 0;
                                    }
                                    if let Err(error) =
                                        create_decoder_for_sequence(state, &next_sequence)
                                    {
                                        state.last_error = Some(error);
                                        return 0;
                                    }
                                    if let Some(config) = state.decoder_config.clone() {
                                        state.record_sequence_decision("recreate");
                                        state.record_recreate(reason, &config);
                                    }
                                }
                                Err(error) => {
                                    state.last_error = Some(error);
                                    return 0;
                                }
                            }
                        }
                        ReconfigureDecision::SkipUnsupported => {
                            state.record_recreate_from(&current);
                            if let Err(error) = destroy_active_decoder(state, "recreate", reason) {
                                state.last_error = Some(error);
                                return 0;
                            }
                            if let Err(error) = create_decoder_for_sequence(state, &next_sequence) {
                                state.last_error = Some(error);
                                return 0;
                            }
                            if let Some(config) = state.decoder_config.clone() {
                                state.record_sequence_decision("recreate");
                                state.record_recreate(reason, &config);
                            }
                        }
                    }
                }
                SequenceChangeDecision::Unsupported(reason) => {
                    state.record_sequence_decision("unsupported");
                    state.last_error = Some(format!("nvdec sequence change unsupported: {reason}"));
                    state.diagnostics.last_stage = Some("sequence".to_string());
                    state.diagnostics.last_api = Some("sequence_callback".to_string());
                    state.diagnostics.last_error_description = Some(reason.to_string());
                    return 0;
                }
            },
        }

        next_sequence.min_decode_surfaces.max(1) as c_int
    }

    unsafe extern "system" fn av1_operating_point_callback(
        _user_data: *mut c_void,
        _operating_point_info: *mut c_void,
    ) -> c_int {
        0
    }

    fn operating_point_callback_for(
        codec: i32,
    ) -> Option<unsafe extern "system" fn(*mut c_void, *mut c_void) -> c_int> {
        (codec == CUDA_VIDEO_CODEC_AV1).then_some(av1_operating_point_callback)
    }

    unsafe extern "system" fn decode_callback(
        user_data: *mut c_void,
        pic_params: *mut CUVIDPICPARAMS,
    ) -> c_int {
        let state = unsafe { &mut *(user_data as *mut CallbackState) };
        if state.decoder.is_null() {
            state.last_error =
                Some("nvdec decode failed at callback-state: decoder was not created".to_string());
            state.diagnostics.last_stage = Some("decode".to_string());
            state.diagnostics.last_api = Some("cuvidDecodePicture".to_string());
            return 0;
        }
        let result = unsafe { (state.cuvid_decode_picture)(state.decoder, pic_params) };
        if result != CUDA_SUCCESS {
            state.record_failure("decode", "cuvidDecodePicture", result, None);
            return 0;
        }
        state.diagnostics.decode_calls += 1;
        state.record_decode_status_snapshot(
            "decode",
            None,
            "cuvidGetDecodeStatus skipped in decode phase: picture index unavailable".to_string(),
        );
        1
    }

    unsafe extern "system" fn display_callback(
        user_data: *mut c_void,
        disp_info: *mut CUVIDPARSERDISPINFO,
    ) -> c_int {
        let state = unsafe { &mut *(user_data as *mut CallbackState) };
        if disp_info.is_null() {
            return 1;
        }
        let disp_info = unsafe { &*disp_info };
        state.diagnostics.display_calls += 1;
        state.diagnostics.last_picture_index = Some(disp_info.picture_index);
        record_decode_status_for_picture(state, "display", disp_info.picture_index);
        if state.sequence_width == 0 || state.sequence_height == 0 {
            return 1;
        }

        let mut dev_ptr = 0_u64;
        let mut pitch = 0_u32;
        let mut proc_params = CUVIDPROCPARAMS {
            progressive_frame: disp_info.progressive_frame,
            second_field: 0,
            top_field_first: disp_info.top_field_first,
            unpaired_field: 0,
            reserved_flags: 0,
            reserved_zero: 0,
            raw_input_dptr: 0,
            raw_input_pitch: 0,
            raw_input_format: 0,
            raw_output_dptr: 0,
            raw_output_pitch: 0,
            raw_output_format: 0,
            raw_output_surface: 0,
            reserved1: 0,
            Reserved: [0; 48],
        };

        let map_result = unsafe {
            (state.cuvid_map_video_frame)(
                state.decoder,
                disp_info.picture_index,
                &mut dev_ptr,
                &mut pitch,
                &mut proc_params,
            )
        };
        if map_result != CUDA_SUCCESS {
            state.record_failure("map", "cuvidMapVideoFrame64", map_result, None);
            return 0;
        }

        let (width, height) = state.output_dimensions();
        let surface_kind = state
            .decoder_config
            .as_ref()
            .map(|config| DecodedSurfaceKind::from_bit_depth(config.bit_depth_minus8))
            .unwrap_or(DecodedSurfaceKind::Nv12);

        // Try GPU zero-copy if shared texture mode is enabled
        let gpu_copy_success = if state.use_shared_texture {
            state.diagnostics.record_shared_copy_attempt();
            if let (Some(d3d11_y), Some(d3d11_uv)) =
                (state.d3d11_y_texture_ptr, state.d3d11_uv_texture_ptr)
            {
                // Attempt GPU zero-copy from CUDA to D3D11
                state.try_gpu_zero_copy(
                    state.cuda_context,
                    d3d11_y,
                    d3d11_uv,
                    dev_ptr,
                    pitch,
                    width,
                    height,
                    surface_kind,
                )
            } else {
                state.record_shared_copy_failure_text(
                    "resource",
                    "d3d11-shared-texture",
                    "D3D11 shared output textures were not initialized",
                );
                false
            }
        } else {
            false
        };

        // Output based on copy result
        if gpu_copy_success {
            // GPU zero-copy succeeded - output shared texture frame
            if let (Some(shared_y), Some(shared_uv)) =
                (state.shared_texture_y, state.shared_texture_uv)
            {
                let data = match surface_kind {
                    DecodedSurfaceKind::Nv12 => NvdecDecodedFrameData::D3D11SharedNv12 {
                        shared_handle_y: shared_y,
                        shared_handle_uv: shared_uv,
                        width: width as u32,
                        height: height as u32,
                    },
                    DecodedSurfaceKind::P010 => NvdecDecodedFrameData::D3D11SharedP010 {
                        shared_handle_y: shared_y,
                        shared_handle_uv: shared_uv,
                        width: width as u32,
                        height: height as u32,
                    },
                };
                state.frames.push(NvdecDecodedFrame {
                    width,
                    height,
                    data,
                });
            } else {
                // Shouldn't happen, but fallback to CPU path
                let y_plane_bytes = pitch as usize * height;
                let uv_plane_bytes = pitch as usize * (height / 2);
                let total = y_plane_bytes + uv_plane_bytes;
                let mut surface = vec![0_u8; total];
                let copy_result = unsafe {
                    (state.cu_memcpy_dtoh)(surface.as_mut_ptr() as *mut c_void, dev_ptr, total)
                };
                if copy_result == CUDA_SUCCESS {
                    push_cpu_decoded_frame(
                        state,
                        width,
                        height,
                        pitch as usize,
                        surface,
                        surface_kind,
                    );
                }
            }
        } else {
            // GPU zero-copy not available or failed - use CPU path
            let y_plane_bytes = pitch as usize * height;
            let uv_plane_bytes = pitch as usize * (height / 2);
            let total = y_plane_bytes + uv_plane_bytes;
            let mut surface = vec![0_u8; total];
            let copy_result = unsafe {
                (state.cu_memcpy_dtoh)(surface.as_mut_ptr() as *mut c_void, dev_ptr, total)
            };
            if copy_result != CUDA_SUCCESS {
                state.record_failure("copy", "cuMemcpyDtoH_v2", copy_result, None);
                let _ = unsafe { (state.cuvid_unmap_video_frame)(state.decoder, dev_ptr) };
                return 0;
            }

            push_cpu_decoded_frame(state, width, height, pitch as usize, surface, surface_kind);
        }

        let unmap_result = unsafe { (state.cuvid_unmap_video_frame)(state.decoder, dev_ptr) };
        if unmap_result != CUDA_SUCCESS {
            state.record_failure("unmap", "cuvidUnmapVideoFrame64", unmap_result, None);
            return 0;
        }
        1
    }

    fn push_cpu_decoded_frame(
        state: &mut CallbackState,
        width: usize,
        height: usize,
        pitch: usize,
        surface: Vec<u8>,
        surface_kind: DecodedSurfaceKind,
    ) {
        match (state.output_mode, surface_kind) {
            (NvdecOutputMode::CpuRgb24, DecodedSurfaceKind::Nv12) => {
                let rgb = nv12_to_rgb(&surface, width, height, pitch);
                state
                    .frames
                    .push(NvdecDecodedFrame::from_cpu_rgb24(width, height, rgb));
            }
            (NvdecOutputMode::CpuRgb24, DecodedSurfaceKind::P010) => {
                let rgb = p010_to_rgb(&surface, width, height, pitch);
                state
                    .frames
                    .push(NvdecDecodedFrame::from_cpu_rgb24(width, height, rgb));
            }
            (NvdecOutputMode::CpuNv12, DecodedSurfaceKind::Nv12) => {
                state.frames.push(NvdecDecodedFrame::from_cpu_nv12(
                    width, height, pitch, surface,
                ));
            }
            (NvdecOutputMode::CpuNv12, DecodedSurfaceKind::P010) => {
                state.frames.push(NvdecDecodedFrame::from_cpu_p010(
                    width, height, pitch, surface,
                ));
            }
        }
    }

    fn cuda_ok(
        cuda: &CudaApi,
        result: CUresult,
        stage: &'static str,
        api: &'static str,
    ) -> Result<(), String> {
        match result {
            CUDA_SUCCESS => Ok(()),
            CUDA_ERROR_NO_DEVICE => Err(format!(
                "nvdec {stage} failed at {api}: no CUDA device available"
            )),
            other => {
                let (name, description) =
                    describe_cuda_error(cuda.cu_get_error_name, cuda.cu_get_error_string, other);
                Err(format_cuda_failure(
                    stage,
                    api,
                    other,
                    name.as_deref(),
                    description.as_deref(),
                    None,
                ))
            }
        }
    }

    fn describe_cuda_error(
        get_error_name: Option<CuGetErrorNameFn>,
        get_error_string: Option<CuGetErrorStringFn>,
        code: CUresult,
    ) -> (Option<String>, Option<String>) {
        let mut name = None;
        let mut description = None;

        if let Some(get_error_name) = get_error_name {
            let mut raw_name = ptr::null();
            let status = unsafe { get_error_name(code, &mut raw_name) };
            if status == CUDA_SUCCESS && !raw_name.is_null() {
                name = Some(c_string_ptr_to_string(raw_name));
            }
        }

        if let Some(get_error_string) = get_error_string {
            let mut raw_description = ptr::null();
            let status = unsafe { get_error_string(code, &mut raw_description) };
            if status == CUDA_SUCCESS && !raw_description.is_null() {
                description = Some(c_string_ptr_to_string(raw_description));
            }
        }

        (name, description)
    }

    fn format_cuda_failure(
        stage: &'static str,
        api: &'static str,
        code: CUresult,
        error_name: Option<&str>,
        error_description: Option<&str>,
        context: Option<&str>,
    ) -> String {
        let mut message = format!("nvdec {stage} failed at {api}: code {code}");
        if let Some(error_name) = error_name {
            message.push_str(" (");
            message.push_str(error_name);
            message.push(')');
        }
        if let Some(error_description) = error_description {
            message.push_str(": ");
            message.push_str(error_description);
        }
        if let Some(context) = context {
            message.push_str(" [");
            message.push_str(context);
            message.push(']');
        }
        message
    }

    fn c_string_ptr_to_string(ptr: *const i8) -> String {
        let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) };
        bytes.to_string_lossy().into_owned()
    }

    fn record_decode_status_for_picture(
        state: &mut CallbackState,
        phase: &'static str,
        picture_index: c_int,
    ) {
        let Some(cuvid_get_decode_status) = state.cuvid_get_decode_status else {
            state.record_decode_status_snapshot(
                phase,
                None,
                "cuvidGetDecodeStatus unavailable".to_string(),
            );
            return;
        };

        let mut status = CUVIDGETDECODESTATUS::default();
        let result = unsafe { cuvid_get_decode_status(state.decoder, picture_index, &mut status) };
        if result != CUDA_SUCCESS {
            let description = format!("cuvidGetDecodeStatus failed: code {result}");
            state.record_decode_status_snapshot(phase, Some(result), description);
            return;
        }

        state.record_decode_status_snapshot(
            phase,
            Some(status.decodeStatus),
            describe_decode_status(status.decodeStatus).to_string(),
        );
    }

    fn describe_decode_status(status: i32) -> &'static str {
        match status {
            0 => "invalid",
            1 => "in-progress",
            2 => "success",
            8 => "error",
            9 => "error-concealed",
            _ => "unknown",
        }
    }

    fn destroy_active_decoder(
        state: &mut CallbackState,
        stage: &'static str,
        reason: &'static str,
    ) -> Result<(), String> {
        if state.decoder.is_null() {
            state.decoder_config = None;
            return Ok(());
        }

        let result = unsafe { (state.cuvid_destroy_decoder)(state.decoder) };
        if result != CUDA_SUCCESS {
            state.record_failure(
                stage,
                "cuvidDestroyDecoder",
                result,
                Some(reason.to_string()),
            );
            return Err(state
                .last_error
                .clone()
                .unwrap_or_else(|| "nvdec recreate failed while destroying decoder".to_string()));
        }

        state.decoder = ptr::null_mut();
        state.decoder_config = None;
        Ok(())
    }

    fn create_decoder_for_sequence(
        state: &mut CallbackState,
        sequence: &SequenceFormat,
    ) -> Result<(), String> {
        match evaluate_support(NvdecSupportRequest::from_sequence(sequence)) {
            NvdecSupportDecision::Supported => {}
            NvdecSupportDecision::Unsupported(reason) => {
                return Err(format!("nvdec sequence unsupported: {reason}"));
            }
        }

        let config = DecoderConfig::from_sequence(sequence);
        let mut create_info = CUVIDDECODECREATEINFO {
            ulWidth: config.coded_width,
            ulHeight: config.coded_height,
            ulNumDecodeSurfaces: config.decode_surfaces,
            CodecType: config.codec,
            ChromaFormat: config.chroma_format,
            ulCreationFlags: CUDA_VIDEO_CREATE_PREFER_CUVID,
            bitDepthMinus8: u32::from(config.bit_depth_minus8),
            ulIntraDecodeOnly: 0,
            ulMaxWidth: config.coded_width,
            ulMaxHeight: config.coded_height,
            Reserved1: 0,
            display_area: ShortRect {
                left: 0,
                top: 0,
                right: config.display_width as i16,
                bottom: config.display_height as i16,
            },
            OutputFormat: DecodedSurfaceKind::from_bit_depth(config.bit_depth_minus8)
                .cuda_output_format(),
            DeinterlaceMode: CUDA_VIDEO_DEINTERLACE_WEAVE,
            ulTargetWidth: config.display_width,
            ulTargetHeight: config.display_height,
            ulNumOutputSurfaces: 2,
            vidLock: ptr::null_mut(),
            target_rect: ShortRect {
                left: 0,
                top: 0,
                right: config.display_width as i16,
                bottom: config.display_height as i16,
            },
            enableHistogram: 0,
            Reserved2: [0; 4],
        };

        let mut decoder = ptr::null_mut();
        let result = unsafe { (state.cuvid_create_decoder)(&mut decoder, &mut create_info) };
        if result != CUDA_SUCCESS {
            state.record_failure(
                "sequence",
                "cuvidCreateDecoder",
                result,
                Some(format!(
                    "width={} height={} surfaces={} chroma={} bit_depth={} target={}x{}",
                    create_info.ulWidth,
                    create_info.ulHeight,
                    create_info.ulNumDecodeSurfaces,
                    create_info.ChromaFormat,
                    create_info.bitDepthMinus8,
                    create_info.ulTargetWidth,
                    create_info.ulTargetHeight,
                )),
            );
            return Err(state
                .last_error
                .clone()
                .unwrap_or_else(|| "nvdec sequence failed at cuvidCreateDecoder".to_string()));
        }

        state.decoder = decoder;
        state.decoder_config = Some(config.clone());
        state.record_active_config(&config);
        Ok(())
    }

    fn try_reconfigure_decoder(
        state: &mut CallbackState,
        current: &DecoderConfig,
        next: &SequenceFormat,
        reason: &'static str,
    ) -> Result<bool, String> {
        state.record_reconfigure_attempt(current, next);
        let Some(cuvid_reconfigure_decoder) = state.cuvid_reconfigure_decoder else {
            state.record_reconfigure_result("unavailable".to_string());
            return Ok(false);
        };

        let mut info = CUVIDRECONFIGUREDECODERINFO {
            ulWidth: next.coded_width,
            ulHeight: next.coded_height,
            ulTargetWidth: next.display_width,
            ulTargetHeight: next.display_height,
            ulNumDecodeSurfaces: u32::from(next.min_decode_surfaces.max(1)),
            display_area: ShortRect {
                left: 0,
                top: 0,
                right: next.display_width as i16,
                bottom: next.display_height as i16,
            },
            target_rect: ShortRect {
                left: 0,
                top: 0,
                right: next.display_width as i16,
                bottom: next.display_height as i16,
            },
            Reserved1: [0; 8],
            Reserved2: [ptr::null_mut(); 6],
        };

        let result = unsafe { cuvid_reconfigure_decoder(state.decoder, &mut info) };
        if result != CUDA_SUCCESS {
            state.record_reconfigure_result(format!(
                "failed: {}",
                format_cuda_failure(
                    "reconfigure",
                    "cuvidReconfigureDecoder",
                    result,
                    None,
                    None,
                    Some(reason)
                )
            ));
            return Ok(false);
        }

        let config = DecoderConfig::from_sequence(next);
        state.decoder_config = Some(config.clone());
        state.record_active_config(&config);
        state.record_reconfigure_result("success".to_string());
        Ok(true)
    }

    impl NvdecSupportRequest {
        fn from_sequence(sequence: &SequenceFormat) -> Self {
            Self {
                codec: match sequence.codec {
                    CUDA_VIDEO_CODEC_H264 => NvdecCodec::H264,
                    CUDA_VIDEO_CODEC_HEVC => NvdecCodec::Hevc,
                    CUDA_VIDEO_CODEC_AV1 => NvdecCodec::Av1,
                    other => NvdecCodec::Unknown(other),
                },
                bit_depth_minus8: sequence.bit_depth_minus8,
                chroma_format: sequence.chroma_format,
            }
        }
    }

    impl NvdecCapabilityRequest {
        fn new(codec: &'static str, bit_depth_minus8: u8, chroma_format: i32) -> Self {
            let codec = match codec {
                "h264" => NvdecCodec::H264,
                "hevc" => NvdecCodec::Hevc,
                "av1" => NvdecCodec::Av1,
                _ => NvdecCodec::Unknown(-1),
            };
            Self {
                codec,
                bit_depth_minus8,
                chroma_format,
            }
        }

        fn codec_name(&self) -> &'static str {
            match self.codec {
                NvdecCodec::H264 => "h264",
                NvdecCodec::Hevc => "hevc",
                NvdecCodec::Av1 => "av1",
                NvdecCodec::Unknown(_) => "unknown",
            }
        }

        fn probe_label(&self) -> String {
            match self.codec {
                NvdecCodec::Hevc if self.bit_depth_minus8 > 0 => {
                    format!("{} main10", self.codec_name())
                }
                _ => format!(
                    "{} {}-bit chroma {}",
                    self.codec_name(),
                    self.bit_depth_minus8 + 8,
                    self.chroma_format
                ),
            }
        }

        fn codec_raw(&self) -> i32 {
            match self.codec {
                NvdecCodec::H264 => CUDA_VIDEO_CODEC_H264,
                NvdecCodec::Hevc => CUDA_VIDEO_CODEC_HEVC,
                NvdecCodec::Av1 => CUDA_VIDEO_CODEC_AV1,
                NvdecCodec::Unknown(raw) => raw,
            }
        }

        fn to_support_request(self) -> NvdecSupportRequest {
            NvdecSupportRequest {
                codec: self.codec,
                bit_depth_minus8: self.bit_depth_minus8,
                chroma_format: self.chroma_format,
            }
        }
    }

    fn evaluate_support(request: NvdecSupportRequest) -> NvdecSupportDecision {
        if request.chroma_format != CUDA_VIDEO_CHROMA_420 {
            return NvdecSupportDecision::Unsupported("unsupported chroma format");
        }

        match request.codec {
            NvdecCodec::H264 => {
                if request.bit_depth_minus8 > 0 {
                    return NvdecSupportDecision::Unsupported("10-bit not wired yet");
                }
            }
            NvdecCodec::Hevc => {
                if !matches!(request.bit_depth_minus8, 0 | 2) {
                    return NvdecSupportDecision::Unsupported("unsupported HEVC bit depth");
                }
            }
            NvdecCodec::Av1 => {
                // AV1 decode support requires Ada Lovelace or newer GPU
                // Let capability probing determine if it's available
                if request.bit_depth_minus8 > 0 {
                    return NvdecSupportDecision::Unsupported("10-bit not wired yet");
                }
            }
            NvdecCodec::Unknown(_) => {
                return NvdecSupportDecision::Unsupported("unknown codec");
            }
        }

        NvdecSupportDecision::Supported
    }

    pub fn probe_capability(
        codec: &'static str,
        bit_depth_minus8: u8,
        chroma_format: i32,
    ) -> Result<NvdecCapabilityProbe, String> {
        let request = NvdecCapabilityRequest::new(codec, bit_depth_minus8, chroma_format);
        let cuda = CudaApi::load()?;
        let cuvid = CuvidApi::load()?;

        unsafe {
            cuda_ok(&cuda, (cuda.cu_init)(0), "init", "cuInit")?;
        }

        let mut count = 0;
        unsafe {
            cuda_ok(
                &cuda,
                (cuda.cu_device_get_count)(&mut count),
                "init",
                "cuDeviceGetCount",
            )?;
        }
        if count <= 0 {
            return Err("cuDeviceGetCount reported no CUDA devices".to_string());
        }

        let wired_decision = evaluate_support(request.to_support_request());
        if let Some(get_caps) = cuvid.cuvid_get_decoder_caps {
            let mut caps = CUVIDDECODECAPS {
                eCodecType: request.codec_raw(),
                eChromaFormat: request.chroma_format,
                nBitDepthMinus8: u32::from(request.bit_depth_minus8),
                ..Default::default()
            };
            let result = unsafe { get_caps(&mut caps) };
            if result != CUDA_SUCCESS {
                return Ok(NvdecCapabilityProbe {
                    codec: request.codec_name().to_string(),
                    bit_depth_minus8: request.bit_depth_minus8,
                    chroma_format: request.chroma_format,
                    runtime_supported: true,
                    runtime_reason: format!(
                        "{} cuvidGetDecoderCaps returned an error; treating runtime support as unknown because decoder creation handles this probe as non-fatal",
                        request.probe_label()
                    ),
                    wired_supported: matches!(wired_decision, NvdecSupportDecision::Supported),
                    wired_reason: support_reason(wired_decision).to_string(),
                });
            }

            let runtime_supported = caps.bIsSupported != 0;
            let runtime_reason = if runtime_supported {
                format!(
                    "{} runtime capability reported by nvdec",
                    request.probe_label()
                )
            } else {
                format!("{} unsupported by runtime", request.probe_label())
            };
            return Ok(NvdecCapabilityProbe {
                codec: request.codec_name().to_string(),
                bit_depth_minus8: request.bit_depth_minus8,
                chroma_format: request.chroma_format,
                runtime_supported,
                runtime_reason,
                wired_supported: matches!(wired_decision, NvdecSupportDecision::Supported),
                wired_reason: support_reason(wired_decision).to_string(),
            });
        }

        Ok(NvdecCapabilityProbe {
            codec: request.codec_name().to_string(),
            bit_depth_minus8: request.bit_depth_minus8,
            chroma_format: request.chroma_format,
            runtime_supported: false,
            runtime_reason: "nvdec runtime probe unavailable: cuvidGetDecoderCaps unavailable"
                .to_string(),
            wired_supported: matches!(wired_decision, NvdecSupportDecision::Supported),
            wired_reason: support_reason(wired_decision).to_string(),
        })
    }

    fn support_reason(decision: NvdecSupportDecision) -> &'static str {
        match decision {
            NvdecSupportDecision::Supported => "wired",
            NvdecSupportDecision::Unsupported(reason) => reason,
        }
    }

    fn describe_codec(codec: i32) -> &'static str {
        match codec {
            CUDA_VIDEO_CODEC_H264 => "h264",
            CUDA_VIDEO_CODEC_HEVC => "hevc",
            CUDA_VIDEO_CODEC_AV1 => "av1",
            _ => "unknown",
        }
    }

    fn parser_flags(codec: i32) -> u32 {
        if codec == CUDA_VIDEO_CODEC_AV1 {
            CUVID_PARSER_ANNEXB
        } else {
            0
        }
    }

    fn av1_low_overhead_obu_to_annexb(buf: &[u8]) -> Option<Vec<u8>> {
        let mut offset = 0_usize;
        let mut frame_unit = Vec::with_capacity(buf.len() + 16);
        while offset < buf.len() {
            let header_offset = offset;
            let header = *buf.get(offset)?;
            if header & 0x80 != 0 || header & 0x01 != 0 {
                return None;
            }
            offset += 1;

            let has_extension = header & 0x04 != 0;
            if has_extension {
                buf.get(offset)?;
                offset += 1;
            }

            if header & 0x02 == 0 {
                return None;
            }

            let (payload_len, size_len) = read_leb128(&buf[offset..])?;
            offset = offset.checked_add(size_len)?;
            let payload_len = usize::try_from(payload_len).ok()?;
            let payload_end = offset.checked_add(payload_len)?;
            if payload_end > buf.len() {
                return None;
            }

            let header_len = 1 + usize::from(has_extension);
            write_leb128((header_len + payload_len) as u64, &mut frame_unit);
            frame_unit.push(header & !0x02);
            if has_extension {
                frame_unit.push(buf[header_offset + 1]);
            }
            frame_unit.extend_from_slice(&buf[offset..payload_end]);
            offset = payload_end;
        }

        if frame_unit.is_empty() {
            return None;
        }

        let mut temporal_unit = Vec::with_capacity(frame_unit.len() + 8);
        write_leb128(frame_unit.len() as u64, &mut temporal_unit);
        temporal_unit.extend_from_slice(&frame_unit);

        let mut out = Vec::with_capacity(temporal_unit.len() + 8);
        write_leb128(temporal_unit.len() as u64, &mut out);
        out.extend_from_slice(&temporal_unit);
        Some(out)
    }

    fn read_leb128(buf: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0_u64;
        for (i, byte) in buf.iter().take(8).enumerate() {
            value |= u64::from(byte & 0x7f) << (i * 7);
            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }
        }
        None
    }

    fn write_leb128(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn looks_like_annexb(buf: &[u8]) -> bool {
        buf.len() >= 4
            && ((buf[0] == 0 && buf[1] == 0 && buf[2] == 1)
                || (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1))
    }

    fn nv12_to_rgb(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
        let mut rgb = vec![0_u8; width * height * 3];
        let uv_base = pitch * height;

        // Integer YUV to RGB conversion (faster than float)
        // R = (298 * Y + 409 * V + 128) >> 8
        // G = (298 * Y - 100 * U - 208 * V + 128) >> 8
        // B = (298 * Y + 516 * U + 128) >> 8

        let mut out_idx = 0;
        for y in 0..height {
            let uv_row_start = uv_base + (y / 2) * pitch;
            for x in 0..width {
                let y_sample = nv12[y * pitch + x] as i32 - 16;
                let uv_offset = uv_row_start + (x / 2) * 2;
                let u = nv12[uv_offset] as i32 - 128;
                let v = nv12[uv_offset + 1] as i32 - 128;

                let r = (298 * y_sample + 409 * v + 128) >> 8;
                let g = (298 * y_sample - 100 * u - 208 * v + 128) >> 8;
                let b = (298 * y_sample + 516 * u + 128) >> 8;

                rgb[out_idx] = clamp_i32(r);
                rgb[out_idx + 1] = clamp_i32(g);
                rgb[out_idx + 2] = clamp_i32(b);
                out_idx += 3;
            }
        }

        rgb
    }

    fn p010_to_rgb(p010: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
        let mut rgb = vec![0_u8; width * height * 3];
        let uv_base = pitch * height;

        for y in 0..height {
            let y_row = y * pitch;
            let uv_row = uv_base + (y / 2) * pitch;
            for x in 0..width {
                let y_idx = y_row + x * 2;
                let uv_idx = uv_row + (x / 2) * 4;
                if y_idx + 1 >= p010.len() || uv_idx + 3 >= p010.len() {
                    continue;
                }

                let y10 = u16::from_le_bytes([p010[y_idx], p010[y_idx + 1]]) >> 6;
                let u10 = u16::from_le_bytes([p010[uv_idx], p010[uv_idx + 1]]) >> 6;
                let v10 = u16::from_le_bytes([p010[uv_idx + 2], p010[uv_idx + 3]]) >> 6;

                let y_val = y10 as i32;
                let u = u10 as i32 - 512;
                let v = v10 as i32 - 512;

                let r = y_val + ((1436 * v) >> 10);
                let g = y_val - ((352 * u + 731 * v) >> 10);
                let b = y_val + ((1815 * u) >> 10);
                let out_idx = (y * width + x) * 3;
                rgb[out_idx] = clamp_10bit_to_8bit(r);
                rgb[out_idx + 1] = clamp_10bit_to_8bit(g);
                rgb[out_idx + 2] = clamp_10bit_to_8bit(b);
            }
        }

        rgb
    }

    #[inline]
    fn clamp_10bit_to_8bit(value: i32) -> u8 {
        ((value.clamp(0, 1023) + 2) >> 2) as u8
    }

    #[inline]
    fn clamp_i32(value: i32) -> u8 {
        value.clamp(0, 255) as u8
    }

    #[cfg(test)]
    mod tests {
        use super::{
            decoder_output_dimensions, evaluate_support, DecodedSurfaceKind, DecoderConfig,
            NvdecCapabilityRequest, NvdecCodec, NvdecSupportDecision, NvdecSupportRequest,
            SequenceChangeDecision, SequenceFormat, CUDA_VIDEO_CHROMA_420, CUDA_VIDEO_CODEC_AV1,
            CUDA_VIDEO_CODEC_H264, CUDA_VIDEO_CODEC_HEVC, CUDA_VIDEO_SURFACE_P016,
            CUVID_PARSER_ANNEXB,
        };

        fn baseline_sequence() -> SequenceFormat {
            SequenceFormat {
                codec: CUDA_VIDEO_CODEC_H264,
                coded_width: 128,
                coded_height: 128,
                display_width: 128,
                display_height: 128,
                chroma_format: CUDA_VIDEO_CHROMA_420,
                bit_depth_minus8: 0,
                min_decode_surfaces: 8,
            }
        }

        fn baseline_config() -> DecoderConfig {
            DecoderConfig::from_sequence(&baseline_sequence())
        }

        #[test]
        fn output_dimensions_use_display_size_for_padded_coded_height() {
            let mut sequence = baseline_sequence();
            sequence.coded_width = 1920;
            sequence.coded_height = 1088;
            sequence.display_width = 1920;
            sequence.display_height = 1080;
            let config = DecoderConfig::from_sequence(&sequence);

            assert_eq!(
                decoder_output_dimensions(
                    Some(&config),
                    sequence.coded_width,
                    sequence.coded_height
                ),
                (1920, 1080)
            );
        }

        #[test]
        fn support_matrix_accepts_h264_8bit_420() {
            let request = NvdecSupportRequest {
                codec: NvdecCodec::H264,
                bit_depth_minus8: 0,
                chroma_format: CUDA_VIDEO_CHROMA_420,
            };

            assert_eq!(evaluate_support(request), NvdecSupportDecision::Supported);
        }

        #[test]
        fn av1_parser_uses_annex_b_and_operating_point_callback() {
            assert_eq!(
                super::parser_flags(CUDA_VIDEO_CODEC_AV1),
                CUVID_PARSER_ANNEXB
            );
            assert!(super::operating_point_callback_for(CUDA_VIDEO_CODEC_AV1).is_some());
            assert_eq!(super::parser_flags(CUDA_VIDEO_CODEC_H264), 0);
            assert!(super::operating_point_callback_for(CUDA_VIDEO_CODEC_H264).is_none());
        }

        #[test]
        fn nvdecode_codec_constants_match_sdk_enum_order() {
            assert_eq!(CUDA_VIDEO_CODEC_H264, 4);
            assert_eq!(CUDA_VIDEO_CODEC_HEVC, 8);
            assert_eq!(CUDA_VIDEO_CODEC_AV1, 11);
        }

        #[test]
        fn av1_low_overhead_obu_converts_to_annex_b_temporal_unit() {
            let low_overhead = [0x12, 0x00, 0x0a, 0x01, 0xaa];
            let annexb = super::av1_low_overhead_obu_to_annexb(&low_overhead).unwrap();
            assert_eq!(annexb, vec![0x06, 0x05, 0x01, 0x10, 0x02, 0x08, 0xaa]);
        }

        #[test]
        fn support_matrix_accepts_av1_8bit_420() {
            let request = NvdecSupportRequest {
                codec: NvdecCodec::Av1,
                bit_depth_minus8: 0,
                chroma_format: CUDA_VIDEO_CHROMA_420,
            };

            assert_eq!(evaluate_support(request), NvdecSupportDecision::Supported);
        }

        #[test]
        fn support_matrix_accepts_hevc_8bit_420() {
            let request = NvdecSupportRequest {
                codec: NvdecCodec::Hevc,
                bit_depth_minus8: 0,
                chroma_format: CUDA_VIDEO_CHROMA_420,
            };

            assert_eq!(evaluate_support(request), NvdecSupportDecision::Supported);
        }

        #[test]
        fn support_matrix_accepts_hevc_main10_420() {
            let request = NvdecSupportRequest {
                codec: NvdecCodec::Hevc,
                bit_depth_minus8: 2,
                chroma_format: CUDA_VIDEO_CHROMA_420,
            };

            assert_eq!(evaluate_support(request), NvdecSupportDecision::Supported);
        }

        #[test]
        fn hevc_main10_uses_p016_decode_surface() {
            assert_eq!(
                DecodedSurfaceKind::from_bit_depth(2).cuda_output_format(),
                CUDA_VIDEO_SURFACE_P016
            );
        }

        #[test]
        fn support_matrix_rejects_ten_bit() {
            let request = NvdecSupportRequest {
                codec: NvdecCodec::H264,
                bit_depth_minus8: 2,
                chroma_format: CUDA_VIDEO_CHROMA_420,
            };

            assert_eq!(
                evaluate_support(request),
                NvdecSupportDecision::Unsupported("10-bit not wired yet")
            );
        }

        #[test]
        fn support_matrix_rejects_non_420() {
            let request = NvdecSupportRequest {
                codec: NvdecCodec::H264,
                bit_depth_minus8: 0,
                chroma_format: 3,
            };

            assert_eq!(
                evaluate_support(request),
                NvdecSupportDecision::Unsupported("unsupported chroma format")
            );
        }

        #[test]
        fn capability_probe_reports_hevc_as_wired() {
            let request = NvdecCapabilityRequest::new("hevc", 0, CUDA_VIDEO_CHROMA_420);
            let wired = evaluate_support(request.to_support_request());

            assert_eq!(wired, NvdecSupportDecision::Supported);
        }

        #[test]
        fn capability_probe_reports_hevc_main10_as_wired() {
            let request = NvdecCapabilityRequest::new("hevc", 2, CUDA_VIDEO_CHROMA_420);
            let wired = evaluate_support(request.to_support_request());

            assert_eq!(wired, NvdecSupportDecision::Supported);
        }

        #[test]
        fn recreate_decision_keeps_compatible_sequence() {
            let decision = baseline_config().evaluate_sequence_change(&baseline_sequence());
            assert_eq!(decision, SequenceChangeDecision::Reuse);
        }

        #[test]
        fn recreate_decision_recreates_on_coded_size_change() {
            let mut next = baseline_sequence();
            next.coded_width = 256;

            let decision = baseline_config().evaluate_sequence_change(&next);
            assert_eq!(
                decision,
                SequenceChangeDecision::Recreate("coded size changed")
            );
        }

        #[test]
        fn recreate_decision_recreates_on_display_size_change() {
            let mut next = baseline_sequence();
            next.display_height = 256;

            let decision = baseline_config().evaluate_sequence_change(&next);
            assert_eq!(
                decision,
                SequenceChangeDecision::Recreate("display size changed")
            );
        }

        #[test]
        fn recreate_decision_recreates_on_bit_depth_change() {
            let mut next = baseline_sequence();
            next.bit_depth_minus8 = 2;

            let decision = baseline_config().evaluate_sequence_change(&next);
            assert_eq!(
                decision,
                SequenceChangeDecision::Recreate("bit depth changed")
            );
        }

        #[test]
        fn recreate_decision_rejects_chroma_change() {
            let mut next = baseline_sequence();
            next.chroma_format = 3;

            let decision = baseline_config().evaluate_sequence_change(&next);
            assert_eq!(
                decision,
                SequenceChangeDecision::Unsupported("chroma format change")
            );
        }

        #[test]
        #[ignore]
        fn perf_nv12_to_rgb_integer_vs_float() {
            use super::nv12_to_rgb;
            use std::time::Instant;

            let width = 1920usize;
            let height = 1080usize;
            let pitch = width;
            let iterations = 100;

            let mut nv12 = vec![0_u8; pitch * height * 3 / 2];
            for (i, byte) in nv12.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }

            // Test integer version
            let int_started = Instant::now();
            let mut int_result = None;
            for _ in 0..iterations {
                int_result = Some(nv12_to_rgb(&nv12, width, height, pitch));
            }
            let int_total = int_started.elapsed();
            let int_ms = int_total.as_secs_f64() * 1000.0;
            let int_per_frame = int_ms / iterations as f64;

            // Test float version
            let float_started = Instant::now();
            let mut float_result = None;
            for _ in 0..iterations {
                float_result = Some(nv12_to_rgb_float(&nv12, width, height, pitch));
            }
            let float_total = float_started.elapsed();
            let float_ms = float_total.as_secs_f64() * 1000.0;
            let float_per_frame = float_ms / iterations as f64;

            let speedup = float_ms / int_ms;

            println!(
                "\nNV12 to RGB Conversion Performance ({width}x{height}, {iterations} iterations):"
            );
            println!(
                "  Float version:   {:.3}s total, {:.3}ms per frame",
                float_total.as_secs_f64(),
                float_per_frame
            );
            println!(
                "  Integer version: {:.3}s total, {:.3}ms per frame",
                int_total.as_secs_f64(),
                int_per_frame
            );
            println!("  Speedup: {:.2}x", speedup);
            println!(
                "  Time saved per frame: {:.3}ms",
                float_per_frame - int_per_frame
            );

            // Verify both produce same result
            let int_rgb = int_result.unwrap();
            let float_rgb = float_result.unwrap();
            assert_eq!(int_rgb.len(), float_rgb.len());
            // Allow small differences due to rounding
            let mut max_diff = 0u8;
            for (i, (&a, &b)) in int_rgb.iter().zip(float_rgb.iter()).enumerate() {
                let diff = a.abs_diff(b);
                max_diff = max_diff.max(diff);
                if diff > 2 {
                    println!(
                        "  Large difference at index {}: {} vs {} (diff: {})",
                        i, a, b, diff
                    );
                    break;
                }
            }
            println!("  Max difference: {}", max_diff);
            assert!(max_diff <= 2, "results differ by more than 2");

            if cfg!(debug_assertions) {
                println!(
                    "  Skipping speedup threshold in debug builds; run with --release to enforce it"
                );
            } else {
                assert!(
                    speedup > 1.5,
                    "integer version should be at least 1.5x faster"
                );
            }
        }

        fn nv12_to_rgb_float(nv12: &[u8], width: usize, height: usize, pitch: usize) -> Vec<u8> {
            let mut rgb = vec![0_u8; width * height * 3];
            let uv_base = pitch * height;

            for y in 0..height {
                for x in 0..width {
                    let y_sample = nv12[y * pitch + x] as f32;
                    let uv_offset = uv_base + (y / 2) * pitch + (x / 2) * 2;
                    let u = nv12[uv_offset] as f32;
                    let v = nv12[uv_offset + 1] as f32;

                    let c = y_sample - 16.0;
                    let d = u - 128.0;
                    let e = v - 128.0;

                    let r = (1.164 * c + 1.596 * e).round();
                    let g = (1.164 * c - 0.392 * d - 0.813 * e).round();
                    let b = (1.164 * c + 2.017 * d).round();

                    let out = (y * width + x) * 3;
                    rgb[out] = r.clamp(0.0, 255.0) as u8;
                    rgb[out + 1] = g.clamp(0.0, 255.0) as u8;
                    rgb[out + 2] = b.clamp(0.0, 255.0) as u8;
                }
            }

            rgb
        }

        #[test]
        #[cfg(windows)]
        fn d3d11_shared_texture_creation() {
            use super::{D3D11SharedTexture, DecodedSurfaceKind};

            let width = 1280u32;
            let height = 720u32;

            match D3D11SharedTexture::new(width, height, DecodedSurfaceKind::Nv12) {
                Ok(texture) => {
                    assert_eq!(texture.width, width);
                    assert_eq!(texture.height, height);
                    assert_ne!(texture.shared_handle_y, 0);
                    assert_ne!(texture.shared_handle_uv, 0);
                }
                Err(e) => {
                    // Test may fail on systems without D3D11 support
                    eprintln!(
                        "D3D11 shared texture creation failed (expected on some systems): {e}"
                    );
                }
            }
        }

        #[test]
        #[cfg(windows)]
        fn d3d11_shared_texture_can_use_external_device_pointer() {
            use super::{
                D3D11CreateDevice, D3D11SharedTexture, DecodedSurfaceKind, ID3D11Device,
                ID3D11DeviceContext,
            };
            use windows::core::Interface;
            use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
            use windows::Win32::Graphics::Direct3D11::{
                D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
            };

            let mut device = None::<ID3D11Device>;
            let mut context = None::<ID3D11DeviceContext>;
            unsafe {
                D3D11CreateDevice(
                    None,
                    D3D_DRIVER_TYPE_HARDWARE,
                    windows::Win32::Foundation::HMODULE::default(),
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    Some(&mut context),
                )
            }
            .expect("create test d3d11 device");
            let device = device.expect("test d3d11 device");

            let texture = unsafe {
                D3D11SharedTexture::new_with_device_ptr(
                    640,
                    360,
                    DecodedSurfaceKind::Nv12,
                    device.as_raw(),
                )
            }
            .expect("create shared texture from external device");

            assert_eq!(texture.width, 640);
            assert_eq!(texture.height, 360);
            assert_ne!(texture.shared_handle_y, 0);
            assert_ne!(texture.shared_handle_uv, 0);
        }
    }
}
