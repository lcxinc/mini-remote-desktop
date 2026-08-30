#![allow(dead_code)]

pub use mrd_pipeline_core::{
    DecodedFrame as CoreDecodedFrame, DecodedFrameData, PipelineError, RuntimeStatus, VideoDecoder,
};
use openh264::{
    decoder::{DecodedYUV, Decoder as OpenH264Decoder},
    formats::YUVSource,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecKind {
    H264,
    Hevc,
    HevcMain10,
    Av1,
    Vvc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Rgb24,
    Bgra32,
    I420,
    Nv12,
    P010,
    D3d11Texture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderDescriptor {
    pub id: &'static str,
    pub codec: CodecKind,
    pub runtime_status: RuntimeStatus,
    pub output_formats: &'static [PixelFormat],
}

const RGB24_OUTPUTS: &[PixelFormat] = &[PixelFormat::Rgb24];
const I420_OUTPUTS: &[PixelFormat] = &[PixelFormat::I420];
const NV12_OUTPUTS: &[PixelFormat] = &[PixelFormat::Nv12];
const P010_OUTPUTS: &[PixelFormat] = &[PixelFormat::P010];
const RGB24_I420_OUTPUTS: &[PixelFormat] = &[PixelFormat::Rgb24, PixelFormat::I420];
const RGB24_I420_P010_OUTPUTS: &[PixelFormat] =
    &[PixelFormat::Rgb24, PixelFormat::I420, PixelFormat::P010];
const D3D11_TEXTURE_OUTPUTS: &[PixelFormat] = &[PixelFormat::D3d11Texture];

const H264_SOFTWARE_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "h264_software",
    codec: CodecKind::H264,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: I420_OUTPUTS,
};

const HEVC_SOFTWARE_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "software_hevc",
    codec: CodecKind::Hevc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_I420_OUTPUTS,
};

const HEVC_MAIN10_SOFTWARE_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "software_hevc_main10",
    codec: CodecKind::HevcMain10,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: P010_OUTPUTS,
};

const AV1_SOFTWARE_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "software_av1",
    codec: CodecKind::Av1,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_I420_OUTPUTS,
};

const VVC_SOFTWARE_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "software_vvc",
    codec: CodecKind::Vvc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_I420_P010_OUTPUTS,
};

const FFMPEG_H264_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "ffmpeg_h264",
    codec: CodecKind::H264,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: NV12_OUTPUTS,
};

const FFMPEG_HEVC_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "ffmpeg_hevc",
    codec: CodecKind::Hevc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: NV12_OUTPUTS,
};

const FFMPEG_VVC_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "ffmpeg_vvc",
    codec: CodecKind::Vvc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: I420_OUTPUTS,
};

const NVDEC_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec",
    codec: CodecKind::H264,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

const NVDEC_D3D11_SHARED_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec_d3d11_shared",
    codec: CodecKind::H264,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: D3D11_TEXTURE_OUTPUTS,
};

const NVDEC_AV1_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec_av1",
    codec: CodecKind::Av1,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

const NVDEC_HEVC_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec_hevc",
    codec: CodecKind::Hevc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

const NVDEC_HEVC_D3D11_SHARED_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec_hevc_d3d11_shared",
    codec: CodecKind::Hevc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: D3D11_TEXTURE_OUTPUTS,
};

const NVDEC_HEVC_MAIN10_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec_hevc_main10",
    codec: CodecKind::HevcMain10,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

const NVDEC_HEVC_MAIN10_D3D11_SHARED_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "nvdec_hevc_main10_d3d11_shared",
    codec: CodecKind::HevcMain10,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: D3D11_TEXTURE_OUTPUTS,
};

#[cfg(target_os = "linux")]
const LINUX_H264_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "linux_h264",
    codec: CodecKind::H264,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

#[cfg(target_os = "linux")]
const LINUX_HEVC_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "linux_hevc",
    codec: CodecKind::Hevc,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

#[cfg(target_os = "linux")]
const LINUX_HEVC_MAIN10_DESCRIPTOR: DecoderDescriptor = DecoderDescriptor {
    id: "linux_hevc_main10",
    codec: CodecKind::HevcMain10,
    runtime_status: RuntimeStatus::RuntimeBacked,
    output_formats: RGB24_OUTPUTS,
};

pub fn available_decoder_descriptors() -> Vec<DecoderDescriptor> {
    let descriptors = vec![
        H264_SOFTWARE_DESCRIPTOR.clone(),
        HEVC_SOFTWARE_DESCRIPTOR.clone(),
        HEVC_MAIN10_SOFTWARE_DESCRIPTOR.clone(),
        AV1_SOFTWARE_DESCRIPTOR.clone(),
        VVC_SOFTWARE_DESCRIPTOR.clone(),
        FFMPEG_H264_DESCRIPTOR.clone(),
        FFMPEG_HEVC_DESCRIPTOR.clone(),
        FFMPEG_VVC_DESCRIPTOR.clone(),
        NVDEC_D3D11_SHARED_DESCRIPTOR.clone(),
        NVDEC_DESCRIPTOR.clone(),
        NVDEC_HEVC_D3D11_SHARED_DESCRIPTOR.clone(),
        NVDEC_HEVC_DESCRIPTOR.clone(),
        NVDEC_HEVC_MAIN10_D3D11_SHARED_DESCRIPTOR.clone(),
        NVDEC_HEVC_MAIN10_DESCRIPTOR.clone(),
        NVDEC_AV1_DESCRIPTOR.clone(),
    ];

    #[cfg(target_os = "linux")]
    {
        let mut descriptors = descriptors;
        descriptors.extend([
            LINUX_H264_DESCRIPTOR.clone(),
            LINUX_HEVC_DESCRIPTOR.clone(),
            LINUX_HEVC_MAIN10_DESCRIPTOR.clone(),
        ]);
        descriptors
    }

    #[cfg(not(target_os = "linux"))]
    descriptors
}

pub fn create_decoder(id: &str) -> Result<Box<dyn VideoDecoder>, PipelineError> {
    match id {
        "h264_software" => Ok(Box::new(H264SoftwareDecoder::new()?)),
        "software_hevc" | "hevc_software" => create_rust_h265_decoder(false),
        "software_hevc_main10" | "hevc_main10_software" => create_rust_h265_decoder(true),
        "software_av1" | "av1_software" => create_dav1d_decoder(),
        "software_vvc" | "vvc_software" | "software_h266" | "h266_software" => {
            create_vvdec_decoder()
        }
        "ffmpeg_h264" | "h264_ffmpeg" => {
            Ok(Box::new(FfmpegCliDecoder::new(FfmpegDecodeCodec::H264)?))
        }
        "ffmpeg_hevc" | "hevc_ffmpeg" | "h265_ffmpeg" => {
            Ok(Box::new(FfmpegCliDecoder::new(FfmpegDecodeCodec::Hevc)?))
        }
        "ffmpeg_vvc" | "vvc_ffmpeg" | "ffmpeg_h266" | "h266_ffmpeg" => {
            Ok(Box::new(FfmpegCliDecoder::new(FfmpegDecodeCodec::Vvc)?))
        }
        "linux_h264" | "gstreamer_h264" | "vaapi_h264" => create_linux_h264_decoder(),
        "linux_hevc" | "gstreamer_hevc" | "vaapi_hevc" => create_linux_hevc_decoder(),
        "linux_hevc_main10" | "gstreamer_hevc_main10" | "vaapi_hevc_main10" => {
            create_linux_hevc_main10_decoder()
        }
        "nvdec" => Ok(Box::new(NvdecVideoDecoder::new()?)),
        "nvdec_d3d11_shared" => Ok(Box::new(NvdecVideoDecoder::new_d3d11_shared()?)),
        "nvdec_hevc_d3d11_shared" | "nvdec_d3d11_shared_hevc" => {
            Ok(Box::new(NvdecVideoDecoder::new_hevc_d3d11_shared()?))
        }
        "nvdec_hevc" => Ok(Box::new(NvdecVideoDecoder::new_hevc()?)),
        "nvdec_hevc_main10_d3d11_shared" | "nvdec_d3d11_shared_hevc_main10" => {
            Ok(Box::new(NvdecVideoDecoder::new_hevc_main10_d3d11_shared()?))
        }
        "nvdec_hevc_main10" => Ok(Box::new(NvdecVideoDecoder::new_hevc_main10()?)),
        "nvdec_av1" => Ok(Box::new(NvdecVideoDecoder::new_av1()?)),
        other => Err(PipelineError::Message(format!(
            "unknown decoder backend: {other}"
        ))),
    }
}

#[cfg(target_os = "linux")]
pub fn probe_linux_h264_hardware_available() -> Result<String, PipelineError> {
    let backend = select_linux_gst_backend(LinuxGstCodec::H264)?;
    Ok(backend.label.to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn probe_linux_h264_hardware_available() -> Result<String, PipelineError> {
    Err(PipelineError::Message(
        "Linux H.264 hardware decode is only available on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
pub fn probe_linux_hevc_hardware_available() -> Result<String, PipelineError> {
    let backend = select_linux_gst_backend(LinuxGstCodec::Hevc)?;
    Ok(backend.label.to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn probe_linux_hevc_hardware_available() -> Result<String, PipelineError> {
    Err(PipelineError::Message(
        "Linux HEVC hardware decode is only available on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
pub fn probe_linux_hevc_main10_hardware_available() -> Result<String, PipelineError> {
    let backend = select_linux_gst_backend(LinuxGstCodec::HevcMain10)?;
    Ok(backend.label.to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn probe_linux_hevc_main10_hardware_available() -> Result<String, PipelineError> {
    Err(PipelineError::Message(
        "Linux HEVC Main10 hardware decode is only available on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn create_linux_h264_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Ok(Box::new(LinuxGstDecoder::new(LinuxGstCodec::H264)?))
}

#[cfg(not(target_os = "linux"))]
fn create_linux_h264_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Err(PipelineError::Message(
        "Linux H.264 hardware decode is only available on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn create_linux_hevc_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Ok(Box::new(LinuxGstDecoder::new(LinuxGstCodec::Hevc)?))
}

#[cfg(not(target_os = "linux"))]
fn create_linux_hevc_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Err(PipelineError::Message(
        "Linux HEVC hardware decode is only available on Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn create_linux_hevc_main10_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Ok(Box::new(LinuxGstDecoder::new(LinuxGstCodec::HevcMain10)?))
}

#[cfg(not(target_os = "linux"))]
fn create_linux_hevc_main10_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Err(PipelineError::Message(
        "Linux HEVC Main10 hardware decode is only available on Linux".to_string(),
    ))
}

pub struct H264SoftwareDecoder {
    decoder: OpenH264Decoder,
    decoded_frames: Vec<CoreDecodedFrame>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftwareYuvLayout {
    I400,
    I420,
    I422,
    I444,
}

#[derive(Clone, Copy)]
struct PlanarYuvFrame<'a> {
    width: usize,
    height: usize,
    layout: SoftwareYuvLayout,
    bit_depth: usize,
    bytes_per_sample: usize,
    y: &'a [u8],
    y_stride: usize,
    u: &'a [u8],
    u_stride: usize,
    v: &'a [u8],
    v_stride: usize,
    full_range: bool,
}

fn software_codec_not_compiled(
    codec_label: &str,
    runtime_label: &str,
    feature: &str,
) -> PipelineError {
    PipelineError::Message(format!(
        "software {codec_label} decoder requires {runtime_label}; rebuild mrd-decode with feature `{feature}` to enable that backend"
    ))
}

#[cfg(feature = "software-rust-h265")]
pub struct RustH265SoftwareDecoder {
    tx: std::sync::mpsc::Sender<RustH265Request>,
    decoded_frames: Vec<CoreDecodedFrame>,
}

#[cfg(feature = "software-rust-h265")]
enum RustH265Request {
    Push {
        access_unit: Vec<u8>,
        reply: std::sync::mpsc::Sender<Result<Vec<CoreDecodedFrame>, PipelineError>>,
    },
    Stop,
}

#[cfg(feature = "software-rust-h265")]
impl RustH265SoftwareDecoder {
    fn new(require_main10: bool) -> Result<Self, PipelineError> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("mrd-rust-h265-decoder".to_string())
            .spawn(move || rust_h265_worker(rx, require_main10))
            .map_err(|error| {
                PipelineError::Message(format!("spawn rust_h265 decoder worker failed: {error}"))
            })?;
        Ok(Self {
            tx,
            decoded_frames: Vec::new(),
        })
    }

    fn push_access_unit_nals(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        let (reply, reply_rx) = std::sync::mpsc::channel();
        self.tx
            .send(RustH265Request::Push {
                access_unit: access_unit.to_vec(),
                reply,
            })
            .map_err(|error| {
                PipelineError::Message(format!("rust_h265 decoder worker stopped: {error}"))
            })?;
        let frames = reply_rx.recv().map_err(|error| {
            PipelineError::Message(format!("rust_h265 decoder worker did not reply: {error}"))
        })??;
        self.decoded_frames.extend(frames);
        Ok(())
    }
}

#[cfg(feature = "software-rust-h265")]
impl Drop for RustH265SoftwareDecoder {
    fn drop(&mut self) {
        let _ = self.tx.send(RustH265Request::Stop);
    }
}

#[cfg(feature = "software-dav1d")]
pub struct Dav1dSoftwareDecoder {
    decoder: shiguredo_dav1d::Decoder,
    decoded_frames: Vec<CoreDecodedFrame>,
    frame_index: u64,
}

#[cfg(feature = "software-dav1d")]
impl Dav1dSoftwareDecoder {
    fn new() -> Result<Self, PipelineError> {
        let mut config = shiguredo_dav1d::DecoderConfig::new();
        config.n_threads = std::thread::available_parallelism()
            .map(|count| count.get().min(8))
            .unwrap_or(1);
        let decoder = shiguredo_dav1d::Decoder::new(config)
            .map_err(|error| PipelineError::Message(format!("dav1d init failed: {error}")))?;
        Ok(Self {
            decoder,
            decoded_frames: Vec::new(),
            frame_index: 0,
        })
    }

    fn collect_frames(&mut self) -> Result<(), PipelineError> {
        loop {
            match self.decoder.next_frame() {
                Ok(Some(frame)) => {
                    let timestamp_us = self.frame_index.saturating_mul(16_667);
                    self.frame_index = self.frame_index.saturating_add(1);
                    self.decoded_frames
                        .push(dav1d_frame_to_core_frame(&frame, timestamp_us)?);
                }
                Ok(None) => return Ok(()),
                Err(error) => {
                    return Err(PipelineError::Message(format!(
                        "dav1d receive frame failed: {error}"
                    )))
                }
            }
        }
    }
}

#[cfg(feature = "software-vvdec")]
pub struct VvdecSoftwareDecoder {
    decoder: vvdec::Decoder,
    decoded_frames: Vec<CoreDecodedFrame>,
    input_index: u64,
    frame_index: u64,
}

#[cfg(feature = "software-vvdec")]
impl VvdecSoftwareDecoder {
    fn new() -> Result<Self, PipelineError> {
        let threads = std::thread::available_parallelism()
            .map(|count| count.get().min(8) as i32)
            .unwrap_or(1);
        let decoder = vvdec::Decoder::builder()
            .num_threads(threads)
            .build()
            .map_err(|error| PipelineError::Message(format!("VVdeC init failed: {error}")))?;
        Ok(Self {
            decoder,
            decoded_frames: Vec::new(),
            input_index: 0,
            frame_index: 0,
        })
    }

    fn push_frame(&mut self, frame: vvdec::Frame) -> Result<(), PipelineError> {
        let timestamp_us = frame
            .cts()
            .unwrap_or_else(|| self.frame_index.saturating_mul(16_667));
        self.frame_index = self.frame_index.saturating_add(1);
        self.decoded_frames
            .push(vvdec_frame_to_core_frame(&frame, timestamp_us)?);
        Ok(())
    }
}

pub struct NvdecVideoDecoder {
    decoder: mrd_decode_nvdec::NvdecDecoder,
    require_shared_output: bool,
}

impl NvdecVideoDecoder {
    pub fn new() -> Result<Self, PipelineError> {
        let decoder = mrd_decode_nvdec::NvdecDecoder::new_with_output_mode(
            mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
        )
        .map_err(|e| PipelineError::Message(format!("nvdec create failed: {e}")))?;
        Ok(Self {
            decoder,
            require_shared_output: false,
        })
    }

    pub fn new_d3d11_shared() -> Result<Self, PipelineError> {
        #[cfg(not(windows))]
        {
            Err(PipelineError::Message(
                "nvdec d3d11 shared output is only available on Windows".to_string(),
            ))
        }

        #[cfg(windows)]
        {
            let mut decoder = mrd_decode_nvdec::NvdecDecoder::new_with_output_mode(
                mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
            )
            .map_err(|e| {
                PipelineError::Message(format!("nvdec d3d11 shared create failed: {e}"))
            })?;
            decoder.enable_shared_texture(true);
            Ok(Self {
                decoder,
                require_shared_output: true,
            })
        }
    }

    pub fn new_av1() -> Result<Self, PipelineError> {
        let decoder = mrd_decode_nvdec::NvdecDecoder::new_av1_with_output_mode(
            mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
        )
        .map_err(|e| PipelineError::Message(format!("nvdec av1 create failed: {e}")))?;
        Ok(Self {
            decoder,
            require_shared_output: false,
        })
    }

    pub fn new_hevc() -> Result<Self, PipelineError> {
        let decoder = mrd_decode_nvdec::NvdecDecoder::new_hevc_with_output_mode(
            mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
        )
        .map_err(|e| PipelineError::Message(format!("nvdec hevc create failed: {e}")))?;
        Ok(Self {
            decoder,
            require_shared_output: false,
        })
    }

    pub fn new_hevc_d3d11_shared() -> Result<Self, PipelineError> {
        #[cfg(not(windows))]
        {
            Err(PipelineError::Message(
                "nvdec hevc d3d11 shared output is only available on Windows".to_string(),
            ))
        }

        #[cfg(windows)]
        {
            let mut decoder = mrd_decode_nvdec::NvdecDecoder::new_hevc_with_output_mode(
                mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
            )
            .map_err(|e| {
                PipelineError::Message(format!("nvdec hevc d3d11 shared create failed: {e}"))
            })?;
            decoder.enable_shared_texture(true);
            Ok(Self {
                decoder,
                require_shared_output: true,
            })
        }
    }

    pub fn new_hevc_main10() -> Result<Self, PipelineError> {
        let decoder = mrd_decode_nvdec::NvdecDecoder::new_hevc_main10_with_output_mode(
            mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
        )
        .map_err(|e| PipelineError::Message(format!("nvdec hevc main10 create failed: {e}")))?;
        Ok(Self {
            decoder,
            require_shared_output: false,
        })
    }

    pub fn new_hevc_main10_d3d11_shared() -> Result<Self, PipelineError> {
        #[cfg(not(windows))]
        {
            Err(PipelineError::Message(
                "nvdec hevc main10 d3d11 shared output is only available on Windows".to_string(),
            ))
        }

        #[cfg(windows)]
        {
            let mut decoder = mrd_decode_nvdec::NvdecDecoder::new_hevc_main10_with_output_mode(
                mrd_decode_nvdec::NvdecOutputMode::CpuNv12,
            )
            .map_err(|e| {
                PipelineError::Message(format!("nvdec hevc main10 d3d11 shared create failed: {e}"))
            })?;
            decoder.enable_shared_texture(true);
            Ok(Self {
                decoder,
                require_shared_output: true,
            })
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
enum LinuxGstCodec {
    H264,
    Hevc,
    HevcMain10,
}

#[cfg(target_os = "linux")]
impl LinuxGstCodec {
    fn parser_element(self) -> &'static str {
        match self {
            Self::H264 => "h264parse",
            Self::Hevc | Self::HevcMain10 => "h265parse",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::H264 => "H.264",
            Self::Hevc => "HEVC",
            Self::HevcMain10 => "HEVC Main10",
        }
    }

    fn parse_dimensions(self, access_unit: &[u8]) -> Result<Option<(usize, usize)>, PipelineError> {
        match self {
            Self::H264 => parse_h264_dimensions(access_unit),
            Self::Hevc | Self::HevcMain10 => parse_hevc_dimensions(access_unit),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct LinuxGstBackend {
    label: &'static str,
    required_elements: &'static [&'static str],
    pipeline_elements: &'static [&'static str],
}

#[cfg(target_os = "linux")]
const LINUX_GST_H264_BACKENDS: &[LinuxGstBackend] = &[
    LinuxGstBackend {
        label: "GStreamer VA H.264 decoder",
        required_elements: &["vah264dec", "vapostproc"],
        pipeline_elements: &["vah264dec", "!", "vapostproc"],
    },
    LinuxGstBackend {
        label: "GStreamer VA-API H.264 decoder",
        required_elements: &["vaapih264dec", "vaapipostproc"],
        pipeline_elements: &["vaapih264dec", "!", "vaapipostproc"],
    },
    LinuxGstBackend {
        label: "GStreamer NVIDIA H.264 decoder",
        required_elements: &["nvh264dec", "cudadownload"],
        pipeline_elements: &["nvh264dec", "!", "cudadownload"],
    },
];

#[cfg(target_os = "linux")]
const LINUX_GST_HEVC_BACKENDS: &[LinuxGstBackend] = &[
    LinuxGstBackend {
        label: "GStreamer VA HEVC decoder",
        required_elements: &["vah265dec", "vapostproc"],
        pipeline_elements: &["vah265dec", "!", "vapostproc"],
    },
    LinuxGstBackend {
        label: "GStreamer VA-API HEVC decoder",
        required_elements: &["vaapih265dec", "vaapipostproc"],
        pipeline_elements: &["vaapih265dec", "!", "vaapipostproc"],
    },
    LinuxGstBackend {
        label: "GStreamer NVIDIA HEVC decoder",
        required_elements: &["nvh265dec", "cudadownload"],
        pipeline_elements: &["nvh265dec", "!", "cudadownload"],
    },
];

#[cfg(target_os = "linux")]
fn select_linux_gst_backend(codec: LinuxGstCodec) -> Result<LinuxGstBackend, PipelineError> {
    if Command::new("gst-inspect-1.0")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Err(PipelineError::Message(
            "GStreamer runtime is missing: gst-inspect-1.0 was not found".to_string(),
        ));
    }

    let backends = match codec {
        LinuxGstCodec::H264 => LINUX_GST_H264_BACKENDS,
        LinuxGstCodec::Hevc | LinuxGstCodec::HevcMain10 => LINUX_GST_HEVC_BACKENDS,
    };

    backends
        .iter()
        .copied()
        .find(|backend| {
            backend
                .required_elements
                .iter()
                .all(|element| gst_element_available(element))
        })
        .ok_or_else(|| {
            PipelineError::Message(format!(
                "No GStreamer hardware {} decoder was found",
                codec.label()
            ))
        })
}

#[cfg(target_os = "linux")]
fn gst_element_available(element: &str) -> bool {
    Command::new("gst-inspect-1.0")
        .arg(element)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub struct LinuxGstDecoder {
    codec: LinuxGstCodec,
    backend: LinuxGstBackend,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frame_rx: Option<mpsc::Receiver<Vec<u8>>>,
    dimensions: Option<(usize, usize)>,
    pending_stream: Vec<u8>,
    decoded_frames: Vec<CoreDecodedFrame>,
    frame_index: u64,
}

#[cfg(target_os = "linux")]
impl LinuxGstDecoder {
    fn new(codec: LinuxGstCodec) -> Result<Self, PipelineError> {
        Ok(Self {
            codec,
            backend: select_linux_gst_backend(codec)?,
            child: None,
            stdin: None,
            frame_rx: None,
            dimensions: None,
            pending_stream: Vec::new(),
            decoded_frames: Vec::new(),
            frame_index: 0,
        })
    }

    fn start_pipeline(&mut self, width: usize, height: usize) -> Result<(), PipelineError> {
        if self.child.is_some() {
            return Ok(());
        }

        let frame_size = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or_else(|| PipelineError::Message("decoded RGB frame size overflow".to_string()))?;

        let mut args = vec!["-q", "fdsrc", "fd=0", "!", self.codec.parser_element(), "!"];
        args.extend_from_slice(self.backend.pipeline_elements);
        args.extend_from_slice(&[
            "!",
            "videoconvert",
            "!",
            "video/x-raw,format=RGB",
            "!",
            "fdsink",
            "fd=1",
            "sync=false",
        ]);

        let mut child = Command::new("gst-launch-1.0")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                PipelineError::Message(format!(
                    "spawn GStreamer {} decoder failed ({}): {error}",
                    self.codec.label(),
                    self.backend.label
                ))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            PipelineError::Message("GStreamer decoder stdout pipe was not created".to_string())
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            PipelineError::Message("GStreamer decoder stdin pipe was not created".to_string())
        })?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || read_raw_rgb_frames(stdout, frame_size, tx));

        self.stdin = Some(stdin);
        self.frame_rx = Some(rx);
        self.child = Some(child);

        Ok(())
    }

    fn write_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            PipelineError::Message("GStreamer decoder stdin is not available".to_string())
        })?;
        stdin
            .write_all(access_unit)
            .and_then(|()| stdin.flush())
            .map_err(|error| {
                PipelineError::Message(format!(
                    "write {} access unit to GStreamer decoder failed: {error}",
                    self.codec.label()
                ))
            })
    }

    fn collect_frames(&mut self) {
        let Some((width, height)) = self.dimensions else {
            return;
        };
        let Some(rx) = self.frame_rx.as_ref() else {
            return;
        };

        while let Ok(rgb) = rx.try_recv() {
            let timestamp_us = self.frame_index.saturating_mul(16_667);
            self.frame_index = self.frame_index.saturating_add(1);
            self.decoded_frames.push(CoreDecodedFrame::from_cpu_rgb24(
                width,
                height,
                timestamp_us,
                rgb,
            ));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxGstDecoder {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "linux")]
impl VideoDecoder for LinuxGstDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        if access_unit.is_empty() {
            return Ok(());
        }

        if let Some((width, height)) = self.codec.parse_dimensions(access_unit)? {
            if let Some((current_width, current_height)) = self.dimensions {
                if (width, height) != (current_width, current_height) {
                    return Err(PipelineError::Message(format!(
                        "Linux {} decoder does not support stream size changes yet: {current_width}x{current_height} -> {width}x{height}",
                        self.codec.label()
                    )));
                }
            } else {
                self.dimensions = Some((width, height));
            }
        }

        if self.child.is_none() {
            self.pending_stream.extend_from_slice(access_unit);
            if let Some((width, height)) = self.dimensions {
                self.start_pipeline(width, height)?;
                let pending = std::mem::take(&mut self.pending_stream);
                self.write_access_unit(&pending)?;
            } else if self.pending_stream.len() > 8 * 1024 * 1024 {
                return Err(PipelineError::Message(format!(
                    "Linux {} decoder is waiting for an SPS NAL to discover stream dimensions",
                    self.codec.label()
                )));
            }
        } else {
            self.write_access_unit(access_unit)?;
        }

        self.collect_frames();
        Ok(())
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        self.collect_frames();
        std::mem::take(&mut self.decoded_frames)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfmpegDecodeCodec {
    H264,
    Hevc,
    Vvc,
}

impl FfmpegDecodeCodec {
    fn label(self) -> &'static str {
        match self {
            Self::H264 => "H.264",
            Self::Hevc => "HEVC",
            Self::Vvc => "VVC",
        }
    }

    fn input_format(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
            Self::Vvc => "vvc",
        }
    }

    fn parse_dimensions(self, access_unit: &[u8]) -> Result<Option<(usize, usize)>, PipelineError> {
        match self {
            Self::H264 => parse_h264_dimensions(access_unit),
            Self::Hevc => parse_hevc_dimensions(access_unit),
            Self::Vvc => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FfmpegOutputPixelFormat {
    Nv12,
    I420,
}

impl FfmpegOutputPixelFormat {
    fn ffmpeg_name(self) -> &'static str {
        match self {
            Self::Nv12 => "nv12",
            Self::I420 => "yuv420p",
        }
    }

    fn frame_size(self, width: usize, height: usize) -> Result<usize, PipelineError> {
        match self {
            Self::Nv12 | Self::I420 => yuv420_8bit_frame_size(width, height),
        }
    }

    fn can_start_without_dimensions(self) -> bool {
        matches!(self, Self::I420)
    }
}

pub struct FfmpegCliDecoder {
    codec: FfmpegDecodeCodec,
    ffmpeg_path: PathBuf,
    output_format: FfmpegOutputPixelFormat,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frame_rx: Option<mpsc::Receiver<FfmpegDecodedFrame>>,
    dimensions: Option<(usize, usize)>,
    pending_stream: Vec<u8>,
    decoded_frames: Vec<CoreDecodedFrame>,
    frame_index: u64,
}

impl FfmpegCliDecoder {
    pub fn new(codec: FfmpegDecodeCodec) -> Result<Self, PipelineError> {
        let settings = ffmpeg_settings_from_environment();
        let probe = mrd_ffmpeg::probe_ffmpeg(&settings);
        let Some(ffmpeg_path) = probe.ffmpeg_path else {
            let reason = probe
                .reason
                .unwrap_or_else(|| "ffmpeg executable was not found".to_string());
            return Err(PipelineError::Message(format!(
                "FFmpeg {} decoder unavailable: {reason}",
                codec.label()
            )));
        };

        Self::new_with_ffmpeg_path(codec, ffmpeg_path)
    }

    pub fn new_with_ffmpeg_path(
        codec: FfmpegDecodeCodec,
        ffmpeg_path: PathBuf,
    ) -> Result<Self, PipelineError> {
        if !ffmpeg_path.is_file() {
            return Err(PipelineError::Message(format!(
                "FFmpeg executable not found: {}",
                ffmpeg_path.display()
            )));
        }

        Ok(Self {
            codec,
            ffmpeg_path,
            output_format: match codec {
                FfmpegDecodeCodec::Vvc => FfmpegOutputPixelFormat::I420,
                FfmpegDecodeCodec::H264 | FfmpegDecodeCodec::Hevc => FfmpegOutputPixelFormat::Nv12,
            },
            child: None,
            stdin: None,
            frame_rx: None,
            dimensions: None,
            pending_stream: Vec::new(),
            decoded_frames: Vec::new(),
            frame_index: 0,
        })
    }

    fn start_process(&mut self, dimensions: Option<(usize, usize)>) -> Result<(), PipelineError> {
        if self.child.is_some() {
            return Ok(());
        }

        let mut args = vec![
            "-hide_banner",
            "-loglevel",
            "error",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
            "-flags",
            "low_delay",
            "-f",
            self.codec.input_format(),
            "-i",
            "pipe:0",
            "-an",
            "-sn",
            "-dn",
        ];
        match self.output_format {
            FfmpegOutputPixelFormat::Nv12 => {
                args.extend([
                    "-f",
                    "rawvideo",
                    "-pix_fmt",
                    self.output_format.ffmpeg_name(),
                    "pipe:1",
                ]);
            }
            FfmpegOutputPixelFormat::I420 => {
                args.extend([
                    "-f",
                    "yuv4mpegpipe",
                    "-pix_fmt",
                    self.output_format.ffmpeg_name(),
                    "pipe:1",
                ]);
            }
        }

        let mut child = Command::new(&self.ffmpeg_path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                PipelineError::Message(format!(
                    "spawn FFmpeg {} decoder failed ({}): {error}",
                    self.codec.label(),
                    self.ffmpeg_path.display()
                ))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            PipelineError::Message("FFmpeg decoder stdout pipe was not created".to_string())
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            PipelineError::Message("FFmpeg decoder stdin pipe was not created".to_string())
        })?;
        let (tx, rx) = mpsc::channel();
        match self.output_format {
            FfmpegOutputPixelFormat::Nv12 => {
                let (width, height) = dimensions.ok_or_else(|| {
                    PipelineError::Message(
                        "FFmpeg rawvideo decoder requires known dimensions".to_string(),
                    )
                })?;
                let frame_size = self.output_format.frame_size(width, height)?;
                thread::spawn(move || {
                    read_ffmpeg_raw_video_frames(stdout, width, height, frame_size, tx)
                });
            }
            FfmpegOutputPixelFormat::I420 => {
                thread::spawn(move || read_y4m_frames(stdout, tx));
            }
        }

        self.stdin = Some(stdin);
        self.frame_rx = Some(rx);
        self.child = Some(child);
        Ok(())
    }

    fn stop_process(&mut self) {
        drop(self.stdin.take());
        self.frame_rx = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn write_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            PipelineError::Message("FFmpeg decoder stdin is not available".to_string())
        })?;
        stdin
            .write_all(access_unit)
            .and_then(|()| stdin.flush())
            .map_err(|error| {
                PipelineError::Message(format!(
                    "write {} access unit to FFmpeg decoder failed: {error}",
                    self.codec.label()
                ))
            })
    }

    fn collect_frames(&mut self, wait_for_first: Option<Duration>) {
        let Some(rx) = self.frame_rx.as_ref() else {
            return;
        };

        let mut raw_frames = Vec::new();
        if let Some(timeout) = wait_for_first {
            if let Ok(frame) = rx.recv_timeout(timeout) {
                raw_frames.push(frame);
            }
        }
        while let Ok(frame) = rx.try_recv() {
            raw_frames.push(frame);
        }

        for frame in raw_frames {
            let timestamp_us = self.frame_index.saturating_mul(16_667);
            self.frame_index = self.frame_index.saturating_add(1);
            self.dimensions = Some((frame.width, frame.height));
            match self.output_format {
                FfmpegOutputPixelFormat::Nv12 => {
                    self.decoded_frames.push(CoreDecodedFrame::from_cpu_nv12(
                        frame.width,
                        frame.height,
                        timestamp_us,
                        frame.width,
                        frame.data,
                    ))
                }
                FfmpegOutputPixelFormat::I420 => {
                    let uv_pitch = frame.width / 2;
                    self.decoded_frames.push(CoreDecodedFrame::from_cpu_i420(
                        frame.width,
                        frame.height,
                        timestamp_us,
                        frame.width,
                        uv_pitch,
                        frame.data,
                    ));
                }
            }
        }
    }
}

impl Drop for FfmpegCliDecoder {
    fn drop(&mut self) {
        self.stop_process();
    }
}

impl VideoDecoder for FfmpegCliDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        if access_unit.is_empty() {
            return Ok(());
        }

        if let Some((width, height)) = self.codec.parse_dimensions(access_unit)? {
            if self
                .dimensions
                .is_some_and(|current| current != (width, height))
            {
                self.stop_process();
                self.pending_stream.clear();
            }
            self.dimensions = Some((width, height));
        }

        if self.child.is_none() {
            self.pending_stream.extend_from_slice(access_unit);
            if let Some((width, height)) = self.dimensions {
                self.start_process(Some((width, height)))?;
                let pending = std::mem::take(&mut self.pending_stream);
                self.write_access_unit(&pending)?;
            } else if self.output_format.can_start_without_dimensions() {
                self.start_process(None)?;
                let pending = std::mem::take(&mut self.pending_stream);
                self.write_access_unit(&pending)?;
            } else if self.pending_stream.len() > 8 * 1024 * 1024 {
                return Err(PipelineError::Message(format!(
                    "FFmpeg {} decoder is waiting for an SPS NAL to discover stream dimensions",
                    self.codec.label()
                )));
            }
        } else {
            self.write_access_unit(access_unit)?;
        }

        self.collect_frames(Some(Duration::from_millis(10)));
        Ok(())
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        self.collect_frames(None);
        std::mem::take(&mut self.decoded_frames)
    }
}

fn ffmpeg_settings_from_environment() -> mrd_ffmpeg::FfmpegSettings {
    let mut settings = mrd_ffmpeg::golden_settings();
    if env_flag_enabled("MRD_FFMPEG_DISABLE") {
        settings.enabled = false;
    }
    if let Ok(path) = std::env::var("MRD_FFMPEG_PATH") {
        if !path.trim().is_empty() {
            settings.ffmpeg_path = Some(PathBuf::from(path));
        }
    }
    if let Ok(path) = std::env::var("MRD_FFPROBE_PATH") {
        if !path.trim().is_empty() {
            settings.ffprobe_path = Some(PathBuf::from(path));
        }
    }
    if let Ok(path) = std::env::var("MRD_FFMPEG_INSTALL_DIR") {
        if !path.trim().is_empty() {
            settings.install_dir = Some(PathBuf::from(path));
        }
    }
    settings
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn yuv420_8bit_frame_size(width: usize, height: usize) -> Result<usize, PipelineError> {
    if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(PipelineError::Message(format!(
            "8-bit 4:2:0 output requires even dimensions, got {width}x{height}"
        )));
    }
    width
        .checked_mul(height)
        .and_then(|luma| luma.checked_add(luma / 2))
        .ok_or_else(|| {
            PipelineError::Message("decoded 8-bit 4:2:0 frame size overflow".to_string())
        })
}

fn read_raw_video_frames(
    mut stdout: std::process::ChildStdout,
    frame_size: usize,
    tx: mpsc::Sender<Vec<u8>>,
) {
    loop {
        let mut frame = vec![0_u8; frame_size];
        match stdout.read_exact(&mut frame) {
            Ok(()) => {
                if tx.send(frame).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn read_ffmpeg_raw_video_frames(
    mut stdout: std::process::ChildStdout,
    width: usize,
    height: usize,
    frame_size: usize,
    tx: mpsc::Sender<FfmpegDecodedFrame>,
) {
    loop {
        let mut data = vec![0_u8; frame_size];
        match stdout.read_exact(&mut data) {
            Ok(()) => {
                if tx
                    .send(FfmpegDecodedFrame {
                        width,
                        height,
                        data,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn read_y4m_frames(stdout: std::process::ChildStdout, tx: mpsc::Sender<FfmpegDecodedFrame>) {
    let mut reader = BufReader::new(stdout);
    let mut header = String::new();
    if reader.read_line(&mut header).is_err() {
        return;
    }
    let Some((width, height)) = parse_y4m_dimensions(&header) else {
        return;
    };
    let Ok(frame_size) = yuv420_8bit_frame_size(width, height) else {
        return;
    };

    loop {
        let mut frame_header = String::new();
        match reader.read_line(&mut frame_header) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if !frame_header.starts_with("FRAME") {
            break;
        }

        let mut data = vec![0_u8; frame_size];
        if reader.read_exact(&mut data).is_err() {
            break;
        }
        if tx
            .send(FfmpegDecodedFrame {
                width,
                height,
                data,
            })
            .is_err()
        {
            break;
        }
    }
}

fn parse_y4m_dimensions(header: &str) -> Option<(usize, usize)> {
    if !header.starts_with("YUV4MPEG2") {
        return None;
    }
    let mut width = None;
    let mut height = None;
    for token in header.split_whitespace().skip(1) {
        if let Some(value) = token.strip_prefix('W') {
            width = value.parse::<usize>().ok();
        } else if let Some(value) = token.strip_prefix('H') {
            height = value.parse::<usize>().ok();
        }
    }
    match (width, height) {
        (Some(width), Some(height)) if width > 0 && height > 0 => Some((width, height)),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn read_raw_rgb_frames(
    stdout: std::process::ChildStdout,
    frame_size: usize,
    tx: mpsc::Sender<Vec<u8>>,
) {
    read_raw_video_frames(stdout, frame_size, tx);
}

impl H264SoftwareDecoder {
    pub fn new() -> Result<Self, PipelineError> {
        Ok(Self {
            decoder: OpenH264Decoder::new()
                .map_err(|e| PipelineError::Message(format!("openh264 init failed: {e}")))?,
            decoded_frames: Vec::new(),
        })
    }
}

#[cfg(feature = "software-rust-h265")]
fn create_rust_h265_decoder(require_main10: bool) -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Ok(Box::new(RustH265SoftwareDecoder::new(require_main10)?))
}

#[cfg(not(feature = "software-rust-h265"))]
fn create_rust_h265_decoder(_require_main10: bool) -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Err(software_codec_not_compiled(
        "HEVC/Main10",
        "rust_h265",
        "software-rust-h265",
    ))
}

#[cfg(feature = "software-dav1d")]
fn create_dav1d_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Ok(Box::new(Dav1dSoftwareDecoder::new()?))
}

#[cfg(not(feature = "software-dav1d"))]
fn create_dav1d_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Err(software_codec_not_compiled(
        "AV1",
        "dav1d",
        "software-dav1d",
    ))
}

#[cfg(feature = "software-vvdec")]
fn create_vvdec_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Ok(Box::new(VvdecSoftwareDecoder::new()?))
}

#[cfg(not(feature = "software-vvdec"))]
fn create_vvdec_decoder() -> Result<Box<dyn VideoDecoder>, PipelineError> {
    Err(software_codec_not_compiled(
        "H.266/VVC",
        "VVdeC",
        "software-vvdec",
    ))
}

#[cfg(feature = "software-rust-h265")]
impl VideoDecoder for RustH265SoftwareDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        if access_unit.is_empty() {
            return Ok(());
        }

        self.push_access_unit_nals(access_unit)
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        std::mem::take(&mut self.decoded_frames)
    }
}

#[cfg(feature = "software-dav1d")]
impl VideoDecoder for Dav1dSoftwareDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        if access_unit.is_empty() {
            return Ok(());
        }

        match self.decoder.decode(access_unit) {
            Ok(()) => {}
            Err(error) if error.is_eagain() => {
                self.collect_frames()?;
                self.decoder.decode(access_unit).map_err(|error| {
                    PipelineError::Message(format!("dav1d decode failed after drain: {error}"))
                })?;
            }
            Err(error) => {
                return Err(PipelineError::Message(format!(
                    "dav1d decode failed: {error}"
                )))
            }
        }

        self.collect_frames()
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        std::mem::take(&mut self.decoded_frames)
    }
}

#[cfg(feature = "software-vvdec")]
impl VideoDecoder for VvdecSoftwareDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        if access_unit.is_empty() {
            return Ok(());
        }

        let mut au = vvdec::AccessUnit::new(access_unit);
        au.cts = Some(self.input_index.saturating_mul(16_667));
        au.dts = Some(self.input_index.saturating_mul(16_667));
        self.input_index = self.input_index.saturating_add(1);
        au.is_random_access_point = vvc_access_unit_contains_random_access_point(access_unit);
        match self.decoder.decode::<&[u8], _>(au) {
            Ok(Some(frame)) => self.push_frame(frame),
            Ok(None) => Ok(()),
            Err(vvdec::Error::TryAgain) => Ok(()),
            Err(error) => Err(PipelineError::Message(format!(
                "VVdeC decode failed: {error}"
            ))),
        }
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        std::mem::take(&mut self.decoded_frames)
    }
}

struct FfmpegDecodedFrame {
    width: usize,
    height: usize,
    data: Vec<u8>,
}

#[cfg(feature = "software-vvdec")]
fn vvc_access_unit_contains_random_access_point(access_unit: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + 5 < access_unit.len() {
        let nal_offset = if access_unit[offset..].starts_with(&[0, 0, 0, 1]) {
            offset + 4
        } else if access_unit[offset..].starts_with(&[0, 0, 1]) {
            offset + 3
        } else {
            offset += 1;
            continue;
        };

        if vvc_nal_is_random_access_point(&access_unit[nal_offset..]) {
            return true;
        }
        offset = nal_offset + 2;
    }
    false
}

#[cfg(feature = "software-vvdec")]
fn vvc_nal_is_random_access_point(nal: &[u8]) -> bool {
    if nal.len() < 2 {
        return false;
    }
    matches!((nal[1] >> 3) & 0x1f, 7..=10)
}

impl VideoDecoder for H264SoftwareDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        let decoded_frame = match self.decoder.decode(access_unit) {
            Ok(Some(decoded)) => Some(decoded_yuv_to_i420_frame(&decoded, 0)?),
            Ok(None) => None,
            Err(e) => {
                return Err(PipelineError::Message(format!(
                    "openh264 decode failed: {e}"
                )))
            }
        };

        if let Some(frame) = decoded_frame {
            self.decoded_frames.push(frame);
        }

        Ok(())
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        std::mem::take(&mut self.decoded_frames)
    }
}

fn decoded_yuv_to_i420_frame(
    decoded: &DecodedYUV<'_>,
    timestamp_us: u64,
) -> Result<CoreDecodedFrame, PipelineError> {
    let (width, height) = decoded.dimensions();
    let strides = decoded.strides();
    let (data, y_pitch, uv_pitch) = planar_i420_8_to_i420(PlanarYuvFrame {
        width,
        height,
        layout: SoftwareYuvLayout::I420,
        bit_depth: 8,
        bytes_per_sample: 1,
        y: decoded.y(),
        y_stride: strides.0,
        u: decoded.u(),
        u_stride: strides.1,
        v: decoded.v(),
        v_stride: strides.2,
        full_range: false,
    })?;
    Ok(CoreDecodedFrame::from_cpu_i420(
        width,
        height,
        timestamp_us,
        y_pitch,
        uv_pitch,
        data,
    ))
}

#[cfg(feature = "software-rust-h265")]
fn rust_h265_worker(rx: std::sync::mpsc::Receiver<RustH265Request>, require_main10: bool) {
    let mut decoder = rust_h265::Decoder::new();
    let mut frame_index = 0_u64;
    while let Ok(request) = rx.recv() {
        match request {
            RustH265Request::Push { access_unit, reply } => {
                let _ = reply.send(decode_rust_h265_access_unit(
                    &mut decoder,
                    &access_unit,
                    require_main10,
                    &mut frame_index,
                ));
            }
            RustH265Request::Stop => break,
        }
    }
}

#[cfg(feature = "software-rust-h265")]
fn decode_rust_h265_access_unit(
    decoder: &mut rust_h265::Decoder,
    access_unit: &[u8],
    require_main10: bool,
    frame_index: &mut u64,
) -> Result<Vec<CoreDecodedFrame>, PipelineError> {
    let nals = rust_h265::parse_annex_b(access_unit);
    if nals.is_empty() {
        return Err(PipelineError::Message(
            "rust_h265 requires Annex B HEVC access units".to_string(),
        ));
    }

    let mut decoded_frames = Vec::new();
    for nal in nals {
        if let Some(frame) = decoder
            .decode_nal(&nal)
            .map_err(|error| PipelineError::Message(format!("rust_h265 decode failed: {error}")))?
        {
            if require_main10 && frame.bit_depth < 10 {
                return Err(PipelineError::Message(format!(
                    "rust_h265 decoded HEVC frame is {}-bit, expected Main10",
                    frame.bit_depth
                )));
            }
            decoded_frames.push(rust_h265_frame_to_core_frame(
                &frame,
                (*frame_index).saturating_mul(16_667),
            )?);
            *frame_index = (*frame_index).saturating_add(1);
        }
    }
    Ok(decoded_frames)
}

#[cfg(feature = "software-rust-h265")]
fn rust_h265_frame_to_core_frame(
    frame: &rust_h265::Frame,
    timestamp_us: u64,
) -> Result<CoreDecodedFrame, PipelineError> {
    let width = frame.width as usize;
    let height = frame.height as usize;
    let chroma_width = width.div_ceil(2);
    let chroma_height = height.div_ceil(2);
    let bit_depth = frame.bit_depth as usize;
    let expected_y = width
        .checked_mul(height)
        .ok_or_else(|| PipelineError::Message("HEVC frame dimensions overflow".to_string()))?;
    let expected_uv = chroma_width
        .checked_mul(chroma_height)
        .ok_or_else(|| PipelineError::Message("HEVC chroma dimensions overflow".to_string()))?;
    if frame.y.len() < expected_y || frame.u.len() < expected_uv || frame.v.len() < expected_uv {
        return Err(PipelineError::Message(format!(
            "rust_h265 returned undersized HEVC planes: y={} u={} v={}, expected y>={expected_y} uv>={expected_uv}",
            frame.y.len(),
            frame.u.len(),
            frame.v.len()
        )));
    }

    match (&frame.y, &frame.u, &frame.v) {
        (rust_h265::PixelData::U8(y), rust_h265::PixelData::U8(u), rust_h265::PixelData::U8(v)) => {
            let (data, y_pitch, uv_pitch) = planar_i420_8_to_i420(PlanarYuvFrame {
                width,
                height,
                layout: SoftwareYuvLayout::I420,
                bit_depth,
                bytes_per_sample: 1,
                y,
                y_stride: width,
                u,
                u_stride: chroma_width,
                v,
                v_stride: chroma_width,
                full_range: false,
            })?;
            Ok(CoreDecodedFrame::from_cpu_i420(
                width,
                height,
                timestamp_us,
                y_pitch,
                uv_pitch,
                data,
            ))
        }
        (
            rust_h265::PixelData::U16(y),
            rust_h265::PixelData::U16(u),
            rust_h265::PixelData::U16(v),
        ) => {
            let (data, pitch) = planar_i420_u16_to_p010(PlanarYuv16Frame {
                width,
                height,
                bit_depth,
                y,
                y_stride: width,
                u,
                u_stride: chroma_width,
                v,
                v_stride: chroma_width,
                full_range: false,
            })?;
            Ok(CoreDecodedFrame::from_cpu_p010(
                width,
                height,
                timestamp_us,
                pitch,
                data,
            ))
        }
        _ => Err(PipelineError::Message(
            "rust_h265 returned mixed bit-depth planes".to_string(),
        )),
    }
}

#[cfg(feature = "software-dav1d")]
fn dav1d_frame_to_core_frame(
    frame: &shiguredo_dav1d::DecodedFrame,
    timestamp_us: u64,
) -> Result<CoreDecodedFrame, PipelineError> {
    let layout = match frame.pixel_layout() {
        shiguredo_dav1d::PixelLayout::I400 => SoftwareYuvLayout::I400,
        shiguredo_dav1d::PixelLayout::I420 => SoftwareYuvLayout::I420,
        shiguredo_dav1d::PixelLayout::I422 => SoftwareYuvLayout::I422,
        shiguredo_dav1d::PixelLayout::I444 => SoftwareYuvLayout::I444,
        shiguredo_dav1d::PixelLayout::Reserved => {
            return Err(PipelineError::Message(
                "dav1d returned a reserved AV1 pixel layout".to_string(),
            ))
        }
    };
    let width = frame.width();
    let height = frame.height();
    let bit_depth = frame.bit_depth();
    let bytes_per_sample = bytes_per_sample_for_bit_depth(bit_depth);
    let planar = PlanarYuvFrame {
        width,
        height,
        layout,
        bit_depth,
        bytes_per_sample,
        y: frame.y_plane(),
        y_stride: frame.y_stride(),
        u: frame.u_plane(),
        u_stride: frame.u_stride(),
        v: frame.v_plane(),
        v_stride: frame.v_stride(),
        full_range: matches!(frame.color_range(), Some(shiguredo_dav1d::ColorRange::Full)),
    };
    if matches!(layout, SoftwareYuvLayout::I420) && bit_depth == 8 && bytes_per_sample == 1 {
        let (data, y_pitch, uv_pitch) = planar_i420_8_to_i420(planar)?;
        return Ok(CoreDecodedFrame::from_cpu_i420(
            width,
            height,
            timestamp_us,
            y_pitch,
            uv_pitch,
            data,
        ));
    }

    let rgb = planar_yuv_to_rgb24(planar)?;
    Ok(CoreDecodedFrame::from_cpu_rgb24(
        width,
        height,
        timestamp_us,
        rgb,
    ))
}

#[cfg(feature = "software-vvdec")]
fn vvdec_frame_to_core_frame(
    frame: &vvdec::Frame,
    timestamp_us: u64,
) -> Result<CoreDecodedFrame, PipelineError> {
    let layout = match frame.color_format() {
        vvdec::ColorFormat::Yuv400Planar => SoftwareYuvLayout::I400,
        vvdec::ColorFormat::Yuv420Planar => SoftwareYuvLayout::I420,
        vvdec::ColorFormat::Yuv422Planar => SoftwareYuvLayout::I422,
        vvdec::ColorFormat::Yuv444Planar => SoftwareYuvLayout::I444,
        other => {
            return Err(PipelineError::Message(format!(
                "VVdeC returned unsupported color format: {other:?}"
            )))
        }
    };
    let y = frame.plane(vvdec::PlaneComponent::Y).ok_or_else(|| {
        PipelineError::Message("VVdeC decoded frame is missing Y plane".to_string())
    })?;
    let u = frame.plane(vvdec::PlaneComponent::U);
    let v = frame.plane(vvdec::PlaneComponent::V);
    let bit_depth = frame.bit_depth() as usize;
    let bytes_per_sample = y.bytes_per_sample() as usize;
    let planar = PlanarYuvFrame {
        width: frame.width() as usize,
        height: frame.height() as usize,
        layout,
        bit_depth,
        bytes_per_sample,
        y: y.as_ref(),
        y_stride: y.stride() as usize,
        u: u.as_ref().map(|plane| plane.as_ref()).unwrap_or(&[]),
        u_stride: u.as_ref().map(|plane| plane.stride() as usize).unwrap_or(0),
        v: v.as_ref().map(|plane| plane.as_ref()).unwrap_or(&[]),
        v_stride: v.as_ref().map(|plane| plane.stride() as usize).unwrap_or(0),
        full_range: false,
    };
    if matches!(layout, SoftwareYuvLayout::I420) && bit_depth == 8 && bytes_per_sample == 1 {
        let (data, y_pitch, uv_pitch) = planar_i420_8_to_i420(planar)?;
        return Ok(CoreDecodedFrame::from_cpu_i420(
            frame.width() as usize,
            frame.height() as usize,
            timestamp_us,
            y_pitch,
            uv_pitch,
            data,
        ));
    }

    let rgb = planar_yuv_to_rgb24(planar)?;
    Ok(CoreDecodedFrame::from_cpu_rgb24(
        frame.width() as usize,
        frame.height() as usize,
        timestamp_us,
        rgb,
    ))
}

fn bytes_per_sample_for_bit_depth(bit_depth: usize) -> usize {
    if bit_depth > 8 {
        2
    } else {
        1
    }
}

fn planar_i420_8_to_i420(
    frame: PlanarYuvFrame<'_>,
) -> Result<(Vec<u8>, usize, usize), PipelineError> {
    if !matches!(frame.layout, SoftwareYuvLayout::I420)
        || frame.bit_depth != 8
        || frame.bytes_per_sample != 1
    {
        return Err(PipelineError::Message(
            "I420 fast path requires 8-bit I420 input".to_string(),
        ));
    }
    if frame.width == 0 || frame.height == 0 {
        return Err(PipelineError::Message(
            "decoded YUV frame has empty dimensions".to_string(),
        ));
    }

    let chroma_width = frame.width.div_ceil(2);
    let chroma_height = frame.height.div_ceil(2);
    let min_y_len = frame
        .height
        .saturating_sub(1)
        .checked_mul(frame.y_stride)
        .and_then(|offset| offset.checked_add(frame.width))
        .ok_or_else(|| PipelineError::Message("decoded Y plane length overflow".to_string()))?;
    let min_u_len = chroma_height
        .saturating_sub(1)
        .checked_mul(frame.u_stride)
        .and_then(|offset| offset.checked_add(chroma_width))
        .ok_or_else(|| PipelineError::Message("decoded U plane length overflow".to_string()))?;
    let min_v_len = chroma_height
        .saturating_sub(1)
        .checked_mul(frame.v_stride)
        .and_then(|offset| offset.checked_add(chroma_width))
        .ok_or_else(|| PipelineError::Message("decoded V plane length overflow".to_string()))?;
    if frame.y.len() < min_y_len || frame.u.len() < min_u_len || frame.v.len() < min_v_len {
        return Err(PipelineError::Message(format!(
            "decoded I420 frame is undersized: y={} u={} v={}, expected y>={min_y_len} u>={min_u_len} v>={min_v_len}",
            frame.y.len(),
            frame.u.len(),
            frame.v.len()
        )));
    }

    let y_len = frame
        .width
        .checked_mul(frame.height)
        .ok_or_else(|| PipelineError::Message("I420 Y plane length overflow".to_string()))?;
    let uv_len = chroma_width
        .checked_mul(chroma_height)
        .ok_or_else(|| PipelineError::Message("I420 UV plane length overflow".to_string()))?;
    let mut i420 = vec![0_u8; y_len + uv_len * 2];

    for row in 0..frame.height {
        let src = row * frame.y_stride;
        let dst = row * frame.width;
        i420[dst..dst + frame.width].copy_from_slice(&frame.y[src..src + frame.width]);
    }

    let u_base = y_len;
    let v_base = y_len + uv_len;
    for row in 0..chroma_height {
        let u_src = row * frame.u_stride;
        let v_src = row * frame.v_stride;
        let dst = row * chroma_width;
        i420[u_base + dst..u_base + dst + chroma_width]
            .copy_from_slice(&frame.u[u_src..u_src + chroma_width]);
        i420[v_base + dst..v_base + dst + chroma_width]
            .copy_from_slice(&frame.v[v_src..v_src + chroma_width]);
    }

    Ok((i420, frame.width, chroma_width))
}

fn planar_yuv_to_rgb24(frame: PlanarYuvFrame<'_>) -> Result<Vec<u8>, PipelineError> {
    if matches!(frame.layout, SoftwareYuvLayout::I420)
        && frame.bit_depth == 8
        && frame.bytes_per_sample == 1
    {
        return planar_i420_8_to_rgb24(frame);
    }

    planar_yuv_to_rgb24_generic(frame)
}

fn planar_i420_8_to_rgb24(frame: PlanarYuvFrame<'_>) -> Result<Vec<u8>, PipelineError> {
    if frame.width == 0 || frame.height == 0 {
        return Err(PipelineError::Message(
            "decoded YUV frame has empty dimensions".to_string(),
        ));
    }

    let chroma_width = frame.width.div_ceil(2);
    let chroma_height = frame.height.div_ceil(2);
    let min_y_len = frame
        .height
        .saturating_sub(1)
        .checked_mul(frame.y_stride)
        .and_then(|offset| offset.checked_add(frame.width))
        .ok_or_else(|| PipelineError::Message("decoded Y plane length overflow".to_string()))?;
    let min_uv_len = chroma_height
        .saturating_sub(1)
        .checked_mul(frame.u_stride)
        .and_then(|offset| offset.checked_add(chroma_width))
        .ok_or_else(|| PipelineError::Message("decoded UV plane length overflow".to_string()))?;
    if frame.y.len() < min_y_len || frame.u.len() < min_uv_len || frame.v.len() < min_uv_len {
        return Err(PipelineError::Message(format!(
            "decoded I420 frame is undersized: y={} u={} v={}, expected y>={min_y_len} uv>={min_uv_len}",
            frame.y.len(),
            frame.u.len(),
            frame.v.len()
        )));
    }

    let mut rgb = vec![0_u8; frame.width * frame.height * 3];
    for y in (0..frame.height).step_by(2) {
        let y0_row = y * frame.y_stride;
        let y1_row = (y + 1).min(frame.height - 1) * frame.y_stride;
        let uv_row = (y / 2) * frame.u_stride;
        let out0_row = y * frame.width * 3;
        let out1_row = (y + 1).min(frame.height - 1) * frame.width * 3;
        for x in (0..frame.width).step_by(2) {
            let uv_offset = uv_row + x / 2;
            let u = frame.u[uv_offset];
            let v = frame.v[uv_offset];
            write_rgb_pixel(
                &mut rgb,
                out0_row + x * 3,
                frame.y[y0_row + x],
                u,
                v,
                frame.full_range,
            );
            if x + 1 < frame.width {
                write_rgb_pixel(
                    &mut rgb,
                    out0_row + (x + 1) * 3,
                    frame.y[y0_row + x + 1],
                    u,
                    v,
                    frame.full_range,
                );
            }
            if y + 1 < frame.height {
                write_rgb_pixel(
                    &mut rgb,
                    out1_row + x * 3,
                    frame.y[y1_row + x],
                    u,
                    v,
                    frame.full_range,
                );
                if x + 1 < frame.width {
                    write_rgb_pixel(
                        &mut rgb,
                        out1_row + (x + 1) * 3,
                        frame.y[y1_row + x + 1],
                        u,
                        v,
                        frame.full_range,
                    );
                }
            }
        }
    }

    Ok(rgb)
}

#[inline]
fn write_rgb_pixel(rgb: &mut [u8], offset: usize, y: u8, u: u8, v: u8, full_range: bool) {
    let [r, g, b] = yuv_to_rgb8(y, u, v, full_range);
    rgb[offset] = r;
    rgb[offset + 1] = g;
    rgb[offset + 2] = b;
}

#[cfg(feature = "software-rust-h265")]
struct PlanarYuv16Frame<'a> {
    width: usize,
    height: usize,
    bit_depth: usize,
    y: &'a [u16],
    y_stride: usize,
    u: &'a [u16],
    u_stride: usize,
    v: &'a [u16],
    v_stride: usize,
    full_range: bool,
}

#[cfg(feature = "software-rust-h265")]
fn planar_i420_u16_to_p010(frame: PlanarYuv16Frame<'_>) -> Result<(Vec<u8>, usize), PipelineError> {
    if frame.width == 0 || frame.height == 0 {
        return Err(PipelineError::Message(
            "decoded YUV frame has empty dimensions".to_string(),
        ));
    }
    if frame.bit_depth <= 8 || frame.bit_depth > 16 {
        return Err(PipelineError::Message(format!(
            "unsupported decoded 16-bit YUV bit depth: {}",
            frame.bit_depth
        )));
    }

    let chroma_width = frame.width.div_ceil(2);
    let chroma_height = frame.height.div_ceil(2);
    let min_y_len = frame
        .height
        .saturating_sub(1)
        .checked_mul(frame.y_stride)
        .and_then(|offset| offset.checked_add(frame.width))
        .ok_or_else(|| PipelineError::Message("decoded Y plane length overflow".to_string()))?;
    let min_u_len = chroma_height
        .saturating_sub(1)
        .checked_mul(frame.u_stride)
        .and_then(|offset| offset.checked_add(chroma_width))
        .ok_or_else(|| PipelineError::Message("decoded U plane length overflow".to_string()))?;
    let min_v_len = chroma_height
        .saturating_sub(1)
        .checked_mul(frame.v_stride)
        .and_then(|offset| offset.checked_add(chroma_width))
        .ok_or_else(|| PipelineError::Message("decoded V plane length overflow".to_string()))?;
    if frame.y.len() < min_y_len || frame.u.len() < min_u_len || frame.v.len() < min_v_len {
        return Err(PipelineError::Message(format!(
            "decoded I420 16-bit frame is undersized: y={} u={} v={}, expected y>={min_y_len} u>={min_u_len} v>={min_v_len}",
            frame.y.len(),
            frame.u.len(),
            frame.v.len()
        )));
    }

    let pitch = chroma_width
        .checked_mul(4)
        .ok_or_else(|| PipelineError::Message("P010 pitch overflow".to_string()))?;
    let y_len = pitch
        .checked_mul(frame.height)
        .ok_or_else(|| PipelineError::Message("P010 Y plane length overflow".to_string()))?;
    let uv_len = pitch
        .checked_mul(chroma_height)
        .ok_or_else(|| PipelineError::Message("P010 UV plane length overflow".to_string()))?;
    let mut p010 = vec![0_u8; y_len + uv_len];
    let shift = 16usize.saturating_sub(frame.bit_depth);

    for row in 0..frame.height {
        let src = row * frame.y_stride;
        let dst = row * pitch;
        for col in 0..frame.width {
            let sample = frame.y[src + col] << shift;
            p010[dst + col * 2..dst + col * 2 + 2].copy_from_slice(&sample.to_le_bytes());
        }
    }

    for row in 0..chroma_height {
        let u_src = row * frame.u_stride;
        let v_src = row * frame.v_stride;
        let dst = y_len + row * pitch;
        for col in 0..chroma_width {
            let u = frame.u[u_src + col] << shift;
            let v = frame.v[v_src + col] << shift;
            let uv = dst + col * 4;
            p010[uv..uv + 2].copy_from_slice(&u.to_le_bytes());
            p010[uv + 2..uv + 4].copy_from_slice(&v.to_le_bytes());
        }
    }

    Ok((p010, pitch))
}

fn planar_yuv_to_rgb24_generic(frame: PlanarYuvFrame<'_>) -> Result<Vec<u8>, PipelineError> {
    if frame.width == 0 || frame.height == 0 {
        return Err(PipelineError::Message(
            "decoded YUV frame has empty dimensions".to_string(),
        ));
    }
    if frame.bit_depth == 0 || frame.bit_depth > 16 {
        return Err(PipelineError::Message(format!(
            "unsupported decoded YUV bit depth: {}",
            frame.bit_depth
        )));
    }

    let mut rgb = vec![0_u8; frame.width * frame.height * 3];
    for y in 0..frame.height {
        for x in 0..frame.width {
            let yy = read_yuv_sample(
                frame.y,
                frame.y_stride,
                x,
                y,
                frame.bytes_per_sample,
                frame.bit_depth,
            )?;
            let (cx, cy) = chroma_coordinates(frame.layout, x, y);
            let uu = if matches!(frame.layout, SoftwareYuvLayout::I400) {
                128
            } else {
                read_yuv_sample(
                    frame.u,
                    frame.u_stride,
                    cx,
                    cy,
                    frame.bytes_per_sample,
                    frame.bit_depth,
                )?
            };
            let vv = if matches!(frame.layout, SoftwareYuvLayout::I400) {
                128
            } else {
                read_yuv_sample(
                    frame.v,
                    frame.v_stride,
                    cx,
                    cy,
                    frame.bytes_per_sample,
                    frame.bit_depth,
                )?
            };
            let [r, g, b] = yuv_to_rgb8(yy, uu, vv, frame.full_range);
            let offset = (y * frame.width + x) * 3;
            rgb[offset] = r;
            rgb[offset + 1] = g;
            rgb[offset + 2] = b;
        }
    }
    Ok(rgb)
}

fn chroma_coordinates(layout: SoftwareYuvLayout, x: usize, y: usize) -> (usize, usize) {
    match layout {
        SoftwareYuvLayout::I400 | SoftwareYuvLayout::I444 => (x, y),
        SoftwareYuvLayout::I420 => (x / 2, y / 2),
        SoftwareYuvLayout::I422 => (x / 2, y),
    }
}

fn read_yuv_sample(
    plane: &[u8],
    stride: usize,
    x: usize,
    y: usize,
    bytes_per_sample: usize,
    bit_depth: usize,
) -> Result<u8, PipelineError> {
    let byte_offset = y
        .checked_mul(stride)
        .and_then(|row| row.checked_add(x.checked_mul(bytes_per_sample)?))
        .ok_or_else(|| PipelineError::Message("decoded YUV plane offset overflow".to_string()))?;
    let sample = match bytes_per_sample {
        1 => *plane.get(byte_offset).ok_or_else(|| {
            PipelineError::Message("decoded YUV 8-bit sample out of bounds".to_string())
        })? as u16,
        2 => {
            let lo = *plane.get(byte_offset).ok_or_else(|| {
                PipelineError::Message("decoded YUV 16-bit sample out of bounds".to_string())
            })?;
            let hi = *plane.get(byte_offset + 1).ok_or_else(|| {
                PipelineError::Message("decoded YUV 16-bit sample out of bounds".to_string())
            })?;
            u16::from_le_bytes([lo, hi])
        }
        other => {
            return Err(PipelineError::Message(format!(
                "unsupported decoded YUV bytes-per-sample: {other}"
            )))
        }
    };
    if bit_depth > 8 {
        Ok((sample >> (bit_depth - 8)).min(255) as u8)
    } else {
        Ok(sample.min(255) as u8)
    }
}

fn yuv_to_rgb8(y: u8, u: u8, v: u8, full_range: bool) -> [u8; 3] {
    let c = if full_range {
        y as i32
    } else {
        (y as i32 - 16).max(0)
    };
    let d = u as i32 - 128;
    let e = v as i32 - 128;
    let luma = if full_range { 256 * c } else { 298 * c };
    [
        clamp_u8((luma + 409 * e + 128) >> 8),
        clamp_u8((luma - 100 * d - 208 * e + 128) >> 8),
        clamp_u8((luma + 516 * d + 128) >> 8),
    ]
}

fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

fn parse_h264_dimensions(access_unit: &[u8]) -> Result<Option<(usize, usize)>, PipelineError> {
    for nal in annex_b_nals(access_unit) {
        if nal.is_empty() {
            continue;
        }
        if nal[0] & 0x1f == 7 {
            return parse_sps_dimensions(&nal[1..]).map(Some);
        }
    }

    Ok(None)
}

fn parse_hevc_dimensions(access_unit: &[u8]) -> Result<Option<(usize, usize)>, PipelineError> {
    for nal in annex_b_nals(access_unit) {
        if nal.len() < 3 {
            continue;
        }

        let nal_unit_type = (nal[0] >> 1) & 0x3f;
        if nal_unit_type == 33 {
            return parse_hevc_sps_dimensions(&nal[2..]).map(Some);
        }
    }

    Ok(None)
}

fn annex_b_nals(bytes: &[u8]) -> Vec<&[u8]> {
    let mut nals = Vec::new();
    let mut offset = 0;

    while let Some((start, start_code_len)) = find_start_code(bytes, offset) {
        let nal_start = start + start_code_len;
        let next_start = find_start_code(bytes, nal_start)
            .map(|(next, _)| next)
            .unwrap_or(bytes.len());
        if nal_start < next_start {
            let mut nal_end = next_start;
            while nal_end > nal_start && bytes[nal_end - 1] == 0 {
                nal_end -= 1;
            }
            nals.push(&bytes[nal_start..nal_end]);
        }
        offset = next_start;
    }

    nals
}

fn find_start_code(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            if bytes[i + 2] == 1 {
                return Some((i, 3));
            }
            if i + 4 <= bytes.len() && bytes[i + 2] == 0 && bytes[i + 3] == 1 {
                return Some((i, 4));
            }
        }
        i += 1;
    }
    None
}

fn parse_sps_dimensions(sps: &[u8]) -> Result<(usize, usize), PipelineError> {
    let rbsp = remove_emulation_prevention_bytes(sps);
    let mut bits = BitReader::new(&rbsp);

    let profile_idc = bits
        .read_bits(8)
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: missing profile".to_string()))?;
    bits.read_bits(8).ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing constraint flags".to_string())
    })?;
    bits.read_bits(8)
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: missing level".to_string()))?;
    bits.read_ue().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing sequence id".to_string())
    })?;

    let mut chroma_format_idc = 1_u32;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = bits.read_ue().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing chroma format".to_string())
        })?;
        if chroma_format_idc == 3 {
            bits.read_bit().ok_or_else(|| {
                PipelineError::Message(
                    "invalid H.264 SPS: missing separate colour plane flag".to_string(),
                )
            })?;
        }
        bits.read_ue().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing bit depth luma".to_string())
        })?;
        bits.read_ue().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing bit depth chroma".to_string())
        })?;
        bits.read_bit().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing qpprime flag".to_string())
        })?;
        if bits.read_bit().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing scaling matrix flag".to_string())
        })? {
            let scaling_list_count = if chroma_format_idc != 3 { 8 } else { 12 };
            for index in 0..scaling_list_count {
                if bits.read_bit().ok_or_else(|| {
                    PipelineError::Message(
                        "invalid H.264 SPS: missing scaling list flag".to_string(),
                    )
                })? {
                    skip_scaling_list(&mut bits, if index < 6 { 16 } else { 64 })?;
                }
            }
        }
    }

    bits.read_ue().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing max frame num".to_string())
    })?;
    let pic_order_cnt_type = bits.read_ue().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing pic order count type".to_string())
    })?;
    if pic_order_cnt_type == 0 {
        bits.read_ue().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing pic order cnt lsb".to_string())
        })?;
    } else if pic_order_cnt_type == 1 {
        bits.read_bit().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing delta pic order flag".to_string())
        })?;
        bits.read_se().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing offset non-ref".to_string())
        })?;
        bits.read_se().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing offset top-bottom".to_string())
        })?;
        let cycle_count = bits.read_ue().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing ref frame cycle count".to_string())
        })?;
        for _ in 0..cycle_count {
            bits.read_se().ok_or_else(|| {
                PipelineError::Message("invalid H.264 SPS: missing ref frame offset".to_string())
            })?;
        }
    }

    bits.read_ue().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing max ref frames".to_string())
    })?;
    bits.read_bit().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing gaps flag".to_string())
    })?;
    let pic_width_in_mbs_minus1 = bits
        .read_ue()
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: missing width".to_string()))?;
    let pic_height_in_map_units_minus1 = bits
        .read_ue()
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: missing height".to_string()))?;
    let frame_mbs_only_flag = bits.read_bit().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing frame mbs flag".to_string())
    })?;
    if !frame_mbs_only_flag {
        bits.read_bit().ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: missing mb adaptive flag".to_string())
        })?;
    }
    bits.read_bit().ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: missing direct 8x8 flag".to_string())
    })?;

    let mut crop_left = 0_u32;
    let mut crop_right = 0_u32;
    let mut crop_top = 0_u32;
    let mut crop_bottom = 0_u32;
    if bits
        .read_bit()
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: missing crop flag".to_string()))?
    {
        crop_left = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: crop left".to_string()))?;
        crop_right = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: crop right".to_string()))?;
        crop_top = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: crop top".to_string()))?;
        crop_bottom = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: crop bottom".to_string()))?;
    }

    let frame_mbs_factor = if frame_mbs_only_flag { 1 } else { 2 };
    let width = (pic_width_in_mbs_minus1 + 1)
        .checked_mul(16)
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: width overflow".to_string()))?;
    let height = (pic_height_in_map_units_minus1 + 1)
        .checked_mul(16)
        .and_then(|value| value.checked_mul(frame_mbs_factor))
        .ok_or_else(|| PipelineError::Message("invalid H.264 SPS: height overflow".to_string()))?;

    let (crop_unit_x, crop_unit_y) = crop_units(chroma_format_idc, frame_mbs_only_flag);
    let crop_width = (crop_left + crop_right)
        .checked_mul(crop_unit_x)
        .ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: crop width overflow".to_string())
        })?;
    let crop_height = (crop_top + crop_bottom)
        .checked_mul(crop_unit_y)
        .ok_or_else(|| {
            PipelineError::Message("invalid H.264 SPS: crop height overflow".to_string())
        })?;
    let display_width = width.checked_sub(crop_width).ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: crop exceeds width".to_string())
    })?;
    let display_height = height.checked_sub(crop_height).ok_or_else(|| {
        PipelineError::Message("invalid H.264 SPS: crop exceeds height".to_string())
    })?;

    if display_width == 0 || display_height == 0 {
        return Err(PipelineError::Message(
            "invalid H.264 SPS: zero-sized frame".to_string(),
        ));
    }

    Ok((display_width as usize, display_height as usize))
}

fn parse_hevc_sps_dimensions(sps: &[u8]) -> Result<(usize, usize), PipelineError> {
    let rbsp = remove_emulation_prevention_bytes(sps);
    let mut bits = BitReader::new(&rbsp);

    bits.read_bits(4)
        .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: missing VPS id".to_string()))?;
    let max_sub_layers_minus1 = bits.read_bits(3).ok_or_else(|| {
        PipelineError::Message("invalid HEVC SPS: missing sub-layer count".to_string())
    })? as usize;
    bits.read_bit().ok_or_else(|| {
        PipelineError::Message("invalid HEVC SPS: missing temporal nesting flag".to_string())
    })?;

    skip_hevc_profile_tier_level(&mut bits, max_sub_layers_minus1)?;

    bits.read_ue().ok_or_else(|| {
        PipelineError::Message("invalid HEVC SPS: missing sequence id".to_string())
    })?;
    let chroma_format_idc = bits.read_ue().ok_or_else(|| {
        PipelineError::Message("invalid HEVC SPS: missing chroma format".to_string())
    })?;
    let separate_colour_plane = if chroma_format_idc == 3 {
        bits.read_bit().ok_or_else(|| {
            PipelineError::Message(
                "invalid HEVC SPS: missing separate colour plane flag".to_string(),
            )
        })?
    } else {
        false
    };
    let pic_width_in_luma_samples = bits
        .read_ue()
        .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: missing width".to_string()))?;
    let pic_height_in_luma_samples = bits
        .read_ue()
        .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: missing height".to_string()))?;

    let mut crop_left = 0_u32;
    let mut crop_right = 0_u32;
    let mut crop_top = 0_u32;
    let mut crop_bottom = 0_u32;
    if bits.read_bit().ok_or_else(|| {
        PipelineError::Message("invalid HEVC SPS: missing conformance window flag".to_string())
    })? {
        crop_left = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: crop left".to_string()))?;
        crop_right = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: crop right".to_string()))?;
        crop_top = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: crop top".to_string()))?;
        crop_bottom = bits
            .read_ue()
            .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: crop bottom".to_string()))?;
    }

    let (crop_unit_x, crop_unit_y) = hevc_crop_units(chroma_format_idc, separate_colour_plane);
    let crop_width = (crop_left + crop_right)
        .checked_mul(crop_unit_x)
        .ok_or_else(|| {
            PipelineError::Message("invalid HEVC SPS: crop width overflow".to_string())
        })?;
    let crop_height = (crop_top + crop_bottom)
        .checked_mul(crop_unit_y)
        .ok_or_else(|| {
            PipelineError::Message("invalid HEVC SPS: crop height overflow".to_string())
        })?;
    let display_width = pic_width_in_luma_samples
        .checked_sub(crop_width)
        .ok_or_else(|| {
            PipelineError::Message("invalid HEVC SPS: crop exceeds width".to_string())
        })?;
    let display_height = pic_height_in_luma_samples
        .checked_sub(crop_height)
        .ok_or_else(|| {
            PipelineError::Message("invalid HEVC SPS: crop exceeds height".to_string())
        })?;

    if display_width == 0 || display_height == 0 {
        return Err(PipelineError::Message(
            "invalid HEVC SPS: zero-sized frame".to_string(),
        ));
    }

    Ok((display_width as usize, display_height as usize))
}

fn skip_hevc_profile_tier_level(
    bits: &mut BitReader<'_>,
    max_sub_layers_minus1: usize,
) -> Result<(), PipelineError> {
    skip_hevc_profile_info(bits)?;
    bits.skip_bits(8).ok_or_else(|| {
        PipelineError::Message("invalid HEVC SPS: missing general level".to_string())
    })?;

    let mut sub_layer_profile_present = vec![false; max_sub_layers_minus1];
    let mut sub_layer_level_present = vec![false; max_sub_layers_minus1];
    for index in 0..max_sub_layers_minus1 {
        sub_layer_profile_present[index] = bits.read_bit().ok_or_else(|| {
            PipelineError::Message("invalid HEVC SPS: sub-layer profile flag".to_string())
        })?;
        sub_layer_level_present[index] = bits.read_bit().ok_or_else(|| {
            PipelineError::Message("invalid HEVC SPS: sub-layer level flag".to_string())
        })?;
    }

    if max_sub_layers_minus1 > 0 {
        for _ in max_sub_layers_minus1..8 {
            bits.skip_bits(2).ok_or_else(|| {
                PipelineError::Message("invalid HEVC SPS: reserved sub-layer bits".to_string())
            })?;
        }
    }

    for index in 0..max_sub_layers_minus1 {
        if sub_layer_profile_present[index] {
            skip_hevc_profile_info(bits)?;
        }
        if sub_layer_level_present[index] {
            bits.skip_bits(8).ok_or_else(|| {
                PipelineError::Message("invalid HEVC SPS: sub-layer level".to_string())
            })?;
        }
    }

    Ok(())
}

fn skip_hevc_profile_info(bits: &mut BitReader<'_>) -> Result<(), PipelineError> {
    bits.skip_bits(2 + 1 + 5 + 32 + 4 + 44)
        .ok_or_else(|| PipelineError::Message("invalid HEVC SPS: profile tier".to_string()))
}

fn hevc_crop_units(chroma_format_idc: u32, separate_colour_plane: bool) -> (u32, u32) {
    let chroma_array_type = if separate_colour_plane {
        0
    } else {
        chroma_format_idc
    };
    match chroma_array_type {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    }
}

fn remove_emulation_prevention_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut zero_count = 0_u8;
    for &byte in bytes {
        if zero_count == 2 && byte == 0x03 {
            zero_count = 0;
            continue;
        }
        out.push(byte);
        if byte == 0 {
            zero_count = zero_count.saturating_add(1).min(2);
        } else {
            zero_count = 0;
        }
    }
    out
}

fn crop_units(chroma_format_idc: u32, frame_mbs_only_flag: bool) -> (u32, u32) {
    let frame_factor = if frame_mbs_only_flag { 1 } else { 2 };
    match chroma_format_idc {
        0 => (1, frame_factor),
        1 => (2, 2 * frame_factor),
        2 => (2, frame_factor),
        3 => (1, frame_factor),
        _ => (1, frame_factor),
    }
}

fn skip_scaling_list(bits: &mut BitReader<'_>, size: usize) -> Result<(), PipelineError> {
    let mut last_scale = 8_i32;
    let mut next_scale = 8_i32;
    for _ in 0..size {
        if next_scale != 0 {
            let delta_scale = bits.read_se().ok_or_else(|| {
                PipelineError::Message("invalid H.264 SPS: scaling list delta".to_string())
            })?;
            next_scale = (last_scale + delta_scale + 256) % 256;
        }
        if next_scale != 0 {
            last_scale = next_scale;
        }
    }
    Ok(())
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit_pos: 0 }
    }

    fn read_bit(&mut self) -> Option<bool> {
        let byte = *self.bytes.get(self.bit_pos / 8)?;
        let shift = 7 - (self.bit_pos % 8);
        self.bit_pos += 1;
        Some(((byte >> shift) & 1) != 0)
    }

    fn read_bits(&mut self, count: usize) -> Option<u32> {
        let mut value = 0_u32;
        for _ in 0..count {
            value = (value << 1) | u32::from(self.read_bit()?);
        }
        Some(value)
    }

    fn skip_bits(&mut self, count: usize) -> Option<()> {
        for _ in 0..count {
            self.read_bit()?;
        }
        Some(())
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut leading_zero_bits = 0_u32;
        while !self.read_bit()? {
            leading_zero_bits += 1;
            if leading_zero_bits > 31 {
                return None;
            }
        }
        if leading_zero_bits == 0 {
            return Some(0);
        }
        let suffix = self.read_bits(leading_zero_bits as usize)?;
        Some((1_u32 << leading_zero_bits) - 1 + suffix)
    }

    fn read_se(&mut self) -> Option<i32> {
        let code_num = self.read_ue()? as i32;
        let magnitude = (code_num + 1) / 2;
        if code_num % 2 == 0 {
            Some(-magnitude)
        } else {
            Some(magnitude)
        }
    }
}

impl VideoDecoder for NvdecVideoDecoder {
    fn push_access_unit(&mut self, access_unit: &[u8]) -> Result<(), PipelineError> {
        self.decoder.push_access_unit(access_unit).map_err(|e| {
            PipelineError::Message(format!(
                "nvdec decode failed: {e}; diagnostics={:?}",
                self.decoder.diagnostics()
            ))
        })
    }

    fn drain_decoded_frames(&mut self) -> Vec<CoreDecodedFrame> {
        use mrd_decode_nvdec::NvdecDecodedFrameData;
        let require_shared_output = self.require_shared_output;
        self.decoder
            .drain_decoded_frames()
            .into_iter()
            .filter_map(|frame| match frame.data {
                NvdecDecodedFrameData::CpuRgb24(data) => (!require_shared_output)
                    .then(|| CoreDecodedFrame::from_cpu_rgb24(frame.width, frame.height, 0, data)),
                NvdecDecodedFrameData::CpuNv12 { data, pitch } => {
                    (!require_shared_output).then(|| {
                        CoreDecodedFrame::from_cpu_nv12(frame.width, frame.height, 0, pitch, data)
                    })
                }
                NvdecDecodedFrameData::CpuP010 { data, pitch } => {
                    (!require_shared_output).then(|| {
                        CoreDecodedFrame::from_cpu_p010(frame.width, frame.height, 0, pitch, data)
                    })
                }
                #[cfg(windows)]
                NvdecDecodedFrameData::D3D11SharedNv12 {
                    shared_handle_y,
                    shared_handle_uv,
                    width: _,
                    height: _,
                } => Some(CoreDecodedFrame::from_d3d11_shared_nv12(
                    frame.width,
                    frame.height,
                    0,
                    shared_handle_y,
                    shared_handle_uv,
                )),
                #[cfg(windows)]
                NvdecDecodedFrameData::D3D11SharedP010 {
                    shared_handle_y,
                    shared_handle_uv,
                    width: _,
                    height: _,
                } => Some(CoreDecodedFrame::from_d3d11_shared_p010(
                    frame.width,
                    frame.height,
                    0,
                    shared_handle_y,
                    shared_handle_uv,
                )),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrd_encode_openh264::OpenH264Encoder;
    use mrd_pipeline_core::{CapturedFrame, FramePixelFormat, VideoEncoder};

    #[test]
    fn parses_openh264_sps_dimensions() {
        let width = 64;
        let height = 48;
        let mut encoder = OpenH264Encoder::new(width, height, 30).expect("create encoder");
        let frame = CapturedFrame::from_cpu(
            width,
            height,
            FramePixelFormat::Bgra32,
            0,
            vec![127; width * height * 4],
        );

        let access_units = encoder.encode(&frame).expect("encode frame");
        let dimensions =
            parse_h264_dimensions(&access_units[0].bytes).expect("parse H.264 dimensions");

        assert_eq!(dimensions, Some((width, height)));
    }

    #[test]
    fn exposes_hevc_d3d11_shared_nvdec_descriptor() {
        let descriptor = available_decoder_descriptors()
            .into_iter()
            .find(|descriptor| descriptor.id == "nvdec_hevc_d3d11_shared")
            .expect("HEVC D3D11 shared NVDEC descriptor");

        assert_eq!(descriptor.codec, CodecKind::Hevc);
        assert_eq!(descriptor.output_formats, D3D11_TEXTURE_OUTPUTS);
    }

    #[cfg(feature = "software-rust-h265")]
    #[test]
    fn rust_h265_main10_frame_converts_to_p010() {
        let frame = rust_h265::Frame {
            y: rust_h265::PixelData::U16(vec![512; 4]),
            u: rust_h265::PixelData::U16(vec![512; 1]),
            v: rust_h265::PixelData::U16(vec![512; 1]),
            width: 2,
            height: 2,
            pic_order_cnt: 0,
            bit_depth: 10,
        };

        let decoded = rust_h265_frame_to_core_frame(&frame, 42).expect("convert Main10 HEVC frame");

        assert_eq!(decoded.width, 2);
        assert_eq!(decoded.height, 2);
        assert_eq!(decoded.timestamp_us, 42);
        match decoded.data {
            DecodedFrameData::CpuP010 { data, pitch } => {
                assert_eq!(pitch, 4);
                assert_eq!(data.len(), 12);
            }
            other => panic!("expected P010 decoded frame, got {other:?}"),
        }
    }

    #[test]
    fn planar_i420_fast_path_packs_i420() {
        let width = 4;
        let height = 4;
        let y = (0..width * height)
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        let u = vec![90, 91, 92, 93];
        let v = vec![180, 181, 182, 183];
        let frame = PlanarYuvFrame {
            width,
            height,
            layout: SoftwareYuvLayout::I420,
            bit_depth: 8,
            bytes_per_sample: 1,
            y: &y,
            y_stride: width,
            u: &u,
            u_stride: width / 2,
            v: &v,
            v_stride: width / 2,
            full_range: false,
        };

        let (i420, y_pitch, uv_pitch) = planar_i420_8_to_i420(frame).expect("pack I420");

        assert_eq!(y_pitch, width);
        assert_eq!(uv_pitch, width / 2);
        assert_eq!(&i420[..width * height], y.as_slice());
        assert_eq!(
            &i420[width * height..width * height + u.len()],
            u.as_slice()
        );
        assert_eq!(&i420[width * height + u.len()..], v.as_slice());
    }

    #[test]
    fn planar_i420_fast_path_matches_generic_yuv_conversion() {
        let width = 4;
        let height = 4;
        let y = (0..width * height)
            .map(|index| 16 + (index as u8 * 7))
            .collect::<Vec<_>>();
        let u = vec![96, 128, 144, 160];
        let v = vec![112, 120, 136, 152];
        let frame = PlanarYuvFrame {
            width,
            height,
            layout: SoftwareYuvLayout::I420,
            bit_depth: 8,
            bytes_per_sample: 1,
            y: &y,
            y_stride: width,
            u: &u,
            u_stride: width / 2,
            v: &v,
            v_stride: width / 2,
            full_range: false,
        };

        let fast = planar_i420_8_to_rgb24(frame).expect("fast I420 conversion");
        let generic = planar_yuv_to_rgb24_generic(frame).expect("generic I420 conversion");

        assert_eq!(fast, generic);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exposes_linux_hardware_decode_descriptors_on_linux() {
        let ids = available_decoder_descriptors()
            .into_iter()
            .map(|descriptor| descriptor.id)
            .collect::<Vec<_>>();

        assert!(ids.contains(&"linux_h264"));
        assert!(ids.contains(&"linux_hevc"));
        assert!(ids.contains(&"linux_hevc_main10"));
    }
}
