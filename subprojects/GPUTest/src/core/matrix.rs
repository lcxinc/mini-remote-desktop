use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct MatrixConfig {
    pub captures: Vec<String>,
    #[serde(default)]
    pub encoders: Vec<String>,
    #[serde(default)]
    pub encoder_backends: Vec<String>,
    #[serde(default)]
    pub codec_types: Vec<String>,
    pub transports: Vec<String>,
    #[serde(default)]
    pub decoders: Vec<String>,
    #[serde(default)]
    pub decoder_backends: Vec<String>,
    #[serde(default)]
    pub decode_codec_types: Vec<String>,
    #[serde(default)]
    pub renders: Vec<String>,
    pub resolutions: Vec<String>,
    pub fps: Vec<u32>,
    pub component_requirements: HashMap<String, Vec<String>>,
    pub valid_paths: Vec<ValidPath>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidPath {
    pub encoder: String,
    pub decoder: String,
}

#[derive(Debug, Clone)]
pub struct MatrixCase {
    pub capture: String,
    pub encoder: String,
    pub encoder_backend: String,
    pub codec_type: String,
    pub transport: String,
    pub decoder: String,
    pub decoder_backend: String,
    pub decode_codec_type: String,
    pub render: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

#[derive(Debug, Clone)]
pub struct SelectedChain {
    pub capture: String,
    pub encoder: String,
    pub transport: String,
    pub decoder: String,
    pub render: String,
}

pub fn load_matrix_config(path: &str) -> Result<MatrixConfig, String> {
    let s = fs::read_to_string(path).map_err(|e| format!("read matrix config {path}: {e}"))?;
    serde_json::from_str::<MatrixConfig>(&s).map_err(|e| format!("parse matrix config {path}: {e}"))
}

pub fn generate_cases(cfg: &MatrixConfig) -> Vec<MatrixCase> {
    let mut out = Vec::new();
    let encoders = expand_encoders(cfg);
    let decoders = expand_decoders(cfg);
    let mut resolutions = Vec::new();
    for r in &cfg.resolutions {
        let p: Vec<&str> = r.split('x').collect();
        if p.len() != 2 {
            continue;
        }
        if let (Ok(w), Ok(h)) = (p[0].trim().parse::<u32>(), p[1].trim().parse::<u32>()) {
            resolutions.push((w, h));
        }
    }
    let renders: Vec<String> = if cfg.renders.is_empty() {
        vec!["gpu_present".to_string()]
    } else {
        cfg.renders.clone()
    };
    for c in &cfg.captures {
        for e in &encoders {
            let (encoder_backend, codec_type) = split_encoder(e);
            for t in &cfg.transports {
                for d in &decoders {
                    let (decoder_backend, decode_codec_type) = split_decoder(d);
                    for r in &renders {
                        for (w, h) in &resolutions {
                            for fps in &cfg.fps {
                                out.push(MatrixCase {
                                    capture: c.clone(),
                                    encoder: e.clone(),
                                    encoder_backend: encoder_backend.clone(),
                                    codec_type: codec_type.clone(),
                                    transport: t.clone(),
                                    decoder: d.clone(),
                                    decoder_backend: decoder_backend.clone(),
                                    decode_codec_type: decode_codec_type.clone(),
                                    render: r.clone(),
                                    width: *w,
                                    height: *h,
                                    fps: *fps,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

pub fn available_encoders(cfg: &MatrixConfig) -> Vec<String> {
    expand_encoders(cfg)
}

pub fn available_decoders(cfg: &MatrixConfig) -> Vec<String> {
    expand_decoders(cfg)
}

pub fn available_renders(cfg: &MatrixConfig) -> Vec<String> {
    let mut out = if cfg.renders.is_empty() {
        vec!["gpu_present".to_string()]
    } else {
        cfg.renders.clone()
    };
    if !out.iter().any(|v| v.eq_ignore_ascii_case("gdi_overlay")) {
        out.push("gdi_overlay".to_string());
    }
    out
}

fn expand_encoders(cfg: &MatrixConfig) -> Vec<String> {
    if !cfg.encoders.is_empty() {
        return cfg.encoders.clone();
    }
    let mut out = Vec::new();
    for backend in &cfg.encoder_backends {
        for codec in &cfg.codec_types {
            if let Some(node) = compose_encoder_node(codec, backend) {
                out.push(node);
            }
        }
    }
    out
}

fn expand_decoders(cfg: &MatrixConfig) -> Vec<String> {
    if !cfg.decoders.is_empty() {
        return cfg.decoders.clone();
    }
    let mut out = Vec::new();
    for backend in &cfg.decoder_backends {
        for codec in &cfg.decode_codec_types {
            if let Some(node) = compose_decoder_node(codec, backend) {
                out.push(node);
            }
        }
    }
    out
}

fn compose_encoder_node(codec: &str, backend: &str) -> Option<String> {
    let codec = codec.to_ascii_lowercase();
    let backend = backend.to_ascii_lowercase();
    match (codec.as_str(), backend.as_str()) {
        ("h264", "software") => Some("h264_software".to_string()),
        ("hevc", "software") => Some("hevc_software".to_string()),
        ("av1", "software") => Some("av1_software".to_string()),
        ("mjpeg", "software") => Some("mjpeg_software".to_string()),
        ("prores", "software") => Some("prores_software".to_string()),
        ("dnxhd", "software") => Some("dnxhd_software".to_string()),
        ("dnxhr", "software") => Some("dnxhr_software".to_string()),
        ("h264", "nvenc") => Some("h264_nvenc".to_string()),
        ("hevc", "nvenc") => Some("hevc_nvenc".to_string()),
        ("av1", "nvenc") => Some("av1_nvenc".to_string()),
        ("h264", "amf") => Some("h264_amf".to_string()),
        ("hevc", "amf") => Some("hevc_amf".to_string()),
        ("av1", "amf") => Some("av1_amf".to_string()),
        ("h264", "qsv") => Some("h264_qsv".to_string()),
        ("hevc", "qsv") => Some("hevc_qsv".to_string()),
        ("av1", "qsv") => Some("av1_qsv".to_string()),
        ("h264", "vaapi") => Some("h264_vaapi".to_string()),
        ("hevc", "vaapi") => Some("hevc_vaapi".to_string()),
        ("av1", "vaapi") => Some("av1_vaapi".to_string()),
        ("h264", "opencl") => Some("opencl".to_string()),
        ("h264", "vulkan") => Some("vulkan".to_string()),
        ("h264", "metal") => Some("metal".to_string()),
        ("vp9", "software") => Some("vp9_software".to_string()),
        _ => None,
    }
}

fn compose_decoder_node(codec: &str, backend: &str) -> Option<String> {
    let codec = codec.to_ascii_lowercase();
    let backend = backend.to_ascii_lowercase();
    match (codec.as_str(), backend.as_str()) {
        ("h264", "software") => Some("h264_software".to_string()),
        ("hevc", "software") => Some("hevc_software".to_string()),
        ("av1", "software") => Some("av1_software".to_string()),
        ("mjpeg", "software") => Some("mjpeg_software".to_string()),
        ("prores", "software") => Some("prores_software".to_string()),
        ("dnxhd", "software") => Some("dnxhd_software".to_string()),
        ("dnxhr", "software") => Some("dnxhr_software".to_string()),
        ("h264", "d3d11va") => Some("h264_d3d11va".to_string()),
        ("hevc", "d3d11va") => Some("hevc_d3d11va".to_string()),
        ("av1", "d3d11va") => Some("av1_d3d11va".to_string()),
        ("h264", "d3d12va") => Some("h264_d3d12va".to_string()),
        ("hevc", "d3d12va") => Some("hevc_d3d12va".to_string()),
        ("av1", "d3d12va") => Some("av1_d3d12va".to_string()),
        ("h264", "dxva2") => Some("h264_dxva2".to_string()),
        ("hevc", "dxva2") => Some("hevc_dxva2".to_string()),
        ("av1", "dxva2") => Some("av1_dxva2".to_string()),
        ("h264", "qsv") => Some("h264_qsv".to_string()),
        ("hevc", "qsv") => Some("hevc_qsv".to_string()),
        ("av1", "qsv") => Some("av1_qsv".to_string()),
        ("h264", "vaapi") => Some("h264_vaapi".to_string()),
        ("hevc", "vaapi") => Some("hevc_vaapi".to_string()),
        ("h264", "cuda") => Some("h264_cuda".to_string()),
        ("hevc", "cuda") => Some("hevc_cuda".to_string()),
        ("vp9", "software") => Some("vp9_software".to_string()),
        _ => None,
    }
}

fn split_encoder(encoder: &str) -> (String, String) {
    let lower = encoder.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("h264_") {
        return (rest.to_string(), "h264".to_string());
    }
    if let Some(rest) = lower.strip_prefix("hevc_") {
        return (rest.to_string(), "hevc".to_string());
    }
    if let Some(rest) = lower.strip_prefix("av1_") {
        return (rest.to_string(), "av1".to_string());
    }
    if let Some(rest) = lower.strip_prefix("vp9_") {
        return (rest.to_string(), "vp9".to_string());
    }
    if let Some(rest) = lower.strip_prefix("mjpeg_") {
        return (rest.to_string(), "mjpeg".to_string());
    }
    if let Some(rest) = lower.strip_prefix("prores_") {
        return (rest.to_string(), "prores".to_string());
    }
    if let Some(rest) = lower.strip_prefix("dnxhd_") {
        return (rest.to_string(), "dnxhd".to_string());
    }
    if let Some(rest) = lower.strip_prefix("dnxhr_") {
        return (rest.to_string(), "dnxhr".to_string());
    }
    (lower, "unspecified".to_string())
}

fn split_decoder(decoder: &str) -> (String, String) {
    let lower = decoder.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("h264_") {
        return (rest.to_string(), "h264".to_string());
    }
    if let Some(rest) = lower.strip_prefix("hevc_") {
        return (rest.to_string(), "hevc".to_string());
    }
    if let Some(rest) = lower.strip_prefix("av1_") {
        return (rest.to_string(), "av1".to_string());
    }
    if let Some(rest) = lower.strip_prefix("vp9_") {
        return (rest.to_string(), "vp9".to_string());
    }
    if let Some(rest) = lower.strip_prefix("mjpeg_") {
        return (rest.to_string(), "mjpeg".to_string());
    }
    if let Some(rest) = lower.strip_prefix("prores_") {
        return (rest.to_string(), "prores".to_string());
    }
    if let Some(rest) = lower.strip_prefix("dnxhd_") {
        return (rest.to_string(), "dnxhd".to_string());
    }
    if let Some(rest) = lower.strip_prefix("dnxhr_") {
        return (rest.to_string(), "dnxhr".to_string());
    }
    (lower, "unspecified".to_string())
}

pub fn is_valid_path(cfg: &MatrixConfig, encoder: &str, decoder: &str) -> bool {
    cfg.valid_paths
        .iter()
        .any(|p| p.encoder == encoder && p.decoder == decoder)
}

pub fn is_debug_only_codec(v: &str) -> bool {
    let s = v.to_ascii_lowercase();
    matches!(
        s.as_str(),
        "raw_bgra" | "raw_bgra_chunked" | "lz4" | "lz4_bgra"
    )
}

pub fn validate_selected_chain(
    cfg: &MatrixConfig,
    chain: &SelectedChain,
    allow_debug_codecs: bool,
    backend_ok: Option<&HashMap<String, bool>>,
) -> Result<(), String> {
    let cap = normalize_capture_name(&chain.capture);
    let enc = chain.encoder.to_ascii_lowercase();
    let tr = chain.transport.to_ascii_lowercase();
    let dec = chain.decoder.to_ascii_lowercase();
    let ren = chain.render.to_ascii_lowercase();

    if !cfg.captures.iter().any(|v| v.eq_ignore_ascii_case(&cap)) {
        return Err(format!("unsupported capture={}", chain.capture));
    }
    if !available_encoders(cfg)
        .iter()
        .any(|v| v.eq_ignore_ascii_case(&enc))
    {
        return Err(format!("unsupported encoder={}", chain.encoder));
    }
    if !cfg.transports.iter().any(|v| v.eq_ignore_ascii_case(&tr)) {
        return Err(format!("unsupported transport={}", chain.transport));
    }
    if !available_decoders(cfg)
        .iter()
        .any(|v| v.eq_ignore_ascii_case(&dec))
    {
        return Err(format!("unsupported decoder={}", chain.decoder));
    }
    if !available_renders(cfg)
        .iter()
        .any(|v| v.eq_ignore_ascii_case(&ren))
    {
        return Err(format!("unsupported renderer={}", chain.render));
    }

    if !allow_debug_codecs && (is_debug_only_codec(&enc) || is_debug_only_codec(&dec)) {
        return Err(format!(
            "debug_only_codec_blocked encoder={} decoder={}",
            chain.encoder, chain.decoder
        ));
    }

    if !is_valid_path(cfg, &enc, &dec) {
        return Err(format!(
            "incompatible_encoder_decoder encoder={} decoder={}",
            chain.encoder, chain.decoder
        ));
    }

    if let Some(backend_ok) = backend_ok {
        for comp in [&cap, &enc, &dec, &ren] {
            if let Some(reqs) = cfg.component_requirements.get(comp) {
                for b in reqs {
                    if !backend_ok
                        .get(&b.to_ascii_lowercase())
                        .copied()
                        .unwrap_or(false)
                    {
                        return Err(format!("backend_unavailable:{}->{}", comp, b));
                    }
                }
            }
        }
    }

    Ok(())
}

fn normalize_capture_name(v: &str) -> String {
    match v.to_ascii_lowercase().as_str() {
        "desktop_gdi" => "desktop_dup".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{compose_decoder_node, compose_encoder_node, split_decoder, split_encoder};

    #[test]
    fn compose_software_medium_priority_codecs() {
        assert_eq!(
            compose_encoder_node("mjpeg", "software"),
            Some("mjpeg_software".to_string())
        );
        assert_eq!(
            compose_encoder_node("prores", "software"),
            Some("prores_software".to_string())
        );
        assert_eq!(
            compose_encoder_node("dnxhd", "software"),
            Some("dnxhd_software".to_string())
        );
        assert_eq!(
            compose_encoder_node("dnxhr", "software"),
            Some("dnxhr_software".to_string())
        );
        assert_eq!(
            compose_decoder_node("mjpeg", "software"),
            Some("mjpeg_software".to_string())
        );
        assert_eq!(
            compose_decoder_node("prores", "software"),
            Some("prores_software".to_string())
        );
        assert_eq!(
            compose_decoder_node("dnxhd", "software"),
            Some("dnxhd_software".to_string())
        );
        assert_eq!(
            compose_decoder_node("dnxhr", "software"),
            Some("dnxhr_software".to_string())
        );
        assert_eq!(
            compose_decoder_node("h264", "d3d12va"),
            Some("h264_d3d12va".to_string())
        );
        assert_eq!(
            compose_decoder_node("hevc", "dxva2"),
            Some("hevc_dxva2".to_string())
        );
        assert_eq!(
            compose_decoder_node("h264", "qsv"),
            Some("h264_qsv".to_string())
        );
        assert_eq!(
            compose_decoder_node("hevc", "vaapi"),
            Some("hevc_vaapi".to_string())
        );
        assert_eq!(
            compose_decoder_node("h264", "cuda"),
            Some("h264_cuda".to_string())
        );
    }

    #[test]
    fn split_medium_priority_codec_nodes() {
        assert_eq!(
            split_encoder("mjpeg_software"),
            ("software".to_string(), "mjpeg".to_string())
        );
        assert_eq!(
            split_encoder("prores_software"),
            ("software".to_string(), "prores".to_string())
        );
        assert_eq!(
            split_decoder("dnxhd_software"),
            ("software".to_string(), "dnxhd".to_string())
        );
        assert_eq!(
            split_decoder("dnxhr_software"),
            ("software".to_string(), "dnxhr".to_string())
        );
    }
}
