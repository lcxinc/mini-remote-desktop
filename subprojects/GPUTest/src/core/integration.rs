use crate::core::matrix::{load_matrix_config, validate_selected_chain, SelectedChain};
use crate::core::nodes::build_stage_profile;
use crate::core::nodes::render::visual_probe::probe_with_retry;
use crate::core::nodes::transport::run_transport;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

#[derive(Debug, Clone)]
pub struct IntegrationRunConfig {
    pub duration_sec: u64,
    pub target_fps: u32,
    pub width: u32,
    pub height: u32,
    pub profile: String,
    pub matrix_config_path: String,
    pub capture: String,
    pub encoder: String,
    pub decoder: String,
    pub transport: String,
    pub render: String,
    pub visualize: bool,
    pub allow_debug_codecs: bool,
}

impl Default for IntegrationRunConfig {
    fn default() -> Self {
        Self {
            duration_sec: 20,
            target_fps: 60,
            width: 1920,
            height: 1080,
            profile: "low_latency".to_string(),
            matrix_config_path: "config/matrix.windows.json".to_string(),
            capture: "desktop_dup".to_string(),
            encoder: "software".to_string(),
            decoder: "software".to_string(),
            transport: "quic".to_string(),
            render: "gpu_present".to_string(),
            visualize: false,
            allow_debug_codecs: false,
        }
    }
}

pub fn run_integration_case(cfg: &IntegrationRunConfig) -> Result<PipelineReport, String> {
    let matrix = load_matrix_config(&cfg.matrix_config_path)?;
    let selected = SelectedChain {
        capture: cfg.capture.clone(),
        encoder: cfg.encoder.clone(),
        transport: cfg.transport.clone(),
        decoder: cfg.decoder.clone(),
        render: cfg.render.clone(),
    };
    validate_selected_chain(&matrix, &selected, cfg.allow_debug_codecs, None)?;

    let stages = build_stage_profile(&cfg.capture, &cfg.encoder, &cfg.decoder, &cfg.render)?;
    let chain_name = format!(
        "{}->{}->{}->{}->{}",
        cfg.capture, cfg.encoder, cfg.transport, cfg.decoder, cfg.render
    );
    if cfg.visualize {
        probe_with_retry(cfg.duration_sec, &chain_name)?;
    }
    let pipeline = PipelineConfig {
        duration_sec: cfg.duration_sec,
        target_fps: cfg.target_fps,
        width: cfg.width,
        height: cfg.height,
        profile: cfg.profile.clone(),
        chain_name,
        stages,
    };
    run_transport(&cfg.transport, pipeline)
}
