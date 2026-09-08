use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};
use crate::core::pipeline_webrtc::run_webrtc_pipeline;

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_webrtc_pipeline(cfg)
}
