use crate::core::pipeline_quic::run_quic_pipeline;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_quic_pipeline(cfg)
}
