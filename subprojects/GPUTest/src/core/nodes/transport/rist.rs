use crate::core::pipeline_rist::run_rist_pipeline;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_rist_pipeline(cfg)
}
