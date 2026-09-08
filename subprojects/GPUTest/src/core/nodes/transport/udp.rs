use crate::core::pipeline_udp::{run_udp_pipeline, PipelineConfig, PipelineReport};

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_udp_pipeline(cfg)
}
