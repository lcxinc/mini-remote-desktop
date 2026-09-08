use crate::core::pipeline_srt::run_srt_pipeline;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_srt_pipeline(cfg)
}
