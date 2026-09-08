use crate::core::pipeline_rtp_rtcp_srtp::run_rtp_rtcp_srtp_pipeline;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_rtp_rtcp_srtp_pipeline(cfg)
}
