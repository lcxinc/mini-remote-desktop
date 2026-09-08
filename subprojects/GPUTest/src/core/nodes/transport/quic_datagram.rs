use crate::core::pipeline_quic_datagram::run_quic_datagram_pipeline;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

pub fn run(cfg: PipelineConfig) -> Result<PipelineReport, String> {
    run_quic_datagram_pipeline(cfg)
}
