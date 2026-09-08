pub mod quic;
pub mod quic_datagram;
pub mod rist;
pub mod rtp_rtcp_srtp;
pub mod srt;
pub mod udp;
pub mod webrtc;

use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};

pub fn run_transport(transport: &str, cfg: PipelineConfig) -> Result<PipelineReport, String> {
    match transport {
        "udp" => udp::run(cfg),
        "quic" => quic::run(cfg),
        "quic_datagram" => quic_datagram::run(cfg),
        "rtp_rtcp_srtp" => rtp_rtcp_srtp::run(cfg),
        "rist" => rist::run(cfg),
        "srt" => srt::run(cfg),
        "webrtc" => webrtc::run(cfg),
        _ => Err(format!("transport_not_implemented:{transport}")),
    }
}
