pub mod capture;
pub mod decoder;
pub mod encoder;
pub mod render;
pub mod transport;

use crate::core::pipeline_udp::PipelineStageConfig;

pub fn build_stage_profile(
    capture: &str,
    encoder: &str,
    decoder: &str,
    render: &str,
) -> Result<PipelineStageConfig, String> {
    let capture_us = capture::capture_work_us(capture)
        .ok_or_else(|| format!("capture_not_implemented:{capture}"))?;
    let encode_us = encoder::encode_work_us(encoder)
        .ok_or_else(|| format!("encoder_not_implemented:{encoder}"))?;
    let decode_us = decoder::decode_work_us(decoder)
        .ok_or_else(|| format!("decoder_not_implemented:{decoder}"))?;
    let render_profile =
        render::render_profile(render).ok_or_else(|| format!("render_not_implemented:{render}"))?;

    Ok(PipelineStageConfig {
        capture_us,
        encode_us,
        decode_us,
        render_us: render_profile.render_us,
        present_us: render_profile.present_us,
    })
}
