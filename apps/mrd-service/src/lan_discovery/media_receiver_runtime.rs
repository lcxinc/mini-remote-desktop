use super::discovery_identity::now_ms;
use super::media_envelope::{
    encode_lan_media_envelope, lan_media_codec_name, lan_media_profile_id, LanMediaEnvelope,
    LAN_MEDIA_CODEC_AV1, LAN_MEDIA_CODEC_H264, LAN_MEDIA_CODEC_HEVC, LAN_MEDIA_PAYLOAD_ACCESS_UNIT,
    LAN_MEDIA_PAYLOAD_PROBE_FRAME,
};
use super::media_frame_preparation::{decoded_frame_format_stage, decoded_frame_pixel_format};
use super::media_probe::decoded_video_probe_format;
use super::media_profile::normalize_lan_media_profile;
use super::media_render_policy::lan_media_payload_hash_for_profile;
#[cfg(any(windows, target_os = "macos"))]
use super::media_render_worker::render_lan_decoded_frame;
use super::session_runtime::selected_media_profile;
use crate::app_state::{AppState, DecodedVideoFrameStats};
use anyhow::Result;
use mrd_ipc::MediaProfile;
use mrd_pipeline_core::DecodedFrame;
use mrd_proto::SessionId;
use mrd_transport_quic_quinn::{
    QuicAuFrame, QuicAuReassemblerStats, QuicMediaCodec, QuicMediaFrame, QuicMediaPayloadType,
};
use std::sync::Arc;

/// Migration rule: an installed Agent route is authoritative even on failure.
pub(super) fn receiver_should_use_local_render_fallback(
    dispatch: crate::agent_runtime::AgentRenderDispatch,
) -> bool {
    dispatch.allows_local_render_fallback()
}

pub(super) async fn quic_media_v3_frame_to_legacy_frame(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    frame: QuicMediaFrame,
    reassembler_stats: QuicAuReassemblerStats,
) -> Result<Option<QuicAuFrame>> {
    let profile = selected_media_profile(app_state, session_id).await;
    let expected_profile_id = lan_media_profile_id(&profile);
    if frame.profile_id != expected_profile_id {
        tracing::debug!(
            session_id = %session_id.0,
            frame_id = frame.frame_id,
            expected_profile_id,
            received_profile_id = frame.profile_id,
            completed = reassembler_stats.completed_frames,
            expired = reassembler_stats.expired_frames,
            evicted = reassembler_stats.evicted_frames,
            duplicate = reassembler_stats.duplicate_fragments,
            rejected = reassembler_stats.rejected_fragments,
            pending = reassembler_stats.pending_frames,
            "LAN media receiver dropped stale v3 profile frame"
        );
        app_state.probes.lock().await.record_transient_frame_drop(
            session_id,
            frame.payload.len() as u64,
            now_ms(),
        );
        return Ok(None);
    }

    let payload_type = match frame.payload_type {
        QuicMediaPayloadType::AccessUnit => LAN_MEDIA_PAYLOAD_ACCESS_UNIT,
        QuicMediaPayloadType::Probe => LAN_MEDIA_PAYLOAD_PROBE_FRAME,
        QuicMediaPayloadType::Control => 3,
    };
    let codec = match frame.codec {
        QuicMediaCodec::None => 0,
        QuicMediaCodec::H264 => LAN_MEDIA_CODEC_H264,
        QuicMediaCodec::Hevc => LAN_MEDIA_CODEC_HEVC,
        QuicMediaCodec::Av1 => LAN_MEDIA_CODEC_AV1,
    };
    if frame.payload_type == QuicMediaPayloadType::AccessUnit
        && !matches!(
            codec,
            LAN_MEDIA_CODEC_H264 | LAN_MEDIA_CODEC_HEVC | LAN_MEDIA_CODEC_AV1
        )
    {
        anyhow::bail!("LAN media v3 access unit has unsupported codec: {codec}");
    }

    let mut envelope_profile = profile;
    if frame.payload_type == QuicMediaPayloadType::AccessUnit && codec != 0 {
        envelope_profile.codec = lan_media_codec_name(codec).to_string();
        normalize_lan_media_profile(&mut envelope_profile);
    }

    let envelope_payload = encode_lan_media_envelope(LanMediaEnvelope {
        payload_type,
        codec,
        sequence: u64::from(frame.frame_id),
        timestamp_us: frame.timestamp_us,
        profile: envelope_profile,
        payload: frame.payload.to_vec(),
    })?;

    Ok(Some(QuicAuFrame {
        frame_id: frame.frame_id,
        timestamp_us: frame.timestamp_us,
        is_keyframe: frame.is_keyframe(),
        payload: envelope_payload.into(),
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_lan_decoded_frames(
    app_state: &Arc<AppState>,
    session_id: &SessionId,
    decoded_frames: Vec<DecodedFrame>,
    bytes_received: u64,
    sequence: u64,
    timestamp_us: u64,
    profile: &MediaProfile,
    encoded_payload: &[u8],
) {
    for decoded_frame in decoded_frames {
        let width = decoded_frame.width as u32;
        let height = decoded_frame.height as u32;
        let decoded_pixel_format = decoded_frame_pixel_format(&decoded_frame);
        let decoded_format_stage = decoded_frame_format_stage(&decoded_frame);

        #[cfg(any(windows, target_os = "macos"))]
        if let Err(error) = render_lan_decoded_frame(app_state, session_id, decoded_frame).await {
            tracing::warn!(
                %error,
                session_id = %session_id.0,
                sequence,
                "LAN media receiver failed to present decoded frame"
            );
        }

        app_state
            .media_pipelines
            .lock()
            .await
            .record_decoded_media_sample(
                session_id.clone(),
                profile,
                width,
                height,
                decoded_pixel_format,
                decoded_format_stage,
            );
        let payload_hash =
            lan_media_payload_hash_for_profile(profile, sequence, timestamp_us, encoded_payload);

        app_state.probes.lock().await.record_decoded_video_frame(
            session_id,
            DecodedVideoFrameStats {
                bytes_received,
                sequence,
                timestamp_us,
                width,
                height,
                target_fps: profile.fps,
                target_bitrate_mbps: profile.bitrate_mbps,
                encoded_bytes: encoded_payload.len() as u32,
                format: decoded_video_probe_format(&profile.codec),
                pixel_format: decoded_pixel_format.to_owned(),
                payload_hash,
                preview_width: None,
                preview_height: None,
                rgb24: None,
            },
            now_ms(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::receiver_should_use_local_render_fallback;
    use crate::agent_runtime::AgentRenderDispatch;

    #[test]
    fn only_an_unavailable_agent_route_allows_service_local_render_fallback() {
        assert!(receiver_should_use_local_render_fallback(
            AgentRenderDispatch::Unavailable
        ));
        assert!(!receiver_should_use_local_render_fallback(
            AgentRenderDispatch::Delivered
        ));
        assert!(!receiver_should_use_local_render_fallback(
            AgentRenderDispatch::Rejected
        ));
    }
}
