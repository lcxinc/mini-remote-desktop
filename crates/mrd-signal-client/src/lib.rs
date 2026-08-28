use mrd_signal_proto::{SignalEnvelope, SignalMessage, SignalProtocolError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignalClientError {
    #[error("serialize signal message failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error(transparent)]
    Protocol(#[from] SignalProtocolError),
    #[error("signal message exceeds the bounded wire size")]
    MessageTooLarge,
}

pub const MAX_SIGNAL_MESSAGE_BYTES: usize = 512 * 1_024;

pub fn encode_message(message: &SignalMessage) -> Result<String, SignalClientError> {
    serde_json::to_string(message).map_err(Into::into)
}

pub fn decode_message(raw: &str) -> Result<SignalMessage, SignalClientError> {
    serde_json::from_str(raw).map_err(Into::into)
}

/// Encode one mandatory-version authenticated signaling envelope.
pub fn encode_authenticated_message(
    envelope: &SignalEnvelope,
) -> Result<String, SignalClientError> {
    envelope.validate_version()?;
    let encoded = serde_json::to_string(envelope)?;
    if encoded.len() > MAX_SIGNAL_MESSAGE_BYTES {
        return Err(SignalClientError::MessageTooLarge);
    }
    Ok(encoded)
}

/// Decode only the authenticated protocol; legacy unversioned JSON is rejected.
pub fn decode_authenticated_message(raw: &str) -> Result<SignalEnvelope, SignalClientError> {
    if raw.len() > MAX_SIGNAL_MESSAGE_BYTES {
        return Err(SignalClientError::MessageTooLarge);
    }
    let value: serde_json::Value = serde_json::from_str(raw)?;
    if let (Some(version), Some(message_type)) = (
        value.get("version").and_then(serde_json::Value::as_u64),
        value
            .get("message")
            .and_then(|message| message.get("type"))
            .and_then(serde_json::Value::as_str),
    ) {
        SignalEnvelope::validate_wire_version(version, message_type)?;
    }
    serde_json::from_value(value).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_authenticated_message, decode_message, encode_authenticated_message, encode_message,
        SignalClientError,
    };
    use mrd_proto::{BackendRole, DeviceId, SessionId};
    use mrd_signal_proto::{RegisterRequest, SessionAccept, SessionRequest, SignalMessage};

    #[test]
    fn register_message_roundtrip() {
        let message = SignalMessage::Register(RegisterRequest {
            role: BackendRole::Controller,
            device_id: Some(DeviceId("controller-1".into())),
            name: "Rdesk".into(),
        });

        let encoded = encode_message(&message).expect("encode register message");
        let decoded = decode_message(&encoded).expect("decode register message");

        assert_eq!(decoded, message);
    }

    #[test]
    fn quic_session_messages_roundtrip() {
        let request = SignalMessage::SessionRequest(SessionRequest {
            session_id: SessionId("session-quic".into()),
            source_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("agent-1".into()),
            transport: "quic_quinn".into(),
            quic_listen_addr: Some("127.0.0.1:5000".into()),
            quic_server_name: Some("localhost".into()),
            quic_cert_der_b64: Some("AQID".into()),
        });
        let accept = SignalMessage::SessionAccept(SessionAccept {
            session_id: SessionId("session-quic".into()),
            transport: "quic_quinn".into(),
            quic_listen_addr: Some("127.0.0.1:6000".into()),
            quic_server_name: Some("localhost".into()),
            quic_cert_der_b64: Some("BAUG".into()),
        });

        let encoded_request = encode_message(&request).expect("encode quic request");
        let decoded_request = decode_message(&encoded_request).expect("decode quic request");
        assert_eq!(decoded_request, request);

        let encoded_accept = encode_message(&accept).expect("encode quic accept");
        let decoded_accept = decode_message(&encoded_accept).expect("decode quic accept");
        assert_eq!(decoded_accept, accept);
    }

    #[test]
    fn authenticated_decode_rejects_legacy_unversioned_message() {
        let legacy = encode_message(&SignalMessage::Register(RegisterRequest {
            role: BackendRole::Controller,
            device_id: Some(DeviceId("controller-1".into())),
            name: "Rdesk".into(),
        }))
        .unwrap();
        assert!(decode_authenticated_message(&legacy).is_err());
    }

    #[test]
    fn authenticated_encode_rejects_in_memory_wrong_version() {
        use mrd_signal_proto::{
            AuthenticatedSignalMessage, ProtocolReasonCode, SignalEnvelope, SignalErrorMessage,
            SIGNAL_PROTOCOL_VERSION,
        };
        let mut envelope = SignalEnvelope::new(AuthenticatedSignalMessage::ProtocolError(
            SignalErrorMessage {
                reason: ProtocolReasonCode::Malformed,
                correlation_id: None,
                detail: "invalid".into(),
            },
        ));
        envelope.version = SIGNAL_PROTOCOL_VERSION + 1;
        assert!(encode_authenticated_message(&envelope).is_err());
    }

    #[test]
    fn authenticated_wire_decode_preserves_unsupported_version() {
        use mrd_signal_proto::{ProtocolReasonCode, SignalProtocolError};

        for raw in [
            r#"{"version":2,"message":{"type":"session_intent","payload":{}}}"#,
            r#"{"version":3,"message":{"type":"protocol_error","payload":{"reason":"malformed","correlation_id":null,"detail":"request rejected"}}}"#,
        ] {
            let error = decode_authenticated_message(raw).unwrap_err();
            assert!(matches!(
                error,
                SignalClientError::Protocol(SignalProtocolError::UnsupportedVersion)
            ));
            let SignalClientError::Protocol(protocol) = error else {
                unreachable!()
            };
            assert_eq!(
                protocol.reason_code(),
                ProtocolReasonCode::UnsupportedVersion
            );
        }
    }

    #[test]
    fn authenticated_codec_roundtrips_versioned_envelope() {
        use mrd_signal_proto::{
            AuthenticatedSignalMessage, ProtocolReasonCode, SignalEnvelope, SignalErrorMessage,
        };
        let envelope = SignalEnvelope::new(AuthenticatedSignalMessage::ProtocolError(
            SignalErrorMessage {
                reason: ProtocolReasonCode::RateLimited,
                correlation_id: Some([3; 16]),
                detail: "retry later".into(),
            },
        ));
        let encoded = encode_authenticated_message(&envelope).unwrap();
        assert_eq!(decode_authenticated_message(&encoded).unwrap(), envelope);
    }
}
