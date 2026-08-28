use mrd_proto::{BackendRole, DeviceId, SessionId};
use serde::{Deserialize, Serialize};

mod authenticated;
mod initial_v3;

pub use authenticated::*;
pub use initial_v3::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload")]
pub enum SignalMessage {
    Register(RegisterRequest),
    Registered(RegisteredResponse),
    SessionRequest(SessionRequest),
    SessionAccept(SessionAccept),
    WebrtcOffer(SessionDescription),
    WebrtcAnswer(SessionDescription),
    IceCandidate(IceCandidate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    pub role: BackendRole,
    pub device_id: Option<DeviceId>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisteredResponse {
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRequest {
    pub session_id: SessionId,
    pub source_device_id: DeviceId,
    pub target_device_id: DeviceId,
    pub transport: String,
    pub quic_listen_addr: Option<String>,
    pub quic_server_name: Option<String>,
    pub quic_cert_der_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAccept {
    pub session_id: SessionId,
    pub transport: String,
    pub quic_listen_addr: Option<String>,
    pub quic_server_name: Option<String>,
    pub quic_cert_der_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDescription {
    pub session_id: SessionId,
    pub sdp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceCandidate {
    pub session_id: SessionId,
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
}

#[cfg(test)]
mod tests {
    use mrd_proto::{DeviceId, SessionId};

    use super::{SessionAccept, SessionRequest, SignalMessage};

    #[test]
    fn quic_session_request_roundtrip_preserves_bootstrap_metadata() {
        let message = SignalMessage::SessionRequest(SessionRequest {
            session_id: SessionId("session-quic".into()),
            source_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("agent-1".into()),
            transport: "quic_quinn".into(),
            quic_listen_addr: Some("127.0.0.1:5000".into()),
            quic_server_name: Some("localhost".into()),
            quic_cert_der_b64: Some("AQID".into()),
        });

        let encoded = serde_json::to_string(&message).expect("encode quic session request");
        let decoded: SignalMessage =
            serde_json::from_str(&encoded).expect("decode quic session request");

        assert_eq!(decoded, message);
    }

    #[test]
    fn quic_session_accept_roundtrip_preserves_bootstrap_metadata() {
        let message = SignalMessage::SessionAccept(SessionAccept {
            session_id: SessionId("session-quic".into()),
            transport: "quic_quinn".into(),
            quic_listen_addr: Some("127.0.0.1:6000".into()),
            quic_server_name: Some("localhost".into()),
            quic_cert_der_b64: Some("BAUG".into()),
        });

        let encoded = serde_json::to_string(&message).expect("encode quic session accept");
        let decoded: SignalMessage =
            serde_json::from_str(&encoded).expect("decode quic session accept");

        assert_eq!(decoded, message);
    }
}
