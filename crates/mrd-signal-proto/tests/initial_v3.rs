use mrd_identity::DeviceIdentity;
use mrd_proto::{DeviceId, SessionId};
use mrd_signal_proto::{
    webrtc_candidate_fingerprint_v3, AuthClaims, AuthenticatedSignalMessage, SessionGrantV3,
    SessionGrantV3Payload, SessionIntentV3, SessionIntentV3Payload, SignalEnvelope,
    SignalProtocolError, SignalReplayGuard, WanAccessModeV3, WanMediaProfileV3,
    WanPermissionScopeV3, WanRoutePolicyV3, WanSessionRequestV3, WebRtcAnswerV3,
    WebRtcAnswerV3Payload, WebRtcCandidateV3, WebRtcCandidateV3Payload, WebRtcDescriptionRoleV3,
    WebRtcOfferV3, WebRtcOfferV3Payload, SIGNAL_PROTOCOL_V3,
};
use ring::rand::SystemRandom;

const NOW_MS: u64 = 1_500;

fn identity() -> DeviceIdentity {
    DeviceIdentity::generate(&SystemRandom::new()).expect("device identity")
}

fn claims(
    identity: &DeviceIdentity,
    issuer: &str,
    intended_peer: &str,
    counter: u64,
) -> AuthClaims {
    AuthClaims {
        issuer_device_id: DeviceId(issuer.into()),
        issuer_key_id: identity.key_id().to_owned(),
        intended_peer_device_id: DeviceId(intended_peer.into()),
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
        counter,
        nonce: [counter as u8; 16],
    }
}

fn request() -> WanSessionRequestV3 {
    WanSessionRequestV3 {
        session_id: SessionId("session-1".into()),
        idempotency_key: [9; 16],
        controller_device_id: DeviceId("controller-1".into()),
        target_device_id: DeviceId("target-1".into()),
        access_mode: WanAccessModeV3::Attended,
        requested_scopes: vec![
            WanPermissionScopeV3::InputKeyboard,
            WanPermissionScopeV3::ScreenView,
        ],
        requested_profile: None,
        route_policy: WanRoutePolicyV3::RelayOnly,
    }
}

fn signed_intent(identity: &DeviceIdentity) -> SessionIntentV3 {
    let request = request();
    let request_commitment = request.commitment().expect("request commitment");
    SessionIntentV3::sign(
        identity,
        SessionIntentV3Payload {
            claims: claims(identity, "controller-1", "target-1", 1),
            request,
            request_commitment,
        },
    )
    .expect("signed intent")
}

fn signed_grant(identity: &DeviceIdentity, intent: &SessionIntentV3) -> SessionGrantV3 {
    SessionGrantV3::sign(
        identity,
        SessionGrantV3Payload {
            claims: claims(identity, "target-1", "controller-1", 2),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            intent_commitment: intent.commitment().expect("intent commitment"),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: None,
            backend_policy_revision: 7,
            policy_expires_at_ms: 9_000,
            relay_generation: 0,
            relay_directory_id: "directory-1".into(),
            primary_relay_node_id: "relay-1".into(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .expect("signed grant")
}

fn candidate_payload(
    identity: &DeviceIdentity,
    role: WebRtcDescriptionRoleV3,
    grant_commitment: String,
    counter: u64,
) -> WebRtcCandidateV3Payload {
    let (issuer, peer) = match role {
        WebRtcDescriptionRoleV3::Offer => ("controller-1", "target-1"),
        WebRtcDescriptionRoleV3::Answer => ("target-1", "controller-1"),
    };
    let session_id = SessionId("session-1".into());
    let candidate = "opaque-candidate-a".to_string();
    let sdp_mid = Some("0".to_string());
    let sdp_mline_index = Some(0);
    let username_fragment = Some("opaque-fragment".to_string());
    let candidate_fingerprint = webrtc_candidate_fingerprint_v3(
        &session_id,
        &grant_commitment,
        role,
        &candidate,
        sdp_mid.as_deref(),
        sdp_mline_index,
        username_fragment.as_deref(),
    );
    WebRtcCandidateV3Payload {
        claims: claims(identity, issuer, peer, counter),
        session_id,
        controller_device_id: DeviceId("controller-1".into()),
        target_device_id: DeviceId("target-1".into()),
        grant_commitment,
        description_role: role,
        candidate,
        sdp_mid,
        sdp_mline_index,
        username_fragment,
        candidate_fingerprint,
    }
}

#[test]
fn attended_request_is_normalized_and_has_a_cross_language_golden_commitment() {
    let request = request();
    assert_eq!(
        request.commitment().unwrap(),
        "d4942aab9c4cd956ba314d4d4b6c19b744cd20132de7a69b2fb18b045de41608"
    );

    let controller = identity();
    let intent = signed_intent(&controller);
    assert_eq!(
        intent.payload.request_commitment,
        request.commitment().unwrap()
    );

    let mut unsorted = request.clone();
    unsorted.requested_scopes.reverse();
    assert_eq!(unsorted.validate(), Err(SignalProtocolError::Malformed));

    let mut duplicated = request;
    duplicated
        .requested_scopes
        .push(WanPermissionScopeV3::ScreenView);
    assert_eq!(duplicated.validate(), Err(SignalProtocolError::Malformed));
}

#[test]
fn intent_rejects_non_normalized_profile_and_request_commitment_mismatch() {
    let controller = identity();
    let mut profile_request = request();
    profile_request.requested_profile = Some(WanMediaProfileV3 {
        width: 1920,
        height: 1080,
        fps: 60,
        bitrate_mbps: 20,
        codec: "H264".into(),
        codec_profile: None,
        bit_depth: Some(8),
        chroma_subsampling: Some("4:2:0".into()),
        pixel_format: Some("nv12".into()),
        hdr_enabled: Some(false),
        color_mode: Some("full".into()),
        color_pipeline: Some("sdr8".into()),
    });
    assert_eq!(
        profile_request.validate(),
        Err(SignalProtocolError::Malformed)
    );

    let error = SessionIntentV3::sign(
        &controller,
        SessionIntentV3Payload {
            claims: claims(&controller, "controller-1", "target-1", 1),
            request: request(),
            request_commitment: "a".repeat(64),
        },
    )
    .unwrap_err();
    assert_eq!(error, SignalProtocolError::Malformed);
}

#[test]
fn grant_carries_the_exact_intent_commitment_and_cannot_expand_scope() {
    let controller = identity();
    let target = identity();
    let intent = signed_intent(&controller);
    let grant = signed_grant(&target, &intent);

    grant.verify_intent(&intent).unwrap();
    assert_eq!(
        grant.payload.intent_commitment,
        intent.commitment().unwrap()
    );

    let mut expanded = grant.clone();
    expanded.payload.approved_scopes = vec![WanPermissionScopeV3::AudioTalk];
    assert_eq!(
        expanded.verify_intent(&intent),
        Err(SignalProtocolError::Malformed)
    );

    let other_controller = identity();
    let other_intent = signed_intent(&other_controller);
    assert_eq!(
        grant.verify_intent(&other_intent),
        Err(SignalProtocolError::Malformed)
    );
}

#[test]
fn grant_profile_binding_rejects_every_non_numeric_mutation() {
    let controller = identity();
    let target = identity();
    let profile = WanMediaProfileV3 {
        width: 1920,
        height: 1080,
        fps: 60,
        bitrate_mbps: 20,
        codec: "h264".into(),
        codec_profile: Some("high".into()),
        bit_depth: Some(8),
        chroma_subsampling: Some("4:2:0".into()),
        pixel_format: Some("nv12".into()),
        hdr_enabled: Some(false),
        color_mode: Some("full".into()),
        color_pipeline: Some("sdr8".into()),
    };
    let mut requested = request();
    requested.requested_profile = Some(profile.clone());
    let request_commitment = requested.commitment().unwrap();
    let intent = SessionIntentV3::sign(
        &controller,
        SessionIntentV3Payload {
            claims: claims(&controller, "controller-1", "target-1", 1),
            request: requested,
            request_commitment,
        },
    )
    .unwrap();
    let grant = SessionGrantV3::sign(
        &target,
        SessionGrantV3Payload {
            claims: claims(&target, "target-1", "controller-1", 2),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            intent_commitment: intent.commitment().unwrap(),
            approved_scopes: vec![WanPermissionScopeV3::ScreenView],
            approved_profile: Some(profile.clone()),
            backend_policy_revision: 7,
            policy_expires_at_ms: 9_000,
            relay_generation: 0,
            relay_directory_id: "directory-1".into(),
            primary_relay_node_id: "relay-1".into(),
            route_policy: WanRoutePolicyV3::RelayOnly,
        },
    )
    .unwrap();
    grant.verify_intent(&intent).unwrap();

    let mut mutations = Vec::new();
    let mut changed = profile.clone();
    changed.codec_profile = Some("main".into());
    mutations.push(changed);
    let mut changed = profile.clone();
    changed.pixel_format = Some("p010".into());
    mutations.push(changed);
    let mut changed = profile.clone();
    changed.hdr_enabled = Some(true);
    mutations.push(changed);
    let mut changed = profile.clone();
    changed.color_mode = Some("limited".into());
    mutations.push(changed);
    let mut changed = profile;
    changed.color_pipeline = Some("hdr10".into());
    mutations.push(changed);

    for approved_profile in mutations {
        let mut mutated = grant.clone();
        mutated.payload.approved_profile = Some(approved_profile);
        assert_eq!(
            mutated.verify_intent(&intent),
            Err(SignalProtocolError::Malformed)
        );
    }
}

#[test]
fn candidate_fingerprint_is_domain_separated_and_binds_optional_presence() {
    let session_id = SessionId("session-1".into());
    let grant_commitment = "b".repeat(64);
    let base = webrtc_candidate_fingerprint_v3(
        &session_id,
        &grant_commitment,
        WebRtcDescriptionRoleV3::Offer,
        "opaque-candidate-a",
        Some("0"),
        Some(0),
        Some("opaque-fragment"),
    );
    assert_eq!(
        base,
        "72582c3ba7cb6e68afae42cabba0d4c96cfae33619951d507cc0bfccede0f572"
    );
    for changed in [
        webrtc_candidate_fingerprint_v3(
            &session_id,
            &grant_commitment,
            WebRtcDescriptionRoleV3::Answer,
            "opaque-candidate-a",
            Some("0"),
            Some(0),
            Some("opaque-fragment"),
        ),
        webrtc_candidate_fingerprint_v3(
            &session_id,
            &grant_commitment,
            WebRtcDescriptionRoleV3::Offer,
            "opaque-candidate-a",
            None,
            Some(0),
            Some("opaque-fragment"),
        ),
        webrtc_candidate_fingerprint_v3(
            &session_id,
            &grant_commitment,
            WebRtcDescriptionRoleV3::Offer,
            "opaque-candidate-a",
            Some("0"),
            None,
            Some("opaque-fragment"),
        ),
        webrtc_candidate_fingerprint_v3(
            &session_id,
            &grant_commitment,
            WebRtcDescriptionRoleV3::Offer,
            "opaque-candidate-a",
            Some("0"),
            Some(0),
            None,
        ),
    ] {
        assert_ne!(changed, base);
    }
}

#[test]
fn offer_and_answer_require_exact_sorted_candidate_manifests() {
    let controller = identity();
    let target = identity();
    let intent = signed_intent(&controller);
    let grant = signed_grant(&target, &intent);
    let grant_commitment = grant.commitment().unwrap();
    let offer_candidate = candidate_payload(
        &controller,
        WebRtcDescriptionRoleV3::Offer,
        grant_commitment.clone(),
        3,
    );
    let offer = WebRtcOfferV3::sign(
        &controller,
        WebRtcOfferV3Payload {
            claims: claims(&controller, "controller-1", "target-1", 4),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            grant_commitment: grant_commitment.clone(),
            sdp: "opaque-offer-description".into(),
            candidate_fingerprints: vec![offer_candidate.candidate_fingerprint.clone()],
        },
    )
    .unwrap();
    offer
        .verify_candidate_manifest(std::slice::from_ref(&offer_candidate))
        .unwrap();
    offer.verify_grant(&grant).unwrap();
    assert_eq!(
        offer.verify_candidate_manifest(&[]),
        Err(SignalProtocolError::Malformed)
    );
    assert_eq!(
        offer.verify_candidate_manifest(&[offer_candidate.clone(), offer_candidate.clone()]),
        Err(SignalProtocolError::Malformed)
    );

    let mut mismatched_grant = grant.clone();
    mismatched_grant.signature[0] ^= 1;
    assert_eq!(
        offer.verify_grant(&mismatched_grant),
        Err(SignalProtocolError::Malformed)
    );

    let answer_candidate = candidate_payload(
        &target,
        WebRtcDescriptionRoleV3::Answer,
        grant_commitment.clone(),
        5,
    );
    let answer = WebRtcAnswerV3::sign(
        &target,
        WebRtcAnswerV3Payload {
            claims: claims(&target, "target-1", "controller-1", 6),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            grant_commitment,
            sdp: "opaque-answer-description".into(),
            candidate_fingerprints: vec![answer_candidate.candidate_fingerprint.clone()],
        },
    )
    .unwrap();
    answer
        .verify_candidate_manifest(std::slice::from_ref(&answer_candidate))
        .unwrap();

    let mut mutated = offer_candidate;
    mutated.candidate = "opaque-candidate-mutated".into();
    assert_eq!(
        offer.verify_candidate_manifest(&[mutated]),
        Err(SignalProtocolError::Malformed)
    );
}

#[test]
fn description_manifest_rejects_empty_duplicate_unsorted_and_oversized_values() {
    let controller = identity();
    let base = WebRtcOfferV3Payload {
        claims: claims(&controller, "controller-1", "target-1", 1),
        session_id: SessionId("session-1".into()),
        controller_device_id: DeviceId("controller-1".into()),
        target_device_id: DeviceId("target-1".into()),
        grant_commitment: "b".repeat(64),
        sdp: "opaque-description".into(),
        candidate_fingerprints: Vec::new(),
    };
    for invalid in [
        Vec::new(),
        vec!["a".repeat(64), "a".repeat(64)],
        vec!["b".repeat(64), "a".repeat(64)],
        (0..257)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>(),
    ] {
        assert_eq!(
            WebRtcOfferV3::sign(
                &controller,
                WebRtcOfferV3Payload {
                    candidate_fingerprints: invalid,
                    ..base.clone()
                }
            ),
            Err(SignalProtocolError::Malformed)
        );
    }
}

#[test]
fn v3_verification_rejects_wrong_peer_expiry_replay_signature_and_role() {
    let controller = identity();
    let target = identity();
    let intent = signed_intent(&controller);
    let grant = signed_grant(&target, &intent);
    let mut replay = SignalReplayGuard::new(8, 64);

    assert_eq!(
        intent.verify_for(&DeviceId("other-target".into()), NOW_MS, &mut replay),
        Err(SignalProtocolError::WrongIntendedPeer)
    );
    assert_eq!(
        intent.verify_for(&DeviceId("target-1".into()), 2_000, &mut replay),
        Err(SignalProtocolError::Expired)
    );
    intent
        .verify_for(&DeviceId("target-1".into()), NOW_MS, &mut replay)
        .unwrap();
    assert_eq!(
        intent.verify_for(&DeviceId("target-1".into()), NOW_MS, &mut replay),
        Err(SignalProtocolError::RepeatedNonce)
    );

    let mut tampered = grant;
    tampered.payload.primary_relay_node_id = "relay-mutated".into();
    assert_eq!(
        tampered.verify_for(
            &DeviceId("controller-1".into()),
            NOW_MS,
            &mut SignalReplayGuard::new(8, 64),
        ),
        Err(SignalProtocolError::InvalidSignature)
    );

    let mut wrong_role =
        candidate_payload(&target, WebRtcDescriptionRoleV3::Offer, "b".repeat(64), 7);
    wrong_role.claims = claims(&target, "target-1", "controller-1", 7);
    assert_eq!(
        WebRtcCandidateV3::sign(&target, wrong_role),
        Err(SignalProtocolError::Malformed)
    );
}

#[test]
fn all_v3_initial_messages_require_v3_and_cross_version_pairs_are_rejected() {
    let controller = identity();
    let target = identity();
    let intent = signed_intent(&controller);
    let grant = signed_grant(&target, &intent);
    let grant_commitment = grant.commitment().unwrap();
    let offer_candidate = candidate_payload(
        &controller,
        WebRtcDescriptionRoleV3::Offer,
        grant_commitment.clone(),
        3,
    );
    let answer_candidate = candidate_payload(
        &target,
        WebRtcDescriptionRoleV3::Answer,
        grant_commitment.clone(),
        4,
    );
    let offer = WebRtcOfferV3::sign(
        &controller,
        WebRtcOfferV3Payload {
            claims: claims(&controller, "controller-1", "target-1", 5),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            grant_commitment: grant_commitment.clone(),
            sdp: "opaque-offer-description".into(),
            candidate_fingerprints: vec![offer_candidate.candidate_fingerprint.clone()],
        },
    )
    .unwrap();
    let answer = WebRtcAnswerV3::sign(
        &target,
        WebRtcAnswerV3Payload {
            claims: claims(&target, "target-1", "controller-1", 6),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            grant_commitment,
            sdp: "opaque-answer-description".into(),
            candidate_fingerprints: vec![answer_candidate.candidate_fingerprint.clone()],
        },
    )
    .unwrap();
    let candidate = WebRtcCandidateV3::sign(&controller, offer_candidate).unwrap();

    for message in [
        AuthenticatedSignalMessage::from(intent),
        AuthenticatedSignalMessage::from(grant),
        AuthenticatedSignalMessage::from(offer),
        AuthenticatedSignalMessage::from(answer),
        AuthenticatedSignalMessage::from(candidate),
    ] {
        let envelope = SignalEnvelope::new(message);
        assert_eq!(envelope.version, SIGNAL_PROTOCOL_V3);
        let encoded = serde_json::to_value(&envelope).unwrap();
        let decoded: SignalEnvelope = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.version, SIGNAL_PROTOCOL_V3);

        let mut downgraded = encoded;
        downgraded["version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<SignalEnvelope>(downgraded).is_err());
    }
}

#[test]
fn v3_identifiers_reject_userinfo_and_non_backend_safe_characters() {
    for invalid in [
        "turn:user:pass@relay.example",
        "session/with/path",
        "session?query=secret",
        "session#fragment",
        "-leading-separator",
    ] {
        let mut invalid_request = request();
        invalid_request.session_id = SessionId(invalid.into());
        assert_eq!(
            invalid_request.validate(),
            Err(SignalProtocolError::Malformed)
        );
    }

    let mut too_long = request();
    too_long.target_device_id = DeviceId("a".repeat(129));
    assert_eq!(too_long.validate(), Err(SignalProtocolError::Malformed));

    let controller = identity();
    let target = identity();
    let intent = signed_intent(&controller);
    let mut grant = signed_grant(&target, &intent).payload;
    grant.relay_directory_id = "turn:user:pass@relay.example".into();
    assert_eq!(
        SessionGrantV3::sign(&target, grant),
        Err(SignalProtocolError::Malformed)
    );
}

#[test]
fn debug_output_redacts_signed_descriptions_candidates_and_grant_bodies() {
    let controller = identity();
    let target = identity();
    let intent = signed_intent(&controller);
    let grant = signed_grant(&target, &intent);
    let grant_commitment = grant.commitment().unwrap();
    let candidate_payload = candidate_payload(
        &controller,
        WebRtcDescriptionRoleV3::Offer,
        grant_commitment.clone(),
        3,
    );
    let candidate_marker = candidate_payload.candidate.clone();
    let candidate = WebRtcCandidateV3::sign(&controller, candidate_payload).unwrap();
    let description_marker = "opaque-private-description";
    let offer = WebRtcOfferV3::sign(
        &controller,
        WebRtcOfferV3Payload {
            claims: claims(&controller, "controller-1", "target-1", 4),
            session_id: SessionId("session-1".into()),
            controller_device_id: DeviceId("controller-1".into()),
            target_device_id: DeviceId("target-1".into()),
            grant_commitment,
            sdp: description_marker.into(),
            candidate_fingerprints: vec![candidate.payload.candidate_fingerprint.clone()],
        },
    )
    .unwrap();
    let debug = format!(
        "{intent:?} {grant:?} {offer:?} {candidate:?} {:?}",
        SignalEnvelope::new(AuthenticatedSignalMessage::from(offer.clone()))
    );
    assert!(!debug.contains(description_marker));
    assert!(!debug.contains(&candidate_marker));
    assert!(!debug.contains(&grant.payload.relay_directory_id));
}
