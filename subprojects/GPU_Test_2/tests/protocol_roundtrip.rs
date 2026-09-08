use gpu_test_2::protocol::{decode_frame_message, encode_frame_message, FrameHeader};

#[test]
fn frame_message_round_trips() {
    let header = FrameHeader::new(1920, 1080, 123, 0, 4096);
    let payload = vec![7u8; 4096];

    let bytes = encode_frame_message(&header, &payload);
    let parsed = decode_frame_message(&bytes).expect("frame should decode");

    assert_eq!(parsed.header.width, 1920);
    assert_eq!(parsed.header.height, 1080);
    assert_eq!(parsed.header.pts, 123);
    assert_eq!(parsed.header.capture_time_ns, 0);
    assert_eq!(parsed.payload, payload);
}
