use gpu_test_2::decode::{decode_first_frame, StreamingDecoder};

#[test]
fn decoder_rejects_invalid_h264_payload() {
    let err = decode_first_frame(&[0, 1, 2, 3]).expect_err("invalid payload should fail");

    assert!(err.to_string().contains("invalid H.264 payload"));
}

#[test]
fn decoder_can_continue_after_invalid_packet() {
    let mut decoder = StreamingDecoder::new().unwrap();
    // Invalid packet returns Ok(None) - no frame produced but decoder is still usable
    assert!(decoder.decode_packet(&[0, 1, 2]).unwrap().is_none());
    // Decoder remains usable after processing invalid packets
    assert!(decoder.decode_packet(&[0, 1, 2]).unwrap().is_none());
    // Latest frame is still None since no valid frames were decoded
    assert!(decoder.latest_frame().is_none());
}
