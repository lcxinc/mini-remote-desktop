use gpu_test_2::encoder::{EncodedFrame, EncoderConfig};

#[test]
fn encoded_frame_keeps_dimensions_and_pts() {
    let frame = EncodedFrame::new(1280, 720, 33, vec![1, 2, 3]);

    assert_eq!(frame.width, 1280);
    assert_eq!(frame.height, 720);
    assert_eq!(frame.pts, 33);
    assert_eq!(frame.bitstream.len(), 3);
}

#[test]
fn encoder_config_rejects_zero_resolution() {
    let err = EncoderConfig::new(0, 720).unwrap_err();
    assert!(err.to_string().contains("width"));
}

#[test]
fn encoder_config_rejects_zero_height() {
    let err = EncoderConfig::new(1920, 0).unwrap_err();
    assert!(err.to_string().contains("height"));
}

#[test]
fn encoder_config_accepts_valid_resolution() {
    EncoderConfig::new(1920, 1080).unwrap();
}
