use gpu_test_2::capture::{CaptureSession, CapturedFrame};

#[test]
fn captured_frame_reports_expected_buffer_len() {
    let frame = CapturedFrame::from_bgra(4, 2, vec![0u8; 32]).expect("valid BGRA frame");

    assert_eq!(frame.width, 4);
    assert_eq!(frame.height, 2);
    assert_eq!(frame.data.len(), 32);
}

#[test]
fn capture_session_rejects_zero_dimensions() {
    let err = CaptureSession::validate_dimensions(0, 1080).unwrap_err();
    assert!(err.to_string().contains("width"));
}

#[test]
fn capture_session_rejects_zero_height() {
    let err = CaptureSession::validate_dimensions(1920, 0).unwrap_err();
    assert!(err.to_string().contains("height"));
}

#[test]
fn capture_session_accepts_valid_dimensions() {
    CaptureSession::validate_dimensions(1920, 1080).unwrap();
}
