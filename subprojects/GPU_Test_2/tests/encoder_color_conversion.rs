use gpu_test_2::capture::CapturedFrame;
use gpu_test_2::encoder::bgra_to_rgba_bytes;

#[test]
fn bgra_conversion_swaps_red_and_blue_channels() {
    let frame = CapturedFrame::from_bgra(1, 1, vec![10, 20, 30, 255]).expect("valid frame");

    let rgba = bgra_to_rgba_bytes(&frame).expect("conversion should work");

    assert_eq!(rgba, vec![30, 20, 10, 255]);
}
