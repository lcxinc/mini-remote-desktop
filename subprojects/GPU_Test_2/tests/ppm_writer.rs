use gpu_test_2::artifacts::encode_ppm;

#[test]
fn ppm_writer_emits_valid_header() {
    let rgb = vec![255u8, 0, 0, 0, 255, 0];

    let bytes = encode_ppm(2, 1, &rgb).expect("valid rgb buffer");

    assert!(bytes.starts_with(b"P6\n2 1\n255\n"));
}
