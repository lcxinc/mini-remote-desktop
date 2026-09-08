use gpu_test_2::telemetry::StreamingStats;

#[test]
fn telemetry_reports_nonzero_drop_rate() {
    let mut stats = StreamingStats::default();
    stats.frames_captured = 100;
    stats.frames_sent = 80;
    assert!(stats.drop_rate() > 0.0);
}

#[test]
fn telemetry_reports_zero_drop_rate_when_all_frames_sent() {
    let mut stats = StreamingStats::default();
    stats.frames_captured = 100;
    stats.frames_sent = 100;
    assert_eq!(stats.drop_rate(), 0.0);
}

#[test]
fn telemetry_calculates_fps_correctly() {
    let mut stats = StreamingStats::default();
    stats.frames_sent = 60;
    stats.elapsed_secs = 1.0;
    assert_eq!(stats.send_fps(), 60.0);
}
