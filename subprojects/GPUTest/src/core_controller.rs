use gpu_test::core::integration::{run_integration_case, IntegrationRunConfig};

fn main() -> Result<(), String> {
    let cfg = build_config()?;
    let report = run_integration_case(&cfg)?;
    print_report("controller", &report)?;
    Ok(())
}

fn build_config() -> Result<IntegrationRunConfig, String> {
    let mut cfg = IntegrationRunConfig::default();
    cfg.duration_sec = arg_value("--duration-sec")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(cfg.duration_sec);
    cfg.target_fps = arg_value("--target-fps")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(cfg.target_fps);
    cfg.width = arg_value("--width")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(cfg.width);
    cfg.height = arg_value("--height")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(cfg.height);
    cfg.profile = arg_value("--profile").unwrap_or(cfg.profile);
    cfg.matrix_config_path = arg_value("--matrix-config").unwrap_or(cfg.matrix_config_path);
    cfg.capture = arg_value("--capture").unwrap_or(cfg.capture);
    cfg.encoder = arg_value("--encoder").unwrap_or(cfg.encoder);
    cfg.decoder = arg_value("--decoder").unwrap_or(cfg.decoder);
    cfg.transport = arg_value("--transport").unwrap_or(cfg.transport);
    cfg.render = arg_value("--render").unwrap_or(cfg.render);
    cfg.visualize = has_flag("--visualize");
    cfg.allow_debug_codecs = has_flag("--allow-debug-codecs")
        || std::env::var("MRD_ALLOW_DEBUG_CODECS")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    Ok(cfg)
}

fn print_report(role: &str, report: &gpu_test::core::pipeline_udp::PipelineReport) -> Result<(), String> {
    let out = serde_json::json!({
        "role": role,
        "transport": report.transport,
        "profile": report.profile,
        "width": report.width,
        "height": report.height,
        "target_fps": report.target_fps,
        "frames_total": report.frames_total,
        "frames_received": report.frames_received,
        "frames_dropped": report.frames_dropped,
        "bitrate_avg_mbps": report.bitrate_avg_mbps,
        "bitrate_p95_mbps": report.bitrate_p95_mbps,
        "wire_overhead_est_mbps": report.wire_overhead_est_mbps,
        "e2e_p50_ms": report.e2e.p50,
        "e2e_p95_ms": report.e2e.p95,
        "e2e_p99_ms": report.e2e.p99,
        "e2e_jitter_ms": report.e2e.jitter,
        "pass": report.pass,
        "fail_reason": report.fail_reason,
    });
    println!("{}", serde_json::to_string_pretty(&out).map_err(|e| format!("serialize report: {e}"))?);
    Ok(())
}

fn arg_value(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn has_flag(flag: &str) -> bool {
    std::env::args().any(|a| a == flag)
}
