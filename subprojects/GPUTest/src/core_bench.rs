use gpu_test::core::bench::{run_bench_matrix, BenchRunConfig};

fn main() -> Result<(), String> {
    let duration_sec = arg_value("--duration-sec")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);
    let csv = arg_value("--csv").unwrap_or_else(|| "artifacts/core_matrix.csv".to_string());
    let profile = arg_value("--profile").unwrap_or_else(|| "low_latency".to_string());
    let matrix_config =
        arg_value("--matrix-config").unwrap_or_else(|| "config/matrix.windows.json".to_string());
    let ffmpeg = arg_value("--ffmpeg").unwrap_or_else(|| {
        "J:/ProjectTest/remote-desktop/mini-remote-desktop/tools/ffmpeg_full_build/bin/ffmpeg.exe"
            .to_string()
    });
    let visualize = !has_flag("--no-visualize");
    let allow_debug_codecs = has_flag("--allow-debug-codecs")
        || std::env::var("MRD_ALLOW_DEBUG_CODECS")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let results = run_bench_matrix(BenchRunConfig {
        duration_sec,
        csv_path: csv.clone(),
        profile,
        matrix_config_path: matrix_config,
        ffmpeg_path: ffmpeg,
        visualize,
        allow_debug_codecs,
    })?;

    println!("bench_csv={}", csv);
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skip = 0usize;
    for r in &results {
        match r.status.as_str() {
            "PASS" => pass += 1,
            "FAIL" => fail += 1,
            "SKIP" => skip += 1,
            _ => {}
        }
    }
    println!(
        "summary total={} pass={} fail={} skip={}",
        results.len(),
        pass,
        fail,
        skip
    );
    for r in results {
        let report = r.report.unwrap_or_default();
        println!(
            "run_id={} status={} {} {}({}/{}) {} {}({}/{}) {} {}x{} {}fps e2e_p95={:.3} reason={}",
            r.run_id,
            r.status,
            r.case.capture,
            r.case.encoder,
            r.case.codec_type,
            r.case.encoder_backend,
            r.case.transport,
            r.case.decoder,
            r.case.decode_codec_type,
            r.case.decoder_backend,
            r.case.render,
            r.case.width,
            r.case.height,
            r.case.fps,
            report.e2e.p95,
            r.reason
        );
    }
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
