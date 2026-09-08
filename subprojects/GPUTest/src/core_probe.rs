use gpu_test::core::csv_out::append_probe_csv;
use gpu_test::core::probe::probe_all;

fn main() -> Result<(), String> {
    let ffmpeg = arg_value("--ffmpeg")
        .unwrap_or_else(|| "J:/ProjectTest/remote-desktop/mini-remote-desktop/tools/ffmpeg_full_build/bin/ffmpeg.exe".to_string());
    let csv = arg_value("--csv").unwrap_or_else(|| "artifacts/core_probe.csv".to_string());

    let rows = probe_all(&ffmpeg)?;
    append_probe_csv(&csv, &rows)?;

    println!("probe_results_csv={}", csv);
    for r in rows {
        println!(
            "backend={} compiled_supported={} runtime_init_ok={} note={}",
            r.backend, r.compiled_supported, r.runtime_init_ok, r.note
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
