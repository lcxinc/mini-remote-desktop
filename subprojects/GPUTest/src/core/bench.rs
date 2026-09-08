use crate::core::csv_out::append_matrix_row_csv;
use crate::core::matrix::{
    generate_cases, load_matrix_config, validate_selected_chain, MatrixCase, MatrixConfig,
    SelectedChain,
};
use crate::core::nodes::build_stage_profile;
use crate::core::nodes::render::visual_probe::probe_with_retry;
use crate::core::nodes::transport::run_transport;
use crate::core::pipeline_udp::{PipelineConfig, PipelineReport};
use crate::core::probe::probe_all;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct BenchRunConfig {
    pub duration_sec: u64,
    pub csv_path: String,
    pub profile: String,
    pub matrix_config_path: String,
    pub ffmpeg_path: String,
    pub visualize: bool,
    pub allow_debug_codecs: bool,
}

impl Default for BenchRunConfig {
    fn default() -> Self {
        Self {
            duration_sec: 5,
            csv_path: "artifacts/core_matrix.csv".to_string(),
            profile: "low_latency".to_string(),
            matrix_config_path: "config/matrix.windows.json".to_string(),
            ffmpeg_path: "J:/ProjectTest/remote-desktop/mini-remote-desktop/tools/ffmpeg_full_build/bin/ffmpeg.exe".to_string(),
            visualize: false,
            allow_debug_codecs: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BenchCaseResult {
    pub run_id: String,
    pub case: MatrixCase,
    pub status: String,
    pub reason: String,
    pub report: Option<PipelineReport>,
}

pub fn run_bench_matrix(cfg: BenchRunConfig) -> Result<Vec<BenchCaseResult>, String> {
    let matrix = load_matrix_config(&cfg.matrix_config_path)?;
    let cases = generate_cases(&matrix);
    let probe = probe_all(&cfg.ffmpeg_path)?;
    let mut backend_ok = HashMap::<String, bool>::new();
    for p in probe {
        backend_ok.insert(p.backend.to_ascii_lowercase(), p.runtime_init_ok);
    }

    let mut out = Vec::new();
    for c in cases {
        let run_id = format!(
            "{}_{}_{}_{}_{}_{}_{}_{}_{}_{}_{}x{}_{}fps",
            now_unix_ms(),
            c.capture,
            c.encoder,
            c.codec_type,
            c.encoder_backend,
            c.transport,
            c.decoder,
            c.decode_codec_type,
            c.decoder_backend,
            c.render,
            c.width,
            c.height,
            c.fps
        );

        let status_reason = prune_reason(&matrix, &backend_ok, &c, cfg.allow_debug_codecs);
        if let Some(reason) = status_reason {
            append_matrix_row_csv(
                &cfg.csv_path,
                &run_id,
                &c.capture,
                &c.encoder,
                &c.encoder_backend,
                &c.codec_type,
                &c.transport,
                &c.decoder,
                &c.decoder_backend,
                &c.decode_codec_type,
                &c.render,
                c.width,
                c.height,
                c.fps,
                "SKIP",
                None,
                &reason,
            )?;
            out.push(BenchCaseResult {
                run_id,
                case: c,
                status: "SKIP".to_string(),
                reason,
                report: None,
            });
            continue;
        }

        match run_case(&cfg, &c) {
            Ok(report) => {
                let status = if report.pass { "PASS" } else { "FAIL" }.to_string();
                append_matrix_row_csv(
                    &cfg.csv_path,
                    &run_id,
                    &c.capture,
                    &c.encoder,
                    &c.encoder_backend,
                    &c.codec_type,
                    &c.transport,
                    &c.decoder,
                    &c.decoder_backend,
                    &c.decode_codec_type,
                    &c.render,
                    c.width,
                    c.height,
                    c.fps,
                    &status,
                    Some(&report),
                    &report.fail_reason,
                )?;
                out.push(BenchCaseResult {
                    run_id,
                    case: c,
                    status,
                    reason: report.fail_reason.clone(),
                    report: Some(report),
                });
            }
            Err(reason) => {
                append_matrix_row_csv(
                    &cfg.csv_path,
                    &run_id,
                    &c.capture,
                    &c.encoder,
                    &c.encoder_backend,
                    &c.codec_type,
                    &c.transport,
                    &c.decoder,
                    &c.decoder_backend,
                    &c.decode_codec_type,
                    &c.render,
                    c.width,
                    c.height,
                    c.fps,
                    "SKIP",
                    None,
                    &reason,
                )?;
                out.push(BenchCaseResult {
                    run_id,
                    case: c,
                    status: "SKIP".to_string(),
                    reason,
                    report: None,
                });
            }
        }
    }
    Ok(out)
}

fn run_case(cfg: &BenchRunConfig, c: &MatrixCase) -> Result<PipelineReport, String> {
    let render = c.render.as_str();
    let stages = build_stage_profile(&c.capture, &c.encoder, &c.decoder, render)?;
    let chain_name = format!(
        "{}->{}->{}->{}->{}",
        c.capture, c.encoder, c.transport, c.decoder, render
    );
    if cfg.visualize {
        probe_with_retry(cfg.duration_sec, &chain_name)?;
    }
    let p = PipelineConfig {
        duration_sec: cfg.duration_sec,
        target_fps: c.fps,
        width: c.width,
        height: c.height,
        profile: cfg.profile.clone(),
        chain_name,
        stages,
    };
    run_transport(&c.transport, p)
}

fn prune_reason(
    cfg: &MatrixConfig,
    backend_ok: &HashMap<String, bool>,
    c: &MatrixCase,
    allow_debug_codecs: bool,
) -> Option<String> {
    let chain = SelectedChain {
        capture: c.capture.clone(),
        encoder: c.encoder.clone(),
        transport: c.transport.clone(),
        decoder: c.decoder.clone(),
        render: c.render.clone(),
    };
    validate_selected_chain(cfg, &chain, allow_debug_codecs, Some(backend_ok)).err()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
