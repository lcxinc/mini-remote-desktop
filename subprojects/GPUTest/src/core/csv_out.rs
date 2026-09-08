use crate::core::pipeline_udp::PipelineReport;
use crate::core::probe::ProbeResult;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn append_probe_csv(path: &str, rows: &[ProbeResult]) -> Result<(), String> {
    ensure_parent(path)?;
    let exists = Path::new(path).exists();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    if !exists {
        writeln!(
            f,
            "timestamp,backend,compiled_supported,runtime_init_ok,note"
        )
        .map_err(|e| format!("write header: {e}"))?;
    }
    let ts = now_unix_ms();
    for r in rows {
        writeln!(
            f,
            "{},{},{},{},{}",
            ts,
            r.backend,
            r.compiled_supported,
            r.runtime_init_ok,
            esc(&r.note)
        )
        .map_err(|e| format!("write row: {e}"))?;
    }
    Ok(())
}

pub fn append_pipeline_csv(
    path: &str,
    report: &PipelineReport,
    run_id: &str,
) -> Result<(), String> {
    ensure_parent(path)?;
    let exists = Path::new(path).exists();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    if !exists {
        writeln!(f, "run_id,timestamp,transport,profile,width,height,target_fps,frames_total,frames_received,frames_dropped,fps_capture,fps_encode,fps_send,fps_recv,fps_decode,fps_render,bitrate_avg_mbps,bitrate_p95_mbps,wire_overhead_est_mbps,lat_capture_ms,lat_capture_p95_ms,lat_encode_ms,lat_encode_p95_ms,lat_send_ms,lat_send_p95_ms,lat_recv_wait_ms,lat_recv_wait_p95_ms,lat_decode_ms,lat_decode_p95_ms,lat_render_ms,lat_render_p95_ms,lat_present_call_ms,lat_present_call_p95_ms,e2e_ms,e2e_p50_ms,e2e_p95_ms,e2e_p99_ms,e2e_jitter_ms,pass_fail,fail_reason")
            .map_err(|e| format!("write header: {e}"))?;
    }
    let ts = now_unix_ms();
    writeln!(
        f,
        "{},{},{},{},{},{},{},{},{},{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{}",
        run_id,
        ts,
        report.transport,
        report.profile,
        report.width,
        report.height,
        report.target_fps,
        report.frames_total,
        report.frames_received,
        report.frames_dropped,
        hz_from_ms(report.capture.avg),
        hz_from_ms(report.encode.avg),
        hz_from_ms(report.send.avg),
        hz_from_ms(report.recv_wait.avg),
        hz_from_ms(report.decode.avg),
        hz_from_ms(report.render.avg),
        report.bitrate_avg_mbps,
        report.bitrate_p95_mbps,
        report.wire_overhead_est_mbps,
        report.capture.avg,
        report.capture.p95,
        report.encode.avg,
        report.encode.p95,
        report.send.avg,
        report.send.p95,
        report.recv_wait.avg,
        report.recv_wait.p95,
        report.decode.avg,
        report.decode.p95,
        report.render.avg,
        report.render.p95,
        report.present_call.avg,
        report.present_call.p95,
        report.e2e.avg,
        report.e2e.p50,
        report.e2e.p95,
        report.e2e.p99,
        report.e2e.jitter,
        if report.pass { "PASS" } else { "FAIL" },
        esc(&report.fail_reason),
    )
    .map_err(|e| format!("write row: {e}"))?;
    Ok(())
}

fn hz_from_ms(ms: f64) -> f64 {
    if ms <= 0.0 {
        0.0
    } else {
        1000.0 / ms
    }
}

fn esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn ensure_parent(path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
    }
    Ok(())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub fn append_matrix_row_csv(
    path: &str,
    run_id: &str,
    capture: &str,
    encoder: &str,
    encoder_backend: &str,
    codec_type: &str,
    transport: &str,
    decoder: &str,
    decoder_backend: &str,
    decode_codec_type: &str,
    render: &str,
    width: u32,
    height: u32,
    target_fps: u32,
    status: &str,
    report: Option<&PipelineReport>,
    reason: &str,
) -> Result<(), String> {
    ensure_parent(path)?;
    let exists = Path::new(path).exists();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    if !exists {
        writeln!(f, "run_id,timestamp,capture,encoder,encoder_backend,codec_type,transport,decoder,decoder_backend,decode_codec_type,render,width,height,target_fps,status,fps_achieved,fps_ratio,bitrate_avg_mbps,bitrate_p95_mbps,wire_overhead_est_mbps,e2e_p50_ms,e2e_p95_ms,e2e_p99_ms,e2e_jitter_ms,present_call_p95_ms,decode_p95_ms,stage_capture_ms,stage_capture_p95_ms,stage_encode_ms,stage_encode_p95_ms,stage_send_ms,stage_send_p95_ms,stage_recv_wait_ms,stage_recv_wait_p95_ms,stage_decode_ms,stage_decode_p95_ms,stage_render_ms,stage_render_p95_ms,stage_present_call_ms,stage_present_call_p95_ms,frames_total,frames_received,frames_dropped,reason")
            .map_err(|e| format!("write header: {e}"))?;
    }
    let ts = now_unix_ms();
    let (
        fps_achieved,
        fps_ratio,
        bitrate_avg,
        bitrate_p95,
        wire_overhead_est,
        e2e_p50,
        e2e_p95,
        e2e_p99,
        e2e_jitter,
        present_p95,
        decode_p95,
        capture_avg,
        capture_p95,
        encode_avg,
        encode_p95,
        send_avg,
        send_p95,
        recv_avg,
        recv_p95,
        decode_avg,
        decode_p95_stage,
        render_avg,
        render_p95,
        present_avg,
        present_p95_stage,
        ft,
        fr,
        fd,
    ) = if let Some(r) = report {
        let fps_achieved = if r.frames_total == 0 {
            0.0
        } else {
            (r.frames_received as f64 / r.frames_total as f64) * target_fps as f64
        };
        let fps_ratio = if target_fps == 0 {
            0.0
        } else {
            fps_achieved / target_fps as f64
        };
        (
            fps_achieved,
            fps_ratio,
            r.bitrate_avg_mbps,
            r.bitrate_p95_mbps,
            r.wire_overhead_est_mbps,
            r.e2e.p50,
            r.e2e.p95,
            r.e2e.p99,
            r.e2e.jitter,
            r.present_call.p95,
            r.decode.p95,
            r.capture.avg,
            r.capture.p95,
            r.encode.avg,
            r.encode.p95,
            r.send.avg,
            r.send.p95,
            r.recv_wait.avg,
            r.recv_wait.p95,
            r.decode.avg,
            r.decode.p95,
            r.render.avg,
            r.render.p95,
            r.present_call.avg,
            r.present_call.p95,
            r.frames_total,
            r.frames_received,
            r.frames_dropped,
        )
    } else {
        (
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0,
        )
    };
    let row = vec![
        run_id.to_string(),
        ts.to_string(),
        capture.to_string(),
        encoder.to_string(),
        encoder_backend.to_string(),
        codec_type.to_string(),
        transport.to_string(),
        decoder.to_string(),
        decoder_backend.to_string(),
        decode_codec_type.to_string(),
        render.to_string(),
        width.to_string(),
        height.to_string(),
        target_fps.to_string(),
        status.to_string(),
        format!("{:.3}", fps_achieved),
        format!("{:.4}", fps_ratio),
        format!("{:.3}", bitrate_avg),
        format!("{:.3}", bitrate_p95),
        format!("{:.3}", wire_overhead_est),
        format!("{:.3}", e2e_p50),
        format!("{:.3}", e2e_p95),
        format!("{:.3}", e2e_p99),
        format!("{:.3}", e2e_jitter),
        format!("{:.3}", present_p95),
        format!("{:.3}", decode_p95),
        format!("{:.3}", capture_avg),
        format!("{:.3}", capture_p95),
        format!("{:.3}", encode_avg),
        format!("{:.3}", encode_p95),
        format!("{:.3}", send_avg),
        format!("{:.3}", send_p95),
        format!("{:.3}", recv_avg),
        format!("{:.3}", recv_p95),
        format!("{:.3}", decode_avg),
        format!("{:.3}", decode_p95_stage),
        format!("{:.3}", render_avg),
        format!("{:.3}", render_p95),
        format!("{:.3}", present_avg),
        format!("{:.3}", present_p95_stage),
        ft.to_string(),
        fr.to_string(),
        fd.to_string(),
        esc(reason),
    ]
    .join(",");
    writeln!(f, "{}", row).map_err(|e| format!("write row: {e}"))?;
    Ok(())
}
