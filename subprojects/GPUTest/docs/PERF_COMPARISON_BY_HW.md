# Performance Comparison By CPU+GPU

Last update: 2026-03-06
Scope: `J:/ProjectTest/GPUTest`

## 1) Hardware Profile

| profile_id | os | cpu | gpu |
|---|---|---|---|
| win11_i5-14600kf_rtx5060ti | Windows 11 10.0.26300 x64 | Intel Core i5-14600KF (14C/20T) | NVIDIA GeForce RTX 5060 Ti |

## 2) Test Cases (10s)

| case_id | capture | encoder | transport | decoder | resolution | fps | visible_output |
|---|---|---|---|---|---|---|---|
| hwchain_udp_10s_1080p60 | synthetic_capture | gpu_proto | udp | gpu_proto | 1920x1080 | 60 | no |
| hwchain_quic_10s_1080p60 | synthetic_capture | gpu_proto | quic | gpu_proto | 1920x1080 | 60 | no |
| desktop_zero_copy_poc_10s | desktop_dup | raw_copy | local | raw_copy | desktop_native | unlocked | yes |

Note:
- `core-pipeline-*` currently uses synthetic stage timing in executor (for matrix stability and protocol tests).
- `desktop_zero_copy_poc` is the current visible capture/render validation in this repo.

## 3) Measured Results

### 3.1 Full pipeline (udp/quic)

Source: `artifacts/core_metrics_hw_10s.csv`

| case_id | status | frames_total | frames_received | dropped | e2e_p50_ms | e2e_p95_ms | e2e_p99_ms | present_call_p95_ms | decode_p95_ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| hwchain_udp_10s_1080p60 | PASS | 601 | 601 | 0 | 0.613 | 0.655 | 0.688 | 0.060 | 0.120 |
| hwchain_quic_10s_1080p60 | PASS | 601 | 601 | 0 | 0.728 | 0.817 | 0.867 | 0.060 | 0.120 |

### 3.2 Visible capture/render

Source: `artifacts/desktop_zero_copy_poc.10s.display.log`

| case_id | duration_s | fps | copy_hit_pct | avg_copy_ms | avg_present_ms | frames | copied_frames |
|---|---:|---:|---:|---:|---:|---:|---:|
| desktop_zero_copy_poc_10s | 10 | 5691.65 | 3.1 | 0.083 | 0.047 | 56917 | 1790 |

## 4) Repro Commands

```powershell
cd J:\ProjectTest\GPUTest

$env:POC_DURATION_SEC='10'
cargo run --bin desktop-zero-copy-poc 2>&1 | Tee-Object -FilePath artifacts/desktop_zero_copy_poc.10s.display.log

cargo run --bin core-pipeline-udp -- --duration-sec 10 --width 1920 --height 1080 --target-fps 60 --csv artifacts/core_metrics_hw_10s.csv --run-id hwchain_udp_10s_1080p60
cargo run --bin core-pipeline-quic -- --duration-sec 10 --width 1920 --height 1080 --target-fps 60 --csv artifacts/core_metrics_hw_10s.csv --run-id hwchain_quic_10s_1080p60
```

## 5) Extension Template (add more CPU/GPU rows)

Duplicate section 1 and section 3 for each machine profile, keeping the same case_id naming.
Suggested profile_id format:

`<os>_<cpu_model>_<gpu_model>`
