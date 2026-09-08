# core-agent / core-controller Matrix Compare

## 目的
- 从 `matrix config` 抽样链路，自动跑同一链路的 `single` 与 `multi`。
- 输出对照结果（CSV/JSON），用于观察多进程相对单进程的指标偏移。

## 脚本
- 路径: `scripts/core_agent_controller_matrix_compare.ps1`

## 用法
在 `J:\ProjectTest\GPUTest` 执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\core_agent_controller_matrix_compare.ps1 `
  -MatrixConfig config/matrix.windows.json `
  -SampleCount 5 `
  -DurationSec 5 `
  -TargetFps 60 `
  -Width 1920 `
  -Height 1080 `
  -Capture desktop_dup `
  -Transport quic `
  -Render gpu_present `
  -Visualize
```

## 输出
- 目录: `artifacts/demo/core_agent_controller_matrix_compare_yyyyMMdd_HHmmss_fff_xxx`
- 文件:
  - `matrix_compare_rows.json`
  - `matrix_compare.csv`
  - `summary.json`

## 说明
- 抽样来源为 `valid_paths`，默认会屏蔽 `raw_bgra/lz4` 这类 debug-only 编解码。
- 每条链路会生成 2 行结果（`agent`、`controller`）。
- 开启 `-Visualize` 后会透传给 demo，触发可视化探针窗口。
- 关键对照字段：
  - `delta_e2e_p50_ms / delta_e2e_p95_ms / delta_e2e_p99_ms`（multi - single）
  - `delta_fps`
  - `delta_bitrate_avg_mbps`
