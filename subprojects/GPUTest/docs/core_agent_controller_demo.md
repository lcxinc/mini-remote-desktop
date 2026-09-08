# core-agent / core-controller Demo

## 目的
- 用统一脚本对 `core-agent` 和 `core-controller` 做单进程与多进程测试。
- 保留相同参数输入，便于对比模式差异。

## 脚本
- 路径: `scripts/core_agent_controller_demo.ps1`

## 运行方式
在 `J:\ProjectTest\GPUTest` 目录执行:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\core_agent_controller_demo.ps1 -Mode single
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\core_agent_controller_demo.ps1 -Mode multi
```

## 常用参数
- `-DurationSec 20`
- `-TargetFps 60`
- `-Width 1920`
- `-Height 1080`
- `-Capture desktop_dup`
- `-Encoder software`
- `-Decoder software`
- `-Transport quic`
- `-Render gpu_present`
- `-MatrixConfig config/matrix.windows.json`
- `-Visualize`
- `-AllowDebugCodecs`

示例:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\core_agent_controller_demo.ps1 `
  -Mode multi `
  -DurationSec 20 `
  -TargetFps 60 `
  -Width 1920 `
  -Height 1080 `
  -Capture desktop_dup `
  -Encoder software `
  -Decoder software `
  -Transport quic `
  -Render gpu_present `
  -Visualize
```

## 输出目录
- 自动生成到: `artifacts/demo/core_agent_controller_yyyyMMdd_HHmmss`
- 文件包含:
  - `run_meta.json`
  - `agent.single.json` / `controller.single.json`
  - 或 `agent.multi.json` / `controller.multi.json`
  - 多进程失败时可查看 `*.stderr.log`

## 说明
- `single` 模式: 顺序运行 `core-agent` 再运行 `core-controller`。
- `multi` 模式: 并发启动两个进程并等待结束，适合验证多进程调度与资源竞争行为。
- 开启 `-Visualize` 后会透传 `--visualize` 给 `core-agent/core-controller`，触发可视化探针窗口。
