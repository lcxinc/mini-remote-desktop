# Mini Remote Desktop

## UI design reference

The independent [Rdesk prototype](prototypes/rdesk/README.md) preserves the earlier mock interface.

## Rebuild Notice

This repository now uses a product-oriented mainline layout.

Current mainline roots:

- `apps/Rdesk`
- `apps/Rdesk-Server`
- `apps/realtime-server`
- `crates/*`
- `common-control-proto`
- `heartbeat-rs`
- `docs/`
- `tests/`
- `tools/`

Historical implementations, temporary scripts, captured outputs, and recovered reference material are moved under `junk/` so they no longer define the active architecture by accident.

极简高性能远程桌面方案 - 完全私有化部署

## 特点

- ✅ **极简架构** - 核心组件，可选数据库
- ✅ **高性能** - 原生 Rust 实现，硬件加速
- ✅ **P2P 连接** - 数据不经过服务器
- ✅ **多协议支持** - WebRTC、QUIC、WebTransport
- ✅ **完全私有** - 所有代码可控
- ✅ **跨平台** - Web、桌面、Qt 控制端

## 架构

```text
mini-remote-desktop/
├── apps/
│   ├── Rdesk/             # 桌面客户端产品主线
│   ├── mrd-service/       # 本机核心服务（会话编排主入口）
│   ├── Rdesk-Server/      # 后端产品主线
│   └── realtime-server/   # 实时侧车服务
├── crates/                # 新主线共享 Rust crates
├── common-control-proto/  # 仍在使用的共享控制协议
├── heartbeat-rs/          # 当前保留的心跳/发现服务
├── docs/                  # 设计与重建计划
├── tests/                 # 验证与回归测试
├── tools/                 # 外部工具与本地依赖
├── labs/                  # 验证性实验目录（待进一步收敛）
└── junk/                  # 历史实现、调试脚本、产物和参考代码
```

### 正在进行的架构迁移

仓库正在迁移到"薄壳 + 本机服务"架构：

- `Rdesk` → UI 壳（仅负责界面展示，通过 IPC 调用服务）
- `mrd-service` → 本机核心服务（会话编排的唯一入口）
- `mrd-application` → 应用层用例编排
- `mrd-session` → 会话领域模型
- `mrd-ipc` → 本机进程间通信协议

详细设计见：`docs/plans/2026-03-20-mrd-service-architecture-migration.md`

## Repository Status

This repository is mid-rebuild. Use the product mainline paths above when adding or restoring functionality.

Do not treat anything under `junk/` as the source of truth. It is retained only for:

- historical implementations
- debugging scripts and one-off experiments
- captured outputs and benchmark artifacts
- reference-only recovered code

`labs/` is reserved for validation-only projects such as `GPUTest`, but that part has not been fully restored yet.

## 文件结构

```text
mini-remote-desktop/
├── apps/
│   ├── Rdesk/             # 桌面客户端产品主线
│   ├── Rdesk-Server/      # 后端产品主线
│   └── realtime-server/   # 实时侧车服务
├── crates/                # 新主线共享 Rust crates
├── common-control-proto/  # 仍在使用的共享控制协议
├── heartbeat-rs/          # 当前保留的心跳/发现服务
├── docs/                  # 设计与重建计划
├── tests/                 # 验证与回归测试
├── tools/                 # 外部工具与本地依赖
├── labs/                  # 验证性实验目录（待进一步收敛）
└── junk/                  # 历史实现、调试脚本、产物和参考代码
```

## Legacy Notes

The sections below still contain useful historical implementation notes, but many of the old paths they mention have already been moved into `junk/`.

When rebuilding or extending the product, prefer the active mainline roots instead of the legacy paths described below.

## 技术栈

| 组件 | 技术 |
|------|------|
| 桌面客户端 | Tauri + React + Vite |
| 后端 API | FastAPI |
| 实时服务 | Rust + Axum/WebSocket |
| 共享能力 | Rust workspace crates |

## 设计与规划

- 主结构重建计划位于 `docs/plans/`
- 历史实现仅作参考，不应直接决定当前架构
- 当前仍保留 `heartbeat-rs` 和 `common-control-proto`，后续可继续收敛到 `crates/*`
