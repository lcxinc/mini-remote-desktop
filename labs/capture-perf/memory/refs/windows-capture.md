---
name: windows-capture
description: High-performance screen capture library for Windows
type: reference
---

# windows-capture

## 项目信息

- **仓库**: https://github.com/DAEng0/windows-capture
- **语言**: Rust
- **用途**: 高性能 Windows 屏幕捕获库

## 特点

- 支持 Windows Graphics Capture API
- 支持窗口和显示器捕获
- 零拷贝内存访问
- 内置 DXGI 和 Direct3D 互操作

## 使用方式

```rust
use windows_capture::capture::GraphicsCaptureApiHandler;
use windows_capture::settings::Settings;

// 创建捕获设置
let settings = Settings::new(
    monitor,
    cursor_settings,
    color_format,
);

// 启动捕获
CaptureHandler::start(settings)?;
```

## 相关文件

- `rust/graphics-capture/Cargo.toml` - 依赖 windows-capture = "1.3"
- `rust/graphics-capture/src/main.rs` - 使用示例

## 性能特点

- 捕获时间: ~0.7-0.8ms
- 依赖显示器刷新率触发回调
- 内存开销相对较高 (~59MB)
