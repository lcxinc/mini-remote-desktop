# Windows屏幕捕获性能测试 - 设计文档

**日期:** 2026-04-30
**作者:** Claude
**状态:** 已批准

## 1. 概述

本项目旨在对比Windows不同屏幕捕获API的性能差异，使用C++和Rust两种语言实现并行测试，以获得全面的性能基准数据。

## 2. 目标

- 对比三种捕获方案的性能：Desktop Duplication API、Graphics Capture API、Desktop Duplication + 共享内存
- 使用C++和Rust两种语言实现，对比语言层面的差异
- 全屏捕获60秒，收集完整的性能指标

## 3. 项目结构

```
CapTest/
├── cpp/                          # C++ 实现
│   ├── src/
│   │   ├── desktop_duplication/      # Desktop Duplication API
│   │   ├── graphics_capture/         # Graphics Capture API
│   │   └── shared_memory_dd/         # DD + 共享内存
│   ├── include/
│   │   └── capture_metrics.h         # 统一的指标收集结构
│   ├── CMakeLists.txt
│   └── build.bat
│
├── rust/                         # Rust 实现
│   ├── desktop-duplication/           # Desktop Duplication API
│   ├── graphics-capture/              # Graphics Capture API
│   └── shared-memory-dd/              # DD + 共享内存
│
├── results/                      # 统一输出目录
│   └── {timestamp}/
│
├── scripts/
│   └── compare_results.py        # 结果对比脚本
│
└── README.md
```

## 4. 输出格式

### CSV 格式
```csv
timestamp,api,language,frame_number,capture_time_ms,total_time_ms,fps,cpu_percent,memory_mb
1714471200,DesktopDuplication,C++,1,2.34,1005.67,59.8,15.3,128.5
```

### JSON 格式
```json
{
  "test_config": {
    "api": "DesktopDuplication",
    "language": "C++",
    "duration_sec": 60,
    "resolution": "1920x1080"
  },
  "statistics": {
    "avg_capture_time_ms": 2.31,
    "min_capture_time_ms": 1.98,
    "max_capture_time_ms": 5.42,
    "p95_capture_time_ms": 3.12,
    "p99_capture_time_ms": 4.21,
    "avg_fps": 59.8,
    "avg_cpu_percent": 15.2,
    "avg_memory_mb": 128.6
  }
}
```

## 5. API实现要点

### Desktop Duplication API
- 使用 `IDXGIOutputDuplication` 接口
- 处理 `DXGI_ERROR_WAIT_TIMEOUT` 情况
- 处理帧更新和光标分离

### Graphics Capture API
- 使用 `Windows.Graphics.Capture` API
- C++通过 WRL，Rust通过 `windows-rs`
- 创建 `GraphicsCaptureItem` 和 `CaptureFramePool`

### Desktop Duplication + 共享内存
- 创建命名共享内存映射
- 生产者-消费者模式
- 使用事件同步

## 6. 性能测量方法

### 帧捕获时间
使用高精度时钟 (`std::chrono` / `std::time::Instant`) 测量单帧捕获耗时。

### CPU和内存使用率
- `GetProcessMemoryInfo()` 获取内存
- `Pdh` API 获取CPU使用率
- 采样频率：每秒1次

### 统计数据
- 平均值、最小值、最大值
- P95、P99 百分位数
- 实际帧率

## 7. 依赖

### C++
- d3d11.lib, dxgi.lib, dxguid.lib
- WindowsApp.lib (Graphics Capture API)

### Rust
- windows crate (Graphics Capture, DirectX)
- chrono, csv, serde_json

## 8. 测试配置

- 捕获区域：主显示器全屏
- 测试时长：60秒
- 预期帧数：约900-1800帧（取决于API性能）
- 输出：控制台实时显示 + 文件保存
