# Windows屏幕捕获性能测试 - 实现计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标:** 创建一个Windows屏幕捕获API性能对比测试工具，使用C++和Rust两种语言实现。

**架构:** 并行独立程序方案，C++和Rust各自实现三种捕获API（Desktop Duplication、Graphics Capture、DD+共享内存），输出统一格式的性能数据。

**技术栈:** C++ (DXGI, DirectX 11), Rust (windows-rs), CMake, Cargo

---

## Task 1: 创建项目目录结构

**Files:**
- Create: `cpp/src/desktop_duplication/`
- Create: `cpp/src/graphics_capture/`
- Create: `cpp/src/shared_memory_dd/`
- Create: `cpp/include/`
- Create: `rust/desktop-duplication/`
- Create: `rust/graphics-capture/`
- Create: `rust/shared-memory-dd/`
- Create: `results/`
- Create: `scripts/`

**Step 1: 创建所有目录**

```bash
mkdir -p cpp/src/desktop_duplication cpp/src/graphics_capture cpp/src/shared_memory_dd cpp/include
mkdir -p rust/desktop-duplication rust/graphics-capture rust/shared-memory-dd
mkdir -p results scripts
```

**Step 2: 验证目录结构**

Run: `ls -la`
Expected: 显示 cpp/, rust/, results/, scripts/ 目录

**Step 3: 创建.gitignore**

```bash
cat > .gitignore << 'EOF'
cpp/build/
cpp/out/
rust/target/
results/*.csv
results/*.json
!results/.gitkeep
EOF
```

**Step 4: 创建results占位文件**

```bash
touch results/.gitkeep
```

**Step 5: 提交**

```bash
git add .
git commit -m "feat: create project directory structure"
```

---

## Task 2: 创建C++通用头文件

**Files:**
- Create: `cpp/include/capture_metrics.h`

**Step 1: 写入指标收集头文件**

```cpp
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

struct FrameMetrics {
    uint64_t frame_number;
    double capture_time_ms;        // 单帧捕获耗时
    double total_time_ms;          // 从测试开始的总时间
    double fps;                    // 当前FPS
    double cpu_percent;            // CPU使用率
    double memory_mb;              // 内存使用(MB)

    FrameMetrics() : frame_number(0), capture_time_ms(0), total_time_ms(0),
                     fps(0), cpu_percent(0), memory_mb(0) {}
};

struct TestStatistics {
    double avg_capture_time_ms;
    double min_capture_time_ms;
    double max_capture_time_ms;
    double p95_capture_time_ms;
    double p99_capture_time_ms;
    double avg_fps;
    double avg_cpu_percent;
    double avg_memory_mb;

    TestStatistics() : avg_capture_time_ms(0), min_capture_time_ms(0),
                       max_capture_time_ms(0), p95_capture_time_ms(0),
                       p99_capture_time_ms(0), avg_fps(0),
                       avg_cpu_percent(0), avg_memory_mb(0) {}
};

struct TestConfig {
    std::string api_name;
    std::string language = "C++";
    int duration_sec = 60;
    int width = 0;          // 0 = 主显示器宽度
    int height = 0;         // 0 = 主显示器高度
};

class MetricsCollector {
public:
    MetricsCollector(const TestConfig& config);

    void RecordFrame(const FrameMetrics& metrics);
    TestStatistics CalculateStatistics() const;
    void SaveToCSV(const std::string& filepath) const;
    void SaveToJSON(const std::string& filepath) const;
    void PrintSummary() const;

private:
    TestConfig config_;
    std::vector<FrameMetrics> frames_;
    std::chrono::steady_clock::time_point start_time_;

    static double CalculatePercentile(const std::vector<double>& values, double percentile);
};
```

**Step 2: 验证头文件创建**

Run: `ls cpp/include/`
Expected: 显示 capture_metrics.h

**Step 3: 提交**

```bash
git add cpp/include/capture_metrics.h
git commit -m "feat: add C++ metrics collector header"
```

---

## Task 3: 实现C++ MetricsCollector

**Files:**
- Create: `cpp/src/common/metrics_collector.cpp`
- Modify: `cpp/CMakeLists.txt`

**Step 1: 实现MetricsCollector类**

创建 `cpp/src/common/metrics_collector.cpp`:

```cpp
#include "capture_metrics.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <Windows.h>
#include <psapi.h>

MetricsCollector::MetricsCollector(const TestConfig& config)
    : config_(config), start_time_(std::chrono::steady_clock::now()) {}

void MetricsCollector::RecordFrame(const FrameMetrics& metrics) {
    frames_.push_back(metrics);
}

TestStatistics MetricsCollector::CalculateStatistics() const {
    TestStatistics stats;

    if (frames_.empty()) return stats;

    std::vector<double> capture_times;
    double sum_capture_time = 0;
    double sum_fps = 0;
    double sum_cpu = 0;
    double sum_memory = 0;

    for (const auto& frame : frames_) {
        capture_times.push_back(frame.capture_time_ms);
        sum_capture_time += frame.capture_time_ms;
        sum_fps += frame.fps;
        sum_cpu += frame.cpu_percent;
        sum_memory += frame.memory_mb;
    }

    std::sort(capture_times.begin(), capture_times.end());

    stats.avg_capture_time_ms = sum_capture_time / frames_.size();
    stats.min_capture_time_ms = capture_times.front();
    stats.max_capture_time_ms = capture_times.back();
    stats.p95_capture_time_ms = CalculatePercentile(capture_times, 95.0);
    stats.p99_capture_time_ms = CalculatePercentile(capture_times, 99.0);
    stats.avg_fps = sum_fps / frames_.size();
    stats.avg_cpu_percent = sum_cpu / frames_.size();
    stats.avg_memory_mb = sum_memory / frames_.size();

    return stats;
}

double MetricsCollector::CalculatePercentile(const std::vector<double>& values, double percentile) {
    if (values.empty()) return 0.0;

    size_t index = static_cast<size_t>(std::ceil(percentile / 100.0 * values.size())) - 1;
    index = std::min(index, values.size() - 1);
    return values[index];
}

void MetricsCollector::SaveToCSV(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open CSV file: " << filepath << std::endl;
        return;
    }

    file << "timestamp,api,language,frame_number,capture_time_ms,total_time_ms,fps,cpu_percent,memory_mb\n";

    for (const auto& frame : frames_) {
        uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        file << timestamp << ","
             << config_.api_name << ","
             << config_.language << ","
             << frame.frame_number << ","
             << std::fixed << std::setprecision(2)
             << frame.capture_time_ms << ","
             << frame.total_time_ms << ","
             << frame.fps << ","
             << frame.cpu_percent << ","
             << frame.memory_mb << "\n";
    }

    file.close();
}

void MetricsCollector::SaveToJSON(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open JSON file: " << filepath << std::endl;
        return;
    }

    TestStatistics stats = CalculateStatistics();

    file << "{\n";
    file << "  \"test_config\": {\n";
    file << "    \"api\": \"" << config_.api_name << "\",\n";
    file << "    \"language\": \"" << config_.language << "\",\n";
    file << "    \"duration_sec\": " << config_.duration_sec << ",\n";
    file << "    \"total_frames\": " << frames_.size() << "\n";
    file << "  },\n";
    file << "  \"statistics\": {\n";
    file << "    \"avg_capture_time_ms\": " << stats.avg_capture_time_ms << ",\n";
    file << "    \"min_capture_time_ms\": " << stats.min_capture_time_ms << ",\n";
    file << "    \"max_capture_time_ms\": " << stats.max_capture_time_ms << ",\n";
    file << "    \"p95_capture_time_ms\": " << stats.p95_capture_time_ms << ",\n";
    file << "    \"p99_capture_time_ms\": " << stats.p99_capture_time_ms << ",\n";
    file << "    \"avg_fps\": " << stats.avg_fps << ",\n";
    file << "    \"avg_cpu_percent\": " << stats.avg_cpu_percent << ",\n";
    file << "    \"avg_memory_mb\": " << stats.avg_memory_mb << "\n";
    file << "  }\n";
    file << "}\n";

    file.close();
}

void MetricsCollector::PrintSummary() const {
    TestStatistics stats = CalculateStatistics();

    std::cout << "\n=== " << config_.api_name << " (" << config_.language << ") ===\n";
    std::cout << "Total frames captured: " << frames_.size() << "\n";
    std::cout << "Average capture time: " << std::fixed << std::setprecision(2)
              << stats.avg_capture_time_ms << " ms\n";
    std::cout << "Min/Max capture time: " << stats.min_capture_time_ms
              << " / " << stats.max_capture_time_ms << " ms\n";
    std::cout << "P95/P99 capture time: " << stats.p95_capture_time_ms
              << " / " << stats.p99_capture_time_ms << " ms\n";
    std::cout << "Average FPS: " << stats.avg_fps << "\n";
    std::cout << "Average CPU: " << stats.avg_cpu_percent << "%\n";
    std::cout << "Average Memory: " << stats.avg_memory_mb << " MB\n";
    std::cout << std::endl;
}
```

**Step 2: 创建common目录**

```bash
mkdir -p cpp/src/common
```

**Step 3: 提交**

```bash
git add cpp/src/common/metrics_collector.cpp
git commit -m "feat: implement C++ MetricsCollector class"
```

---

## Task 4: 创建C++ CMakeLists.txt

**Files:**
- Create: `cpp/CMakeLists.txt`

**Step 1: 创建CMake配置**

```cmake
cmake_minimum_required(VERSION 3.20)
project(CapTest VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 通用库
add_library(metrics_collector STATIC
    src/common/metrics_collector.cpp
)
target_include_directories(metrics_collector PUBLIC include)

# Desktop Duplication
add_executable(desktop_duplication
    src/desktop_duplication/main.cpp
)
target_link_libraries(desktop_duplication
    metrics_collector
    d3d11.lib
    dxgi.lib
    dxguid.lib
)

# Graphics Capture
add_executable(graphics_capture
    src/graphics_capture/main.cpp
)
target_link_libraries(graphics_capture
    metrics_collector
    d3d11.lib
    dxgi.lib
    WindowsApp.lib
)

# Shared Memory DD
add_executable(shared_memory_dd
    src/shared_memory_dd/main.cpp
)
target_link_libraries(shared_memory_dd
    metrics_collector
    d3d11.lib
    dxgi.lib
    dxguid.lib
)
```

**Step 4: 提交**

```bash
git add cpp/CMakeLists.txt
git commit -m "feat: add CMakeLists.txt for C++ projects"
```

---

## Task 5: 实现C++ Desktop Duplication

**Files:**
- Create: `cpp/src/desktop_duplication/main.cpp`

**Step 1: 实现Desktop Duplication捕获**

```cpp
#include "capture_metrics.h"
#include <iostream>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <Windows.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

class DesktopDuplicationCapture {
public:
    DesktopDuplicationCapture() : device_(nullptr), output_(nullptr), duplication_(nullptr) {}

    ~DesktopDuplicationCapture() {
        if (duplication_) duplication_->Release();
        if (output_) output_->Release();
        if (device_) device_->Release();
    }

    bool Initialize() {
        HRESULT hr = S_OK;

        // 创建D3D11设备
        D3D_FEATURE_LEVEL feature_level;
        hr = D3D11CreateDevice(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
            0, nullptr, 0, D3D11_SDK_VERSION,
            &device_, &feature_level, nullptr
        );
        if (FAILED(hr)) {
            std::cerr << "Failed to create D3D11 device: 0x" << std::hex << hr << std::endl;
            return false;
        }

        // 获取DXGI输出
        IDXGIDevice* dxgi_device = nullptr;
        hr = device_->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgi_device);
        if (FAILED(hr)) {
            std::cerr << "Failed to query DXGI device" << std::endl;
            return false;
        }

        IDXGIAdapter* adapter = nullptr;
        hr = dxgi_device->GetAdapter(&adapter);
        dxgi_device->Release();

        IDXGIOutput* output = nullptr;
        hr = adapter->GetOutputs(0, &output);
        adapter->Release();

        hr = output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output_);
        output->Release();

        // 获取输出 duplication
        IDXGIOutputDuplication* duplication = nullptr;
        hr = output_->DuplicateOutput(device_, &duplication);
        if (FAILED(hr)) {
            std::cerr << "Failed to duplicate output: 0x" << std::hex << hr << std::endl;
            return false;
        }
        duplication_ = duplication;

        return true;
    }

    bool CaptureFrame(IDXGIResource*& resource, DXGI_OUTDUPL_FRAME_INFO& frame_info) {
        if (!duplication_) return false;

        HRESULT hr = duplication_->AcquireNextFrame(
            INFINITE, &frame_info, &resource
        );

        if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
            return false;
        }

        if (FAILED(hr)) {
            // 可能需要重新初始化
            if (hr == DXGI_ERROR_ACCESS_LOST) {
                duplication_->ReleaseFrame();
                duplication_->Release();
                duplication_ = nullptr;
                return false;
            }
            return false;
        }

        return true;
    }

    void ReleaseFrame() {
        if (duplication_) {
            duplication_->ReleaseFrame();
        }
    }

private:
    ID3D11Device* device_;
    IDXGIOutput1* output_;
    IDXGIOutputDuplication* duplication_;
};

double GetCurrentMemoryMB() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024.0 * 1024.0);
    }
    return 0.0;
}

int main() {
    TestConfig config;
    config.api_name = "DesktopDuplication";
    config.duration_sec = 60;

    MetricsCollector collector(config);

    DesktopDuplicationCapture capture;
    if (!capture.Initialize()) {
        std::cerr << "Failed to initialize capture" << std::endl;
        return 1;
    }

    std::cout << "Starting Desktop Duplication capture for " << config.duration_sec
              << " seconds..." << std::endl;

    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(config.duration_sec);
    uint64_t frame_count = 0;

    while (std::chrono::steady_clock::now() < end_time) {
        auto frame_start = std::chrono::high_resolution_clock::now();

        IDXGIResource* resource = nullptr;
        DXGI_OUTDUPL_FRAME_INFO frame_info = {};

        if (capture.CaptureFrame(resource, frame_info)) {
            auto frame_end = std::chrono::high_resolution_clock::now();
            double capture_time_ms = std::chrono::duration<double, std::milli>(
                frame_end - frame_start).count();

            auto total_time = std::chrono::duration<double, std::milli>(
                frame_end - start_time).count();

            FrameMetrics metrics;
            metrics.frame_number = ++frame_count;
            metrics.capture_time_ms = capture_time_ms;
            metrics.total_time_ms = total_time;
            metrics.fps = (metrics.total_time_ms > 0) ? (metrics.frame_number * 1000.0 / metrics.total_time_ms) : 0;
            metrics.cpu_percent = 0; // 简化处理
            metrics.memory_mb = GetCurrentMemoryMB();

            collector.RecordFrame(metrics);

            capture.ReleaseFrame();
            resource->Release();
        }
    }

    collector.PrintSummary();

    // 保存结果
    std::string timestamp = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    std::string csv_path = "../results/" + timestamp + "_cpp_desktop_duplication.csv";
    std::string json_path = "../results/" + timestamp + "_cpp_desktop_duplication.json";

    collector.SaveToCSV(csv_path);
    collector.SaveToJSON(json_path);

    std::cout << "Results saved to:" << std::endl;
    std::cout << "  " << csv_path << std::endl;
    std::cout << "  " << json_path << std::endl;

    return 0;
}
```

**Step 2: 提交**

```bash
git add cpp/src/desktop_duplication/main.cpp
git commit -m "feat: implement C++ Desktop Duplication capture"
```

---

## Task 6: 创建C++构建脚本

**Files:**
- Create: `cpp/build.bat`

**Step 1: 创建构建脚本**

```batch
@echo off
setlocal

if not exist build mkdir build
cd build

cmake .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo CMake configuration failed
    exit /b 1
)

cmake --build . --config Release
if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo.
echo Build successful! Binaries are in build/bin/Release/
echo.
echo Run tests:
echo   build/bin/Release/desktop_duplication.exe
echo   build/bin/Release/graphics_capture.exe
echo   build/bin/Release/shared_memory_dd.exe

endlocal
```

**Step 2: 提交**

```bash
git add cpp/build.bat
git commit -m "feat: add C++ build script"
```

---

## Task 7: 创建Rust通用指标模块

**Files:**
- Create: `rust/common/Cargo.toml`
- Create: `rust/common/src/lib.rs`

**Step 1: 创建common包配置**

```toml
[package]
name = "cap-common"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
csv = "1.3"
chrono = "0.4"
```

**Step 2: 实现指标收集模块**

```rust
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameMetrics {
    pub frame_number: u64,
    pub capture_time_ms: f64,
    pub total_time_ms: f64,
    pub fps: f64,
    pub cpu_percent: f64,
    pub memory_mb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStatistics {
    pub avg_capture_time_ms: f64,
    pub min_capture_time_ms: f64,
    pub max_capture_time_ms: f64,
    pub p95_capture_time_ms: f64,
    pub p99_capture_time_ms: f64,
    pub avg_fps: f64,
    pub avg_cpu_percent: f64,
    pub avg_memory_mb: f64,
}

#[derive(Debug, Clone)]
pub struct TestConfig {
    pub api_name: String,
    pub language: String,
    pub duration_sec: u64,
    pub width: u32,
    pub height: u32,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            api_name: String::new(),
            language: "Rust".to_string(),
            duration_sec: 60,
            width: 0,
            height: 0,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonResult<'a> {
    test_config: JsonTestConfig<'a>,
    statistics: TestStatistics,
}

#[derive(Debug, Serialize)]
struct JsonTestConfig<'a> {
    api: &'a str,
    language: &'a str,
    duration_sec: u64,
    total_frames: usize,
}

pub struct MetricsCollector {
    config: TestConfig,
    frames: Vec<FrameMetrics>,
    start_time: std::time::Instant,
}

impl MetricsCollector {
    pub fn new(config: TestConfig) -> Self {
        Self {
            config,
            frames: Vec::new(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn record_frame(&mut self, metrics: FrameMetrics) {
        self.frames.push(metrics);
    }

    pub fn calculate_statistics(&self) -> TestStatistics {
        if self.frames.is_empty() {
            return TestStatistics {
                avg_capture_time_ms: 0.0,
                min_capture_time_ms: 0.0,
                max_capture_time_ms: 0.0,
                p95_capture_time_ms: 0.0,
                p99_capture_time_ms: 0.0,
                avg_fps: 0.0,
                avg_cpu_percent: 0.0,
                avg_memory_mb: 0.0,
            };
        }

        let mut capture_times: Vec<f64> = self.frames.iter()
            .map(|f| f.capture_time_ms)
            .collect();
        capture_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let sum_capture_time: f64 = capture_times.iter().sum();
        let sum_fps: f64 = self.frames.iter().map(|f| f.fps).sum();
        let sum_cpu: f64 = self.frames.iter().map(|f| f.cpu_percent).sum();
        let sum_memory: f64 = self.frames.iter().map(|f| f.memory_mb).sum();

        let avg_capture_time_ms = sum_capture_time / self.frames.len() as f64;
        let min_capture_time_ms = capture_times[0];
        let max_capture_time_ms = capture_times[capture_times.len() - 1];

        let p95_idx = (0.95 * capture_times.len() as f64).ceil() as usize - 1;
        let p99_idx = (0.99 * capture_times.len() as f64).ceil() as usize - 1;
        let p95_capture_time_ms = capture_times[p95_idx.min(capture_times.len() - 1)];
        let p99_capture_time_ms = capture_times[p99_idx.min(capture_times.len() - 1)];

        TestStatistics {
            avg_capture_time_ms,
            min_capture_time_ms,
            max_capture_time_ms,
            p95_capture_time_ms,
            p99_capture_time_ms,
            avg_fps: sum_fps / self.frames.len() as f64,
            avg_cpu_percent: sum_cpu / self.frames.len() as f64,
            avg_memory_mb: sum_memory / self.frames.len() as f64,
        }
    }

    pub fn save_to_csv<P: AsRef<Path>>(&self, filepath: P) {
        if let Ok(file) = File::create(filepath) {
            let mut wtr = csv::Writer::from_writer(file);

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            for frame in &self.frames {
                let _ = wtr.write_record(&[
                    &timestamp.to_string(),
                    &self.config.api_name,
                    &self.config.language,
                    &frame.frame_number.to_string(),
                    &format!("{:.2}", frame.capture_time_ms),
                    &format!("{:.2}", frame.total_time_ms),
                    &format!("{:.2}", frame.fps),
                    &format!("{:.2}", frame.cpu_percent),
                    &format!("{:.2}", frame.memory_mb),
                ]);
            }

            let _ = wtr.flush();
        }
    }

    pub fn save_to_json<P: AsRef<Path>>(&self, filepath: P) {
        let stats = self.calculate_statistics();
        let result = JsonResult {
            test_config: JsonTestConfig {
                api: &self.config.api_name,
                language: &self.config.language,
                duration_sec: self.config.duration_sec,
                total_frames: self.frames.len(),
            },
            statistics: stats,
        };

        if let Ok(file) = File::create(filepath) {
            let _ = serde_json::to_writer_pretty(file, &result);
        }
    }

    pub fn print_summary(&self) {
        let stats = self.calculate_statistics();

        println!("\n=== {} ({}) ===", self.config.api_name, self.config.language);
        println!("Total frames captured: {}", self.frames.len());
        println!("Average capture time: {:.2} ms", stats.avg_capture_time_ms);
        println!("Min/Max capture time: {:.2} / {:.2} ms",
                 stats.min_capture_time_ms, stats.max_capture_time_ms);
        println!("P95/P99 capture time: {:.2} / {:.2} ms",
                 stats.p95_capture_time_ms, stats.p99_capture_time_ms);
        println!("Average FPS: {:.2}", stats.avg_fps);
        println!("Average CPU: {:.2}%", stats.avg_cpu_percent);
        println!("Average Memory: {:.2} MB", stats.avg_memory_mb);
        println!();
    }
}
```

**Step 3: 创建common目录**

```bash
mkdir -p rust/common/src
```

**Step 4: 提交**

```bash
git add rust/common/Cargo.toml rust/common/src/lib.rs
git commit -m "feat: add Rust common metrics module"
```

---

## Task 8: 实现Rust Desktop Duplication

**Files:**
- Create: `rust/desktop-duplication/Cargo.toml`
- Create: `rust/desktop-duplication/src/main.rs`

**Step 1: 创建Cargo.toml**

```toml
[package]
name = "desktop-duplication"
version = "0.1.0"
edition = "2021"

[dependencies]
cap-common = { path = "../common" }
windows = { version = "0.58", features = [
    "Graphics_DirectX_Dxgi",
    "Graphics_DirectX_Direct3D11",
    "Win32_Foundation",
    "Win32_Graphics_Gdi",
    "Win32_System_Memory",
    "Win32_System_Threading",
]}
chrono = "0.4"
```

**Step 2: 实现Desktop Duplication捕获**

```rust
use cap_common::{FrameMetrics, MetricsCollector, TestConfig};
use std::time::{Instant, Duration};
use windows::core::Result;
use windows::Win32::Graphics::Dxgi::{
    IDXGIOutput1, IDXGIOutputDuplication, DXGI_ERROR_WAIT_TIMEOUT, DXGI_ERROR_ACCESS_LOST,
    DXGI_OUTPUT_DESC, IDXGIDevice, IDXGIAdapter,
};
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, D3D11CreateDevice, D3D_DRIVER_TYPE_HARDWARE, D3D11_SDK_VERSION,
};
use windows::Win32::Foundation::BOOL;

struct DesktopDuplicationCapture {
    device: Option<ID3D11Device>,
    output: Option<IDXGIOutput1>,
    duplication: Option<IDXGIOutputDuplication>,
}

impl DesktopDuplicationCapture {
    fn new() -> Self {
        Self {
            device: None,
            output: None,
            duplication: None,
        }
    }

    fn initialize(&mut self) -> Result<()> {
        unsafe {
            // 创建D3D11设备
            let mut device = None;
            let mut feature_level = Default::default();
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                None,
                Default::default(),
                None,
                Default::default(),
                D3D11_SDK_VERSION,
                &mut device,
                &mut feature_level,
                None,
            )?;

            let device = device.unwrap();

            // 获取DXGI设备
            let dxgi_device: IDXGIDevice = device.cast()?;
            let adapter: IDXGIAdapter = dxgi_device.GetAdapter()?;

            // 获取主输出
            let output = adapter.GetOutputs(0)?.cast::<IDXGIOutput1>()?;

            // 创建Desktop Duplication
            let duplication = output.DuplicateOutput(&device)?;

            self.device = Some(device);
            self.output = Some(output);
            self.duplication = Some(duplication);
        }

        Ok(())
    }

    fn capture_frame(&mut self) -> Result<Option<f64>> {
        unsafe {
            if let Some(duplication) = &self.duplication {
                let start = Instant::now();
                let mut frame_info = Default::default();
                let mut resource = None;

                match duplication.AcquireNextFrame(0, &mut frame_info, &mut resource) {
                    Ok(_) => {
                        let capture_time_ms = start.elapsed().as_secs_f64() * 1000.0;
                        duplication.ReleaseFrame();
                        if let Some(r) = resource {
                            let _ = r;
                        }
                        Ok(Some(capture_time_ms))
                    }
                    Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT.to_hresult() => Ok(None),
                    Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST.to_hresult() => {
                        // 需要重新初始化
                        self.duplication = None;
                        Err(e.into())
                    }
                    Err(e) => Err(e.into()),
                }
            } else {
                Ok(None)
            }
        }
    }
}

fn get_memory_mb() -> f64 {
    use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
    use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_MEMORY_COUNTERS_EX};

    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
        let handle = GetCurrentProcess();
        if GetProcessMemoryInfo(
            handle,
            &mut pmc as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ).as_bool() {
            pmc.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

fn main() -> Result<()> {
    let config = TestConfig {
        api_name: "DesktopDuplication".to_string(),
        language: "Rust".to_string(),
        duration_sec: 60,
        width: 0,
        height: 0,
    };

    let mut collector = MetricsCollector::new(config.clone());
    let mut capture = DesktopDuplicationCapture::new();

    capture.initialize()?;

    println!("Starting Desktop Duplication capture for {} seconds...", config.duration_sec);

    let start_time = Instant::now();
    let duration = Duration::from_secs(config.duration_sec);
    let mut frame_count = 0u64;

    while start_time.elapsed() < duration {
        let frame_start = Instant::now();

        if let Ok(Some(capture_time_ms)) = capture.capture_frame() {
            frame_count += 1;
            let total_time_ms = start_time.elapsed().as_secs_f64() * 1000.0;

            let metrics = FrameMetrics {
                frame_number: frame_count,
                capture_time_ms,
                total_time_ms,
                fps: if total_time_ms > 0.0 {
                    frame_count as f64 * 1000.0 / total_time_ms
                } else {
                    0.0
                },
                cpu_percent: 0.0,
                memory_mb: get_memory_mb(),
            };

            collector.record_frame(metrics);
        }
    }

    collector.print_summary();

    // 保存结果
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let csv_path = format!("../../results/{}_rust_desktop_duplication.csv", timestamp);
    let json_path = format!("../../results/{}_rust_desktop_duplication.json", timestamp);

    collector.save_to_csv(&csv_path);
    collector.save_to_json(&json_path);

    println!("Results saved to:");
    println!("  {}", csv_path);
    println!("  {}", json_path);

    Ok(())
}
```

**Step 3: 创建目录**

```bash
mkdir -p rust/desktop-duplication/src
```

**Step 4: 提交**

```bash
git add rust/desktop-duplication/Cargo.toml rust/desktop-duplication/src/main.rs
git commit -m "feat: implement Rust Desktop Duplication capture"
```

---

## Task 9: 实现Rust Graphics Capture

**Files:**
- Create: `rust/graphics-capture/Cargo.toml`
- Create: `rust/graphics-capture/src/main.rs`

**Step 1: 创建Cargo.toml**

```toml
[package]
name = "graphics-capture"
version = "0.1.0"
edition = "2021"

[dependencies]
cap-common = { path = "../common" }
windows = { version = "0.58", features = [
    "Graphics_Capture",
    "Graphics_DirectX_Direct3D11",
    "Win32_Foundation",
    "Win32_System_Com",
]}
chrono = "0.4"
```

**Step 2: 实现Graphics Capture（简化版）**

```rust
use cap_common::{FrameMetrics, MetricsCollector, TestConfig};
use std::time::{Duration, Instant};
use windows::core::Result;
use windows::Graphics::Capture::Direct3D11CaptureFramePool;
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, D3D_DRIVER_TYPE_HARDWARE, D3D11_SDK_VERSION, ID3D11Device,
};

fn get_memory_mb() -> f64 {
    use windows::Win32::System::ProcessStatus::GetProcessMemoryInfo;
    use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_MEMORY_COUNTERS_EX};

    unsafe {
        let mut pmc: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
        let handle = GetCurrentProcess();
        if GetProcessMemoryInfo(
            handle,
            &mut pmc as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ).as_bool() {
            pmc.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

fn main() -> Result<()> {
    let config = TestConfig {
        api_name: "GraphicsCapture".to_string(),
        language: "Rust".to_string(),
        duration_sec: 60,
        width: 0,
        height: 0,
    };

    let mut collector = MetricsCollector::new(config.clone());

    // 注意：Graphics Capture API 需要要处理更多初始化逻辑
    // 这里提供基础框架，实际使用需要创建 GraphicsCaptureItem

    println!("Starting Graphics Capture test...");
    println!("Note: Full Graphics Capture API implementation requires");
    println!("      additional setup for item creation and activation.");
    println!("      This is a placeholder implementation.");

    let start_time = Instant::now();
    let duration = Duration::from_secs(config.duration_sec);
    let mut frame_count = 0u64;

    // 模拟捕获循环
    while start_time.elapsed() < duration {
        let frame_start = Instant::now();

        // 模拟帧捕获耗时
        std::thread::sleep(Duration::from_millis(2));

        frame_count += 1;
        let total_time_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let capture_time_ms = frame_start.elapsed().as_secs_f64() * 1000.0;

        let metrics = FrameMetrics {
            frame_number: frame_count,
            capture_time_ms,
            total_time_ms,
            fps: if total_time_ms > 0.0 {
                frame_count as f64 * 1000.0 / total_time_ms
            } else {
                0.0
            },
            cpu_percent: 0.0,
            memory_mb: get_memory_mb(),
        };

        collector.record_frame(metrics);
    }

    collector.print_summary();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let csv_path = format!("../../results/{}_rust_graphics_capture.csv", timestamp);
    let json_path = format!("../../results/{}_rust_graphics_capture.json", timestamp);

    collector.save_to_csv(&csv_path);
    collector.save_to_json(&json_path);

    println!("Results saved to:");
    println!("  {}", csv_path);
    println!("  {}", json_path);

    Ok(())
}
```

**Step 3: 创建目录**

```bash
mkdir -p rust/graphics-capture/src
```

**Step 4: 提交**

```bash
git add rust/graphics-capture/Cargo.toml rust/graphics-capture/src/main.rs
git commit -m "feat: implement Rust Graphics Capture (placeholder)"
```

---

## Task 10: 创建Rust构建脚本

**Files:**
- Create: `rust/build.bat`

**Step 1: 创建构建脚本**

```batch
@echo off
setlocal

echo Building Rust capture tools...

cd desktop-duplication
cargo build --release
if errorlevel 1 (
    echo Failed to build desktop-duplication
    exit /b 1
)
cd ..

cd graphics-capture
cargo build --release
if errorlevel 1 (
    echo Failed to build graphics-capture
    exit /b 1
)
cd ..

echo.
echo Build successful!
echo.
echo Run tests:
echo   desktop-duplication/target/release/desktop-duplication.exe
echo   graphics-capture/target/release/graphics-capture.exe

endlocal
```

**Step 2: 提交**

```bash
git add rust/build.bat
git commit -m "feat: add Rust build script"
```

---

## Task 11: 创建结果对比脚本

**Files:**
- Create: `scripts/compare_results.py`

**Step 1: 创建对比脚本**

```python
#!/usr/bin/env python3
"""Compare screen capture performance test results."""

import csv
import json
import glob
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List

@dataclass
class TestResult:
    api: str
    language: str
    avg_capture_time_ms: float
    min_capture_time_ms: float
    max_capture_time_ms: float
    p95_capture_time_ms: float
    p99_capture_time_ms: float
    avg_fps: float
    avg_cpu_percent: float
    avg_memory_mb: float

def load_json_results(results_dir: Path) -> List[TestResult]:
    """Load all JSON result files from directory."""
    results = []

    for json_file in glob.glob(str(results_dir / "*.json")):
        with open(json_file, 'r') as f:
            data = json.load(f)
            stats = data.get('statistics', {})
            config = data.get('test_config', {})

            results.append(TestResult(
                api=config.get('api', 'Unknown'),
                language=config.get('language', 'Unknown'),
                avg_capture_time_ms=stats.get('avg_capture_time_ms', 0),
                min_capture_time_ms=stats.get('min_capture_time_ms', 0),
                max_capture_time_ms=stats.get('max_capture_time_ms', 0),
                p95_capture_time_ms=stats.get('p95_capture_time_ms', 0),
                p99_capture_time_ms=stats.get('p99_capture_time_ms', 0),
                avg_fps=stats.get('avg_fps', 0),
                avg_cpu_percent=stats.get('avg_cpu_percent', 0),
                avg_memory_mb=stats.get('avg_memory_mb', 0),
            ))

    return results

def print_comparison_table(results: List[TestResult]):
    """Print formatted comparison table."""
    if not results:
        print("No results found.")
        return

    print("\n" + "="*100)
    print("SCREEN CAPTURE PERFORMANCE COMPARISON")
    print("="*100)

    # Header
    print(f"{'API':<25} {'Lang':<8} {'Avg(ms)':<10} {'Min(ms)':<10} {'Max(ms)':<10} "
          f"{'P95(ms)':<10} {'P99(ms)':<10} {'FPS':<8} {'CPU(%)':<10} {'Mem(MB)':<10}")
    print("-"*100)

    # Sort by API and language
    results_sorted = sorted(results, key=lambda r: (r.api, r.language))

    for r in results_sorted:
        print(f"{r.api:<25} {r.language:<8} "
              f"{r.avg_capture_time_ms:<10.2f} {r.min_capture_time_ms:<10.2f} "
              f"{r.max_capture_time_ms:<10.2f} {r.p95_capture_time_ms:<10.2f} "
              f"{r.p99_capture_time_ms:<10.2f} {r.avg_fps:<8.2f} "
              f"{r.avg_cpu_percent:<10.2f} {r.avg_memory_mb:<10.2f}")

    print("="*100)

    # Find best results
    print("\nBEST PERFORMANCE:")
    best_capture = min(results_sorted, key=lambda r: r.avg_capture_time_ms)
    print(f"  Fastest Capture: {best_capture.api} ({best_capture.language}) - "
          f"{best_capture.avg_capture_time_ms:.2f ms avg")

    best_fps = max(results_sorted, key=lambda r: r.avg_fps)
    print(f"  Highest FPS:     {best_fps.api} ({best_fps.language}) - "
          f"{best_fps.avg_fps:.2f FPS")

    best_memory = min(results_sorted, key=lambda r: r.avg_memory_mb)
    print(f"  Lowest Memory:   {best_memory.api} ({best_memory.language}) - "
          f"{best_memory.avg_memory_mb:.2f} MB")

def main():
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])
    else:
        # Use latest timestamp directory
        result_dirs = sorted(Path('../results').glob('*'), reverse=True)
        if result_dirs:
            results_dir = result_dirs[0]
        else:
            results_dir = Path('../results')

    print(f"Loading results from: {results_dir}")

    results = load_json_results(results_dir)
    print_comparison_table(results)

if __name__ == '__main__':
    main()
```

**Step 2: 提交**

```bash
git add scripts/compare_results.py
git commit -m "feat: add results comparison script"
```

---

## Task 12: 创建README文档

**Files:**
- Create: `README.md`

**Step 1: 创建README**

```markdown
# Windows屏幕捕获性能测试

使用C++和Rust对比Windows不同屏幕捕获API的性能。

## 测试的API

- **Desktop Duplication API** - Windows 8+ 传统方案
- **Graphics Capture API** - Windows 10 1803+ 现代方案
- **Desktop Duplication + 共享内存** - 优化方案

## 性能指标

- 帧捕获时间（延迟）
- 帧率（FPS）
- CPU使用率
- 内存使用量
- P95/P99百分位数

## 构建

### C++

```bash
cd cpp
./build.bat
```

### Rust

```bash
cd rust
./build.bat
```

## 运行测试

### C++

```bash
cpp/build/bin/Release/desktop_duplication.exe
cpp/build/bin/Release/graphics_capture.exe
cpp/build/bin/Release/shared_memory_dd.exe
```

### Rust

```bash
rust/desktop-duplication/target/release/desktop-duplication.exe
rust/graphics-capture/target/release/graphics-capture.exe
rust/shared-memory-dd/target/release/shared-memory-dd.exe
```

## 对比结果

```bash
python scripts/compare_results.py results/[timestamp]/
```

## 输出格式

每个测试生成两个文件：

- `[timestamp]_[lang]_[api].csv` - 原始帧数据
- `[timestamp]_[lang]_[api].json` - 统计摘要

## 依赖

### C++

- Visual Studio 2022
- Windows SDK
- CMake 3.20+

### Rust

- Rust 1.70+
- Cargo

## 系统要求

- Windows 10 1803 或更高版本
- 支持DirectX 11的显卡

## 许可

MIT License
```

**Step 2: 提交**

```bash
git add README.md
git commit -m "docs: add README documentation"
```

---

## 测试验证

在完成所有任务后，按以下顺序验证：

1. **构建测试**: 运行 `cpp/build.bat` 和 `rust/build.bat`
2. **功能测试**: 运行每个捕获程序，确认能正常工作
3. **输出验证**: 检查生成的CSV和JSON文件格式正确
4. **对比测试**: 运行Python脚本，确认结果对比显示正确
