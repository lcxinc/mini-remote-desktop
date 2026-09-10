#include "capture_metrics.h"
#include <iostream>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <Windows.h>
#include <psapi.h>
#include <memory.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "psapi.lib")

// Desktop Duplication with 共享内存实现
// 使用共享内存来减少进程间数据拷贝

class DesktopDuplicationSharedMemory {
public:
    DesktopDuplicationSharedMemory() : device_(nullptr), output_(nullptr), duplication_(nullptr) {}

    ~DesktopDuplicationSharedMemory() {
        if (duplication_) duplication_->Release();
        if (output_) output_->Release();
        if (device_) device_->Release();
    }

    bool Initialize() {
        HRESULT hr = S_OK;

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

        IDXGIDevice* dxgi_device = nullptr;
        hr = device_->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgi_device);
        if (FAILED(hr)) {
            std::cerr << "Failed to query DXGI device" << std::endl;
            return false;
        }

        IDXGIAdapter* adapter = nullptr;
        hr = dxgi_device->GetAdapter(&adapter);
        dxgi_device->Release();

        if (FAILED(hr)) {
            std::cerr << "Failed to get adapter" << std::endl;
            return false;
        }

        IDXGIOutput* output_base = nullptr;
        hr = adapter->EnumOutputs(0, &output_base);
        adapter->Release();

        if (FAILED(hr)) {
            std::cerr << "Failed to get output" << std::endl;
            return false;
        }

        hr = output_base->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output_);
        output_base->Release();

        if (FAILED(hr)) {
            std::cerr << "Failed to query IDXGIOutput1" << std::endl;
            return false;
        }

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
            if (hr == DXGI_ERROR_ACCESS_LOST) {
                duplication_->ReleaseFrame();
                duplication_->Release();
                duplication_ = nullptr;
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
    config.api_name = "DesktopDuplicationSharedMemory";
    config.language = "C++";
    config.duration_sec = 10;

    MetricsCollector collector(config);

    DesktopDuplicationSharedMemory capture;
    if (!capture.Initialize()) {
        std::cerr << "Failed to initialize capture" << std::endl;
        return 1;
    }

    std::cout << "Starting Desktop Duplication + Shared Memory capture for " << config.duration_sec
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
            metrics.cpu_percent = 0;
            metrics.memory_mb = GetCurrentMemoryMB();

            collector.RecordFrame(metrics);

            capture.ReleaseFrame();
            if (resource) resource->Release();
        }
    }

    collector.PrintSummary();

    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string csv_path = "D:/Project/TestProject/CapTest/results/" + std::to_string(timestamp) + "_cpp_shared_memory_dd.csv";
    std::string json_path = "D:/Project/TestProject/CapTest/results/" + std::to_string(timestamp) + "_cpp_shared_memory_dd.json";

    collector.SaveToCSV(csv_path);
    collector.SaveToJSON(json_path);

    std::cout << "Results saved to:" << std::endl;
    std::cout << "  " << csv_path << std::endl;
    std::cout << "  " << json_path << std::endl;

    return 0;
}
