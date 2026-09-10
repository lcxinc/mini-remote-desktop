#include "../include/window.h"
#ifdef USE_D3D12
#include "../include/d3d12_renderer.h"
#else
#include "../include/d3d11_renderer.h"
#endif
#include "../include/capture_sources.h"
#include "../include/capture_render_metrics.h"
#include "../include/viewer_options.h"

#include <windows.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

namespace {

using HighResClock = std::chrono::high_resolution_clock;
using SteadyClock = std::chrono::steady_clock;

double ElapsedMs(HighResClock::time_point start, HighResClock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::filesystem::path ExeDirectory() {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) {
        return std::filesystem::current_path();
    }

    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

std::filesystem::path FindResultsDirectory() {
    std::vector<std::filesystem::path> starts = {
        std::filesystem::current_path(),
        ExeDirectory(),
    };

    for (const auto& start : starts) {
        std::filesystem::path current = start;
        for (int i = 0; i < 8 && !current.empty(); ++i) {
            std::filesystem::path candidate = current / "results";
            if (std::filesystem::exists(candidate) && std::filesystem::is_directory(candidate)) {
                return candidate;
            }

            if (!current.has_parent_path() || current == current.parent_path()) {
                break;
            }
            current = current.parent_path();
        }
    }

    std::filesystem::path fallback = std::filesystem::current_path() / "results";
    std::error_code ec;
    std::filesystem::create_directories(fallback, ec);
    return fallback;
}

void SaveMetrics(CaptureRenderMetricsCollector& collector) {
    const auto resultsDir = FindResultsDirectory();
    const auto timestamp = static_cast<long long>(std::time(nullptr));
    const std::string sourceName = collector.Config().api_name.empty()
        ? "UnknownCapture"
        : collector.Config().api_name;
    const std::string rendererName = collector.Config().renderer.empty()
        ? "UnknownRenderer"
        : collector.Config().renderer;
    const std::string stem =
        std::to_string(timestamp) + "_cpp_" + sourceName + "_" + rendererName + "_capture_render";

    const auto csvPath = resultsDir / (stem + ".csv");
    const auto jsonPath = resultsDir / (stem + ".json");

    const bool csvOk = collector.SaveToCSV(csvPath.string());
    const bool jsonOk = collector.SaveToJSON(jsonPath.string());

    if (csvOk && jsonOk) {
        std::cout << "Saved capture-render metrics:\n"
                  << "  " << csvPath.string() << "\n"
                  << "  " << jsonPath.string() << "\n";
    } else {
        std::cerr << "Failed to save one or more metrics files under "
                  << resultsDir.string() << "\n";
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    const ViewerOptions options = ParseViewerOptions(GetCommandLineArgs());

    Window window;
    if (!window.Initialize(
#ifdef USE_D3D12
            L"CapTest Capture Render Base (D3D12)",
#else
            L"CapTest Capture Render Base (D3D11)",
#endif
            1280,
            720)) {
        return 1;
    }

#ifdef USE_D3D12
    D3D12Renderer renderer;
    const char* rendererName = "D3D12";
#else
    D3D11Renderer renderer;
    const char* rendererName = "D3D11";
#endif
    if (!renderer.Initialize(window.GetHandle(), 1280, 720)) {
        return 1;
    }

    std::unique_ptr<ICaptureSource> capture = CreateCaptureSource(options.source);
#ifdef USE_D3D12
    ID3D11Device* captureDevice = renderer.GetCaptureDevice();
#else
    ID3D11Device* captureDevice = renderer.GetDevice();
#endif
    if (!capture || !capture->Initialize(captureDevice)) {
        return 1;
    }

    renderer.SetApiName(capture->OverlayName().c_str());
    renderer.SetResolution(capture->GetWidth(), capture->GetHeight());

    CaptureRenderConfig config;
    config.api_name = capture->ApiName();
    config.language = "C++";
    config.renderer = rendererName;
    config.duration_sec = options.duration_seconds;
    config.width = capture->GetWidth();
    config.height = capture->GetHeight();

    CaptureRenderMetricsCollector metricsCollector(config);

    window.SetResizeCallback([&](int width, int height) {
        if (width > 0 && height > 0) {
            renderer.Resize(width, height);
        }
    });

    MSG msg = {};
    uint64_t frameNumber = 0;
    uint64_t capturedSinceFps = 0;
    double currentFps = 0.0;
    auto lastFpsUpdate = SteadyClock::now();
    const auto testStart = SteadyClock::now();

    bool running = true;
    while (running) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                running = false;
                break;
            }

            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        if (!running) {
            break;
        }

        if (options.duration_seconds > 0 &&
            SteadyClock::now() - testStart >= std::chrono::seconds(options.duration_seconds)) {
            running = false;
            break;
        }

        const auto frameStart = HighResClock::now();
        CaptureFrameResult captureResult = capture->AcquireNextFrame(16);

        CaptureRenderFrameMetrics frameMetrics;
        frameMetrics.frame_number = ++frameNumber;
        frameMetrics.status = captureResult.status;
        frameMetrics.capture_time_ms = captureResult.capture_time_ms;
        frameMetrics.width = capture->GetWidth();
        frameMetrics.height = capture->GetHeight();

        if (captureResult.status == FrameStatus::Captured && captureResult.texture) {
            const auto renderStart = HighResClock::now();
            renderer.Render(captureResult.texture.Get());
            const auto renderEnd = HighResClock::now();
            frameMetrics.render_time_ms = ElapsedMs(renderStart, renderEnd);

            capture->ReleaseFrame();
            capturedSinceFps++;
        } else if (captureResult.status == FrameStatus::AccessLost) {
            capture->Initialize(captureDevice);
        } else if (captureResult.status == FrameStatus::Error) {
            std::wcerr << L"Capture error: 0x" << std::hex << captureResult.hr << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }

        const auto presentStart = HighResClock::now();
        renderer.Present();
        const auto presentEnd = HighResClock::now();
        frameMetrics.present_time_ms = ElapsedMs(presentStart, presentEnd);
        frameMetrics.total_time_ms = ElapsedMs(frameStart, presentEnd);

        const auto now = SteadyClock::now();
        const double fpsElapsed = std::chrono::duration<double>(now - lastFpsUpdate).count();
        if (fpsElapsed >= 0.5) {
            currentFps = static_cast<double>(capturedSinceFps) / fpsElapsed;
            capturedSinceFps = 0;
            lastFpsUpdate = now;
        }

        frameMetrics.fps = currentFps;
        frameMetrics.memory_mb = GetCurrentProcessMemoryMb();
        metricsCollector.RecordFrame(frameMetrics);

        renderer.SetFPS(currentFps);
        renderer.SetResolution(capture->GetWidth(), capture->GetHeight());
        renderer.SetCaptureTime(frameMetrics.capture_time_ms);
        renderer.SetRenderTime(frameMetrics.render_time_ms);
        renderer.SetPresentTime(frameMetrics.present_time_ms);
    }

    capture->ReleaseFrame();
    SaveMetrics(metricsCollector);

    return 0;
}
