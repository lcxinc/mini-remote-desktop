#include "capture_metrics.h"
#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <Windows.h>
#include <psapi.h>
#include <d3d11.h>
#include <dxgi1_6.h>

// Windows SDK 互操作接口
#include <Windows.Graphics.Capture.Interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>

// C++/WinRT - 在互操作接口之后
#pragma comment(lib, "windowsapp")
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>
#include <winrt/Windows.Graphics.DirectX.h>

namespace winrt {
    using namespace Windows::Foundation;
    using namespace Windows::Graphics::Capture;
    using namespace Windows::Graphics::DirectX::Direct3D11;
    using namespace Windows::Graphics::DirectX;
}

std::queue<float> g_frame_times;
std::mutex g_frame_times_mutex;

double GetCurrentMemoryMB() {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024.0 * 1024.0);
    }
    return 0.0;
}

class GraphicsCaptureCapture {
private:
    ID3D11Device* m_d3dDevice = nullptr;
    ID3D11DeviceContext* m_d3dContext = nullptr;
    winrt::IDirect3DDevice m_winrtDevice{ nullptr };
    winrt::Direct3D11CaptureFramePool m_framePool{ nullptr };
    winrt::GraphicsCaptureSession m_session{ nullptr };
    winrt::GraphicsCaptureItem m_item{ nullptr };
    winrt::event_token m_frameToken;
    std::atomic<uint64_t> m_callbackCount{0};

public:
    ~GraphicsCaptureCapture() {
        Cleanup();
    }

    bool Initialize() {
        try {
            winrt::init_apartment();

            D3D_FEATURE_LEVEL featureLevels[] = {
                D3D_FEATURE_LEVEL_11_1,
                D3D_FEATURE_LEVEL_11_0,
            };
            D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;

            HRESULT hr = D3D11CreateDevice(
                nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                featureLevels, 2, D3D11_SDK_VERSION,
                &m_d3dDevice, &featureLevel, &m_d3dContext
            );

            if (FAILED(hr) || !m_d3dDevice) {
                std::wcerr << L"Failed to create D3D11 device: 0x" << std::hex << hr << std::endl;
                return false;
            }

            // 获取 IDXGIDevice
            IDXGIDevice* dxgiDevice = nullptr;
            hr = m_d3dDevice->QueryInterface(__uuidof(IDXGIDevice), reinterpret_cast<void**>(&dxgiDevice));

            if (SUCCEEDED(hr) && dxgiDevice) {
                ::IInspectable* deviceInspectable = nullptr;
                hr = CreateDirect3D11DeviceFromDXGIDevice(dxgiDevice, &deviceInspectable);
                if (SUCCEEDED(hr) && deviceInspectable) {
                    winrt::attach_abi(m_winrtDevice, deviceInspectable);
                }

                // 从 DXGI 获取主显示器
                IDXGIAdapter* adapter = nullptr;
                hr = dxgiDevice->GetAdapter(&adapter);
                if (SUCCEEDED(hr) && adapter) {
                    IDXGIOutput* output = nullptr;
                    hr = adapter->EnumOutputs(0, &output);
                    if (SUCCEEDED(hr) && output) {
                        DXGI_OUTPUT_DESC desc;
                        output->GetDesc(&desc);

                        std::cout << "Found monitor, creating capture item..." << std::endl;

                        // 从显示器创建捕获项
                        auto activationFactory = winrt::get_activation_factory<winrt::GraphicsCaptureItem>();
                        winrt::com_ptr<IGraphicsCaptureItemInterop> interop;
                        hr = activationFactory.as(__uuidof(IGraphicsCaptureItemInterop),
                            reinterpret_cast<void**>(winrt::put_abi(interop)));

                        if (FAILED(hr)) {
                            std::cerr << "Failed to get interop interface: 0x" << std::hex << hr << std::endl;
                        } else if (!interop) {
                            std::cerr << "Interop interface is null" << std::endl;
                        } else {
                            ::IInspectable* itemInspectable = nullptr;
                            GUID guid = winrt::guid_of<winrt::GraphicsCaptureItem>();
                            hr = interop->CreateForMonitor(desc.Monitor, guid,
                                reinterpret_cast<void**>(&itemInspectable));
                            if (FAILED(hr)) {
                                std::cerr << "CreateForMonitor failed: 0x" << std::hex << hr << std::endl;
                            } else if (itemInspectable) {
                                winrt::attach_abi(m_item, itemInspectable);
                                std::cout << "Capture item created successfully" << std::endl;
                            }
                        }
                        output->Release();
                    }
                    adapter->Release();
                }
                dxgiDevice->Release();
            }

            if (!m_item) {
                std::cerr << "Failed to create capture item" << std::endl;
                return false;
            }

            auto size = m_item.Size();
            std::cout << "Capture item size: " << size.Width << "x" << size.Height << std::endl;

            m_framePool = winrt::Direct3D11CaptureFramePool::Create(
                m_winrtDevice,
                winrt::DirectXPixelFormat::B8G8R8A8UIntNormalized,
                2,
                { size.Width, size.Height }
            );

            if (!m_framePool) {
                std::cerr << "Failed to create frame pool" << std::endl;
                return false;
            }

            m_frameToken = m_framePool.FrameArrived(
                [this](auto&& sender, auto&&) {
                    m_callbackCount++;
                    auto frameStart = std::chrono::high_resolution_clock::now();
                    auto frame = sender.TryGetNextFrame();
                    if (frame) {
                        auto surface = frame.Surface();
                        auto desc = surface.Description();
                        (void)desc;

                        auto frameEnd = std::chrono::high_resolution_clock::now();
                        auto elapsed = std::chrono::duration<float, std::milli>(frameEnd - frameStart).count();
                        std::lock_guard<std::mutex> lock(g_frame_times_mutex);
                        g_frame_times.push(elapsed);
                    }
                }
            );

            m_session = m_framePool.CreateCaptureSession(m_item);
            if (!m_session) {
                std::cerr << "Failed to create capture session" << std::endl;
                return false;
            }

            m_session.IsCursorCaptureEnabled(false);
            m_session.StartCapture();

            std::cout << "Capture session started, waiting for frames..." << std::endl;

            // 等待捕获会话初始化和用户响应权限对话框
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            std::cout << "Wait complete, checking for frames..." << std::endl;

            return true;
        }
        catch (const winrt::hresult_error& e) {
            std::wcerr << L"Initialize exception: " << e.message().c_str() << std::endl;
            return false;
        }
    }

    bool TryGetFrameTime(float& timeMs) {
        std::lock_guard<std::mutex> lock(g_frame_times_mutex);
        if (g_frame_times.empty()) return false;
        timeMs = g_frame_times.front();
        g_frame_times.pop();
        return true;
    }

    uint64_t GetCallbackCount() const {
        return m_callbackCount.load();
    }

    void Cleanup() {
        try {
            if (m_session) {
                m_session.Close();
                m_session = nullptr;
            }
            if (m_framePool) {
                m_framePool.Close();
                m_framePool = nullptr;
            }
            m_item = nullptr;
            m_winrtDevice = nullptr;
            if (m_d3dContext) {
                m_d3dContext->Release();
                m_d3dContext = nullptr;
            }
            if (m_d3dDevice) {
                m_d3dDevice->Release();
                m_d3dDevice = nullptr;
            }
        } catch (...) {}
    }
};

int main() {
    TestConfig config;
    config.api_name = "GraphicsCapture";
    config.language = "C++";
    config.duration_sec = 10;

    MetricsCollector collector(config);

    std::cout << "Starting Graphics Capture test..." << std::endl;
    std::cout << "Note: Windows will show a permission dialog for screen capture." << std::endl;
    std::cout << "      Please click 'Yes' to allow capture." << std::endl;

    GraphicsCaptureCapture capture;
    if (!capture.Initialize()) {
        std::cerr << "Failed to initialize capture!" << std::endl;
        return 1;
    }

    std::cout << "Capture initialized successfully!" << std::endl;

    auto startTime = std::chrono::steady_clock::now();
    auto endTime = startTime + std::chrono::seconds(config.duration_sec);
    uint64_t frameCount = 0;
    uint64_t emptyLoops = 0;

    std::cout << "Starting capture loop..." << std::endl;

    while (std::chrono::steady_clock::now() < endTime) {
        // 泵送 Windows 消息队列
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        float captureTimeMs = 0;
        if (capture.TryGetFrameTime(captureTimeMs)) {
            frameCount++;
            auto totalTime = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - startTime).count();

            FrameMetrics metrics;
            metrics.frame_number = frameCount;
            metrics.capture_time_ms = captureTimeMs;
            metrics.total_time_ms = totalTime;
            metrics.fps = (metrics.total_time_ms > 0) ? (metrics.frame_number * 1000.0 / metrics.total_time_ms) : 0;
            metrics.cpu_percent = 0;
            metrics.memory_mb = GetCurrentMemoryMB();

            collector.RecordFrame(metrics);

            // 每 100 帧打印一次
            if (frameCount % 100 == 0) {
                std::cout << "Captured " << frameCount << " frames..." << std::endl;
            }
        } else {
            emptyLoops++;
            if (emptyLoops % 5000 == 0) {
                std::cout << "Waiting for frames... (" << emptyLoops << " empty loops)" << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    std::cout << "Callback count: " << capture.GetCallbackCount() << std::endl;
    capture.Cleanup();

    collector.PrintSummary();

    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::string csvPath = "D:/Project/TestProject/CapTest/results/" + std::to_string(timestamp) + "_cpp_graphics_capture.csv";
    std::string jsonPath = "D:/Project/TestProject/CapTest/results/" + std::to_string(timestamp) + "_cpp_graphics_capture.json";

    collector.SaveToCSV(csvPath);
    collector.SaveToJSON(jsonPath);

    std::cout << "Results saved to:" << std::endl;
    std::cout << "  " << csvPath << std::endl;
    std::cout << "  " << jsonPath << std::endl;

    return 0;
}
