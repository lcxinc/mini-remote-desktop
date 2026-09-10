#include "capture_sources.h"

#include <windows.h>
#include <d3d11_4.h>

#include <Windows.Graphics.Capture.Interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>

using Microsoft::WRL::ComPtr;

namespace {

using HighResClock = std::chrono::high_resolution_clock;

double ElapsedMs(HighResClock::time_point start, HighResClock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

class DesktopDuplicationSource final : public ICaptureSource {
public:
    bool Initialize(ID3D11Device* device) override {
        return capture_.Initialize(device);
    }

    CaptureFrameResult AcquireNextFrame(UINT timeout_ms) override {
        return capture_.AcquireNextFrame(timeout_ms);
    }

    void ReleaseFrame() override {
        capture_.ReleaseFrame();
    }

    void Reset() override {
        capture_.Reset();
    }

    int GetWidth() const override {
        return capture_.GetWidth();
    }

    int GetHeight() const override {
        return capture_.GetHeight();
    }

    std::string ApiName() const override {
        return SourceKindToApiName(CaptureSourceKind::DesktopDuplication);
    }

    std::wstring OverlayName() const override {
        return SourceKindToOverlayName(CaptureSourceKind::DesktopDuplication);
    }

private:
    DesktopDuplicationCapture capture_;
};

class SharedMemoryDesktopDuplicationSource final : public ICaptureSource {
public:
    ~SharedMemoryDesktopDuplicationSource() override {
        Reset();
    }

    bool Initialize(ID3D11Device* device) override {
        Reset();
        if (!device) {
            return false;
        }

        device_ = device;
        device_->GetImmediateContext(&context_);
        return capture_.Initialize(device);
    }

    CaptureFrameResult AcquireNextFrame(UINT timeout_ms) override {
        CaptureFrameResult source = capture_.AcquireNextFrame(timeout_ms);
        if (source.status != FrameStatus::Captured || !source.texture) {
            return source;
        }
        const auto copyStart = HighResClock::now();

        CaptureFrameResult result;
        result.status = FrameStatus::Error;
        result.hr = E_FAIL;

        D3D11_TEXTURE2D_DESC desc = {};
        source.texture->GetDesc(&desc);
        if (!EnsureBuffers(desc)) {
            capture_.ReleaseFrame();
            return result;
        }

        context_->CopyResource(staging_.Get(), source.texture.Get());

        D3D11_MAPPED_SUBRESOURCE mapped = {};
        HRESULT hr = context_->Map(staging_.Get(), 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hr)) {
            result.hr = hr;
            capture_.ReleaseFrame();
            return result;
        }

        const uint32_t rowBytes = desc.Width * 4;
        uint8_t* destination = mapped_memory_;
        const uint8_t* sourceRows = static_cast<const uint8_t*>(mapped.pData);
        for (UINT row = 0; row < desc.Height; ++row) {
            std::memcpy(destination + row * rowBytes, sourceRows + row * mapped.RowPitch, rowBytes);
        }

        context_->Unmap(staging_.Get(), 0);
        capture_.ReleaseFrame();

        context_->UpdateSubresource(output_.Get(), 0, nullptr, mapped_memory_, rowBytes, 0);

        result.status = FrameStatus::Captured;
        result.hr = S_OK;
        result.texture = output_;
        result.capture_time_ms = source.capture_time_ms + ElapsedMs(copyStart, HighResClock::now());
        return result;
    }

    void ReleaseFrame() override {}

    void Reset() override {
        capture_.Reset();
        output_.Reset();
        staging_.Reset();
        context_.Reset();
        device_.Reset();
        width_ = 0;
        height_ = 0;
        format_ = DXGI_FORMAT_UNKNOWN;

        if (mapped_memory_) {
            UnmapViewOfFile(mapped_memory_);
            mapped_memory_ = nullptr;
        }
        if (mapping_) {
            CloseHandle(mapping_);
            mapping_ = nullptr;
        }
        mapping_size_ = 0;
    }

    int GetWidth() const override {
        return width_ != 0 ? width_ : capture_.GetWidth();
    }

    int GetHeight() const override {
        return height_ != 0 ? height_ : capture_.GetHeight();
    }

    std::string ApiName() const override {
        return SourceKindToApiName(CaptureSourceKind::SharedMemoryDesktopDuplication);
    }

    std::wstring OverlayName() const override {
        return SourceKindToOverlayName(CaptureSourceKind::SharedMemoryDesktopDuplication);
    }

private:
    bool EnsureBuffers(const D3D11_TEXTURE2D_DESC& sourceDesc) {
        if (!device_ || !context_) {
            return false;
        }

        if (sourceDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM &&
            sourceDesc.Format != DXGI_FORMAT_R8G8B8A8_UNORM) {
            std::wcerr << L"Unsupported shared-memory capture format: "
                       << static_cast<int>(sourceDesc.Format) << std::endl;
            return false;
        }

        if (output_ &&
            width_ == static_cast<int>(sourceDesc.Width) &&
            height_ == static_cast<int>(sourceDesc.Height) &&
            format_ == sourceDesc.Format) {
            return true;
        }

        output_.Reset();
        staging_.Reset();
        if (mapped_memory_) {
            UnmapViewOfFile(mapped_memory_);
            mapped_memory_ = nullptr;
        }
        if (mapping_) {
            CloseHandle(mapping_);
            mapping_ = nullptr;
        }

        D3D11_TEXTURE2D_DESC stagingDesc = sourceDesc;
        stagingDesc.BindFlags = 0;
        stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        stagingDesc.MiscFlags = 0;
        stagingDesc.Usage = D3D11_USAGE_STAGING;

        HRESULT hr = device_->CreateTexture2D(&stagingDesc, nullptr, &staging_);
        if (FAILED(hr)) {
            return false;
        }

        D3D11_TEXTURE2D_DESC outputDesc = sourceDesc;
        outputDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        outputDesc.CPUAccessFlags = 0;
        outputDesc.MiscFlags = 0;
        outputDesc.Usage = D3D11_USAGE_DEFAULT;

        hr = device_->CreateTexture2D(&outputDesc, nullptr, &output_);
        if (FAILED(hr)) {
            return false;
        }

        mapping_size_ = static_cast<size_t>(sourceDesc.Width) * sourceDesc.Height * 4;
        const DWORD low = static_cast<DWORD>(mapping_size_ & 0xFFFFFFFFu);
        const DWORD high = static_cast<DWORD>((mapping_size_ >> 32) & 0xFFFFFFFFu);
        mapping_ = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            nullptr,
            PAGE_READWRITE,
            high,
            low,
            L"Local\\CapTestCaptureRenderSharedMemory");
        if (!mapping_) {
            return false;
        }

        mapped_memory_ = static_cast<uint8_t*>(
            MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size_));
        if (!mapped_memory_) {
            return false;
        }

        width_ = static_cast<int>(sourceDesc.Width);
        height_ = static_cast<int>(sourceDesc.Height);
        format_ = sourceDesc.Format;
        return true;
    }

    DesktopDuplicationCapture capture_;
    ComPtr<ID3D11Device> device_;
    ComPtr<ID3D11DeviceContext> context_;
    ComPtr<ID3D11Texture2D> staging_;
    ComPtr<ID3D11Texture2D> output_;
    HANDLE mapping_ = nullptr;
    uint8_t* mapped_memory_ = nullptr;
    size_t mapping_size_ = 0;
    int width_ = 0;
    int height_ = 0;
    DXGI_FORMAT format_ = DXGI_FORMAT_UNKNOWN;
};

class WindowsGraphicsCaptureSource final : public ICaptureSource {
public:
    ~WindowsGraphicsCaptureSource() override {
        Reset();
    }

    bool Initialize(ID3D11Device* device) override {
        Reset();
        if (!device) {
            return false;
        }

        try {
            winrt::init_apartment(winrt::apartment_type::single_threaded);
        } catch (...) {
            // The thread may already be initialized by the host.
        }

        device_ = device;
        device_->GetImmediateContext(&context_);

        ComPtr<ID3D11Multithread> multithread;
        if (SUCCEEDED(device_.As(&multithread))) {
            multithread->SetMultithreadProtected(TRUE);
        }

        if (!CreateWinRtDevice() || !CreateCaptureItem()) {
            Reset();
            return false;
        }

        const auto size = item_.Size();
        width_ = size.Width;
        height_ = size.Height;

        frame_pool_ = winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool::Create(
            winrt_device_,
            winrt::Windows::Graphics::DirectX::DirectXPixelFormat::B8G8R8A8UIntNormalized,
            2,
            size);
        if (!frame_pool_) {
            Reset();
            return false;
        }

        frame_token_ = frame_pool_.FrameArrived(
            [this](auto&& sender, auto&&) {
                OnFrameArrived(sender);
            });

        session_ = frame_pool_.CreateCaptureSession(item_);
        if (!session_) {
            Reset();
            return false;
        }

        session_.IsCursorCaptureEnabled(false);
        session_.StartCapture();
        return true;
    }

    CaptureFrameResult AcquireNextFrame(UINT timeout_ms) override {
        CaptureFrameResult result;
        std::unique_lock<std::mutex> lock(mutex_);
        if (!pending_frame_ready_) {
            if (!condition_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
                    return pending_frame_ready_ || access_lost_;
                })) {
                result.status = FrameStatus::Timeout;
                return result;
            }
        }

        if (access_lost_) {
            result.status = FrameStatus::AccessLost;
            result.hr = DXGI_ERROR_ACCESS_LOST;
            access_lost_ = false;
            return result;
        }

        active_frame_ = pending_frame_;
        active_texture_ = pending_texture_;
        active_capture_time_ms_ = pending_capture_time_ms_;
        pending_frame_ = nullptr;
        pending_texture_.Reset();
        pending_frame_ready_ = false;

        result.texture = active_texture_;
        result.capture_time_ms = active_capture_time_ms_;
        result.status = result.texture ? FrameStatus::Captured : FrameStatus::Timeout;
        result.hr = result.texture ? S_OK : DXGI_ERROR_WAIT_TIMEOUT;
        return result;
    }

    void ReleaseFrame() override {
        std::lock_guard<std::mutex> lock(mutex_);
        active_texture_.Reset();
        active_frame_ = nullptr;
        active_capture_time_ms_ = 0.0;
    }

    void Reset() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pending_frame_ready_ = false;
            access_lost_ = false;
            pending_texture_.Reset();
            active_texture_.Reset();
            pending_frame_ = nullptr;
            active_frame_ = nullptr;
            pending_capture_time_ms_ = 0.0;
            active_capture_time_ms_ = 0.0;
        }

        if (frame_pool_ && frame_token_) {
            try {
                frame_pool_.FrameArrived(frame_token_);
            } catch (...) {}
        }
        frame_token_ = {};

        try {
            if (session_) {
                session_.Close();
            }
            if (frame_pool_) {
                frame_pool_.Close();
            }
        } catch (...) {}

        session_ = nullptr;
        frame_pool_ = nullptr;
        item_ = nullptr;
        winrt_device_ = nullptr;
        context_.Reset();
        device_.Reset();
        width_ = 0;
        height_ = 0;
    }

    int GetWidth() const override {
        return width_;
    }

    int GetHeight() const override {
        return height_;
    }

    std::string ApiName() const override {
        return SourceKindToApiName(CaptureSourceKind::WindowsGraphicsCapture);
    }

    std::wstring OverlayName() const override {
        return SourceKindToOverlayName(CaptureSourceKind::WindowsGraphicsCapture);
    }

private:
    bool CreateWinRtDevice() {
        ComPtr<IDXGIDevice> dxgiDevice;
        HRESULT hr = device_.As(&dxgiDevice);
        if (FAILED(hr)) {
            return false;
        }

        ::IInspectable* inspectable = nullptr;
        hr = CreateDirect3D11DeviceFromDXGIDevice(dxgiDevice.Get(), &inspectable);
        if (FAILED(hr) || !inspectable) {
            return false;
        }

        winrt::attach_abi(winrt_device_, inspectable);
        return winrt_device_ != nullptr;
    }

    bool CreateCaptureItem() {
        ComPtr<IDXGIDevice> dxgiDevice;
        HRESULT hr = device_.As(&dxgiDevice);
        if (FAILED(hr)) {
            return false;
        }

        ComPtr<IDXGIAdapter> adapter;
        hr = dxgiDevice->GetAdapter(&adapter);
        if (FAILED(hr)) {
            return false;
        }

        ComPtr<IDXGIOutput> output;
        hr = adapter->EnumOutputs(0, &output);
        if (FAILED(hr)) {
            return false;
        }

        DXGI_OUTPUT_DESC desc = {};
        hr = output->GetDesc(&desc);
        if (FAILED(hr)) {
            return false;
        }

        auto activationFactory =
            winrt::get_activation_factory<winrt::Windows::Graphics::Capture::GraphicsCaptureItem>();
        winrt::com_ptr<IGraphicsCaptureItemInterop> interop;
        hr = activationFactory.as(
            __uuidof(IGraphicsCaptureItemInterop),
            reinterpret_cast<void**>(winrt::put_abi(interop)));
        if (FAILED(hr) || !interop) {
            return false;
        }

        ::IInspectable* inspectable = nullptr;
        const GUID itemGuid =
            winrt::guid_of<winrt::Windows::Graphics::Capture::GraphicsCaptureItem>();
        hr = interop->CreateForMonitor(
            desc.Monitor,
            itemGuid,
            reinterpret_cast<void**>(&inspectable));
        if (FAILED(hr) || !inspectable) {
            return false;
        }

        winrt::attach_abi(item_, inspectable);
        return item_ != nullptr;
    }

    void OnFrameArrived(
        winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool const& sender) {
        const auto start = HighResClock::now();
        try {
            auto frame = sender.TryGetNextFrame();
            if (!frame) {
                return;
            }

            auto surface = frame.Surface();
            winrt::com_ptr<
                Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess> access =
                surface.as<Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();

            ComPtr<ID3D11Texture2D> frameTexture;
            HRESULT hr = access->GetInterface(IID_PPV_ARGS(&frameTexture));
            if (FAILED(hr) || !frameTexture) {
                return;
            }

            D3D11_TEXTURE2D_DESC desc = {};
            frameTexture->GetDesc(&desc);

            ComPtr<ID3D11Texture2D> outputTexture = frameTexture;
            bool keepFrameAlive = true;

            if ((desc.BindFlags & D3D11_BIND_SHADER_RESOURCE) == 0) {
                keepFrameAlive = false;
                if (!fallback_texture_ ||
                    width_ != static_cast<int>(desc.Width) ||
                    height_ != static_cast<int>(desc.Height)) {
                    D3D11_TEXTURE2D_DESC copyDesc = desc;
                    copyDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
                    copyDesc.CPUAccessFlags = 0;
                    copyDesc.MiscFlags = 0;
                    copyDesc.Usage = D3D11_USAGE_DEFAULT;
                    HRESULT hr = device_->CreateTexture2D(&copyDesc, nullptr, &fallback_texture_);
                    if (FAILED(hr)) {
                        fallback_texture_.Reset();
                        return;
                    }
                }

                context_->CopyResource(fallback_texture_.Get(), frameTexture.Get());
                outputTexture = fallback_texture_;
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                pending_frame_ = keepFrameAlive ? frame : nullptr;
                pending_texture_ = outputTexture;
                pending_capture_time_ms_ = ElapsedMs(start, HighResClock::now());
                pending_frame_ready_ = true;
                width_ = static_cast<int>(desc.Width);
                height_ = static_cast<int>(desc.Height);
            }
            condition_.notify_one();
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                access_lost_ = true;
            }
            condition_.notify_one();
        }
    }

    ComPtr<ID3D11Device> device_;
    ComPtr<ID3D11DeviceContext> context_;
    winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice winrt_device_{nullptr};
    winrt::Windows::Graphics::Capture::GraphicsCaptureItem item_{nullptr};
    winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool frame_pool_{nullptr};
    winrt::Windows::Graphics::Capture::GraphicsCaptureSession session_{nullptr};
    winrt::event_token frame_token_{};

    mutable std::mutex mutex_;
    std::condition_variable condition_;
    winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame pending_frame_{nullptr};
    winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame active_frame_{nullptr};
    ComPtr<ID3D11Texture2D> pending_texture_;
    ComPtr<ID3D11Texture2D> active_texture_;
    ComPtr<ID3D11Texture2D> fallback_texture_;
    double pending_capture_time_ms_ = 0.0;
    double active_capture_time_ms_ = 0.0;
    bool pending_frame_ready_ = false;
    bool access_lost_ = false;
    int width_ = 0;
    int height_ = 0;
};

}  // namespace

std::unique_ptr<ICaptureSource> CreateCaptureSource(CaptureSourceKind source) {
    switch (source) {
        case CaptureSourceKind::WindowsGraphicsCapture:
            return std::make_unique<WindowsGraphicsCaptureSource>();
        case CaptureSourceKind::SharedMemoryDesktopDuplication:
            return std::make_unique<SharedMemoryDesktopDuplicationSource>();
        case CaptureSourceKind::DesktopDuplication:
        default:
            return std::make_unique<DesktopDuplicationSource>();
    }
}
