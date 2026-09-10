#pragma once

#include "capture_render_metrics.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

struct CaptureFrameResult {
    FrameStatus status = FrameStatus::Error;
    ComPtr<ID3D11Texture2D> texture;
    double capture_time_ms = 0.0;
    HRESULT hr = S_OK;
};

class DesktopDuplicationCapture {
public:
    bool Initialize(ID3D11Device* device);
    CaptureFrameResult AcquireNextFrame(UINT timeout_ms);
    void ReleaseFrame();
    void Reset();

    int GetWidth() const { return width_; }
    int GetHeight() const { return height_; }
    bool IsInitialized() const { return duplication_ != nullptr; }

private:
    bool CreateDuplication();

    ComPtr<ID3D11Device> device_;
    ComPtr<IDXGIOutputDuplication> duplication_;
    bool frame_acquired_ = false;
    int width_ = 0;
    int height_ = 0;
};
