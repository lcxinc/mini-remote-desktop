#include "desktop_duplication_capture.h"

#include <chrono>
#include <iostream>

bool DesktopDuplicationCapture::Initialize(ID3D11Device* device) {
    Reset();
    if (!device) {
        return false;
    }

    device_ = device;
    return CreateDuplication();
}

bool DesktopDuplicationCapture::CreateDuplication() {
    if (!device_) {
        return false;
    }

    ComPtr<IDXGIDevice> dxgiDevice;
    HRESULT hr = device_.As(&dxgiDevice);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to query IDXGIDevice: 0x" << std::hex << hr << std::endl;
        return false;
    }

    ComPtr<IDXGIAdapter> adapter;
    hr = dxgiDevice->GetAdapter(&adapter);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to get DXGI adapter: 0x" << std::hex << hr << std::endl;
        return false;
    }

    ComPtr<IDXGIOutput> output;
    hr = adapter->EnumOutputs(0, &output);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to get primary output: 0x" << std::hex << hr << std::endl;
        return false;
    }

    DXGI_OUTPUT_DESC outputDesc = {};
    hr = output->GetDesc(&outputDesc);
    if (SUCCEEDED(hr)) {
        width_ = outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left;
        height_ = outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top;
    }

    ComPtr<IDXGIOutput1> output1;
    hr = output.As(&output1);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to query IDXGIOutput1: 0x" << std::hex << hr << std::endl;
        return false;
    }

    hr = output1->DuplicateOutput(device_.Get(), &duplication_);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to duplicate output: 0x" << std::hex << hr << std::endl;
        duplication_.Reset();
        return false;
    }

    return true;
}

CaptureFrameResult DesktopDuplicationCapture::AcquireNextFrame(UINT timeout_ms) {
    CaptureFrameResult result;
    if (!duplication_) {
        result.status = FrameStatus::AccessLost;
        result.hr = DXGI_ERROR_ACCESS_LOST;
        return result;
    }

    if (frame_acquired_) {
        ReleaseFrame();
    }

    const auto start = std::chrono::high_resolution_clock::now();

    DXGI_OUTDUPL_FRAME_INFO frameInfo = {};
    ComPtr<IDXGIResource> resource;
    HRESULT hr = duplication_->AcquireNextFrame(timeout_ms, &frameInfo, &resource);

    const auto end = std::chrono::high_resolution_clock::now();
    result.capture_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    result.hr = hr;

    if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
        result.status = FrameStatus::Timeout;
        return result;
    }

    if (hr == DXGI_ERROR_ACCESS_LOST) {
        result.status = FrameStatus::AccessLost;
        Reset();
        return result;
    }

    if (FAILED(hr)) {
        result.status = FrameStatus::Error;
        return result;
    }

    frame_acquired_ = true;
    hr = resource.As(&result.texture);
    if (FAILED(hr)) {
        result.status = FrameStatus::Error;
        result.hr = hr;
        ReleaseFrame();
        return result;
    }

    result.status = FrameStatus::Captured;
    return result;
}

void DesktopDuplicationCapture::ReleaseFrame() {
    if (!duplication_ || !frame_acquired_) {
        return;
    }

    duplication_->ReleaseFrame();
    frame_acquired_ = false;
}

void DesktopDuplicationCapture::Reset() {
    if (duplication_ && frame_acquired_) {
        duplication_->ReleaseFrame();
    }

    frame_acquired_ = false;
    duplication_.Reset();
    width_ = 0;
    height_ = 0;
}
