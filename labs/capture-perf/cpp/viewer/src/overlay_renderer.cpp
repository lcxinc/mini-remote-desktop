#include "overlay_renderer.h"
#include <d3d11.h>
#include <iostream>
#include <wchar.h>

#ifdef DrawText
#undef DrawText
#endif

OverlayRenderer::OverlayRenderer() = default;

OverlayRenderer::~OverlayRenderer() {
    if (d2dContext_) {
        d2dContext_->EndDraw();
    }
}

bool OverlayRenderer::Initialize(ID3D11Device* d3d11Device, ID3D11DeviceContext* d3d11Context) {
    d3d11Device_ = d3d11Device;
    d3d11Context_ = d3d11Context;

    return CreateD2DResources() && CreateDWriteResources();
}

bool OverlayRenderer::CreateD2DResources() {
    D2D1_FACTORY_OPTIONS options = {};
#ifdef _DEBUG
    options.debugLevel = D2D1_DEBUG_LEVEL_INFORMATION;
#endif

    HRESULT hr = D2D1CreateFactory(
        D2D1_FACTORY_TYPE_SINGLE_THREADED,
        __uuidof(ID2D1Factory1),
        &options,
        reinterpret_cast<void**>(d2dFactory_.GetAddressOf())
    );

    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D2D factory: 0x" << std::hex << hr << std::endl;
        return false;
    }

    // Create D2D device
    ComPtr<IDXGIDevice> dxgiDevice;
    hr = d3d11Device_->QueryInterface(IID_PPV_ARGS(&dxgiDevice));
    if (FAILED(hr)) return false;

    hr = d2dFactory_->CreateDevice(dxgiDevice.Get(), d2dDevice_.GetAddressOf());
    if (FAILED(hr)) return false;

    hr = d2dDevice_->CreateDeviceContext(
        D2D1_DEVICE_CONTEXT_OPTIONS_NONE,
        d2dContext_.GetAddressOf()
    );

    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D2D context: 0x" << std::hex << hr << std::endl;
        return false;
    }

    d2dContext_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);

    return true;
}

bool OverlayRenderer::CreateDWriteResources() {
    HRESULT hr = DWriteCreateFactory(
        DWRITE_FACTORY_TYPE_SHARED,
        __uuidof(IDWriteFactory),
        &dwriteFactory_
    );

    if (FAILED(hr)) {
        std::wcerr << L"Failed to create DWrite factory: 0x" << std::hex << hr << std::endl;
        return false;
    }

    // Create text formats
    hr = dwriteFactory_->CreateTextFormat(
        L"Segoe UI",
        nullptr,
        DWRITE_FONT_WEIGHT_NORMAL,
        DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL,
        16.0f,
        L"en-us",
        &textFormatSmall_
    );

    if (SUCCEEDED(hr)) {
        textFormatSmall_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        textFormatSmall_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    }

    hr = dwriteFactory_->CreateTextFormat(
        L"Segoe UI",
        nullptr,
        DWRITE_FONT_WEIGHT_BOLD,
        DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL,
        24.0f,
        L"en-us",
        &textFormatLarge_
    );

    if (SUCCEEDED(hr)) {
        textFormatLarge_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        textFormatLarge_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    }

    return SUCCEEDED(hr);
}

void OverlayRenderer::Render(ID3D11Texture2D* backBuffer, int width, int height) {
    if (!d2dContext_) return;

    // Create D2D bitmap from D3D11 texture
    if (!d2dBitmap_) {
        ComPtr<IDXGISurface> surface;
        HRESULT hr = backBuffer->QueryInterface(IID_PPV_ARGS(&surface));
        if (FAILED(hr)) return;

        D2D1_BITMAP_PROPERTIES1 props = D2D1::BitmapProperties1(
            D2D1_BITMAP_OPTIONS_TARGET | D2D1_BITMAP_OPTIONS_CANNOT_DRAW,
            D2D1::PixelFormat(DXGI_FORMAT_R8G8B8A8_UNORM, D2D1_ALPHA_MODE_IGNORE),
            96.0f,
            96.0f
        );

        hr = d2dContext_->CreateBitmapFromDxgiSurface(surface.Get(), &props, d2dBitmap_.GetAddressOf());
        if (FAILED(hr)) return;
    }

    // Begin drawing
    d2dContext_->BeginDraw();
    d2dContext_->SetTarget(d2dBitmap_.Get());

    // Clear with transparent color
    d2dContext_->Clear(D2D1::ColorF(0.0f, 0.0f));

    // Draw overlay text
    float y = 10.0f;
    const float x = 10.0f;

    if (!apiName_.empty()) {
        RenderText(apiName_.c_str(), x, y, 24.0f, D2D1::ColorF(1.0f, 1.0f, 1.0f));
        y += 35.0f;
    }

    if (currentFps_ > 0.0) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(1) << L"FPS: " << currentFps_;
        RenderText(ss.str().c_str(), x, y, 18.0f, D2D1::ColorF(0.2f, 1.0f, 0.2f));
        y += 25.0f;
    }

    if (resolutionWidth_ > 0 && resolutionHeight_ > 0) {
        std::wstringstream ss;
        ss << L"Resolution: " << resolutionWidth_ << L"x" << resolutionHeight_;
        RenderText(ss.str().c_str(), x, y, 16.0f, D2D1::ColorF(0.8f, 0.8f, 0.8f));
        y += 25.0f;
    }

    if (captureTimeMs_ > 0.0) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(2) << L"Capture: " << captureTimeMs_ << L" ms";
        RenderText(ss.str().c_str(), x, y, 16.0f, D2D1::ColorF(0.8f, 0.8f, 0.8f));
        y += 25.0f;
    }

    if (renderTimeMs_ > 0.0) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(2) << L"Render: " << renderTimeMs_ << L" ms";
        RenderText(ss.str().c_str(), x, y, 16.0f, D2D1::ColorF(0.8f, 0.8f, 0.8f));
        y += 25.0f;
    }

    if (presentTimeMs_ > 0.0) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(2) << L"Present: " << presentTimeMs_ << L" ms";
        RenderText(ss.str().c_str(), x, y, 16.0f, D2D1::ColorF(0.8f, 0.8f, 0.8f));
    }

    d2dContext_->EndDraw();
}

void OverlayRenderer::RenderText(const wchar_t* text, float x, float y, float fontSize, D2D1::ColorF color) {
    if (!d2dContext_.Get() || !dwriteFactory_.Get()) return;

    // Create temporary text format
    ComPtr<IDWriteTextFormat> format;
    HRESULT hr = dwriteFactory_->CreateTextFormat(
        L"Segoe UI",
        nullptr,
        DWRITE_FONT_WEIGHT_NORMAL,
        DWRITE_FONT_STYLE_NORMAL,
        DWRITE_FONT_STRETCH_NORMAL,
        fontSize,
        L"en-us",
        &format
    );

    if (FAILED(hr)) return;

    format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
    format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);

    ComPtr<ID2D1SolidColorBrush> brush;
    hr = d2dContext_->CreateSolidColorBrush(color, brush.GetAddressOf());
    if (FAILED(hr)) return;

    // Draw text
    D2D1_RECT_F rect = { x, y, x + 1000.0f, y + 100.0f };
    static_cast<ID2D1RenderTarget*>(d2dContext_.Get())
        ->DrawTextA(text, static_cast<UINT32>(wcslen(text)), format.Get(), &rect, brush.Get());
}

void OverlayRenderer::SetFPS(double fps) {
    currentFps_ = fps;
}

void OverlayRenderer::SetResolution(int width, int height) {
    resolutionWidth_ = width;
    resolutionHeight_ = height;
}

void OverlayRenderer::SetCaptureTime(double timeMs) {
    captureTimeMs_ = timeMs;
}

void OverlayRenderer::SetRenderTime(double timeMs) {
    renderTimeMs_ = timeMs;
}

void OverlayRenderer::SetPresentTime(double timeMs) {
    presentTimeMs_ = timeMs;
}

void OverlayRenderer::SetApiName(const wchar_t* name) {
    apiName_ = name;
}

void OverlayRenderer::UpdateStats() {
    // Stats are updated via Set methods
}

void OverlayRenderer::ResetTarget() {
    d2dBitmap_.Reset();
}
