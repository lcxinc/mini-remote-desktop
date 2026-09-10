#pragma once

#include <d3d11.h>
#include <d2d1_1.h>
#include <dwrite.h>
#include <wrl/client.h>
#include <string>
#include <sstream>
#include <iomanip>

using Microsoft::WRL::ComPtr;

class OverlayRenderer {
public:
    OverlayRenderer();
    ~OverlayRenderer();

    bool Initialize(ID3D11Device* d3d11Device, ID3D11DeviceContext* d3d11Context);
    void Render(ID3D11Texture2D* backBuffer, int width, int height);

    void SetFPS(double fps);
    void SetResolution(int width, int height);
    void SetCaptureTime(double timeMs);
    void SetRenderTime(double timeMs);
    void SetPresentTime(double timeMs);
    void SetApiName(const wchar_t* name);
    void UpdateStats();
    void ResetTarget();

private:
    bool CreateD2DResources();
    bool CreateDWriteResources();
    void RenderText(const wchar_t* text, float x, float y, float fontSize, D2D1::ColorF color);

    ComPtr<ID2D1Factory1> d2dFactory_;
    ComPtr<ID2D1Device> d2dDevice_;
    ComPtr<ID2D1DeviceContext> d2dContext_;
    ComPtr<ID2D1Bitmap1> d2dBitmap_;

    ComPtr<IDWriteFactory> dwriteFactory_;
    ComPtr<IDWriteTextFormat> textFormatSmall_;
    ComPtr<IDWriteTextFormat> textFormatLarge_;

    ID3D11Device* d3d11Device_ = nullptr;
    ID3D11DeviceContext* d3d11Context_ = nullptr;

    double currentFps_ = 0.0;
    int resolutionWidth_ = 0;
    int resolutionHeight_ = 0;
    double captureTimeMs_ = 0.0;
    double renderTimeMs_ = 0.0;
    double presentTimeMs_ = 0.0;
    std::wstring apiName_;
};
