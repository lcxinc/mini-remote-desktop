#pragma once

#include <d3d11.h>
#include <wrl/client.h>
#include <string>

using Microsoft::WRL::ComPtr;

class Renderer {
public:
    virtual ~Renderer() = default;

    virtual bool Initialize(HWND hwnd, int width, int height) = 0;
    virtual void Render(ID3D11Texture2D* sourceTexture) = 0;
    virtual void Present() = 0;
    virtual void Resize(int width, int height) = 0;

    virtual void SetOverlayText(const wchar_t* text) {}
    virtual void Clear() = 0;

protected:
    int width_ = 0;
    int height_ = 0;
    HWND hwnd_ = nullptr;
};
