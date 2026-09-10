#pragma once

#include "renderer.h"
#include "overlay_renderer.h"
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <DirectXMath.h>
#include <string>
#include <memory>

using Microsoft::WRL::ComPtr;

struct Vertex {
    DirectX::XMFLOAT3 position;
    DirectX::XMFLOAT2 uv;
};

class D3D11Renderer : public Renderer {
public:
    D3D11Renderer();
    ~D3D11Renderer() override;

    bool Initialize(HWND hwnd, int width, int height) override;
    void Render(ID3D11Texture2D* sourceTexture) override;
    void Present() override;
    void Resize(int width, int height) override;
    void Clear() override;

    void SetOverlayText(const wchar_t* text) override;

    ID3D11Device* GetDevice() const { return device_.Get(); }
    ID3D11DeviceContext* GetContext() const { return context_.Get(); }

    // Overlay stats
    void SetFPS(double fps) { overlayRenderer_->SetFPS(fps); }
    void SetResolution(int width, int height) { overlayRenderer_->SetResolution(width, height); }
    void SetCaptureTime(double timeMs) { overlayRenderer_->SetCaptureTime(timeMs); }
    void SetRenderTime(double timeMs) { overlayRenderer_->SetRenderTime(timeMs); }
    void SetPresentTime(double timeMs) { overlayRenderer_->SetPresentTime(timeMs); }
    void SetApiName(const wchar_t* name) { overlayRenderer_->SetApiName(name); }

private:
    bool CreateDeviceAndSwapChain();
    bool CreateRenderTarget();
    bool CreateShaders();
    bool CreateVertexBuffer();
    bool CreateSampler();
    void RenderOverlay();

    ComPtr<ID3D11Device> device_;
    ComPtr<ID3D11DeviceContext> context_;
    ComPtr<IDXGISwapChain> swapChain_;
    ComPtr<ID3D11RenderTargetView> renderTargetView_;
    ComPtr<ID3D11VertexShader> vertexShader_;
    ComPtr<ID3D11PixelShader> pixelShader_;
    ComPtr<ID3D11InputLayout> inputLayout_;
    ComPtr<ID3D11Buffer> vertexBuffer_;
    ComPtr<ID3D11SamplerState> samplerState_;
    ComPtr<ID3D11ShaderResourceView> textureView_;

    std::unique_ptr<OverlayRenderer> overlayRenderer_;
    ComPtr<ID3D11Texture2D> backBuffer_;

    std::wstring overlayText_;
    bool overlayDirty_ = true;
};
