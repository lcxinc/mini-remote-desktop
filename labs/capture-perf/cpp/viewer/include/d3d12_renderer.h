#pragma once

#include "renderer.h"
#include <d3d11.h>
#include <d3d11on12.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <DirectXMath.h>
#include <string>

using Microsoft::WRL::ComPtr;

class D3D12Renderer : public Renderer {
public:
    D3D12Renderer();
    ~D3D12Renderer() override;

    bool Initialize(HWND hwnd, int width, int height) override;
    void Render(ID3D11Texture2D* sourceTexture) override;
    void Present() override;
    void Resize(int width, int height) override;
    void Clear() override;

    void SetOverlayText(const wchar_t* text) override;

    ID3D11Device* GetCaptureDevice() const { return d3d11Device_.Get(); }

    void SetFPS(double) {}
    void SetResolution(int, int) {}
    void SetCaptureTime(double) {}
    void SetRenderTime(double) {}
    void SetPresentTime(double) {}
    void SetApiName(const wchar_t*) {}

private:
    bool CreateDevice();
    bool CreateCommandQueue();
    bool CreateSwapChain();
    bool CreateRenderTargets();
    bool CreateCommandList();
    bool CreatePipelineState();
    bool CreateVertexBuffer();
    bool CreateDescriptorHeap();
    bool CreateFence();
    bool CreateCaptureDevice();
    bool ResolveSourceResource(
        ID3D11Texture2D* sourceTexture,
        Microsoft::WRL::ComPtr<ID3D12Resource>& texture12,
        bool& unwrapped);
    bool EnsureFallbackTexture(const D3D11_TEXTURE2D_DESC& sourceDesc);
    void WaitForGpu();

    void RenderOverlay();

    // D3D12 objects
    ComPtr<ID3D12Device> device_;
    ComPtr<ID3D12CommandQueue> commandQueue_;
    ComPtr<ID3D12CommandAllocator> commandAllocator_;
    ComPtr<ID3D12GraphicsCommandList> commandList_;
    ComPtr<IDXGISwapChain3> swapChain_;
    ComPtr<ID3D12DescriptorHeap> rtvHeap_;
    ComPtr<ID3D12DescriptorHeap> srvHeap_;
    ComPtr<ID3D12PipelineState> pipelineState_;
    ComPtr<ID3D12RootSignature> rootSignature_;
    ComPtr<ID3D12Resource> renderTargets_[2];
    ComPtr<ID3D12Resource> vertexBuffer_;
    ComPtr<ID3D12Fence> fence_;
    ComPtr<ID3D12Resource> sharedTexture12_;

    ComPtr<ID3D11Device> d3d11Device_;
    ComPtr<ID3D11DeviceContext> d3d11Context_;
    ComPtr<ID3D11Texture2D> sharedTexture11_;
    ComPtr<ID3D11Query> sharedCopyQuery_;
    ComPtr<IDXGIAdapter1> adapter_;

    D3D12_VERTEX_BUFFER_VIEW vertexBufferView_ = {};
    UINT64 fenceValue_ = 1;
    HANDLE fenceEvent_ = nullptr;

    UINT rtvDescriptorSize_;
    UINT srvDescriptorSize_;
    UINT frameIndex_ = 0;
    int textureWidth_ = 0;
    int textureHeight_ = 0;
    DXGI_FORMAT textureFormat_ = DXGI_FORMAT_UNKNOWN;
    bool lastRenderUsedZeroCopy_ = false;

    // Overlay text
    std::wstring overlayText_;
    bool overlayDirty_ = true;
};
