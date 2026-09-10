#include "d3d11_renderer.h"
#include <d2d1.h>
#include <dwrite.h>
#include <iostream>
#include <memory>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")

// Simple vertex shader for full-screen quad
static const char* vertexShaderCode = R"(
cbuffer ConstantBuffer : register(b0)
{
    float2 uvScale;
    float2 uvOffset;
};

struct VSInput
{
    float3 position : POSITION;
    float2 uv : TEXCOORD;
};

struct PSInput
{
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};

PSInput main(VSInput input)
{
    PSInput output;
    output.position = float4(input.position, 1.0);
    output.uv = input.uv * uvScale + uvOffset;
    return output;
}
)";

// Simple pixel shader
static const char* pixelShaderCode = R"(
Texture2D tex : register(t0);
SamplerState samplerState : register(s0);

struct PSInput
{
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};

float4 main(PSInput input) : SV_TARGET
{
    return tex.Sample(samplerState, input.uv);
}
)";

D3D11Renderer::D3D11Renderer() {
    overlayRenderer_ = std::make_unique<OverlayRenderer>();
}

D3D11Renderer::~D3D11Renderer() {
    if (context_) {
        context_->ClearState();
    }
}

bool D3D11Renderer::Initialize(HWND hwnd, int width, int height) {
    hwnd_ = hwnd;
    width_ = width;
    height_ = height;

    if (!CreateDeviceAndSwapChain()) return false;
    if (!CreateRenderTarget()) return false;
    if (!CreateShaders()) return false;
    if (!CreateVertexBuffer()) return false;
    if (!CreateSampler()) return false;

    // Initialize overlay renderer
    if (!overlayRenderer_->Initialize(device_.Get(), context_.Get())) {
        std::wcerr << L"Failed to initialize overlay renderer" << std::endl;
        // Continue without overlay
    }

    return true;
}

bool D3D11Renderer::CreateDeviceAndSwapChain() {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = width_;
    sd.BufferDesc.Height = height_;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd_;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;

    D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
    };

    UINT createFlags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
#ifdef _DEBUG
    createFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevel;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        createFlags,
        featureLevels,
        2,
        D3D11_SDK_VERSION,
        &sd,
        &swapChain_,
        &device_,
        &featureLevel,
        &context_
    );

    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D3D11 device: 0x" << std::hex << hr << std::endl;
        return false;
    }

    return true;
}

bool D3D11Renderer::CreateRenderTarget() {
    ComPtr<ID3D11Texture2D> backBuffer;
    HRESULT hr = swapChain_->GetBuffer(0, __uuidof(ID3D11Texture2D), &backBuffer);
    if (FAILED(hr)) return false;

    hr = device_->CreateRenderTargetView(backBuffer.Get(), nullptr, &renderTargetView_);
    if (FAILED(hr)) return false;

    D3D11_VIEWPORT vp = {};
    vp.Width = (float)width_;
    vp.Height = (float)height_;
    vp.MinDepth = 0.0f;
    vp.MaxDepth = 1.0f;
    vp.TopLeftX = 0;
    vp.TopLeftY = 0;
    context_->RSSetViewports(1, &vp);

    return true;
}

bool D3D11Renderer::CreateShaders() {
    // Compile vertex shader
    ComPtr<ID3DBlob> vsBlob, psBlob;
    HRESULT hr = D3DCompile(
        vertexShaderCode,
        strlen(vertexShaderCode),
        nullptr,
        nullptr,
        nullptr,
        "main",
        "vs_5_0",
        0,
        0,
        &vsBlob,
        nullptr
    );
    if (FAILED(hr)) {
        std::wcerr << L"Failed to compile vertex shader" << std::endl;
        return false;
    }

    hr = device_->CreateVertexShader(
        vsBlob->GetBufferPointer(),
        vsBlob->GetBufferSize(),
        nullptr,
        &vertexShader_
    );
    if (FAILED(hr)) return false;

    // Compile pixel shader
    hr = D3DCompile(
        pixelShaderCode,
        strlen(pixelShaderCode),
        nullptr,
        nullptr,
        nullptr,
        "main",
        "ps_5_0",
        0,
        0,
        &psBlob,
        nullptr
    );
    if (FAILED(hr)) {
        std::wcerr << L"Failed to compile pixel shader" << std::endl;
        return false;
    }

    hr = device_->CreatePixelShader(
        psBlob->GetBufferPointer(),
        psBlob->GetBufferSize(),
        nullptr,
        &pixelShader_
    );
    if (FAILED(hr)) return false;

    // Create input layout
    D3D11_INPUT_ELEMENT_DESC layout[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };

    hr = device_->CreateInputLayout(
        layout,
        2,
        vsBlob->GetBufferPointer(),
        vsBlob->GetBufferSize(),
        &inputLayout_
    );

    return SUCCEEDED(hr);
}

bool D3D11Renderer::CreateVertexBuffer() {
    // Full-screen quad with UV coordinates
    Vertex vertices[] = {
        { DirectX::XMFLOAT3(-1.0f,  1.0f, 0.0f), DirectX::XMFLOAT2(0.0f, 0.0f) },
        { DirectX::XMFLOAT3( 1.0f,  1.0f, 0.0f), DirectX::XMFLOAT2(1.0f, 0.0f) },
        { DirectX::XMFLOAT3(-1.0f, -1.0f, 0.0f), DirectX::XMFLOAT2(0.0f, 1.0f) },
        { DirectX::XMFLOAT3( 1.0f, -1.0f, 0.0f), DirectX::XMFLOAT2(1.0f, 1.0f) },
    };

    D3D11_BUFFER_DESC bd = {};
    bd.Usage = D3D11_USAGE_IMMUTABLE;
    bd.ByteWidth = sizeof(vertices);
    bd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    bd.CPUAccessFlags = 0;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = vertices;

    HRESULT hr = device_->CreateBuffer(&bd, &initData, &vertexBuffer_);
    return SUCCEEDED(hr);
}

bool D3D11Renderer::CreateSampler() {
    D3D11_SAMPLER_DESC sd = {};
    sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    sd.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
    sd.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
    sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    sd.MinLOD = 0;
    sd.MaxLOD = D3D11_FLOAT32_MAX;

    HRESULT hr = device_->CreateSamplerState(&sd, &samplerState_);
    return SUCCEEDED(hr);
}

void D3D11Renderer::Render(ID3D11Texture2D* sourceTexture) {
    if (!sourceTexture) return;

    float clearColor[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
    context_->ClearRenderTargetView(renderTargetView_.Get(), clearColor);

    context_->OMSetRenderTargets(1, renderTargetView_.GetAddressOf(), nullptr);
    context_->IASetInputLayout(inputLayout_.Get());

    UINT stride = sizeof(Vertex);
    UINT offset = 0;
    context_->IASetVertexBuffers(0, 1, vertexBuffer_.GetAddressOf(), &stride, &offset);
    context_->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);

    context_->VSSetShader(vertexShader_.Get(), nullptr, 0);
    context_->PSSetShader(pixelShader_.Get(), nullptr, 0);
    context_->PSSetSamplers(0, 1, samplerState_.GetAddressOf());

    // Create shader resource view from source texture
    D3D11_TEXTURE2D_DESC desc;
    sourceTexture->GetDesc(&desc);

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = desc.Format;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = 1;

    ComPtr<ID3D11ShaderResourceView> srv;
    if (SUCCEEDED(device_->CreateShaderResourceView(sourceTexture, &srvDesc, &srv))) {
        context_->PSSetShaderResources(0, 1, srv.GetAddressOf());
    }

    context_->Draw(4, 0);

    ID3D11ShaderResourceView* nullSrv[] = { nullptr };
    context_->PSSetShaderResources(0, 1, nullSrv);

    // Render overlay
    RenderOverlay();
}

void D3D11Renderer::RenderOverlay() {
    if (!overlayRenderer_) return;

    // Get back buffer for overlay rendering
    ComPtr<ID3D11Texture2D> backBuffer;
    HRESULT hr = swapChain_->GetBuffer(0, __uuidof(ID3D11Texture2D), &backBuffer);
    if (SUCCEEDED(hr)) {
        overlayRenderer_->Render(backBuffer.Get(), width_, height_);
    }
}

void D3D11Renderer::Present() {
    swapChain_->Present(1, 0);
}

void D3D11Renderer::Clear() {
    float clearColor[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
    context_->ClearRenderTargetView(renderTargetView_.Get(), clearColor);
}

void D3D11Renderer::Resize(int width, int height) {
    width_ = width;
    height_ = height;

    context_->ClearState();
    renderTargetView_.Reset();
    if (overlayRenderer_) {
        overlayRenderer_->ResetTarget();
    }

    HRESULT hr = swapChain_->ResizeBuffers(
        2,
        width,
        height,
        DXGI_FORMAT_R8G8B8A8_UNORM,
        0
    );

    if (SUCCEEDED(hr)) {
        CreateRenderTarget();
    }

    D3D11_VIEWPORT vp = {};
    vp.Width = (float)width_;
    vp.Height = (float)height_;
    vp.MinDepth = 0.0f;
    vp.MaxDepth = 1.0f;
    vp.TopLeftX = 0;
    vp.TopLeftY = 0;
    context_->RSSetViewports(1, &vp);
}

void D3D11Renderer::SetOverlayText(const wchar_t* text) {
    overlayText_ = text;
    overlayDirty_ = true;
}
