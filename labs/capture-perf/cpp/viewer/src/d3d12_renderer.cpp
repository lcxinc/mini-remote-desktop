#include "d3d12_renderer.h"

#include <array>
#include <cstring>
#include <iostream>

namespace {

constexpr UINT kFrameCount = 2;

const char* kVertexShaderCode = R"(
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
    output.uv = input.uv;
    return output;
}
)";

const char* kPixelShaderCode = R"(
Texture2D sourceTexture : register(t0);
SamplerState sourceSampler : register(s0);

struct PSInput
{
    float4 position : SV_POSITION;
    float2 uv : TEXCOORD;
};

float4 main(PSInput input) : SV_TARGET
{
    return sourceTexture.Sample(sourceSampler, input.uv);
}
)";

struct D3D12Vertex {
    DirectX::XMFLOAT3 position;
    DirectX::XMFLOAT2 uv;
};

D3D12_RESOURCE_BARRIER TransitionBarrier(
    ID3D12Resource* resource,
    D3D12_RESOURCE_STATES before,
    D3D12_RESOURCE_STATES after) {
    D3D12_RESOURCE_BARRIER barrier = {};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
    barrier.Transition.pResource = resource;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = before;
    barrier.Transition.StateAfter = after;
    return barrier;
}

DXGI_FORMAT NormalizeTextureFormat(DXGI_FORMAT format) {
    switch (format) {
        case DXGI_FORMAT_B8G8R8A8_UNORM:
        case DXGI_FORMAT_R8G8B8A8_UNORM:
            return format;
        default:
            return DXGI_FORMAT_B8G8R8A8_UNORM;
    }
}

}  // namespace

D3D12Renderer::D3D12Renderer() = default;

D3D12Renderer::~D3D12Renderer() {
    WaitForGpu();
    if (fenceEvent_) {
        CloseHandle(fenceEvent_);
        fenceEvent_ = nullptr;
    }
}

bool D3D12Renderer::Initialize(HWND hwnd, int width, int height) {
    hwnd_ = hwnd;
    width_ = width;
    height_ = height;

    if (!CreateDevice()) return false;
    if (!CreateCommandQueue()) return false;
    if (!CreateSwapChain()) return false;
    if (!CreateRenderTargets()) return false;
    if (!CreateCommandList()) return false;
    if (!CreateDescriptorHeap()) return false;
    if (!CreatePipelineState()) return false;
    if (!CreateVertexBuffer()) return false;
    if (!CreateFence()) return false;
    if (!CreateCaptureDevice()) return false;

    return true;
}

bool D3D12Renderer::CreateDevice() {
    UINT dxgiFactoryFlags = 0;
#ifdef _DEBUG
    ComPtr<ID3D12Debug> debugController;
    if (SUCCEEDED(D3D12GetDebugInterface(IID_PPV_ARGS(&debugController)))) {
        debugController->EnableDebugLayer();
        dxgiFactoryFlags |= DXGI_CREATE_FACTORY_DEBUG;
    }
#endif

    ComPtr<IDXGIFactory6> factory;
    HRESULT hr = CreateDXGIFactory2(dxgiFactoryFlags, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create DXGI factory: 0x" << std::hex << hr << std::endl;
        return false;
    }

    ComPtr<IDXGIAdapter1> adapter;
    for (UINT index = 0; factory->EnumAdapters1(index, &adapter) != DXGI_ERROR_NOT_FOUND; ++index) {
        DXGI_ADAPTER_DESC1 desc = {};
        adapter->GetDesc1(&desc);
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            continue;
        }

        hr = D3D12CreateDevice(adapter.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device_));
        if (SUCCEEDED(hr)) {
            adapter_ = adapter;
            return true;
        }
    }

    hr = D3D12CreateDevice(nullptr, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device_));
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D3D12 device: 0x" << std::hex << hr << std::endl;
        return false;
    }

    return true;
}

bool D3D12Renderer::CreateCommandQueue() {
    D3D12_COMMAND_QUEUE_DESC queueDesc = {};
    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    queueDesc.Priority = D3D12_COMMAND_QUEUE_PRIORITY_NORMAL;
    queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
    queueDesc.NodeMask = 0;

    HRESULT hr = device_->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&commandQueue_));
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D3D12 command queue: 0x" << std::hex << hr << std::endl;
        return false;
    }

    return true;
}

bool D3D12Renderer::CreateSwapChain() {
    ComPtr<IDXGIFactory4> factory;
    HRESULT hr = CreateDXGIFactory2(0, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        return false;
    }

    DXGI_SWAP_CHAIN_DESC1 swapChainDesc = {};
    swapChainDesc.Width = width_;
    swapChainDesc.Height = height_;
    swapChainDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapChainDesc.Stereo = FALSE;
    swapChainDesc.SampleDesc.Count = 1;
    swapChainDesc.SampleDesc.Quality = 0;
    swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapChainDesc.BufferCount = kFrameCount;
    swapChainDesc.Scaling = DXGI_SCALING_STRETCH;
    swapChainDesc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    swapChainDesc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;

    ComPtr<IDXGISwapChain1> swapChain1;
    hr = factory->CreateSwapChainForHwnd(
        commandQueue_.Get(),
        hwnd_,
        &swapChainDesc,
        nullptr,
        nullptr,
        &swapChain1);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D3D12 swap chain: 0x" << std::hex << hr << std::endl;
        return false;
    }

    factory->MakeWindowAssociation(hwnd_, DXGI_MWA_NO_ALT_ENTER);

    hr = swapChain1.As(&swapChain_);
    if (FAILED(hr)) {
        return false;
    }

    frameIndex_ = swapChain_->GetCurrentBackBufferIndex();
    return true;
}

bool D3D12Renderer::CreateRenderTargets() {
    for (auto& target : renderTargets_) {
        target.Reset();
    }
    rtvHeap_.Reset();

    D3D12_DESCRIPTOR_HEAP_DESC rtvHeapDesc = {};
    rtvHeapDesc.NumDescriptors = kFrameCount;
    rtvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    rtvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;

    HRESULT hr = device_->CreateDescriptorHeap(&rtvHeapDesc, IID_PPV_ARGS(&rtvHeap_));
    if (FAILED(hr)) {
        return false;
    }

    rtvDescriptorSize_ = device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

    D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = rtvHeap_->GetCPUDescriptorHandleForHeapStart();
    for (UINT index = 0; index < kFrameCount; ++index) {
        hr = swapChain_->GetBuffer(index, IID_PPV_ARGS(&renderTargets_[index]));
        if (FAILED(hr)) {
            return false;
        }

        device_->CreateRenderTargetView(renderTargets_[index].Get(), nullptr, rtvHandle);
        rtvHandle.ptr += rtvDescriptorSize_;
    }

    return true;
}

bool D3D12Renderer::CreateCommandList() {
    HRESULT hr = device_->CreateCommandAllocator(
        D3D12_COMMAND_LIST_TYPE_DIRECT,
        IID_PPV_ARGS(&commandAllocator_));
    if (FAILED(hr)) {
        return false;
    }

    hr = device_->CreateCommandList(
        0,
        D3D12_COMMAND_LIST_TYPE_DIRECT,
        commandAllocator_.Get(),
        nullptr,
        IID_PPV_ARGS(&commandList_));
    if (FAILED(hr)) {
        return false;
    }

    commandList_->Close();
    return true;
}

bool D3D12Renderer::CreateDescriptorHeap() {
    D3D12_DESCRIPTOR_HEAP_DESC srvHeapDesc = {};
    srvHeapDesc.NumDescriptors = 1;
    srvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    srvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

    HRESULT hr = device_->CreateDescriptorHeap(&srvHeapDesc, IID_PPV_ARGS(&srvHeap_));
    if (FAILED(hr)) {
        return false;
    }

    srvDescriptorSize_ =
        device_->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    return true;
}

bool D3D12Renderer::CreatePipelineState() {
    D3D12_DESCRIPTOR_RANGE srvRange = {};
    srvRange.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    srvRange.NumDescriptors = 1;
    srvRange.BaseShaderRegister = 0;
    srvRange.RegisterSpace = 0;
    srvRange.OffsetInDescriptorsFromTableStart = D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND;

    D3D12_ROOT_PARAMETER rootParameter = {};
    rootParameter.ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    rootParameter.DescriptorTable.NumDescriptorRanges = 1;
    rootParameter.DescriptorTable.pDescriptorRanges = &srvRange;
    rootParameter.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

    D3D12_STATIC_SAMPLER_DESC samplerDesc = {};
    samplerDesc.Filter = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
    samplerDesc.AddressU = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    samplerDesc.AddressV = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    samplerDesc.AddressW = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
    samplerDesc.MipLODBias = 0.0f;
    samplerDesc.MaxAnisotropy = 1;
    samplerDesc.ComparisonFunc = D3D12_COMPARISON_FUNC_ALWAYS;
    samplerDesc.BorderColor = D3D12_STATIC_BORDER_COLOR_OPAQUE_BLACK;
    samplerDesc.MinLOD = 0.0f;
    samplerDesc.MaxLOD = D3D12_FLOAT32_MAX;
    samplerDesc.ShaderRegister = 0;
    samplerDesc.RegisterSpace = 0;
    samplerDesc.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

    D3D12_ROOT_SIGNATURE_DESC rootSignatureDesc = {};
    rootSignatureDesc.NumParameters = 1;
    rootSignatureDesc.pParameters = &rootParameter;
    rootSignatureDesc.NumStaticSamplers = 1;
    rootSignatureDesc.pStaticSamplers = &samplerDesc;
    rootSignatureDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;

    ComPtr<ID3DBlob> signature;
    ComPtr<ID3DBlob> error;
    HRESULT hr = D3D12SerializeRootSignature(
        &rootSignatureDesc,
        D3D_ROOT_SIGNATURE_VERSION_1,
        &signature,
        &error);
    if (FAILED(hr)) {
        if (error) {
            std::cerr << static_cast<const char*>(error->GetBufferPointer()) << std::endl;
        }
        return false;
    }

    hr = device_->CreateRootSignature(
        0,
        signature->GetBufferPointer(),
        signature->GetBufferSize(),
        IID_PPV_ARGS(&rootSignature_));
    if (FAILED(hr)) {
        return false;
    }

    ComPtr<ID3DBlob> vsBlob;
    ComPtr<ID3DBlob> psBlob;
    hr = D3DCompile(
        kVertexShaderCode,
        std::strlen(kVertexShaderCode),
        nullptr,
        nullptr,
        nullptr,
        "main",
        "vs_5_0",
        0,
        0,
        &vsBlob,
        &error);
    if (FAILED(hr)) {
        if (error) {
            std::cerr << static_cast<const char*>(error->GetBufferPointer()) << std::endl;
        }
        return false;
    }

    hr = D3DCompile(
        kPixelShaderCode,
        std::strlen(kPixelShaderCode),
        nullptr,
        nullptr,
        nullptr,
        "main",
        "ps_5_0",
        0,
        0,
        &psBlob,
        &error);
    if (FAILED(hr)) {
        if (error) {
            std::cerr << static_cast<const char*>(error->GetBufferPointer()) << std::endl;
        }
        return false;
    }

    D3D12_INPUT_ELEMENT_DESC inputLayout[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0,
          D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
        { "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 12,
          D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
    };

    D3D12_RASTERIZER_DESC rasterizerDesc = {};
    rasterizerDesc.FillMode = D3D12_FILL_MODE_SOLID;
    rasterizerDesc.CullMode = D3D12_CULL_MODE_NONE;
    rasterizerDesc.FrontCounterClockwise = FALSE;
    rasterizerDesc.DepthBias = D3D12_DEFAULT_DEPTH_BIAS;
    rasterizerDesc.DepthBiasClamp = D3D12_DEFAULT_DEPTH_BIAS_CLAMP;
    rasterizerDesc.SlopeScaledDepthBias = D3D12_DEFAULT_SLOPE_SCALED_DEPTH_BIAS;
    rasterizerDesc.DepthClipEnable = TRUE;
    rasterizerDesc.MultisampleEnable = FALSE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;
    rasterizerDesc.ForcedSampleCount = 0;
    rasterizerDesc.ConservativeRaster = D3D12_CONSERVATIVE_RASTERIZATION_MODE_OFF;

    D3D12_BLEND_DESC blendDesc = {};
    blendDesc.AlphaToCoverageEnable = FALSE;
    blendDesc.IndependentBlendEnable = FALSE;
    blendDesc.RenderTarget[0].BlendEnable = FALSE;
    blendDesc.RenderTarget[0].LogicOpEnable = FALSE;
    blendDesc.RenderTarget[0].SrcBlend = D3D12_BLEND_ONE;
    blendDesc.RenderTarget[0].DestBlend = D3D12_BLEND_ZERO;
    blendDesc.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
    blendDesc.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
    blendDesc.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_ZERO;
    blendDesc.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
    blendDesc.RenderTarget[0].LogicOp = D3D12_LOGIC_OP_NOOP;
    blendDesc.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;

    D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc = {};
    psoDesc.InputLayout = { inputLayout, 2 };
    psoDesc.pRootSignature = rootSignature_.Get();
    psoDesc.VS = { vsBlob->GetBufferPointer(), vsBlob->GetBufferSize() };
    psoDesc.PS = { psBlob->GetBufferPointer(), psBlob->GetBufferSize() };
    psoDesc.RasterizerState = rasterizerDesc;
    psoDesc.BlendState = blendDesc;
    psoDesc.DepthStencilState.DepthEnable = FALSE;
    psoDesc.DepthStencilState.StencilEnable = FALSE;
    psoDesc.SampleMask = UINT_MAX;
    psoDesc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
    psoDesc.NumRenderTargets = 1;
    psoDesc.RTVFormats[0] = DXGI_FORMAT_R8G8B8A8_UNORM;
    psoDesc.SampleDesc.Count = 1;

    hr = device_->CreateGraphicsPipelineState(&psoDesc, IID_PPV_ARGS(&pipelineState_));
    return SUCCEEDED(hr);
}

bool D3D12Renderer::CreateVertexBuffer() {
    D3D12Vertex vertices[] = {
        { DirectX::XMFLOAT3(-1.0f,  1.0f, 0.0f), DirectX::XMFLOAT2(0.0f, 0.0f) },
        { DirectX::XMFLOAT3( 1.0f,  1.0f, 0.0f), DirectX::XMFLOAT2(1.0f, 0.0f) },
        { DirectX::XMFLOAT3(-1.0f, -1.0f, 0.0f), DirectX::XMFLOAT2(0.0f, 1.0f) },
        { DirectX::XMFLOAT3( 1.0f, -1.0f, 0.0f), DirectX::XMFLOAT2(1.0f, 1.0f) },
    };

    const UINT vertexBufferSize = sizeof(vertices);

    D3D12_HEAP_PROPERTIES heapProps = {};
    heapProps.Type = D3D12_HEAP_TYPE_UPLOAD;

    D3D12_RESOURCE_DESC resourceDesc = {};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Width = vertexBufferSize;
    resourceDesc.Height = 1;
    resourceDesc.DepthOrArraySize = 1;
    resourceDesc.MipLevels = 1;
    resourceDesc.Format = DXGI_FORMAT_UNKNOWN;
    resourceDesc.SampleDesc.Count = 1;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

    HRESULT hr = device_->CreateCommittedResource(
        &heapProps,
        D3D12_HEAP_FLAG_NONE,
        &resourceDesc,
        D3D12_RESOURCE_STATE_GENERIC_READ,
        nullptr,
        IID_PPV_ARGS(&vertexBuffer_));
    if (FAILED(hr)) {
        return false;
    }

    void* data = nullptr;
    D3D12_RANGE readRange = { 0, 0 };
    hr = vertexBuffer_->Map(0, &readRange, &data);
    if (FAILED(hr)) {
        return false;
    }
    std::memcpy(data, vertices, vertexBufferSize);
    vertexBuffer_->Unmap(0, nullptr);

    vertexBufferView_.BufferLocation = vertexBuffer_->GetGPUVirtualAddress();
    vertexBufferView_.SizeInBytes = vertexBufferSize;
    vertexBufferView_.StrideInBytes = sizeof(D3D12Vertex);
    return true;
}

bool D3D12Renderer::CreateFence() {
    HRESULT hr = device_->CreateFence(0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence_));
    if (FAILED(hr)) {
        return false;
    }

    fenceEvent_ = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    return fenceEvent_ != nullptr;
}

bool D3D12Renderer::CreateCaptureDevice() {
    const D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
    };

    D3D_FEATURE_LEVEL chosenLevel = D3D_FEATURE_LEVEL_11_0;
    HRESULT hr = D3D11CreateDevice(
        adapter_.Get(),
        adapter_ ? D3D_DRIVER_TYPE_UNKNOWN : D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        featureLevels,
        static_cast<UINT>(sizeof(featureLevels) / sizeof(featureLevels[0])),
        D3D11_SDK_VERSION,
        &d3d11Device_,
        &chosenLevel,
        &d3d11Context_);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create D3D11 capture device: 0x" << std::hex << hr << std::endl;
        return false;
    }

    return true;
}

bool D3D12Renderer::EnsureFallbackTexture(const D3D11_TEXTURE2D_DESC& sourceDesc) {
    const DXGI_FORMAT format = NormalizeTextureFormat(sourceDesc.Format);
    if (sharedTexture12_ &&
        textureWidth_ == static_cast<int>(sourceDesc.Width) &&
        textureHeight_ == static_cast<int>(sourceDesc.Height) &&
        textureFormat_ == format) {
        return true;
    }

    WaitForGpu();
    sharedCopyQuery_.Reset();
    sharedTexture11_.Reset();
    sharedTexture12_.Reset();

    D3D11_TEXTURE2D_DESC sharedDesc = {};
    sharedDesc.Width = sourceDesc.Width;
    sharedDesc.Height = sourceDesc.Height;
    sharedDesc.MipLevels = 1;
    sharedDesc.ArraySize = 1;
    sharedDesc.Format = format;
    sharedDesc.SampleDesc.Count = 1;
    sharedDesc.Usage = D3D11_USAGE_DEFAULT;
    sharedDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    sharedDesc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE;

    HRESULT hr = d3d11Device_->CreateTexture2D(&sharedDesc, nullptr, &sharedTexture11_);
    if (FAILED(hr)) {
        return false;
    }

    ComPtr<IDXGIResource1> dxgiResource;
    hr = sharedTexture11_.As(&dxgiResource);
    if (FAILED(hr)) {
        sharedTexture11_.Reset();
        return false;
    }

    HANDLE sharedHandle = nullptr;
    hr = dxgiResource->CreateSharedHandle(
        nullptr,
        DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
        nullptr,
        &sharedHandle);
    if (FAILED(hr)) {
        sharedTexture11_.Reset();
        return false;
    }

    hr = device_->OpenSharedHandle(sharedHandle, IID_PPV_ARGS(&sharedTexture12_));
    CloseHandle(sharedHandle);
    if (FAILED(hr)) {
        sharedTexture11_.Reset();
        return false;
    }

    D3D11_QUERY_DESC queryDesc = {};
    queryDesc.Query = D3D11_QUERY_EVENT;
    hr = d3d11Device_->CreateQuery(&queryDesc, &sharedCopyQuery_);
    if (FAILED(hr)) {
        sharedTexture12_.Reset();
        sharedTexture11_.Reset();
        return false;
    }

    textureWidth_ = static_cast<int>(sourceDesc.Width);
    textureHeight_ = static_cast<int>(sourceDesc.Height);
    textureFormat_ = format;
    return true;
}

bool D3D12Renderer::ResolveSourceResource(
    ID3D11Texture2D* sourceTexture,
    ComPtr<ID3D12Resource>& texture12,
    bool& unwrapped) {
    unwrapped = false;
    texture12.Reset();

    if (!sourceTexture) {
        return false;
    }

    D3D11_TEXTURE2D_DESC sourceDesc = {};
    sourceTexture->GetDesc(&sourceDesc);
    if (!EnsureFallbackTexture(sourceDesc)) {
        return false;
    }

    d3d11Context_->CopyResource(sharedTexture11_.Get(), sourceTexture);
    d3d11Context_->End(sharedCopyQuery_.Get());
    while (d3d11Context_->GetData(sharedCopyQuery_.Get(), nullptr, 0, 0) == S_FALSE) {
        Sleep(0);
    }

    texture12 = sharedTexture12_;
    lastRenderUsedZeroCopy_ = false;
    return true;
}

void D3D12Renderer::Render(ID3D11Texture2D* sourceTexture) {
    ComPtr<ID3D12Resource> source12;
    bool sourceUnwrapped = false;
    if (!ResolveSourceResource(sourceTexture, source12, sourceUnwrapped)) {
        return;
    }

    D3D12_RESOURCE_DESC sourceDesc = source12->GetDesc();

    D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = sourceDesc.Format;
    srvDesc.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    srvDesc.Texture2D.MipLevels = 1;
    device_->CreateShaderResourceView(
        source12.Get(),
        &srvDesc,
        srvHeap_->GetCPUDescriptorHandleForHeapStart());

    commandAllocator_->Reset();
    commandList_->Reset(commandAllocator_.Get(), pipelineState_.Get());

    auto toRenderTarget = TransitionBarrier(
        renderTargets_[frameIndex_].Get(),
        D3D12_RESOURCE_STATE_PRESENT,
        D3D12_RESOURCE_STATE_RENDER_TARGET);
    commandList_->ResourceBarrier(1, &toRenderTarget);

    D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = rtvHeap_->GetCPUDescriptorHandleForHeapStart();
    rtvHandle.ptr += frameIndex_ * rtvDescriptorSize_;
    commandList_->OMSetRenderTargets(1, &rtvHandle, FALSE, nullptr);

    const float clearColor[] = { 0.0f, 0.0f, 0.0f, 1.0f };
    commandList_->ClearRenderTargetView(rtvHandle, clearColor, 0, nullptr);

    D3D12_VIEWPORT viewport = {};
    viewport.TopLeftX = 0.0f;
    viewport.TopLeftY = 0.0f;
    viewport.Width = static_cast<float>(width_);
    viewport.Height = static_cast<float>(height_);
    viewport.MinDepth = 0.0f;
    viewport.MaxDepth = 1.0f;
    commandList_->RSSetViewports(1, &viewport);

    D3D12_RECT scissorRect = { 0, 0, width_, height_ };
    commandList_->RSSetScissorRects(1, &scissorRect);

    ID3D12DescriptorHeap* descriptorHeaps[] = { srvHeap_.Get() };
    commandList_->SetDescriptorHeaps(1, descriptorHeaps);
    commandList_->SetGraphicsRootSignature(rootSignature_.Get());
    commandList_->SetGraphicsRootDescriptorTable(
        0,
        srvHeap_->GetGPUDescriptorHandleForHeapStart());
    commandList_->SetPipelineState(pipelineState_.Get());

    commandList_->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
    commandList_->IASetVertexBuffers(0, 1, &vertexBufferView_);
    commandList_->DrawInstanced(4, 1, 0, 0);

    auto toPresent = TransitionBarrier(
        renderTargets_[frameIndex_].Get(),
        D3D12_RESOURCE_STATE_RENDER_TARGET,
        D3D12_RESOURCE_STATE_PRESENT);
    commandList_->ResourceBarrier(1, &toPresent);

    commandList_->Close();

    ID3D12CommandList* lists[] = { commandList_.Get() };
    commandQueue_->ExecuteCommandLists(1, lists);

    (void)sourceUnwrapped;
}

void D3D12Renderer::Present() {
    if (!swapChain_) {
        return;
    }

    HRESULT hr = swapChain_->Present(1, 0);
    if (SUCCEEDED(hr)) {
        frameIndex_ = swapChain_->GetCurrentBackBufferIndex();
    }
    WaitForGpu();
}

void D3D12Renderer::Clear() {}

void D3D12Renderer::Resize(int width, int height) {
    if (width <= 0 || height <= 0 || !swapChain_) {
        return;
    }

    WaitForGpu();

    width_ = width;
    height_ = height;
    for (auto& target : renderTargets_) {
        target.Reset();
    }

    DXGI_SWAP_CHAIN_DESC desc = {};
    swapChain_->GetDesc(&desc);
    HRESULT hr = swapChain_->ResizeBuffers(
        kFrameCount,
        width,
        height,
        desc.BufferDesc.Format,
        desc.Flags);
    if (SUCCEEDED(hr)) {
        frameIndex_ = swapChain_->GetCurrentBackBufferIndex();
        CreateRenderTargets();
    }
}

void D3D12Renderer::SetOverlayText(const wchar_t* text) {
    overlayText_ = text ? text : L"";
    overlayDirty_ = true;
}

void D3D12Renderer::RenderOverlay() {}

void D3D12Renderer::WaitForGpu() {
    if (!commandQueue_ || !fence_ || !fenceEvent_) {
        return;
    }

    const UINT64 signalValue = fenceValue_++;
    if (FAILED(commandQueue_->Signal(fence_.Get(), signalValue))) {
        return;
    }

    if (fence_->GetCompletedValue() < signalValue) {
        fence_->SetEventOnCompletion(signalValue, fenceEvent_);
        WaitForSingleObject(fenceEvent_, INFINITE);
    }
}
