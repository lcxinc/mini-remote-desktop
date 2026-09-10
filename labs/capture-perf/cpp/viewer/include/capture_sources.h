#pragma once

#include "desktop_duplication_capture.h"
#include "viewer_options.h"

#include <d3d11.h>

#include <memory>
#include <string>

class ICaptureSource {
public:
    virtual ~ICaptureSource() = default;

    virtual bool Initialize(ID3D11Device* device) = 0;
    virtual CaptureFrameResult AcquireNextFrame(UINT timeout_ms) = 0;
    virtual void ReleaseFrame() = 0;
    virtual void Reset() = 0;

    virtual int GetWidth() const = 0;
    virtual int GetHeight() const = 0;
    virtual std::string ApiName() const = 0;
    virtual std::wstring OverlayName() const = 0;
};

std::unique_ptr<ICaptureSource> CreateCaptureSource(CaptureSourceKind source);
