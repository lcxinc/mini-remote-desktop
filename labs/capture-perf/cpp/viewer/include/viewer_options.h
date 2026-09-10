#pragma once

#include <string>
#include <vector>

enum class CaptureSourceKind {
    DesktopDuplication,
    WindowsGraphicsCapture,
    SharedMemoryDesktopDuplication,
};

struct ViewerOptions {
    CaptureSourceKind source = CaptureSourceKind::DesktopDuplication;
    int duration_seconds = 0;
};

ViewerOptions ParseViewerOptions(const std::vector<std::wstring>& args);
std::vector<std::wstring> GetCommandLineArgs();

std::string SourceKindToApiName(CaptureSourceKind source);
std::wstring SourceKindToOverlayName(CaptureSourceKind source);
