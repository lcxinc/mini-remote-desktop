#include "viewer_options.h"

#include <cassert>
#include <string>
#include <vector>

int main() {
    {
        std::vector<std::wstring> args = {L"viewer.exe"};
        ViewerOptions options = ParseViewerOptions(args);
        assert(options.source == CaptureSourceKind::DesktopDuplication);
        assert(options.duration_seconds == 0);
        assert(SourceKindToApiName(options.source) == std::string("DesktopDuplication"));
    }

    {
        std::vector<std::wstring> args = {
            L"viewer.exe",
            L"--source",
            L"wgc",
            L"--duration",
            L"3",
        };
        ViewerOptions options = ParseViewerOptions(args);
        assert(options.source == CaptureSourceKind::WindowsGraphicsCapture);
        assert(options.duration_seconds == 3);
        assert(SourceKindToApiName(options.source) == std::string("WindowsGraphicsCapture"));
    }

    {
        std::vector<std::wstring> args = {
            L"viewer.exe",
            L"--source=shared-memory",
            L"--duration=7",
        };
        ViewerOptions options = ParseViewerOptions(args);
        assert(options.source == CaptureSourceKind::SharedMemoryDesktopDuplication);
        assert(options.duration_seconds == 7);
        assert(SourceKindToOverlayName(options.source) == std::wstring(L"Desktop Duplication -> Shared Memory -> D3D11"));
    }

    {
        std::vector<std::wstring> args = {L"viewer.exe", L"--source", L"unknown"};
        ViewerOptions options = ParseViewerOptions(args);
        assert(options.source == CaptureSourceKind::DesktopDuplication);
    }

    return 0;
}
