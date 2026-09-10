#include "viewer_options.h"

#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cwctype>

namespace {

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool TryParsePositiveInt(const std::wstring& value, int& output) {
    if (value.empty()) {
        return false;
    }

    int result = 0;
    for (wchar_t ch : value) {
        if (ch < L'0' || ch > L'9') {
            return false;
        }
        result = result * 10 + (ch - L'0');
    }

    output = result;
    return true;
}

CaptureSourceKind ParseSourceKind(const std::wstring& value) {
    const std::wstring source = ToLower(value);
    if (source == L"wgc" || source == L"graphics-capture" || source == L"windows-graphics-capture") {
        return CaptureSourceKind::WindowsGraphicsCapture;
    }
    if (source == L"shared" || source == L"shared-memory" || source == L"shared-memory-dd") {
        return CaptureSourceKind::SharedMemoryDesktopDuplication;
    }
    return CaptureSourceKind::DesktopDuplication;
}

bool TryConsumeValue(
    const std::vector<std::wstring>& args,
    size_t& index,
    const std::wstring& arg,
    const std::wstring& name,
    std::wstring& value) {
    const std::wstring prefix = name + L"=";
    if (arg == name) {
        if (index + 1 >= args.size()) {
            return false;
        }
        value = args[++index];
        return true;
    }
    if (arg.rfind(prefix, 0) == 0) {
        value = arg.substr(prefix.size());
        return true;
    }
    return false;
}

}  // namespace

ViewerOptions ParseViewerOptions(const std::vector<std::wstring>& args) {
    ViewerOptions options;

    for (size_t i = 1; i < args.size(); ++i) {
        std::wstring value;
        if (TryConsumeValue(args, i, args[i], L"--source", value)) {
            options.source = ParseSourceKind(value);
            continue;
        }

        if (TryConsumeValue(args, i, args[i], L"--duration", value)) {
            int duration = 0;
            if (TryParsePositiveInt(value, duration)) {
                options.duration_seconds = duration;
            }
        }
    }

    return options;
}

std::vector<std::wstring> GetCommandLineArgs() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        return {};
    }

    std::vector<std::wstring> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    LocalFree(argv);
    return args;
}

std::string SourceKindToApiName(CaptureSourceKind source) {
    switch (source) {
        case CaptureSourceKind::WindowsGraphicsCapture:
            return "WindowsGraphicsCapture";
        case CaptureSourceKind::SharedMemoryDesktopDuplication:
            return "DesktopDuplicationSharedMemory";
        case CaptureSourceKind::DesktopDuplication:
        default:
            return "DesktopDuplication";
    }
}

std::wstring SourceKindToOverlayName(CaptureSourceKind source) {
    switch (source) {
        case CaptureSourceKind::WindowsGraphicsCapture:
            return L"Windows Graphics Capture -> D3D11";
        case CaptureSourceKind::SharedMemoryDesktopDuplication:
            return L"Desktop Duplication -> Shared Memory -> D3D11";
        case CaptureSourceKind::DesktopDuplication:
        default:
            return L"Desktop Duplication -> D3D11";
    }
}
