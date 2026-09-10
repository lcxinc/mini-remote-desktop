#include "capture_sources.h"

#include <cassert>
#include <memory>

int main() {
    {
        std::unique_ptr<ICaptureSource> source =
            CreateCaptureSource(CaptureSourceKind::DesktopDuplication);
        assert(source);
        assert(source->ApiName() == std::string("DesktopDuplication"));
    }

    {
        std::unique_ptr<ICaptureSource> source =
            CreateCaptureSource(CaptureSourceKind::WindowsGraphicsCapture);
        assert(source);
        assert(source->ApiName() == std::string("WindowsGraphicsCapture"));
    }

    {
        std::unique_ptr<ICaptureSource> source =
            CreateCaptureSource(CaptureSourceKind::SharedMemoryDesktopDuplication);
        assert(source);
        assert(source->ApiName() == std::string("DesktopDuplicationSharedMemory"));
    }

    return 0;
}
