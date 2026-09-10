#include "capture_render_metrics.h"

#include <cmath>
#include <iostream>

namespace {

bool near(double actual, double expected) {
    return std::fabs(actual - expected) < 0.001;
}

int fail(const char* message) {
    std::cerr << message << '\n';
    return 1;
}

}  // namespace

int main() {
    CaptureRenderConfig config;
    config.api_name = "DesktopDuplication";
    config.language = "C++";
    config.renderer = "D3D11";
    config.width = 1920;
    config.height = 1080;

    CaptureRenderMetricsCollector collector(config);

    CaptureRenderFrameMetrics first;
    first.frame_number = 1;
    first.status = FrameStatus::Captured;
    first.capture_time_ms = 1.0;
    first.render_time_ms = 2.0;
    first.present_time_ms = 3.0;
    first.total_time_ms = 6.0;
    first.fps = 100.0;
    first.memory_mb = 50.0;
    first.width = 1920;
    first.height = 1080;
    collector.RecordFrame(first);

    CaptureRenderFrameMetrics second = first;
    second.frame_number = 2;
    second.capture_time_ms = 3.0;
    second.render_time_ms = 4.0;
    second.present_time_ms = 5.0;
    second.total_time_ms = 12.0;
    second.fps = 80.0;
    second.memory_mb = 70.0;
    collector.RecordFrame(second);

    const CaptureRenderStatistics stats = collector.CalculateStatistics();

    if (!near(stats.avg_capture_time_ms, 2.0)) return fail("avg capture time mismatch");
    if (!near(stats.avg_render_time_ms, 3.0)) return fail("avg render time mismatch");
    if (!near(stats.avg_present_time_ms, 4.0)) return fail("avg present time mismatch");
    if (!near(stats.avg_total_time_ms, 9.0)) return fail("avg total time mismatch");
    if (!near(stats.avg_fps, 90.0)) return fail("avg fps mismatch");
    if (!near(stats.avg_memory_mb, 60.0)) return fail("avg memory mismatch");
    if (stats.captured_frames != 2) return fail("captured frame count mismatch");
    if (stats.timeout_frames != 0) return fail("timeout frame count mismatch");

    return 0;
}
