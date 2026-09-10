#include "capture_render_metrics.h"

#include <windows.h>
#include <psapi.h>

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "psapi.lib")

namespace {

uint64_t UnixTimestampSeconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string EscapeJson(const std::string& value) {
    std::ostringstream escaped;
    for (char ch : value) {
        switch (ch) {
            case '\\':
                escaped << "\\\\";
                break;
            case '"':
                escaped << "\\\"";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                escaped << ch;
                break;
        }
    }
    return escaped.str();
}

}  // namespace

CaptureRenderMetricsCollector::CaptureRenderMetricsCollector(CaptureRenderConfig config)
    : config_(std::move(config)) {}

void CaptureRenderMetricsCollector::RecordFrame(const CaptureRenderFrameMetrics& metrics) {
    frames_.push_back(metrics);
}

CaptureRenderStatistics CaptureRenderMetricsCollector::CalculateStatistics() const {
    CaptureRenderStatistics stats;
    if (frames_.empty()) {
        return stats;
    }

    for (const auto& frame : frames_) {
        switch (frame.status) {
            case FrameStatus::Captured:
                stats.captured_frames++;
                break;
            case FrameStatus::Timeout:
                stats.timeout_frames++;
                break;
            case FrameStatus::AccessLost:
                stats.access_lost_frames++;
                break;
            case FrameStatus::Error:
                stats.error_frames++;
                break;
        }

        stats.avg_capture_time_ms += frame.capture_time_ms;
        stats.avg_render_time_ms += frame.render_time_ms;
        stats.avg_present_time_ms += frame.present_time_ms;
        stats.avg_total_time_ms += frame.total_time_ms;
        stats.avg_fps += frame.fps;
        stats.avg_memory_mb += frame.memory_mb;
    }

    const double count = static_cast<double>(frames_.size());
    stats.avg_capture_time_ms /= count;
    stats.avg_render_time_ms /= count;
    stats.avg_present_time_ms /= count;
    stats.avg_total_time_ms /= count;
    stats.avg_fps /= count;
    stats.avg_memory_mb /= count;

    return stats;
}

bool CaptureRenderMetricsCollector::SaveToCSV(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    file << "timestamp,api,language,renderer,frame_number,status,capture_time_ms,"
            "render_time_ms,present_time_ms,total_time_ms,fps,memory_mb,width,height\n";

    const uint64_t timestamp = UnixTimestampSeconds();
    file << std::fixed << std::setprecision(3);

    for (const auto& frame : frames_) {
        file << timestamp << ','
             << config_.api_name << ','
             << config_.language << ','
             << config_.renderer << ','
             << frame.frame_number << ','
             << FrameStatusToString(frame.status) << ','
             << frame.capture_time_ms << ','
             << frame.render_time_ms << ','
             << frame.present_time_ms << ','
             << frame.total_time_ms << ','
             << frame.fps << ','
             << frame.memory_mb << ','
             << frame.width << ','
             << frame.height << '\n';
    }

    return file.good();
}

bool CaptureRenderMetricsCollector::SaveToJSON(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    const CaptureRenderStatistics stats = CalculateStatistics();

    file << std::fixed << std::setprecision(3);
    file << "{\n";
    file << "  \"test_config\": {\n";
    file << "    \"api\": \"" << EscapeJson(config_.api_name) << "\",\n";
    file << "    \"language\": \"" << EscapeJson(config_.language) << "\",\n";
    file << "    \"renderer\": \"" << EscapeJson(config_.renderer) << "\",\n";
    file << "    \"duration_sec\": " << config_.duration_sec << ",\n";
    file << "    \"width\": " << config_.width << ",\n";
    file << "    \"height\": " << config_.height << ",\n";
    file << "    \"total_frames\": " << frames_.size() << "\n";
    file << "  },\n";
    file << "  \"statistics\": {\n";
    file << "    \"avg_capture_time_ms\": " << stats.avg_capture_time_ms << ",\n";
    file << "    \"avg_render_time_ms\": " << stats.avg_render_time_ms << ",\n";
    file << "    \"avg_present_time_ms\": " << stats.avg_present_time_ms << ",\n";
    file << "    \"avg_total_time_ms\": " << stats.avg_total_time_ms << ",\n";
    file << "    \"avg_fps\": " << stats.avg_fps << ",\n";
    file << "    \"avg_memory_mb\": " << stats.avg_memory_mb << ",\n";
    file << "    \"captured_frames\": " << stats.captured_frames << ",\n";
    file << "    \"timeout_frames\": " << stats.timeout_frames << ",\n";
    file << "    \"access_lost_frames\": " << stats.access_lost_frames << ",\n";
    file << "    \"error_frames\": " << stats.error_frames << "\n";
    file << "  }\n";
    file << "}\n";

    return file.good();
}

const char* FrameStatusToString(FrameStatus status) {
    switch (status) {
        case FrameStatus::Captured:
            return "captured";
        case FrameStatus::Timeout:
            return "timeout";
        case FrameStatus::AccessLost:
            return "access_lost";
        case FrameStatus::Error:
            return "error";
    }

    return "unknown";
}

double GetCurrentProcessMemoryMb() {
    PROCESS_MEMORY_COUNTERS_EX counters = {};
    if (!GetProcessMemoryInfo(
            GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
            sizeof(counters))) {
        return 0.0;
    }

    return static_cast<double>(counters.WorkingSetSize) / (1024.0 * 1024.0);
}
