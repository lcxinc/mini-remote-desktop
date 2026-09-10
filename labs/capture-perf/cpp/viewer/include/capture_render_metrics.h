#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class FrameStatus {
    Captured,
    Timeout,
    AccessLost,
    Error,
};

struct CaptureRenderFrameMetrics {
    uint64_t frame_number = 0;
    FrameStatus status = FrameStatus::Captured;
    double capture_time_ms = 0.0;
    double render_time_ms = 0.0;
    double present_time_ms = 0.0;
    double total_time_ms = 0.0;
    double fps = 0.0;
    double memory_mb = 0.0;
    int width = 0;
    int height = 0;
};

struct CaptureRenderStatistics {
    double avg_capture_time_ms = 0.0;
    double avg_render_time_ms = 0.0;
    double avg_present_time_ms = 0.0;
    double avg_total_time_ms = 0.0;
    double avg_fps = 0.0;
    double avg_memory_mb = 0.0;
    uint64_t captured_frames = 0;
    uint64_t timeout_frames = 0;
    uint64_t access_lost_frames = 0;
    uint64_t error_frames = 0;
};

struct CaptureRenderConfig {
    std::string api_name = "DesktopDuplication";
    std::string language = "C++";
    std::string renderer = "D3D11";
    int duration_sec = 0;
    int width = 0;
    int height = 0;
};

class CaptureRenderMetricsCollector {
public:
    explicit CaptureRenderMetricsCollector(CaptureRenderConfig config);

    void RecordFrame(const CaptureRenderFrameMetrics& metrics);
    CaptureRenderStatistics CalculateStatistics() const;
    bool SaveToCSV(const std::string& filepath) const;
    bool SaveToJSON(const std::string& filepath) const;

    const std::vector<CaptureRenderFrameMetrics>& Frames() const { return frames_; }
    const CaptureRenderConfig& Config() const { return config_; }

private:
    CaptureRenderConfig config_;
    std::vector<CaptureRenderFrameMetrics> frames_;
};

const char* FrameStatusToString(FrameStatus status);
double GetCurrentProcessMemoryMb();
