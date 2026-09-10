#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

struct FrameMetrics {
    uint64_t frame_number;
    double capture_time_ms;
    double total_time_ms;
    double fps;
    double cpu_percent;
    double memory_mb;

    FrameMetrics() : frame_number(0), capture_time_ms(0), total_time_ms(0),
                     fps(0), cpu_percent(0), memory_mb(0) {}
};

struct TestStatistics {
    double avg_capture_time_ms;
    double min_capture_time_ms;
    double max_capture_time_ms;
    double p95_capture_time_ms;
    double p99_capture_time_ms;
    double avg_fps;
    double avg_cpu_percent;
    double avg_memory_mb;

    TestStatistics() : avg_capture_time_ms(0), min_capture_time_ms(0),
                       max_capture_time_ms(0), p95_capture_time_ms(0),
                       p99_capture_time_ms(0), avg_fps(0),
                       avg_cpu_percent(0), avg_memory_mb(0) {}
};

struct TestConfig {
    std::string api_name;
    std::string language = "C++";
    int duration_sec = 60;
    int width = 0;
    int height = 0;
};

class MetricsCollector {
public:
    MetricsCollector(const TestConfig& config);

    void RecordFrame(const FrameMetrics& metrics);
    TestStatistics CalculateStatistics() const;
    void SaveToCSV(const std::string& filepath) const;
    void SaveToJSON(const std::string& filepath) const;
    void PrintSummary() const;

private:
    TestConfig config_;
    std::vector<FrameMetrics> frames_;
    std::chrono::steady_clock::time_point start_time_;

    static double CalculatePercentile(const std::vector<double>& values, double percentile);
};
