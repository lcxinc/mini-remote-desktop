#include "capture_metrics.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cmath>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

MetricsCollector::MetricsCollector(const TestConfig& config)
    : config_(config), start_time_(std::chrono::steady_clock::now()) {}

void MetricsCollector::RecordFrame(const FrameMetrics& metrics) {
    frames_.push_back(metrics);
}

TestStatistics MetricsCollector::CalculateStatistics() const {
    TestStatistics stats;

    if (frames_.empty()) return stats;

    std::vector<double> capture_times;
    double sum_capture_time = 0;
    double sum_cpu = 0;
    double sum_memory = 0;

    for (const auto& frame : frames_) {
        capture_times.push_back(frame.capture_time_ms);
        sum_capture_time += frame.capture_time_ms;
        sum_cpu += frame.cpu_percent;
        sum_memory += frame.memory_mb;
    }

    std::sort(capture_times.begin(), capture_times.end());

    stats.avg_capture_time_ms = sum_capture_time / frames_.size();
    stats.min_capture_time_ms = capture_times.front();
    stats.max_capture_time_ms = capture_times.back();
    stats.p95_capture_time_ms = CalculatePercentile(capture_times, 95.0);
    stats.p99_capture_time_ms = CalculatePercentile(capture_times, 99.0);

    // 正确的 FPS 计算：总帧数 / 总时间（秒）
    double total_time_sec = frames_.back().total_time_ms / 1000.0;
    stats.avg_fps = (total_time_sec > 0) ? (frames_.size() / total_time_sec) : 0.0;

    stats.avg_cpu_percent = sum_cpu / frames_.size();
    stats.avg_memory_mb = sum_memory / frames_.size();

    return stats;
}

double MetricsCollector::CalculatePercentile(const std::vector<double>& values, double percentile) {
    if (values.empty()) return 0.0;

    size_t index = static_cast<size_t>(std::ceil(percentile / 100.0 * values.size())) - 1;
    index = std::min(index, values.size() - 1);
    return values[index];
}

void MetricsCollector::SaveToCSV(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open CSV file: " << filepath << std::endl;
        return;
    }

    file << "timestamp,api,language,frame_number,capture_time_ms,total_time_ms,fps,cpu_percent,memory_mb\n";

    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    for (const auto& frame : frames_) {
        file << timestamp << ","
             << config_.api_name << ","
             << config_.language << ","
             << frame.frame_number << ","
             << std::fixed << std::setprecision(2)
             << frame.capture_time_ms << ","
             << frame.total_time_ms << ","
             << frame.fps << ","
             << frame.cpu_percent << ","
             << frame.memory_mb << "\n";
    }

    file.close();
}

void MetricsCollector::SaveToJSON(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open JSON file: " << filepath << std::endl;
        return;
    }

    TestStatistics stats = CalculateStatistics();

    file << "{\n";
    file << "  \"test_config\": {\n";
    file << "    \"api\": \"" << config_.api_name << "\",\n";
    file << "    \"language\": \"" << config_.language << "\",\n";
    file << "    \"duration_sec\": " << config_.duration_sec << ",\n";
    file << "    \"total_frames\": " << frames_.size() << "\n";
    file << "  },\n";
    file << "  \"statistics\": {\n";
    file << "    \"avg_capture_time_ms\": " << stats.avg_capture_time_ms << ",\n";
    file << "    \"min_capture_time_ms\": " << stats.min_capture_time_ms << ",\n";
    file << "    \"max_capture_time_ms\": " << stats.max_capture_time_ms << ",\n";
    file << "    \"p95_capture_time_ms\": " << stats.p95_capture_time_ms << ",\n";
    file << "    \"p99_capture_time_ms\": " << stats.p99_capture_time_ms << ",\n";
    file << "    \"avg_fps\": " << stats.avg_fps << ",\n";
    file << "    \"avg_cpu_percent\": " << stats.avg_cpu_percent << ",\n";
    file << "    \"avg_memory_mb\": " << stats.avg_memory_mb << "\n";
    file << "  }\n";
    file << "}\n";

    file.close();
}

void MetricsCollector::PrintSummary() const {
    TestStatistics stats = CalculateStatistics();

    std::cout << "\n=== " << config_.api_name << " (" << config_.language << ") ===\n";
    std::cout << "Total frames captured: " << frames_.size() << "\n";
    std::cout << "Average capture time: " << std::fixed << std::setprecision(2)
              << stats.avg_capture_time_ms << " ms\n";
    std::cout << "Min/Max capture time: " << stats.min_capture_time_ms
              << " / " << stats.max_capture_time_ms << " ms\n";
    std::cout << "P95/P99 capture time: " << stats.p95_capture_time_ms
              << " / " << stats.p99_capture_time_ms << " ms\n";
    std::cout << "Average FPS: " << stats.avg_fps << "\n";
    std::cout << "Average CPU: " << stats.avg_cpu_percent << "%\n";
    std::cout << "Average Memory: " << stats.avg_memory_mb << " MB\n";
    std::cout << std::endl;
}
