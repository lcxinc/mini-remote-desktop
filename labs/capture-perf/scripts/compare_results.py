#!/usr/bin/env python3
"""Compare screen capture performance test results."""

import csv
import json
import glob
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List

@dataclass
class TestResult:
    api: str
    language: str
    avg_capture_time_ms: float
    min_capture_time_ms: float
    max_capture_time_ms: float
    p95_capture_time_ms: float
    p99_capture_time_ms: float
    avg_fps: float
    avg_cpu_percent: float
    avg_memory_mb: float

def load_json_results(results_dir: Path) -> List[TestResult]:
    """Load all JSON result files from directory."""
    results = []

    for json_file in glob.glob(str(results_dir / "*.json")):
        with open(json_file, 'r') as f:
            data = json.load(f)
            stats = data.get('statistics', {})
            config = data.get('test_config', {})

            results.append(TestResult(
                api=config.get('api', 'Unknown'),
                language=config.get('language', 'Unknown'),
                avg_capture_time_ms=stats.get('avg_capture_time_ms', 0),
                min_capture_time_ms=stats.get('min_capture_time_ms', 0),
                max_capture_time_ms=stats.get('max_capture_time_ms', 0),
                p95_capture_time_ms=stats.get('p95_capture_time_ms', 0),
                p99_capture_time_ms=stats.get('p99_capture_time_ms', 0),
                avg_fps=stats.get('avg_fps', 0),
                avg_cpu_percent=stats.get('avg_cpu_percent', 0),
                avg_memory_mb=stats.get('avg_memory_mb', 0),
            ))

    return results

def print_comparison_table(results: List[TestResult]):
    """Print formatted comparison table."""
    if not results:
        print("No results found.")
        return

    print("\n" + "="*110)
    print("SCREEN CAPTURE PERFORMANCE COMPARISON")
    print("="*110)

    print(f"{'API':<25} {'Lang':<8} {'Avg(ms)':<10} {'Min(ms)':<10} {'Max(ms)':<10} "
          f"{'P95(ms)':<10} {'P99(ms)':<10} {'FPS':<8} {'CPU(%)':<10} {'Mem(MB)':<10}")
    print("-"*110)

    results_sorted = sorted(results, key=lambda r: (r.api, r.language))

    for r in results_sorted:
        print(f"{r.api:<25} {r.language:<8} "
              f"{r.avg_capture_time_ms:<10.2f} {r.min_capture_time_ms:<10.2f} "
              f"{r.max_capture_time_ms:<10.2f} {r.p95_capture_time_ms:<10.2f} "
              f"{r.p99_capture_time_ms:<10.2f} {r.avg_fps:<8.2f} "
              f"{r.avg_cpu_percent:<10.2f} {r.avg_memory_mb:<10.2f}")

    print("="*110)

    print("\nBEST PERFORMANCE:")
    best_capture = min(results_sorted, key=lambda r: r.avg_capture_time_ms)
    print(f"  Fastest Capture: {best_capture.api} ({best_capture.language}) - "
          f"{best_capture.avg_capture_time_ms:.2f} ms avg")

    best_fps = max(results_sorted, key=lambda r: r.avg_fps)
    print(f"  Highest FPS:     {best_fps.api} ({best_fps.language}) - "
          f"{best_fps.avg_fps:.2f} FPS")

    best_memory = min(results_sorted, key=lambda r: r.avg_memory_mb)
    print(f"  Lowest Memory:   {best_memory.api} ({best_memory.language}) - "
          f"{best_memory.avg_memory_mb:.2f} MB")

    print("\nLANGUAGE COMPARISON:")
    cpp_results = [r for r in results_sorted if r.language == "C++"]
    rust_results = [r for r in results_sorted if r.language == "Rust"]

    if cpp_results:
        cpp_avg = sum(r.avg_capture_time_ms for r in cpp_results) / len(cpp_results)
        print(f"  C++  avg capture time: {cpp_avg:.2f} ms")
    if rust_results:
        rust_avg = sum(r.avg_capture_time_ms for r in rust_results) / len(rust_results)
        print(f"  Rust avg capture time: {rust_avg:.2f} ms")

def main():
    results_dir = Path("results")

    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])

    if not results_dir.is_absolute():
        results_dir = Path(__file__).parent.parent / results_dir

    print(f"Loading results from: {results_dir}")

    if not results_dir.exists():
        print(f"Directory not found: {results_dir}")
        return

    results = load_json_results(results_dir)
    print_comparison_table(results)

if __name__ == '__main__':
    main()
