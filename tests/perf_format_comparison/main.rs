#![cfg(windows)]

use std::time::Instant;

use mrd_render::{RenderFrame, RenderPixelFormat, RenderTarget, RendererFactory};
use mrd_render_d3d11::D3d11RendererFactory;

fn main() {
    let sample_count = 500;
    let width = 1920usize;
    let height = 1080usize;

    let factory = D3d11RendererFactory;
    let mut renderer = factory.create().expect("create d3d11 renderer");
    renderer
        .attach_target(RenderTarget::WindowHandle(0))
        .expect("attach render target");

    println!("Performance Test: {width}x{height}, {sample_count} samples\n");

    // Test RGB24
    let rgb_frame = RenderFrame {
        width,
        height,
        pixel_format: RenderPixelFormat::Rgb24,
        data: synthetic_rgb24_frame(width, height),
    };

    let mut rgb_latencies = Vec::with_capacity(sample_count);
    let rgb_started = Instant::now();

    for _ in 0..sample_count {
        let start = Instant::now();
        let _ = renderer.upload_frame(rgb_frame.clone());
        rgb_latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let rgb_total = rgb_started.elapsed();

    // Test BGRA32
    let bgra_frame = RenderFrame {
        width,
        height,
        pixel_format: RenderPixelFormat::Bgra32,
        data: synthetic_bgra32_frame(width, height),
    };

    let mut bgra_latencies = Vec::with_capacity(sample_count);
    let bgra_started = Instant::now();

    for _ in 0..sample_count {
        let start = Instant::now();
        let _ = renderer.upload_frame(bgra_frame.clone());
        bgra_latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let bgra_total = bgra_started.elapsed();

    // Calculate statistics
    let rgb_latencies_sorted = {
        let mut v = rgb_latencies.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    };
    let bgra_latencies_sorted = {
        let mut v = bgra_latencies.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v
    };

    let rgb_p50 = rgb_latencies_sorted[sample_count / 2];
    let rgb_p95 = rgb_latencies_sorted[(sample_count * 95) / 100];
    let rgb_p99 = rgb_latencies_sorted[(sample_count * 99) / 100];
    let rgb_avg: f64 = rgb_latencies.iter().sum::<f64>() / sample_count as f64;

    let bgra_p50 = bgra_latencies_sorted[sample_count / 2];
    let bgra_p95 = bgra_latencies_sorted[(sample_count * 95) / 100];
    let bgra_p99 = bgra_latencies_sorted[(sample_count * 99) / 100];
    let bgra_avg: f64 = bgra_latencies.iter().sum::<f64>() / sample_count as f64;

    println!("RGB24 Results:");
    println!("  Total:  {:.2}s ({:.2} FPS)", rgb_total.as_secs_f64(), sample_count as f64 / rgb_total.as_secs_f64());
    println!("  Avg:    {:.3}ms", rgb_avg);
    println!("  P50:    {:.3}ms", rgb_p50);
    println!("  P95:    {:.3}ms", rgb_p95);
    println!("  P99:    {:.3}ms", rgb_p99);

    println!("\nBGRA32 Results:");
    println!("  Total:  {:.2}s ({:.2} FPS)", bgra_total.as_secs_f64(), sample_count as f64 / bgra_total.as_secs_f64());
    println!("  Avg:    {:.3}ms", bgra_avg);
    println!("  P50:    {:.3}ms", bgra_p50);
    println!("  P95:    {:.3}ms", bgra_p95);
    println!("  P99:    {:.3}ms", bgra_p99);

    println!("\nImprovement (BGRA32 vs RGB24):");
    println!("  Avg:  {:.2}%", ((rgb_avg - bgra_avg) / rgb_avg) * 100.0);
    println!("  P50:  {:.2}%", ((rgb_p50 - bgra_p50) / rgb_p50) * 100.0);
    println!("  P95:  {:.2}%", ((rgb_p95 - bgra_p95) / rgb_p95) * 100.0);
    println!("  P99:  {:.2}%", ((rgb_p99 - bgra_p99) / rgb_p99) * 100.0);
    println!("  FPS:  +{:.1}%", (sample_count as f64 / bgra_total.as_secs_f64() / (sample_count as f64 / rgb_total.as_secs_f64()) - 1.0) * 100.0);
}

fn synthetic_rgb24_frame(width: usize, height: usize) -> Vec<u8> {
    let mut data = vec![0_u8; width * height * 3];
    for (index, chunk) in data.as_chunks_mut::<3>().0.iter_mut().enumerate() {
        chunk[0] = (index % 255) as u8;
        chunk[1] = ((index / 2) % 255) as u8;
        chunk[2] = ((index / 3) % 255) as u8;
    }
    data
}

fn synthetic_bgra32_frame(width: usize, height: usize) -> Vec<u8> {
    let mut data = vec![0_u8; width * height * 4];
    for (index, chunk) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        chunk[0] = ((index / 3) % 255) as u8; // B
        chunk[1] = ((index / 2) % 255) as u8; // G
        chunk[2] = (index % 255) as u8;       // R
        chunk[3] = 255;                       // A
    }
    data
}
