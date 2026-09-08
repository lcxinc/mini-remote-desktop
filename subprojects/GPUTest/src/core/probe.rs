use std::process::Command;

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub backend: String,
    pub compiled_supported: bool,
    pub runtime_init_ok: bool,
    pub note: String,
}

pub fn probe_all(ffmpeg: &str) -> Result<Vec<ProbeResult>, String> {
    let mut out = Vec::new();
    let hwaccels = list_hwaccels(ffmpeg)?;
    let backends = [
        "cuda", "vaapi", "dxva2", "qsv", "d3d11va", "opencl", "vulkan", "d3d12va", "amf", "metal",
    ];
    for backend in backends {
        let compiled_supported = hwaccels.iter().any(|x| x == backend);
        let (runtime_init_ok, note) = test_runtime_init(ffmpeg, backend)?;
        out.push(ProbeResult {
            backend: backend.to_string(),
            compiled_supported,
            runtime_init_ok,
            note,
        });
    }
    Ok(out)
}

fn list_hwaccels(ffmpeg: &str) -> Result<Vec<String>, String> {
    let output = Command::new(ffmpeg)
        .arg("-hide_banner")
        .arg("-hwaccels")
        .output()
        .map_err(|e| format!("run ffmpeg -hwaccels: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("Hardware acceleration methods:") {
            continue;
        }
        if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            rows.push(t.to_ascii_lowercase());
        }
    }
    Ok(rows)
}

fn test_runtime_init(ffmpeg: &str, backend: &str) -> Result<(bool, String), String> {
    let init = match backend {
        "cuda" => "cuda=dev:0",
        "vaapi" => "vaapi=dev:0",
        "dxva2" => "dxva2=dev:0",
        "qsv" => "qsv=dev:0",
        "d3d11va" => "d3d11va=dev:0",
        "opencl" => "opencl=dev:0.0",
        "vulkan" => "vulkan=dev:0",
        "d3d12va" => "d3d12va=dev:0",
        "amf" => "amf=dev:0",
        _ => return Ok((false, "unknown backend".to_string())),
    };
    let output = Command::new(ffmpeg)
        .arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-init_hw_device")
        .arg(init)
        .arg("-f")
        .arg("lavfi")
        .arg("-i")
        .arg("nullsrc=s=64x64:r=1")
        .arg("-frames:v")
        .arg("1")
        .arg("-f")
        .arg("null")
        .arg("-")
        .output()
        .map_err(|e| format!("run ffmpeg init for {backend}: {e}"))?;

    if output.status.success() {
        return Ok((true, "ok".to_string()));
    }
    let err = String::from_utf8_lossy(&output.stderr);
    let note = err
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("init failed")
        .trim()
        .to_string();
    Ok((false, note))
}
