use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub fn probe_visualization(duration_sec: u64, chain_name: &str) -> Result<(), String> {
    let exe = locate_visual_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.env("POC_DURATION_SEC", duration_sec.to_string());
    let status = cmd
        .status()
        .map_err(|e| format!("launch visual renderer {}: {e}", exe.display()))?;
    if status.success() {
        eprintln!(
            "[RENDER-VISUAL] chain={} renderer={} status=ok",
            chain_name,
            exe.display()
        );
        Ok(())
    } else {
        Err(format!(
            "visual_renderer_failed:{} exit={}",
            exe.display(),
            status
        ))
    }
}

fn locate_visual_exe() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let dir = current
        .parent()
        .ok_or_else(|| "no parent for current exe".to_string())?;
    let candidate = dir.join("desktop-zero-copy-poc.exe");
    if candidate.exists() {
        return Ok(candidate);
    }
    let fallback = PathBuf::from("target/debug/desktop-zero-copy-poc.exe");
    if fallback.exists() {
        return Ok(fallback);
    }
    Err("desktop-zero-copy-poc.exe not found; build it first".to_string())
}

pub fn probe_with_retry(duration_sec: u64, chain_name: &str) -> Result<(), String> {
    match probe_visualization(duration_sec, chain_name) {
        Ok(()) => Ok(()),
        Err(first_err) => {
            std::thread::sleep(Duration::from_millis(300));
            probe_visualization(duration_sec, chain_name).map_err(|second_err| {
                format!(
                    "line_unavailable:render_visualization_failed first={} second={}",
                    first_err, second_err
                )
            })
        }
    }
}
