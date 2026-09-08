use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};

pub fn encode_ppm(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>> {
    let expected_len = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(3))
        .expect("ppm dimensions should fit in memory");
    ensure!(
        rgb.len() == expected_len,
        "RGB buffer length mismatch: expected {expected_len} bytes, got {}",
        rgb.len()
    );

    let mut bytes = format!("P6\n{width} {height}\n255\n").into_bytes();
    bytes.extend_from_slice(rgb);
    Ok(bytes)
}

pub fn write_artifact(path: impl AsRef<Path>, bytes: &[u8]) -> Result<PathBuf> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(path.to_path_buf())
}
