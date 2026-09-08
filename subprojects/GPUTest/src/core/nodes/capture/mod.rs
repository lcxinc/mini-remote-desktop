pub mod desktop_dup;
pub mod windows_graphics_capture;

pub fn capture_work_us(name: &str) -> Option<u64> {
    match name {
        "desktop_dup" => Some(desktop_dup::capture_work_us()),
        "windows_graphics_capture" => Some(windows_graphics_capture::capture_work_us()),
        _ => None,
    }
}
