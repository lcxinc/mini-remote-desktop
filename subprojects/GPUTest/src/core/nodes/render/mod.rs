pub mod cpu_upload;
pub mod d3d11;
pub mod d3d12;
pub mod gpu_present;
pub mod metal;
pub mod opencl;
pub mod visual_probe;
pub mod vulkan;

#[derive(Debug, Clone, Copy)]
pub struct RenderProfile {
    pub render_us: u64,
    pub present_us: u64,
}

pub fn render_profile(name: &str) -> Option<RenderProfile> {
    match name {
        "cpu_upload" => Some(cpu_upload::render_profile()),
        "d3d11" => Some(d3d11::render_profile()),
        "d3d12" => Some(d3d12::render_profile()),
        "gpu_present" => Some(gpu_present::render_profile()),
        "metal" => Some(metal::render_profile()),
        "opencl" => Some(opencl::render_profile()),
        "vulkan" => Some(vulkan::render_profile()),
        _ => None,
    }
}
