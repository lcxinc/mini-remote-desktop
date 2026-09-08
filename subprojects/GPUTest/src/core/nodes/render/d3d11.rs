use crate::core::nodes::render::RenderProfile;

pub fn render_profile() -> RenderProfile {
    RenderProfile {
        render_us: 115,
        present_us: 48,
    }
}
