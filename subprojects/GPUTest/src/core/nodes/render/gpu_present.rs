use crate::core::nodes::render::RenderProfile;

pub fn render_profile() -> RenderProfile {
    RenderProfile {
        render_us: 140,
        present_us: 60,
    }
}
