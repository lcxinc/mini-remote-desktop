use crate::core::nodes::render::RenderProfile;

pub fn render_profile() -> RenderProfile {
    RenderProfile {
        render_us: 110,
        present_us: 45,
    }
}
