#[cfg(windows)]
use mrd_capture_dxgi::DxgiSharedTextureCapture;

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BrowserPreviewDisplaySource {
    Primary,
    DisplaySourceId(String),
}

#[cfg(any(windows, test))]
pub(crate) fn parse_browser_preview_display_source_id(
    source_id: Option<&str>,
) -> Result<BrowserPreviewDisplaySource, String> {
    let Some(source_id) = source_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(BrowserPreviewDisplaySource::Primary);
    };

    let parts = source_id.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        ["windows", "display", index] | ["windows", "display-shared", index]
            if index.parse::<u32>().is_ok() =>
        {
            Ok(BrowserPreviewDisplaySource::DisplaySourceId(
                source_id.to_string(),
            ))
        }
        _ => Err(format!(
            "browser preview source_id must be a Windows display source, got {source_id}"
        )),
    }
}

#[cfg(windows)]
pub(crate) fn open_browser_preview_dxgi_capture(
    source_id: Option<&str>,
) -> Result<DxgiSharedTextureCapture, String> {
    match parse_browser_preview_display_source_id(source_id)? {
        BrowserPreviewDisplaySource::Primary => DxgiSharedTextureCapture::new_primary()
            .map_err(|error| format!("DXGI capture unavailable: {error}")),
        BrowserPreviewDisplaySource::DisplaySourceId(source_id) => {
            let device_name = crate::display_mode::display_device_name_for_source_id(&source_id)
                .map_err(|error| format!("resolve display source {source_id} failed: {error}"))?;
            DxgiSharedTextureCapture::new_for_device_name(&device_name).map_err(|error| {
                format!("DXGI capture unavailable for {source_id} ({device_name}): {error}")
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_preview_source_id_accepts_empty_as_primary() {
        assert_eq!(
            parse_browser_preview_display_source_id(None).unwrap(),
            BrowserPreviewDisplaySource::Primary
        );
        assert_eq!(
            parse_browser_preview_display_source_id(Some("   ")).unwrap(),
            BrowserPreviewDisplaySource::Primary
        );
    }

    #[test]
    fn browser_preview_source_id_accepts_windows_display_sources() {
        assert_eq!(
            parse_browser_preview_display_source_id(Some("windows:display-shared:1")).unwrap(),
            BrowserPreviewDisplaySource::DisplaySourceId("windows:display-shared:1".to_string())
        );
        assert_eq!(
            parse_browser_preview_display_source_id(Some("windows:display:0")).unwrap(),
            BrowserPreviewDisplaySource::DisplaySourceId("windows:display:0".to_string())
        );
    }

    #[test]
    fn browser_preview_source_id_rejects_window_sources() {
        let error =
            parse_browser_preview_display_source_id(Some("windows:window:0x1234")).unwrap_err();

        assert!(error.contains("display source"));
    }
}
