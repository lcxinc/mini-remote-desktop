#[cfg(any(windows, target_os = "macos", test))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(any(windows, target_os = "macos", test))]
pub(super) fn duration_as_millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn duration_as_millis_preserves_fractional_milliseconds() {
        assert_eq!(duration_as_millis(Duration::from_micros(1_500)), 1.5);
    }

    #[test]
    fn now_us_is_unix_microsecond_timestamp() {
        let first = now_us();
        let second = now_us();

        assert!(first > 1_000_000_000_000_000);
        assert!(second >= first);
    }
}
