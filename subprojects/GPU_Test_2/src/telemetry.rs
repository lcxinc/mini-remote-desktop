/// Runtime telemetry statistics for low-latency streaming.
#[derive(Debug, Default, Clone, Copy)]
pub struct StreamingStats {
    pub frames_captured: u64,
    pub frames_encoded: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub frames_decoded: u64,
    pub capture_timeouts: u64,
    pub encode_errors: u64,
    pub send_errors: u64,
    pub decode_errors: u64,
    pub total_bytes: u64,
    pub elapsed_secs: f64,
}

impl StreamingStats {
    /// Calculate the drop rate (frames captured but not sent).
    pub fn drop_rate(&self) -> f64 {
        if self.frames_captured == 0 {
            0.0
        } else {
            let dropped = self.frames_captured.saturating_sub(self.frames_sent);
            dropped as f64 / self.frames_captured as f64
        }
    }

    /// Calculate capture fps.
    pub fn capture_fps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.frames_captured as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate encode fps.
    pub fn encode_fps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.frames_encoded as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate send fps.
    pub fn send_fps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.frames_sent as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate receive fps.
    pub fn receive_fps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.frames_received as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate decode fps.
    pub fn decode_fps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.frames_decoded as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Calculate bitrate in mbps.
    pub fn bitrate_mbps(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            (self.total_bytes as f64 * 8.0 / 1_000_000.0) / self.elapsed_secs
        } else {
            0.0
        }
    }

    /// Format stats as a summary string.
    pub fn summary(&self) -> String {
        format!(
            "captured: {:.1} fps ({}) | encoded: {:.1} fps ({}) | sent: {:.1} fps ({}) | dropped: {:.1}% | timeouts: {} | errors: e{} s{} d{}",
            self.capture_fps(),
            self.frames_captured,
            self.encode_fps(),
            self.frames_encoded,
            self.send_fps(),
            self.frames_sent,
            self.drop_rate() * 100.0,
            self.capture_timeouts,
            self.encode_errors,
            self.send_errors,
            self.decode_errors,
        )
    }
}
