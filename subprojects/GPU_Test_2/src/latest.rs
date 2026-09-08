use std::sync::atomic::{AtomicU64, Ordering};

/// A single-slot storage that always holds the most recent u64 value.
///
/// Stores overwrite any previous value. Takes return the current value and clear the slot.
pub struct LatestFrameSlot {
    value: AtomicU64,
    drops: AtomicU64,
}

impl LatestFrameSlot {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(u64::MAX),
            drops: AtomicU64::new(0),
        }
    }

    /// Store a new value, overwriting any previous value.
    /// Returns true if this overwrote a value that hadn't been consumed yet (a drop occurred).
    pub fn store(&self, value: u64) -> bool {
        let mut dropped = false;
        self.value.fetch_update(
            Ordering::Release,
            Ordering::Relaxed,
            |current| {
                if current == u64::MAX {
                    // Slot was empty, no drop
                    Some(value)
                } else {
                    // Overwriting an unconsumed value - count as a drop
                    dropped = true;
                    self.drops.fetch_add(1, Ordering::Relaxed);
                    Some(value)
                }
            },
        ).ok();
        dropped
    }

    /// Take the current value, clearing the slot. Returns None if empty.
    pub fn take(&self) -> Option<u64> {
        let mut current = self.value.load(Ordering::Acquire);
        loop {
            if current == u64::MAX {
                return None;
            }
            match self.value.compare_exchange(current, u64::MAX, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(current),
                Err(new_current) => current = new_current,
            }
        }
    }

    /// Get the number of dropped frames (overwrites before consumption).
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Reset the drop counter.
    pub fn reset_drops(&self) {
        self.drops.store(0, Ordering::Relaxed);
    }
}

impl Default for LatestFrameSlot {
    fn default() -> Self {
        Self::new()
    }
}
