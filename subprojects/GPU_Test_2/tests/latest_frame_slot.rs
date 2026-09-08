use gpu_test_2::latest::LatestFrameSlot;

#[test]
fn latest_slot_discards_older_frame() {
    let slot = LatestFrameSlot::default();
    slot.store(1);
    slot.store(2);
    assert_eq!(slot.take(), Some(2));
}

#[test]
fn latest_slot_only_returns_newest_value_after_multiple_stores() {
    let slot = LatestFrameSlot::default();
    for value in 0..10u64 {
        slot.store(value);
    }
    assert_eq!(slot.take(), Some(9));
}

#[test]
fn latest_slot_tracks_drops_when_overwriting_unconsumed_values() {
    let slot = LatestFrameSlot::default();
    slot.store(1);
    slot.store(2); // Overwrites 1 before it was consumed
    assert_eq!(slot.drops(), 1);
    assert_eq!(slot.take(), Some(2));
}

#[test]
fn latest_slot_no_drops_when_values_are_consumed() {
    let slot = LatestFrameSlot::default();
    slot.store(1);
    slot.take(); // Consume before overwrite
    slot.store(2);
    assert_eq!(slot.drops(), 0);
    assert_eq!(slot.take(), Some(2));
}
