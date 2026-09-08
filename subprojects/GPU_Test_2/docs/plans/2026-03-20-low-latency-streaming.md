# Low-Latency Streaming Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn the current one-frame NVENC-over-QUIC validation into a continuous low-latency streaming pipeline that prioritizes newest-frame delivery and reaches 30+ fps without queue buildup.

**Architecture:** Reuse the validated capture, encode, transport, and decode layers, but convert them from one-shot helpers into persistent components. The sender will run long-lived capture, encode, and network stages connected by single-slot or tiny-ring latest-frame handoff, and the receiver will decode continuously from one long-lived QUIC stream while emitting lightweight performance telemetry and low-frequency artifact snapshots.

**Tech Stack:** Rust, DXGI Desktop Duplication, D3D11, NVENC, Quinn QUIC, Tokio, OpenH264, lock-free/latest-frame handoff, runtime telemetry

---

### Task 1: Replace EOF-based framing with streaming frame reads

**Files:**
- Modify: `src/protocol.rs`
- Modify: `src/transport.rs`
- Test: `tests/frame_stream_io.rs`

**Step 1: Write the failing test**

Create `tests/frame_stream_io.rs` with an async test that writes two frame messages into one duplex stream and reads them back sequentially:

```rust
#[tokio::test]
async fn reads_two_frames_from_one_stream() {
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let first = FrameHeader::new(640, 360, 1, 2);
    let second = FrameHeader::new(640, 360, 2, 3);

    write_frame_message(&mut writer, &first, &[1, 2]).await.unwrap();
    write_frame_message(&mut writer, &second, &[3, 4, 5]).await.unwrap();

    let parsed1 = read_frame_message(&mut reader).await.unwrap();
    let parsed2 = read_frame_message(&mut reader).await.unwrap();
    assert_eq!(parsed1.header.pts, 1);
    assert_eq!(parsed2.header.pts, 2);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test frame_stream_io`
Expected: FAIL because current `read_frame_message` relies on `read_to_end()` and cannot parse a long-lived stream correctly.

**Step 3: Write minimal implementation**

Update `src/protocol.rs` and `src/transport.rs` to:
- expose a fixed header length constant or helper
- read exactly one header
- read exactly `payload_len` bytes for that frame
- return without consuming future frames

Do not add batching or buffering beyond what is required for one-frame-at-a-time parsing.

**Step 4: Run test to verify it passes**

Run: `cargo test --test frame_stream_io`
Expected: PASS

**Step 5: Commit**

```bash
git add src/protocol.rs src/transport.rs tests/frame_stream_io.rs
git commit -m "feat: support multi-frame stream parsing"
```

### Task 2: Introduce latest-frame handoff primitives

**Files:**
- Create: `src/latest.rs`
- Modify: `src/lib.rs`
- Test: `tests/latest_frame_slot.rs`

**Step 1: Write the failing test**

Create `tests/latest_frame_slot.rs` to prove a newer value overwrites an older one:

```rust
use gpu_test_2::latest::LatestFrameSlot;

#[test]
fn latest_slot_discards_older_frame() {
    let slot = LatestFrameSlot::default();
    slot.store(1u64);
    slot.store(2u64);
    assert_eq!(slot.take(), Some(2));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test latest_frame_slot`
Expected: FAIL because `LatestFrameSlot` does not exist yet.

**Step 3: Write minimal implementation**

Create `src/latest.rs` with a small synchronization primitive suitable for low-latency overwrite semantics:
- `LatestFrameSlot<T>`
- `store`
- `take`

Use the simplest correct synchronization strategy first. Do not add metrics or wait-free complexity yet.

**Step 4: Run test to verify it passes**

Run: `cargo test --test latest_frame_slot`
Expected: PASS

**Step 5: Commit**

```bash
git add src/latest.rs src/lib.rs tests/latest_frame_slot.rs
git commit -m "feat: add latest-frame slot"
```

### Task 3: Persist capture state across frames

**Files:**
- Modify: `src/capture.rs`
- Test: `tests/captured_frame_layout.rs`

**Step 1: Write the failing test**

Add a new test in `tests/captured_frame_layout.rs` covering a stateful capture session constructor API:

```rust
#[test]
fn capture_session_rejects_zero_dimensions() {
    let err = CaptureSession::validate_dimensions(0, 1080).unwrap_err();
    assert!(err.to_string().contains("width"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test captured_frame_layout`
Expected: FAIL because `CaptureSession` validation API does not exist yet.

**Step 3: Write minimal implementation**

Refactor `src/capture.rs` so it has:
- `CaptureSession`
- one-time D3D11 / duplication initialization
- `capture_next_frame(&mut self) -> Result<CapturedFrame>`

Keep existing one-shot capture helper only if it becomes a thin wrapper around `CaptureSession`.

**Step 4: Run test to verify it passes**

Run: `cargo test --test captured_frame_layout`
Expected: PASS

**Step 5: Commit**

```bash
git add src/capture.rs tests/captured_frame_layout.rs
git commit -m "refactor: make capture session persistent"
```

### Task 4: Persist NVENC state across frames

**Files:**
- Modify: `src/encoder.rs`
- Test: `tests/encoded_frame_metadata.rs`
- Test: `tests/encoder_color_conversion.rs`

**Step 1: Write the failing test**

Add a small test in `tests/encoded_frame_metadata.rs` proving encoder configuration validation:

```rust
#[test]
fn encoder_config_rejects_zero_resolution() {
    let err = EncoderConfig::new(0, 720).unwrap_err();
    assert!(err.to_string().contains("width"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test encoded_frame_metadata`
Expected: FAIL because `EncoderConfig` and persistent encoder setup do not exist yet.

**Step 3: Write minimal implementation**

Refactor `src/encoder.rs` to provide:
- `EncoderConfig`
- `PersistentNvencEncoder`
- one-time NVENC session initialization
- `encode_frame(&mut self, frame: &CapturedFrame, pts: u64) -> Result<EncodedFrame>`

Avoid per-frame encoder/session recreation. Keep color conversion helper separate from session lifecycle.

**Step 4: Run test to verify it passes**

Run: `cargo test --test encoded_frame_metadata --test encoder_color_conversion`
Expected: PASS

**Step 5: Commit**

```bash
git add src/encoder.rs tests/encoded_frame_metadata.rs tests/encoder_color_conversion.rs
git commit -m "refactor: persist NVENC session across frames"
```

### Task 5: Stream frames continuously on one QUIC connection

**Files:**
- Modify: `examples/nvenc_quic_sender.rs`
- Modify: `examples/nvenc_quic_receiver.rs`
- Modify: `src/transport.rs`
- Test: `tests/frame_stream_io.rs`

**Step 1: Write the failing test**

Extend `tests/frame_stream_io.rs` with a stream loop case that reads until a controlled writer shutdown:

```rust
#[tokio::test]
async fn stream_reader_can_consume_multiple_messages_without_eof_between_frames() {
    // write several frames, then close writer, and verify all were read in order
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test frame_stream_io`
Expected: FAIL if sender/receiver helpers still assume one frame per stream lifecycle.

**Step 3: Write minimal implementation**

Update examples so that:
- sender opens one stream and writes frames in a loop
- receiver accepts one stream and reads frames in a loop
- both sides shut down cleanly when the loop exits

Do not add display or artifact-per-frame behavior in this step.

**Step 4: Run test to verify it passes**

Run: `cargo test --test frame_stream_io`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/nvenc_quic_sender.rs examples/nvenc_quic_receiver.rs src/transport.rs tests/frame_stream_io.rs
git commit -m "feat: stream frames on one QUIC channel"
```

### Task 6: Add low-latency sender pipeline with overwrite semantics

**Files:**
- Modify: `examples/nvenc_quic_sender.rs`
- Modify: `src/latest.rs`
- Modify: `src/capture.rs`
- Modify: `src/encoder.rs`
- Test: `tests/latest_frame_slot.rs`

**Step 1: Write the failing test**

Add a test in `tests/latest_frame_slot.rs` covering producer overwrite behavior:

```rust
#[test]
fn latest_slot_only_returns_newest_value_after_multiple_stores() {
    let slot = LatestFrameSlot::default();
    for value in 0..10 {
        slot.store(value);
    }
    assert_eq!(slot.take(), Some(9));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test latest_frame_slot`
Expected: FAIL if current slot behavior still leaves room for stale values or queue semantics.

**Step 3: Write minimal implementation**

Implement sender pipeline stages:
- capture thread stores newest captured frame
- encode thread consumes newest frame and stores newest encoded frame
- network thread consumes newest encoded frame and writes to QUIC

Collect counters for overwritten/dropped frames in each stage.

**Step 4: Run test to verify it passes**

Run: `cargo test --test latest_frame_slot`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/nvenc_quic_sender.rs src/latest.rs src/capture.rs src/encoder.rs tests/latest_frame_slot.rs
git commit -m "feat: add low-latency sender pipeline"
```

### Task 7: Add continuous receiver decode loop and sampled artifact output

**Files:**
- Modify: `examples/nvenc_quic_receiver.rs`
- Modify: `src/decode.rs`
- Modify: `src/artifacts.rs`
- Test: `tests/decoder_errors.rs`

**Step 1: Write the failing test**

Add a test in `tests/decoder_errors.rs` verifying decode loop keeps going after one invalid packet:

```rust
#[test]
fn decoder_can_continue_after_invalid_packet() {
    let mut decoder = StreamingDecoder::new().unwrap();
    assert!(decoder.decode_packet(&[0, 1, 2]).is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test decoder_errors`
Expected: FAIL because streaming decoder state does not exist yet.

**Step 3: Write minimal implementation**

Refactor receiver decode path to:
- keep decoder state alive across frames
- decode continuously
- retain latest decoded frame
- write `artifacts/latest.ppm` at a low fixed rate such as once per second

Avoid per-frame file writes.

**Step 4: Run test to verify it passes**

Run: `cargo test --test decoder_errors`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/nvenc_quic_receiver.rs src/decode.rs src/artifacts.rs tests/decoder_errors.rs
git commit -m "feat: add continuous receiver decode loop"
```

### Task 8: Add low-latency telemetry and 30-second soak verification

**Files:**
- Modify: `examples/nvenc_quic_sender.rs`
- Modify: `examples/nvenc_quic_receiver.rs`
- Modify: `README.md`

**Step 1: Write the failing test**

Add a small unit test in a new file `tests/telemetry_stats.rs`:

```rust
#[test]
fn telemetry_reports_nonzero_drop_rate() {
    let mut stats = StreamingStats::default();
    stats.frames_captured = 100;
    stats.frames_sent = 80;
    assert!(stats.drop_rate() > 0.0);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test telemetry_stats`
Expected: FAIL because telemetry aggregation helpers do not exist yet.

**Step 3: Write minimal implementation**

Add runtime telemetry that prints:
- capture fps
- encode fps
- send fps
- decode fps
- bitrate
- stage overwrite counts
- moving latency estimate from capture timestamp to decode timestamp

Update `README.md` with the exact 30-second soak commands and expected console metrics.

**Step 4: Run test to verify it passes**

Run: `cargo test --test telemetry_stats`
Expected: PASS

**Step 5: Commit**

```bash
git add examples/nvenc_quic_sender.rs examples/nvenc_quic_receiver.rs README.md tests/telemetry_stats.rs
git commit -m "feat: add low-latency streaming telemetry"
```

### Task 9: Verify low-latency continuous streaming behavior manually

**Files:**
- Modify: `README.md`

**Step 1: Run receiver**

Run: `cargo run --example nvenc_quic_receiver --release`
Expected: receiver starts, accepts one connection, and begins reporting decode fps and sampled artifact updates

**Step 2: Run sender**

Run: `cargo run --example nvenc_quic_sender --release`
Expected: sender streams continuously and prints capture / encode / send metrics

**Step 3: Soak for 30 seconds**

Observe:
- stable connection
- no unbounded latency growth
- sender and receiver remain above 30 fps for meaningful intervals
- overwrite counters increase under load instead of queue length growing

**Step 4: Verify artifacts**

Check:
- `artifacts/latest.ppm`

Expected: file exists and updates during the soak without one-file-per-frame churn

**Step 5: Commit**

```bash
git add README.md artifacts
git commit -m "docs: verify low-latency continuous streaming"
```
