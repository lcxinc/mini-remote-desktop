# NVENC Resource Reuse Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rework the persistent NVENC encoder so it reuses output and input-side NVENC resources across frames instead of creating and destroying them on every encode.

**Architecture:** Keep the current `PersistentNvencEncoder` as the only high-performance encoder path, but extend it to own the D3D11 context, one reusable upload texture, one registered NVENC input resource, and one reusable NVENC bitstream buffer. Each frame should only update texture contents, call `encode_picture`, lock the reusable bitstream buffer, and copy the encoded bytes out.

**Tech Stack:** Rust, D3D11 via `windows`, `nvenc` crate 0.1.0, existing cargo tests/examples, 30-second local soak using `nvenc_quic_sender_parallel` and `nvenc_quic_receiver`

---

### Task 1: Lock down the current encoder behavior with tests

**Files:**
- Modify: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\src\encoder.rs`
- Create: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\tests\persistent_encoder_state.rs`

**Step 1: Write the failing tests**

Add a focused test file that checks pure-Rust behavior without requiring NVENC hardware:

```rust
use gpu_test_2::encoder::EncoderRuntimeState;

#[test]
fn first_frame_is_idr_then_p_frames() {
    let mut state = EncoderRuntimeState::default();
    assert!(state.next_picture_type().is_idr());
    assert!(state.next_picture_type().is_p());
    assert!(state.next_picture_type().is_p());
}

#[test]
fn runtime_state_tracks_frame_count() {
    let mut state = EncoderRuntimeState::default();
    state.on_frame_encoded();
    state.on_frame_encoded();
    assert_eq!(state.frame_count(), 2);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test persistent_encoder_state`

Expected: FAIL because `EncoderRuntimeState` does not exist yet.

**Step 3: Write minimal implementation**

In `src/encoder.rs`, add a small internal/public-for-tests helper that owns:
- current `frame_count`
- helper for “first frame IDR, later P”
- helper for incrementing state after successful encode

Keep this helper independent from NVENC handles so it remains unit-testable.

**Step 4: Run test to verify it passes**

Run: `cargo test --test persistent_encoder_state`

Expected: PASS

**Step 5: Commit**

```bash
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 add src/encoder.rs tests/persistent_encoder_state.rs
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 commit -m "test: lock down persistent encoder runtime state"
```

### Task 2: Refactor encoder construction to own reusable resources

**Files:**
- Modify: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\src\encoder.rs`

**Step 1: Write the failing compile-target change**

Refactor `PersistentNvencEncoder` to add owned reusable fields:

```rust
pub struct PersistentNvencEncoder {
    _device: ID3D11Device,
    device_context: ID3D11DeviceContext,
    encoder: Encoder,
    config: EncoderConfig,
    runtime: EncoderRuntimeState,
    upload_texture: ID3D11Texture2D,
    registered_input: RegisteredResource,
    output_bitstream: BitStream,
}
```

Also change device creation helper to return both device and immediate context.

**Step 2: Run targeted compile to verify it fails in useful places**

Run: `cargo check --lib`

Expected: FAIL with missing imports/types/constructor mismatches around `PersistentNvencEncoder::new`.

**Step 3: Write minimal implementation**

In `PersistentNvencEncoder::new`:
- create device and context once
- create one empty upload texture sized to `config.width/height`
- register that texture once with NVENC
- create one reusable bitstream buffer once
- initialize `runtime` with zero encoded frames

Add/adjust helpers as needed:
- `create_nvenc_device_and_context() -> Result<(ID3D11Device, ID3D11DeviceContext)>`
- `create_empty_rgba_texture(...) -> Result<ID3D11Texture2D>`

Do not change the public encoder API yet.

**Step 4: Run compile to verify it passes**

Run: `cargo check --lib`

Expected: PASS

**Step 5: Commit**

```bash
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 add src/encoder.rs
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 commit -m "refactor: persist nvenc resources in encoder"
```

### Task 3: Reuse the upload texture each frame instead of recreating it

**Files:**
- Modify: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\src\encoder.rs`
- Modify: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\tests\encoder_color_conversion.rs`

**Step 1: Write the failing test**

Add a small helper test around frame upload preparation, for example:

```rust
#[test]
fn bgra_to_rgba_preserves_pixel_count() {
    // existing style test plus explicit stride/length expectations
}
```

If needed, add a pure helper for computing upload pitch/length expectations so the upload path has test coverage even without a GPU.

**Step 2: Run test to verify it fails**

Run: `cargo test --test encoder_color_conversion`

Expected: FAIL if new helper/API is missing.

**Step 3: Write minimal implementation**

Replace per-frame `create_rgba_texture(...)` with:
- BGRA to RGBA conversion as today
- `device_context.UpdateSubresource(...)` or equivalent write into `self.upload_texture`

Then encode from the already-registered `self.registered_input`.

Remove per-frame:
- texture creation
- resource registration

Keep dimensions validated exactly as before.

**Step 4: Run tests to verify they pass**

Run: `cargo test --test encoder_color_conversion`

Expected: PASS

**Step 5: Commit**

```bash
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 add src/encoder.rs tests/encoder_color_conversion.rs
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 commit -m "perf: reuse upload texture for nvenc frames"
```

### Task 4: Reuse the NVENC bitstream buffer across frames

**Files:**
- Modify: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\src\encoder.rs`

**Step 1: Write the failing compile-target change**

Update `encode_frame()` to stop calling:

```rust
let output = self.encoder.create_bitstream_buffer()?;
```

and instead use `self.output_bitstream`.

**Step 2: Run compile to verify it fails in the expected place**

Run: `cargo check --lib`

Expected: FAIL due to borrow/lifetime issues around `self.output_bitstream`.

**Step 3: Write minimal implementation**

Refactor `encode_frame()` so it:
- uses `self.registered_input` as input
- uses `self.output_bitstream` as output
- locks the reusable bitstream buffer
- copies bytes into a fresh `Vec<u8>`
- drops the lock guard before returning
- advances `runtime` only after successful encode and non-empty output

Preserve current behavior:
- first frame IDR
- later frames P
- empty bitstream is an error

**Step 4: Run compile and targeted tests**

Run: `cargo check --lib`

Run: `cargo test --test encoded_frame_metadata --test persistent_encoder_state`

Expected: PASS

**Step 5: Commit**

```bash
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 add src/encoder.rs tests/persistent_encoder_state.rs
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 commit -m "perf: reuse nvenc bitstream buffer"
```

### Task 5: Verify single-frame and parallel sender paths still build

**Files:**
- Modify: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\README.md`

**Step 1: Update docs only if outputs/notes changed**

If the implementation removes the repeated `Dropping bitstream buffer` noise, add a brief note in README’s soak section that encoder resources are now reused across frames.

**Step 2: Run build verification**

Run: `cargo check --example nvenc_quic_sender_serial --example nvenc_quic_sender_parallel --example nvenc_quic_receiver`

Expected: PASS

**Step 3: Run unit/integration tests**

Run: `cargo test --test protocol_roundtrip --test encoded_frame_metadata --test encoder_color_conversion --test persistent_encoder_state`

Expected: PASS

**Step 4: Commit**

```bash
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 add README.md src/encoder.rs tests/persistent_encoder_state.rs tests/encoder_color_conversion.rs
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 commit -m "docs: describe persistent nvenc resource reuse"
```

### Task 6: Re-run the 30-second soak and compare against the baseline

**Files:**
- Verify runtime artifacts only: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\receiver.out.log`
- Verify runtime artifacts only: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\receiver.err.log`
- Verify runtime artifacts only: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\artifacts\latest.ppm`
- Verify runtime artifacts only: `G:\Project\mini-remote-desktop\subprojects\GPU_Test_2\artifacts\final.ppm`

**Step 1: Start receiver**

Run:

```bash
cargo run --example nvenc_quic_receiver --release
```

Expected: `receiver listening on 0.0.0.0:4433`

**Step 2: Run sender soak**

Run:

```bash
cargo run --example nvenc_quic_sender_parallel --release
```

Expected:
- 30-second run completes
- no per-frame `Dropping bitstream buffer`
- no `encode_errors`
- no `send_errors`

**Step 3: Compare against baseline**

Record and compare against the known baseline from 2026-03-20:
- captured: `2651 (87.4 fps)`
- encoded: `2578 (85.0 fps)`
- sent: `2477 (81.6 fps)`
- dropped: `72`

Success means:
- soak still completes
- output artifacts still written
- encoded/sent fps are not worse in a material way
- per-frame bitstream-drop log spam is gone

**Step 4: Commit**

```bash
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 add README.md src/encoder.rs tests/persistent_encoder_state.rs tests/encoder_color_conversion.rs
git -C G:\Project\mini-remote-desktop\subprojects\GPU_Test_2 commit -m "perf: reuse nvenc resources across frames"
```
