# Validation (2026-09-10)

Windows host, MSVC 19.44.35226.0, SDK 10.0.26100.0:

- CMake configure and Debug builds of the three existing C++ test executables passed.
- CTest Debug: **3/3 passed** (`capture_render_metrics`, `viewer_options`,
  `capture_source_factory`). These do not initiate capture. Debug keeps assert
  expressions enabled in the factory test.
- `cargo check --locked --manifest-path rust/desktop-duplication/Cargo.toml`: passed.
- `cargo check --locked --manifest-path rust/graphics-capture/Cargo.toml`: passed.
- `cargo test --manifest-path rust/common/Cargo.toml`: compiled successfully,
  **0 tests present**; this is a build check, not behavioral test coverage.
- Missing ordinary Cargo dependencies were fetched; no datasets or screen images
  were downloaded. Existing package lockfiles were kept; common now has a lockfile.
- Source-file/blob/mode coverage verified; generated files and binaries excluded.

The Rust builds report existing unused field/method warnings. Rust viewer,
shared-memory and test-gc-api binaries and complete C++ viewer applications were
not built. No actual screen capture, performance benchmark, HDR/resize/access-loss
test or production session was run. Main product Cargo files and application
sources are unchanged. This PR preserves experiments without certifying them as
production capture backends.
