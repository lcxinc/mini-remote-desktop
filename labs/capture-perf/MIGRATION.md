# Capture performance lab

This directory is the maintained location of the standalone CapTest experiments.
The product capture pipeline continues to use crates/mrd-capture-*; this lab is
not a replacement backend. No recorded desktop frames or target/ binaries were
imported. Original README/build scripts and result comparison tooling remain.

Each Rust package declares its own workspace to preserve independent dependency
versions and existing lockfiles. Run from this directory:

    cargo check --locked --manifest-path rust/desktop-duplication/Cargo.toml
    cmake -S cpp/viewer -B cpp/viewer_build
    cmake --build cpp/viewer_build --config Debug --target capture_render_metrics_tests viewer_options_tests capture_source_tests
    ctest --test-dir cpp/viewer_build -C Debug --output-on-failure

Debug is required for the factory test's assert checks. These tests do not start
screen capture. Interactive capture/render validation needs a Windows desktop
and appropriate graphics hardware. Consult docs/repository-consolidation/CapTest
at the repository root for coverage, review findings and validation results.
