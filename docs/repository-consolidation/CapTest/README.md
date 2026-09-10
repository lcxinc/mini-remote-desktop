# CapTest consolidation review

Source: https://github.com/lcxinc/CapTest at `9868ba4cda6bc84a8d554d6f0d3aa3a8e289a809`.
Location: `labs/capture-perf/`.

All 2,670 tracked paths are accounted for: 66 source/build/documentation files
migrated, 2,604 generated files beneath target/ excluded. Source Cargo manifests
gain independent workspaces; original bytes are archived. Existing C++ tests
are registered with CTest. Root product Cargo.toml/Cargo.lock are unchanged.

## Code review

- Independent C++ and Rust DD/WGC capture benchmarks, shared-memory experiments,
  D3D11/D3D12 viewer, percentile/resource metrics and result comparison are kept.
- C++ shared-memory viewer checks BGRA/RGBA 8-bit formats, copies row-by-row using
  RowPitch, unmaps staging resources and releases the acquired duplication frame.
  Mapping handles are closed on reset. These paths were inspected, not proven
  by a live capture test.
- The WGC viewer uses a frame pool, pending/active frame ownership and explicit
  release/reset. Desktop resize, access loss, HDR and callback shutdown races
  still require interactive validation before any production adoption.
- Rust packages mix windows 0.61/0.62 and windows-capture versions. They must
  remain isolated from product dependencies; experiments are not all assumed
  build-compatible merely because the shared metrics library compiles.

See VALIDATION.md for actual build/test outcomes. No screen capture was started
and no performance numbers are claimed. After merge, recheck manifest and source
tip before source retirement; preserve any needed complete history, releases
and hosted records independently.
