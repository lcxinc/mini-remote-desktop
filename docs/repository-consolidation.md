# Repository consolidation

## P2P_Test bootstrap snapshot

The former `subprojects/P2P_Test` submodule pinned commit
`5264acfbd91e1226e753fd7c80d8c7401e990e42` from
`https://github.com/lcxinc/P2P_Test` (previously addressed through
`https://github.com/a1112/P2P_Test`). Its entire tracked tree consisted of
one `README.md` describing a bootstrap commit; it contained no implementation.

That README is now an ordinary tracked file at the same path. The source
gitlink and its `.gitmodules` section have been removed, so initializing this
consumer's submodules no longer requires the P2P_Test remote repository.
This does not add a P2P runtime or change any existing transport implementation.

## Obsolete Rdesk configuration

The `.gitmodules` entry for the old root-level `Rdesk` path had no matching
gitlink in the consumer's current tree. It has been removed. The maintained
desktop client remains under `apps/Rdesk`; its code is unchanged.
Removing this stale entry does not certify that every feature of the separate
Rdesk prototype has been migrated.

## GPU experiments imported at their existing pins

`subprojects/GPUTest` and `subprojects/GPU_Test_2` are now ordinary source
directories. Their existing pins are preserved in the manifests under
`docs/repository-consolidation/GPU-experiments/`. The repository owner explicitly
authorized publishing the reviewed source from these private repositories.

GPUTest retains all 415 source files, including vendored libsrt sources and its
MPL license. An empty workspace table isolates its Cargo manifest from the
product workspace; the original manifest is archived. GPU_Test_2 retains 46 of
55 files. Nine generated desktop captures and logs (about 32 MB) stay in the
original local checkout and are excluded from publication. Its ignore rules now
exclude future capture/log outputs. No large dataset was downloaded.

The experiments remain independent from the product crates. Third-party
reference submodules and the root Cargo workspace are unchanged. Current clones
no longer need the three source remotes GPUTest, GPU_Test_2 or P2P_Test.

Both experiment manifests pass `cargo metadata --offline --no-deps` and local
path/workspace checks. Complete protocol testing with Cargo is blocked by the
missing offline `nvenc` dependency. No GPU capture/encode run or full build is
claimed. See the manifests for exact-blob verification and explicit exclusions.
Seven existing latest-frame-slot and telemetry tests passed using a standalone
Rust test harness against the imported source modules. This checks those modules
without replacing dependencies or implying the full package compiled.

## Publication boundary

Keep source remotes until this change is merged and verified on the maintained
branch. Historical consumer commits still refer to the old submodules; preserve
their histories separately if historical recursive checkouts must remain
reproducible. File manifests do not back up branches, releases or hosted records.
