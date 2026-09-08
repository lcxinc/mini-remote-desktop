# GPU_Test_2 Submodule Implementation Plan

> Historical plan, superseded on 2026-09-08: GPU_Test_2 is now imported as ordinary
> source at the same path. Do not rerun the submodule-add steps below. See
> [repository consolidation](../repository-consolidation.md) for current status.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `GPU_Test_2` to the `mini-remote-desktop` repository as a git submodule at `subprojects/GPU_Test_2`.

**Architecture:** Clone the main repository, then register `GPU_Test_2` as a submodule that points at its GitHub remote. This keeps the child project independently versioned while allowing the parent repository to pin an exact commit.

**Tech Stack:** Git, Git submodules, GitHub remotes

---

### Task 1: Add the submodule

**Files:**
- Create: `subprojects/GPU_Test_2`
- Modify: `.gitmodules`

**Step 1: Inspect the target repository state**

Run: `git status --short --branch`
Expected: clean checkout on the default branch

**Step 2: Add the submodule**

Run: `git submodule add https://github.com/a1112/GPU_Test_2 subprojects/GPU_Test_2`
Expected: `.gitmodules` updated and `subprojects/GPU_Test_2` checked out

**Step 3: Verify the registration**

Run: `git submodule status --recursive`
Expected: one entry for `subprojects/GPU_Test_2`

**Step 4: Verify working tree changes**

Run: `git status --short`
Expected: staged or unstaged additions for `.gitmodules` and `subprojects/GPU_Test_2`
