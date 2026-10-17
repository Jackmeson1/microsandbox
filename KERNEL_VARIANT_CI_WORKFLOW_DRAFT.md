# Kernel variant release lane — review draft

This is a proposed **sidecar lane** for the existing release workflow, not an active release change. Its [jobs fragment](drafts/kernel-variants/release-jobs.yml) and [helper](drafts/kernel-variants/kernel_variants.py) are intended to be copied into `.github/workflows/release.yml` under `jobs:` and `scripts/ci/kernel_variants.py` **after** the six feature profiles are approved. The live workflow and its five baseline `msb`/SDK builds remain unchanged in this draft.

## Exact prerequisite before these jobs can run

Create `scripts/ci/kernel-variant-profiles.json` with **six ordered, approved groups**. Each group must have a stable `id` and nonempty requested `CONFIG_*: "y"` maps for both `x86_64` and `aarch64`:

```json
{
  "groups": [
    {
      "id": "approved-group-name",
      "x86_64": {"CONFIG_APPROVED_SYMBOL": "y"},
      "aarch64": {"CONFIG_APPROVED_SYMBOL": "y"}
    }
  ]
}
```

The one-group schema example is intentionally **not a valid six-group profile**; `variant-profile-check` fails until six real groups are supplied. The group order assigns bit 0 through bit 5. `v00` is the existing default; `v01` through `v3f` select nonempty combinations. Validate each group's Kconfig dependencies and guest workload before filling the file. In particular, the current design proposal defers an architecture-neutral security group; this draft does not invent one. The helper rejects a requested symbol that `olddefconfig` does not resolve to `y`, records the resolved `.config`, and checks core baseline symbols remain enabled. It does not prove runtime behavior or complete cross-version compatibility.

## Job graph and counts

```text
existing kernel-sources ───────┐
approved profile check ────────┴─> 16 firmware jobs (2 guest arches × 8 shards)
existing default firmware ────────> existing five baseline runtime/SDK pipelines
16 firmware artifacts ──────────┬─> 2 Linux link jobs (63 variants each)
                                ├─> 1 macOS link job (63 variants)
                                └─> 16 Windows link jobs (2 targets × 8 shards)
                                     └─> variant-ready barrier
```

Each firmware shard builds seven or eight masks, so the new jobs produce **126 kernels**; the two existing defaults make **128 guest-architecture bundles**. The link jobs produce **315 new libraries**; the five existing default runtime jobs make **320 libraries total** across the five current host targets. The matrix creates 16 firmware jobs and 16 Windows link jobs, both below GitHub's per-job matrix limit. Both matrices set `max-parallel: 16`, allowing all shards to start in one wave when the stated 20-job Free account ceiling has capacity. This leaves four potential slots for other jobs, but does not reserve them; account contention and architecture-specific runner availability can still queue shards. The eight Windows shards limit each DLL job to eight links. The three Unix jobs link sequentially after downloading only the matching architecture's eight compressed firmware shards. All Linux libraries use the existing manylinux 2.28 images; Windows uses the pinned MSVC helper and current `windows-latest`/`windows-11-arm` labels.

The fragment names artifacts `variant-firmware-<guest arch>-s<0..7>` and `variant-libs-<target>` (Windows adds `-s<0..7>`). Every nondefault library sits at `vXX/<canonical libkrunfw filename>` with a checksum manifest. Shard archives include `kernel.c`, resolved `.config`, and a manifest per variant. The helper verifies source digests before linking and library digests before upload. The baseline keeps its existing filename, packaging, and discovery path.

## Adoption points and release gate

1. Copy the helper to `scripts/ci/kernel_variants.py`; add the approved profile file; then merge the [jobs fragment](drafts/kernel-variants/release-jobs.yml) under `jobs:` in `.github/workflows/release.yml`. Add `scripts/ci/kernel_variants.py`, `scripts/ci/kernel-variant-profiles.json`, and `vendor/libkrunfw` to that workflow's `pull_request.paths` so profile and firmware changes exercise the lane. Do not replace `kernel-sources`, `firmware-x86_64`, `firmware-aarch64`, or any existing reusable workflow call. Keep the existing `release-linux.yml`, `release-macos.yml`, and `release-windows.yml` baseline runtime paths intact.
2. Decide where the large variant payload will live. The draft uploads short-lived Actions artifacts for validation only and **does not publish variant binaries** or update SDK/CLI selection. Add the approved release-asset or external-object-store publication and a manifest consumer as a separate change. Current `release-ready` validates an exact baseline asset list; do not add `variant-libs-*` to its `release-*` download pattern or silently change that list.
3. Once every variant artifact can be validated and published, add `variant-ready` to `release-ready.needs` and add `test "${{ needs.variant-ready.result }}" = success` to its existing success-check step. Add aggregate identity/count and installed-variant smoke checks to the release gate before any publisher can run. No variant can be requested by an SDK until the bidirectional v0.6.x launch and persisted-state compatibility review is complete.

The resulting payload is large: at roughly 22–25 MB per library, 320 libraries occupy about **7–8 GB before kernel artifacts, manifests, and archive overhead**. `retention-days: 1` limits long-term Actions storage but not peak storage or download volume. Each of the sixteen Windows shard jobs downloads one matching firmware archive; each of the three Unix jobs downloads eight matching-architecture archives. The large Unix variant-library artifacts are uploaded once per target. The current GitHub Free artifact quota may make a full 64-combination release lane infeasible without external storage, demand-selected publication, or a larger plan. Check the account's actual available artifact storage before adoption. Account-wide runner contention likewise prevents a reliable wall-clock promise.

## Validation required after profiles exist

Resolve every requested mask on each architecture, compare resolved symbols with the manifest, boot representative combinations, and exercise the named features plus baseline filesystems/networking/agent/shutdown. Measure variant kernel size and Windows DLL resource behavior. Check Linux glibc baseline, macOS library loading, and native Windows x86_64/aarch64 loading. Test library selection, old SDK/new `msb` and new SDK/old `msb`, restarts, snapshots, and explicit unsupported-feature errors before enabling feature requests or publication. The draft CI helper checks build integrity; it does **not** replace those gates.
