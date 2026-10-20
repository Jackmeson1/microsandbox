# Historical snapshot qualification

`historical-snapshots.py` creates fixtures using actual released CLI/firmware pairs, then restores them with a candidate. It currently covers the single-checkpoint directory and self-contained archive cells of the lifecycle compatibility matrix. A pass is a real guest checksum/metadata check followed by a write, stop, restart and persistent-write check. Parsing, importing, or starting a VM alone is insufficient.

The selected producers are 0.6.0 (the supported floor), 0.6.6 (the final `manifest.json` release), 0.6.7 (the following `snapshot.json` format), 0.6.18 (the end of the 0.6 line), and 0.7.8 (the released group/checkpoint format before the proposed CLI restructure). This selection does not claim every patch release or full-memory checkpoint is tested. Version 0.6 disk artifacts must not be described as memory checkpoints.

## Provision a producer

Download the matching platform bundle and its checksum list from the exact release. For example, on an Apple Silicon Mac:

```sh
mkdir -p /tmp/msb-historical-release/v0.6.0
gh release download v0.6.0 --repo superradcompany/microsandbox \
  --pattern microsandbox-darwin-aarch64.tar.gz --pattern checksums.sha256 \
  --dir /tmp/msb-historical-release/v0.6.0
python3 scripts/smoke/cli/historical-snapshots.py produce \
  --version 0.6.0 --release-dir /tmp/msb-historical-release/v0.6.0 \
  --output /tmp/msb-historical-fixture-060
```

For Linux x86-64 use `microsandbox-linux-x86_64.tar.gz`. The helper verifies the bundle checksum before extracting only the CLI and matching firmware, and checks the executable's exact version before creating a sandbox. Do not substitute a current firmware or agent for the producer. The released CLI supplies its own embedded agent. On Mac, the released signature must be valid; a locally built candidate needs the repository's VM entitlement signature.

The fixture uses a private short-path home under `/tmp`, explicit runtime/firmware selection, and no ambient `MSB_*` settings. Its source contains a random 4 MiB payload, 500 named files, a hardlink, a symlink and a non-default mode. It stops the source before capture, records integrity, exports the pinned image with the archive, and removes the source sandbox. The report includes binary/firmware/bundle hashes, platform, image descriptor, commands and original artifact hashes.

## Qualify a candidate

```sh
python3 scripts/smoke/cli/historical-snapshots.py qualify \
  --fixture /tmp/msb-historical-fixture-060 \
  --candidate /absolute/path/to/msb \
  --firmware /absolute/path/to/libkrunfw.5.dylib \
  --agent /absolute/path/to/matching/agentd \
  --output /tmp/msb-historical-result-060
```

Use the Linux firmware path on Linux. Omit `--agent` only when the candidate has its matching embedded agent. Every output directory must be new; failed runs and original fixtures are retained for diagnosis. The candidate gets another private home. Archive creation uses `--pull never`; the subsequent directory case reuses the image cache installed from that archive. Thus the directory case does not independently establish an image-free or fresh-cache restore. Directory migration operates on a private copy, never a hardlink to the original. The fixture inventory is checked before and after qualification. After directory restore, the original descriptor must remain byte-for-byte intact, either under its original name or as `.manifest.json.legacy` when migration occurred. Cleanup failures cannot produce a passing case.

The harness stops/removes its candidate sandboxes after each case. It retains private homes and logs for inspection; it never operates on the caller's normal home. Non-interactive stdin is explicit so commands cannot consume a surrounding SSH script. Commands have bounded timeouts and their own process groups. Interrupted supervisors are reaped; persistent runtime cleanup is attempted in the fixture's `finally` paths. Inspect cleanup results before deleting diagnostic homes after a failure.

## Evidence and remaining cells

Keep `fixture.json`, original archives/directories, all command logs, and `report.json`. Each case records its own pass/fail result; a failed archive case does not silently skip the directory attempt. Record the exact candidate commit separately from the binary hash. Mac and Linux fixtures are separate producers; same-host passes do not prove cross-host transfer.

The complete PR4 acceptance matrix additionally requires dependent histories and missing dependencies, installed name/ID selectors where supported, cross-host movement, populated-cache/conflicting import, reordered image metadata and foreign VMDK paths, interrupted upgrade/import/downgrade and retry, and downgrade refusal for unrepresentable newer states. These cells remain required even after every baseline case in this harness passes. New saved-config artifacts need final qualification after PR3's capture and restore paths are enabled.

VM-free harness checks:

```sh
python3 -m unittest discover -s scripts/smoke/cli -p test_historical_snapshots.py
```

## Baseline qualification on 2026-10-20

The candidate product tree `2e9553feaaf446f626391f157f7b937784feef3d` passed the following baseline on Apple Silicon macOS and x86-64 Linux. Every cell includes actual guest checksum/metadata verification, a new persistent write across restart, unchanged originals, and successful candidate stop/removal. The final harness hash was `763a00129b2760560b7cc8723483e2ad79c8b4ad7ed8f1f3422f9a339e031384`.

| Producer | Mac archive | Mac directory | Linux archive | Linux directory | Descriptor after directory restore |
| --- | --- | --- | --- | --- | --- |
| 0.6.0 | Pass | Pass | Pass | Pass | Exact original retained as `.manifest.json.legacy` |
| 0.6.6 | Pass | Pass | Pass | Pass | Exact original retained as `.manifest.json.legacy` |
| 0.6.7 | Pass | Pass | Pass | Pass | Original `snapshot.json` unchanged |
| 0.6.18 | Pass | Pass | Pass | Pass | Original `snapshot.json` unchanged |
| 0.7.8 | Pass | Pass | Pass | Pass | Original `snapshot.json` unchanged |

The complete CLI harness unit suite passed 124 tests on each host, including seven new historical-harness checks. Earlier diagnostic runs exposed inherited SSH stdin consuming later commands; the final harness uses `DEVNULL` and verifies this behavior. Existing Python SQLite resource warnings remain in the broad harness output. This evidence establishes these baseline cells, not the additional scenarios listed above. It demonstrates that no new converter is necessary for these specific historical artifacts.
