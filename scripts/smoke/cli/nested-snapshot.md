# Running nested VM snapshot qualification

`nested-snapshot.py` runs an inner Linux VM through full snapshot restore, two
forks, a second snapshot generation, and archive export/import. It checks the
inner workload's memory identity, monotonic timer and counter, and disk readback
records for ten seconds after each operation. The source must keep progressing.
The outer sandbox uses a managed root disk, so this also exercises Microsandbox's
disk capture and restore integration.

This is a manual hardware qualification test. The public runtime still rejects
nested execution capture. Set `NESTED_EXPECT_UNSUPPORTED=1` with a public build to
check rejection of both full snapshots and forks while the source keeps running.
The positive matrix requires the isolated diagnostic build described in
libkrun's `tests/nested-restore/README.md`; never ship its admission bypass.

## Fixture

Use the matching libkrun `tests/nested-restore/os/build.sh` on Linux of the guest
architecture. Its parent root contains QEMU, an inner kernel, initramfs and ext4
disk. Add `/bin/sh` pointing to `busybox`, a `/root` directory, and these files:

```text
# /etc/passwd
root:x:0:0:root:/root:/bin/sh
# /etc/group
root:x:0:
```

Package that parent root as an OCI image for the same architecture, with
`PATH=/bin:/usr/bin` and `/bin/sh` as its default command. For example, copy the
parent contents into a scratch Docker image and export it with `docker save`.
Load the archive with `msb image load -i nested-image.tar`. A plain directory image
cannot provide the managed root disk required by this test.

The outer firmware must include KVM support. Use a matching inner Linux kernel
with the devices and filesystem support listed in libkrun's fixture README.

## Run

Use a disposable home and an absolute path to the candidate binary. On macOS,
codesign that exact binary with `msb-entitlements.plist` before running it.

```sh
export MSB_HOME=/tmp/nested-snapshot-home
export MSB_PATH=/absolute/path/to/msb
export NESTED_IMAGE=nested-restore-test:latest
export NESTED_RESULTS=/tmp/nested-snapshot-results
# Set MSB_LIBKRUNFW_PATH if using a local firmware build.
python3 scripts/smoke/cli/nested-snapshot.py
```

`NESTED_ARCH` can override the host architecture when needed. Results contain
numbered command outputs and a `result.json` only after all checks pass. The
script stops its uniquely named sandboxes in a `finally` block. Keep the home
until evidence has been inspected, then remove it through normal cleanup.

This does not qualify cross-host migration, networking, external mounts, or
hardware platforms on which the matrix has not run. A diagnostic pass does not
open public nested-snapshot admission.
