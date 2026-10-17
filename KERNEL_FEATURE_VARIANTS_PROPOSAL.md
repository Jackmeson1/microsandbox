# Optional libkrunfw kernel feature variants — draft

## Recommendation

Keep the existing kernel as the **default**. Organize requests by workload rather than treating every absent Kconfig symbol as a switch. For an initial experiment, use five optional groups spanning guest networking, protected files, desktop buffers, observability, and compressed memory. Security policy and process checkpointing need more design work before becoming switches. Publish only combinations justified by workloads; a group is a tested capability contract, not a promise that arbitrary Linux symbols are available.

Five independent groups have `2^5 = 32` possible feature sets **per guest architecture, including default** (64 x86_64/aarch64 kernels if every set is built). Ten have `2^10 = 1,024` per architecture (2,048 across those two). These counts precede host OS linking, release assets, validation, and storage. Choosing a prebuilt binary whose verified features cover a request, while accepting extras, avoids publishing every exact combination. It does not make the full power set cheap; start with default, single-group variants, and a few measured supersets.

## What the default already contains

The pinned normal x86_64 and aarch64 inputs in `vendor/libkrunfw` (`21f169f`) show:

| Area | Present in both default config inputs | Material gap or caveat |
| --- | --- | --- |
| **Networking** | `CONFIG_BPF_SYSCALL`, `CONFIG_NF_TABLES`, `CONFIG_BRIDGE`, `CONFIG_VETH`, `CONFIG_VXLAN`, and `CONFIG_TUN` are `y`. | `CONFIG_BPF_JIT`, `CONFIG_WIREGUARD`, `CONFIG_MACVLAN`, `CONFIG_IPVLAN`, `CONFIG_MPTCP`, and `CONFIG_IP_SCTP` are off. |
| **Filesystems and storage** | ext4, XFS, Btrfs, EROFS, FUSE, OverlayFS, and loop block devices are `y` (`CONFIG_EXT4_FS`, `CONFIG_XFS_FS`, `CONFIG_BTRFS_FS`, `CONFIG_EROFS_FS`, `CONFIG_FUSE_FS`, `CONFIG_OVERLAY_FS`, `CONFIG_BLK_DEV_LOOP`). | `CONFIG_FS_ENCRYPTION` and `CONFIG_FS_VERITY` are off. SquashFS is `y` on aarch64 but off on x86_64; `CONFIG_DM_CRYPT=y` on x86_64, so neither is a uniform optional gap. A filesystem driver's presence does not establish every compression, ACL, or security subfeature. |
| **Graphics and input** | `CONFIG_DRM_VIRTIO_GPU=y` and `CONFIG_VIRTIO_INPUT=y`. | `CONFIG_UDMABUF` and `CONFIG_HID` are off; `CONFIG_HID_SUPPORT=y` alone is not a HID driver. Host device support and guest userspace still matter. |
| **Observability** | BPF syscall and `CONFIG_PERF_EVENTS=y`. | `CONFIG_FTRACE` and `CONFIG_BPF_JIT` are off. |
| **Memory and process** | Existing VM memory and snapshot behavior is the baseline. | `CONFIG_ZRAM` and `CONFIG_CHECKPOINT_RESTORE` are off; neither setting alone provides a Microsandbox snapshot feature. |
| **Security policy** | x86_64 has `CONFIG_SECURITY=y` and SELinux built in. | aarch64 has `CONFIG_SECURITY` off; AppArmor is off on x86_64. This is not one architecture-neutral toggle. |

These are **config-file observations**, not measurements of a freshly resolved or booted variant. The Makefile downloads and patches Linux 6.12.111, copies `config-libkrunfw_<guest arch>` to `.config`, runs `olddefconfig`, builds the kernel, and embeds the image in `kernel.c`/libkrunfw. The release graph currently builds one `kernel.c` per guest architecture and links it into host libraries. Runtime resolution selects one `msb`/libkrunfw pair or an explicit library path; VM launch passes that path to libkrun. It has no feature manifest or feature-aware selector today. Windows x86_64, SEV, TDX, and riscv64 use distinct config paths and are outside the initial normal-kernel recommendation.

## Five candidate optional groups

The Kconfig names below are **requests to test against the pinned patched kernel**. A published variant must be described by its resolved `.config`, because dependencies may hide, change, or add symbols.

| Group | Workload and candidate Kconfig requests beyond default | Boundary to check |
| --- | --- | --- |
| **Advanced guest networking** | WireGuard and guest policy routes: `CONFIG_WIREGUARD=y`, `CONFIG_IP_ADVANCED_ROUTER=y`, `CONFIG_IP_MULTIPLE_TABLES=y`, `CONFIG_IPV6_MULTIPLE_TABLES=y`. Guest-created container links: `CONFIG_MACVLAN=y`, `CONFIG_IPVLAN=y`. | All visible candidate gaps are off in both inputs; `IP_MULTIPLE_TABLES` appears only after its parent is enabled. These are one practical network-workload switch for a small matrix, not kernel dependencies on each other. If VPN and virtual-link demand diverge, split the group and accept a larger matrix. Existing bridge/VXLAN/nftables remain baseline. |
| **Protected files** | Filesystem-level confidentiality/integrity: `CONFIG_FS_ENCRYPTION=y`, `CONFIG_FS_VERITY=y`. | Both are off in both inputs. They solve different problems and need matching filesystem modes, keys/metadata, and guest userspace. The group is justified only for a workload using both; otherwise publish one targeted variant or split it. Do not assume `CONFIG_DM_VERITY` or full encrypted-disk support is implied. |
| **Desktop buffers** | DMA-BUF export for a demonstrated virtio-GPU/Wayland workflow: `CONFIG_UDMABUF=y`. | Off in both inputs. Virtio GPU and virtio input are already baseline. Add `CONFIG_HID=y` only if an actual device path requires it; a kernel option cannot create a host GPU/input device, permissions, or display stack. |
| **Guest tracing** | Function/event tracing: `CONFIG_FTRACE=y`; evaluate `CONFIG_FUNCTION_TRACER`, `CONFIG_KPROBE_EVENTS`, `CONFIG_UPROBE_EVENTS`, `CONFIG_BPF_EVENTS`, and possibly `CONFIG_BPF_JIT` after dependency resolution. | FTRACE and BPF JIT are off in both inputs; the event options may be hidden until parents are enabled. Measure image size, startup, runtime overhead, and security exposure. BPF syscall/perf already belong to default. |
| **Compressed memory** | Guest-managed compressed swap or RAM block device: `CONFIG_ZRAM=y`. | Off in both inputs. This needs guest setup and a memory-pressure benefit; do not equate it with host VM memory compression or snapshots. |

Do not silently enable broad parents merely to make a requested symbol resolve. Record every required dependency and decide whether the resulting feature still belongs in the group. Overlaps matter: filesystem protection may need crypto already used by networking, and tracing may change BPF capabilities. Validate combinations rather than assuming independent Kconfig effects from independent product switches.

## Capabilities to defer

- **Other network protocols:** `CONFIG_MPTCP`, `CONFIG_IP_SCTP`, and `CONFIG_GENEVE` are off in both inputs. Add a transport or overlay group only for a concrete use case; they need not ride with VPN routing. IPsec, traffic control, and IPVS also need separate workload review.
- **Other storage formats:** x86_64 lacks SquashFS while aarch64 already has it. An image-format group might target that specific x86_64 gap, but should be driven by an image that needs it. `CONFIG_DM_VERITY` is off on x86_64; assess its block-device and boot-policy path separately from `FS_VERITY`.
- **Process restore:** `CONFIG_CHECKPOINT_RESTORE` is off on both. Guest CRIU-style use, Microsandbox VM snapshots, and persisted snapshot compatibility are different contracts; do not fold them into compressed memory.
- **Security policy:** x86_64 SELinux and aarch64's disabled `CONFIG_SECURITY` make a uniform AppArmor/SELinux switch misleading. Define the policy-loading, LSM ordering, architecture parity, and compatibility behavior before proposing a security variant.

## Manifest, selection, and validation

Publish an immutable manifest per binary: compatible release/build identity, guest architecture, host OS/ABI, group IDs, exact resolved capability symbols, resolved `.config` digest, kernel/patch and library digests, and workload validation. Keep the default library at its existing path. For a request, choose a compatible published binary whose **verified** capabilities cover the requested groups, prefer the fewest extras with a deterministic tie-break, and return a clear unavailable-feature error if none qualifies. Never infer support from a filename or silently choose default. Older SDK/`msb` peers must not silently drop a new request; review both launch directions and persisted sandbox/restart/snapshot behavior against the supported v0.6.x horizon before implementation.

First, resolve default plus each single-group request with `olddefconfig` on both normal guest architectures and diff requested versus actual symbols. Next, boot each variant and representative overlaps, exercise the named workload and baseline networking/filesystem/agent/shutdown paths, and measure size, build time, boot time, and tracing cost. Finally, test manifest selection, missing/tampered binaries, restarts, snapshots, and cross-version launch before changing release packaging or public APIs. Host OS and distinct Windows/TEE paths require their own validation.

This is a design proposal only. No variant config was resolved, kernel built, guest booted, or CI cost measured for this draft.
