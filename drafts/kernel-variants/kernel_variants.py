#!/usr/bin/env python3
"""Draft CI helper for six-group libkrunfw kernel variants.

This file is not wired into the release workflow. Move it to
scripts/ci/kernel_variants.py when the profile contract has been approved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path


ARCHES = ("x86_64", "aarch64")
TARGET_ARCH = {
    "linux-x86_64": "x86_64",
    "linux-aarch64": "aarch64",
    "darwin-aarch64": "aarch64",
    "windows-x86_64": "x86_64",
    "windows-aarch64": "aarch64",
}
BASELINE = (
    "CONFIG_EXT4_FS",
    "CONFIG_EROFS_FS",
    "CONFIG_FUSE_FS",
    "CONFIG_OVERLAY_FS",
    "CONFIG_DRM_VIRTIO_GPU",
    "CONFIG_VIRTIO_INPUT",
)
SYMBOL = re.compile(r"CONFIG_[A-Z0-9_]+\Z")
GROUP_ID = re.compile(r"[a-z][a-z0-9-]*\Z")
PROFILE_FILE = Path(__file__).with_name("kernel-variant-profiles.json")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def profile_groups(path: Path) -> list[dict]:
    if not path.is_file():
        raise ValueError(f"required approved profile file is missing: {path}")
    payload = json.loads(path.read_text())
    if set(payload) != {"groups"} or not isinstance(payload["groups"], list):
        raise ValueError("profile must contain only a groups array")
    groups = payload["groups"]
    if len(groups) != 6:
        raise ValueError("exactly six ordered groups are required")
    ids = []
    for group in groups:
        if set(group) != {"id", "x86_64", "aarch64"}:
            raise ValueError("each group needs id, x86_64, and aarch64")
        if not isinstance(group["id"], str) or not GROUP_ID.fullmatch(group["id"]):
            raise ValueError(f"invalid group id: {group['id']!r}")
        ids.append(group["id"])
        for arch in ARCHES:
            symbols = group[arch]
            if not isinstance(symbols, dict) or not symbols:
                raise ValueError(f"{group['id']} needs a nonempty {arch} symbol map")
            for key, value in symbols.items():
                if not SYMBOL.fullmatch(key) or value != "y":
                    raise ValueError(f"invalid {group['id']}/{arch} request: {key}={value}")
    if len(set(ids)) != len(ids):
        raise ValueError("group ids must be unique")
    return groups


def selected(groups: list[dict], arch: str, mask: int) -> tuple[list[str], list[str]]:
    names = []
    requested = set()
    for bit, group in enumerate(groups):
        if mask & (1 << bit):
            names.append(group["id"])
            requested.update(group[arch])
    return names, sorted(requested)


def render_config(base: str, requested: list[str]) -> str:
    # Remove every old assignment before appending a single requested value.
    matches = {key for key in requested}
    lines = []
    for line in base.splitlines():
        found = re.match(r"(?:# )?(CONFIG_[A-Z0-9_]+)(?:=| is not set)", line)
        if found is None or found.group(1) not in matches:
            lines.append(line)
    lines.extend(f"{key}=y" for key in requested)
    return "\n".join(lines) + "\n"


def resolved_config(path: Path) -> dict[str, str]:
    resolved = {}
    for line in path.read_text().splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            resolved[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            resolved[line[2:-11]] = "n"
    return resolved


def variant_name(mask: int) -> str:
    if not 0 <= mask <= 63:
        raise ValueError("variant mask must be 0..63")
    return f"v{mask:02x}"


def build_shard(args: argparse.Namespace) -> None:
    groups = profile_groups(args.profiles)
    root = args.repo.resolve()
    fw = root / "vendor/libkrunfw"
    base_path = fw / f"config-libkrunfw_{args.arch}"
    original = base_path.read_text()
    version_match = re.search(r"^KERNEL_VERSION = (linux-[\d.]+)$", (fw / "Makefile").read_text(), re.M)
    if version_match is None:
        raise ValueError("cannot identify pinned Linux source directory")
    source_dir = fw / version_match.group(1)
    output = args.output.resolve()
    shard_dir = output / f"s{args.shard}"
    shard_dir.mkdir(parents=True, exist_ok=False)
    firmware_rev = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=fw, text=True).strip()
    try:
        for mask in range(max(1, args.shard * 8), args.shard * 8 + 8):
            names, requested = selected(groups, args.arch, mask)
            run("make", "clean", cwd=fw)
            base_path.write_text(render_config(original, requested))
            run("make", f"-j{os.cpu_count() or 2}", "kernel.c", cwd=fw)

            config = source_dir / ".config"
            resolved = resolved_config(config)
            missing = [key for key in (*requested, *BASELINE) if resolved.get(key) != "y"]
            if missing:
                raise ValueError(f"{args.arch}/{variant_name(mask)} unresolved symbols: {missing}")

            variant = shard_dir / variant_name(mask)
            variant.mkdir()
            shutil.copyfile(fw / "kernel.c", variant / "kernel.c")
            shutil.copyfile(config, variant / "resolved.config")
            manifest = {
                "schema": 1,
                "guest_arch": args.arch,
                "variant": variant_name(mask),
                "mask": mask,
                "groups": names,
                "requested_y": requested,
                "kernel_c_sha256": sha256(variant / "kernel.c"),
                "resolved_config_sha256": sha256(variant / "resolved.config"),
                "libkrunfw_revision": firmware_rev,
                "profile_sha256": sha256(args.profiles),
            }
            (variant / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    finally:
        base_path.write_text(original)

    archive = output / f"firmware-{args.arch}-s{args.shard}.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=1) as tar:
        tar.add(shard_dir, arcname=shard_dir.name)
    print(archive)


def unpack(args: argparse.Namespace) -> None:
    archives = sorted(args.archives.glob("firmware-*.tar.gz"))
    if len(archives) != args.expected_archives:
        raise ValueError(f"expected {args.expected_archives} archives, got {len(archives)}")
    args.output.mkdir(parents=True, exist_ok=False)
    seen = set()
    for archive in archives:
        match = re.fullmatch(rf"firmware-{args.arch}-s([0-7])\.tar\.gz", archive.name)
        if match is None or match.group(1) in seen:
            raise ValueError(f"unexpected or duplicate archive: {archive.name}")
        seen.add(match.group(1))
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                parts = Path(member.name).parts
                if (
                    len(parts) < 1
                    or parts[0] != f"s{match.group(1)}"
                    or any(part in (".", "..") for part in parts)
                    or not (member.isdir() or member.isfile())
                ):
                    raise ValueError(f"unsafe archive entry: {member.name}")
                destination = args.output.joinpath(*parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as source, destination.open("wb") as target:
                        shutil.copyfileobj(source, target)


def source_variant(root: Path, arch: str, mask: int) -> tuple[Path, dict]:
    variant = root / f"s{mask // 8}" / variant_name(mask)
    manifest = json.loads((variant / "manifest.json").read_text())
    if manifest["schema"] != 1 or manifest["guest_arch"] != arch or manifest["mask"] != mask:
        raise ValueError(f"wrong firmware manifest: {variant}")
    if manifest["profile_sha256"] != sha256(PROFILE_FILE):
        raise ValueError(f"profile digest mismatch: {variant}")
    for filename, field in (("kernel.c", "kernel_c_sha256"), ("resolved.config", "resolved_config_sha256")):
        if sha256(variant / filename) != manifest[field]:
            raise ValueError(f"firmware digest mismatch: {variant / filename}")
    return variant, manifest


def record_library(source: Path, manifest: dict, library: Path, output: Path, target: str) -> None:
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(library, output / library.name)
    payload = {
        "schema": 1,
        "host_target": target,
        "guest_arch": manifest["guest_arch"],
        "variant": manifest["variant"],
        "groups": manifest["groups"],
        "firmware_manifest_sha256": sha256(source / "manifest.json"),
        "library_filename": library.name,
        "library_sha256": sha256(output / library.name),
    }
    (output / "manifest.json").write_text(json.dumps(payload, sort_keys=True) + "\n")


def link_unix(args: argparse.Namespace) -> None:
    arch = TARGET_ARCH[args.target]
    if args.target.startswith("linux-"):
        filename = "libkrunfw.so.5.6.1"
        extra = ["-Wl,-soname,libkrunfw.so.5"]
    elif args.target == "darwin-aarch64":
        filename = "libkrunfw.5.dylib"
        extra = []
    else:
        raise ValueError(f"not a Unix target: {args.target}")
    for mask in range(1, 64):
        variant, manifest = source_variant(args.firmware, arch, mask)
        temp = args.output / f"tmp-{variant_name(mask)}"
        temp.mkdir(parents=True)
        library = temp / filename
        run("cc", "-fPIC", "-DABI_VERSION=5", "-shared", *extra, "-o", str(library), str(variant / "kernel.c"))
        if args.target.startswith("linux-"):
            run("strip", str(library))
        record_library(variant, manifest, library, args.output / variant_name(mask), args.target)
        shutil.rmtree(temp)


def record_windows(args: argparse.Namespace) -> None:
    arch = TARGET_ARCH[args.target]
    variant, manifest = source_variant(args.firmware, arch, args.mask)
    record_library(variant, manifest, args.library, args.output / variant_name(args.mask), args.target)


def verify_linked(args: argparse.Namespace) -> None:
    masks = range(1, 64) if args.shard is None else range(max(1, args.shard * 8), args.shard * 8 + 8)
    expected = {variant_name(mask) for mask in masks}
    found = {path.name for path in args.output.iterdir() if path.is_dir()}
    if found != expected:
        raise ValueError(f"library variants differ: missing={expected - found}, extra={found - expected}")
    for name in expected:
        folder = args.output / name
        manifest = json.loads((folder / "manifest.json").read_text())
        if manifest["host_target"] != args.target or manifest["variant"] != name:
            raise ValueError(f"wrong library manifest: {folder}")
        library = folder / manifest["library_filename"]
        if sha256(library) != manifest["library_sha256"]:
            raise ValueError(f"library digest mismatch: {library}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check-profiles")
    check.add_argument("--profiles", type=Path, required=True)
    build = sub.add_parser("build-shard")
    build.add_argument("--profiles", type=Path, required=True)
    build.add_argument("--repo", type=Path, default=Path("."))
    build.add_argument("--arch", choices=ARCHES, required=True)
    build.add_argument("--shard", type=int, choices=range(8), required=True)
    build.add_argument("--output", type=Path, required=True)
    extract = sub.add_parser("unpack")
    extract.add_argument("--arch", choices=ARCHES, required=True)
    extract.add_argument("--archives", type=Path, required=True)
    extract.add_argument("--expected-archives", type=int, required=True)
    extract.add_argument("--output", type=Path, required=True)
    link = sub.add_parser("link-unix")
    link.add_argument("--target", choices=[name for name in TARGET_ARCH if not name.startswith("windows-")], required=True)
    link.add_argument("--firmware", type=Path, required=True)
    link.add_argument("--output", type=Path, required=True)
    win = sub.add_parser("record-windows")
    win.add_argument("--target", choices=[name for name in TARGET_ARCH if name.startswith("windows-")], required=True)
    win.add_argument("--mask", type=int, choices=range(1, 64), required=True)
    win.add_argument("--firmware", type=Path, required=True)
    win.add_argument("--library", type=Path, required=True)
    win.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify-linked")
    verify.add_argument("--target", choices=TARGET_ARCH, required=True)
    verify.add_argument("--shard", type=int, choices=range(8))
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "check-profiles":
        profile_groups(args.profiles)
    elif args.command == "build-shard":
        build_shard(args)
    elif args.command == "unpack":
        unpack(args)
    elif args.command == "link-unix":
        link_unix(args)
    elif args.command == "record-windows":
        record_windows(args)
    elif args.command == "verify-linked":
        verify_linked(args)


if __name__ == "__main__":
    main()
