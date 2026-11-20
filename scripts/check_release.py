#!/usr/bin/env python3
"""Verify the archive manifest, contents, and embedded release version."""
import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile

TARGETS = (
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
)

def check_archive(path: Path, platform: str):
    exe = "netkit.exe" if platform == "windows" else "netkit"
    required = {exe, "README.md", "licenses/public_suffix_list.dat"}
    if platform == "windows":
        with zipfile.ZipFile(path) as archive:
            members = set(archive.namelist())
            if members != required:
                raise ValueError(f"{path}: wrong archive members {members!r}")
            if not archive.read(exe):
                raise ValueError(f"{path}: empty binary")
            psl = archive.read("licenses/public_suffix_list.dat")
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = {m.name for m in archive.getmembers()}
            if members != required:
                raise ValueError(f"{path}: wrong archive members {members!r}")
            executable = archive.getmember(exe)
            if not executable.mode & 0o111:
                raise ValueError(f"{path}: executable mode missing")
            if executable.size <= 0:
                raise ValueError(f"{path}: empty binary")
            psl = archive.extractfile("licenses/public_suffix_list.dat").read()
    if b"Mozilla Public" not in psl:
        raise ValueError(f"{path}: third-party PSL source/license header missing")

def verify(dist: Path, version: str):
    checksum_path = dist / "checksums.txt"
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    expected = {}
    for system, arch in TARGETS:
        stem = f"netkit_{version}_{system}_{arch}"
        expected[stem + (".zip" if system == "windows" else ".tar.gz")] = system
    if len(lines) != len(expected):
        raise ValueError("expected exactly one checksum per release target")
    seen = set()
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (netkit_[A-Za-z0-9._-]+\.(?:tar\.gz|zip))", line)
        if not match:
            raise ValueError(f"invalid checksum row: {line!r}")
        digest, name = match.groups()
        if name in seen or name not in expected:
            raise ValueError(f"duplicate or unexpected archive: {name}")
        seen.add(name)
        source = dist / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError(f"checksum mismatch: {name}")
        check_archive(source, expected[name])
    if seen != set(expected):
        raise ValueError(f"missing release assets: {set(expected) - seen}")
    if {p.name for p in dist.iterdir()} != set(expected) | {"checksums.txt"}:
        raise ValueError("unexpected files in release output directory")
    return len(expected)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", default="dist")
    args = parser.parse_args()
    count = verify(Path(args.dist).resolve(), args.version)
    print(f"Verified {count} platform archives and all SHA256 checksums")

if __name__ == "__main__":
    main()
