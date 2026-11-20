#!/usr/bin/env python3
"""Build portable, reproducible NetKit release archives with Python stdlib.

Run on a clean checkout with Go 1.23+:
    python3 scripts/package_release.py --version dev --output dist

Only packages artifacts; never creates a tag, GitHub Release or Homebrew update.
"""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = (
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
)
PAYLOADS = (
    ("README.md", "README.md"),
    ("cmd/netkit/public_suffix_list.dat", "licenses/public_suffix_list.dat"),
)

def source_commit():
    return subprocess.check_output(
        ["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT, text=True
    ).strip()

def archive_entries(binary: bytes, binary_name: str):
    entries = [(binary_name, binary, 0o755)]
    for path, target in PAYLOADS:
        entries.append((target, (ROOT / path).read_bytes(), 0o644))
    return sorted(entries, key=lambda item: item[0])

def tar_archive(destination: Path, entries):
    with destination.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data, mode in entries:
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = mode
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(data))

def zip_archive(destination: Path, entries):
    with zipfile.ZipFile(destination, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (mode << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="dev", help="dev or vMAJOR.MINOR.PATCH")
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()
    if args.version != "dev" and not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("version must be 'dev' or a strict vMAJOR.MINOR.PATCH tag")
    destination = Path(args.output).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        parser.error(f"output directory must be empty: {destination}")
    commit = source_commit()
    manifest = []
    with tempfile.TemporaryDirectory(prefix="netkit-build-") as temp_dir:
        for system, architecture in TARGETS:
            exe = "netkit.exe" if system == "windows" else "netkit"
            temporary = Path(temp_dir) / (system + "-" + architecture + "-" + exe)
            env = dict(os.environ, GOOS=system, GOARCH=architecture, CGO_ENABLED="0")
            ldflags = f"-s -w -buildid= -X main.version={args.version} -X main.commit={commit}"
            subprocess.run(
                ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags,
                 "-o", str(temporary), "./cmd/netkit"],
                cwd=ROOT, env=env, check=True,
            )
            stem = f"netkit_{args.version}_{system}_{architecture}"
            windows = system == "windows"
            path = destination / (stem + (".zip" if windows else ".tar.gz"))
            entries = archive_entries(temporary.read_bytes(), exe)
            if windows:
                zip_archive(path, entries)
            else:
                tar_archive(path, entries)
            manifest.append((path.name, hashlib.sha256(path.read_bytes()).hexdigest()))
            print(f"Created {path.name}")
    with (destination / "checksums.txt").open("w", encoding="utf-8", newline="\n") as out:
        for name, digest in sorted(manifest):
            out.write(f"{digest}  {name}\n")
    print(f"Wrote checksums for {len(manifest)} archives to {destination / 'checksums.txt'}")

if __name__ == "__main__":
    main()
