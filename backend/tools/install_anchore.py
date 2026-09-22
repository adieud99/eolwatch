#!/usr/bin/env python3
"""Install the Linux worker tools from checksum-pinned official release archives."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import tarfile
from urllib.request import urlopen


# 2026-09-22: 1.51.1 / 0.118.0 -> 1.52.0 / 0.119.0 (grype: deterministic --by-cve merge, distro-dropped matches in
# ignoredMatches; syft: bounded .deb/kernel-module decompression). Checksums verified against the release assets.
VERSIONS = {"syft": "1.52.0", "grype": "0.119.0"}
# https://github.com/anchore/{tool}/releases/download/v{version}/{tool}_{version}_checksums.txt
# https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt (2026-09-22)
TRIVY_VERSION = "0.74.0"
TRIVY_CHECKSUMS = {"amd64": "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
                   "arm64": "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"}
CHECKSUMS = {
    ("syft", "amd64"): "caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d",
    ("syft", "arm64"): "c46d5e4c28e12aa4c5becfaa343ef1c7f89045b6b895f2c21d471c62db09c706",
    ("grype", "amd64"): "3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b",
    ("grype", "arm64"): "29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8",
}


def install(destination: Path) -> None:
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if platform.system() != "Linux" or arch is None:
        raise RuntimeError("Analysis worker tools require Linux arm64 or amd64")
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {"system": "Linux", "architecture": arch, "tools": {}, "remote_syft": {}}
    for name, version in VERSIONS.items():
        filename = f"{name}_{version}_linux_{arch}.tar.gz"
        url = f"https://github.com/anchore/{name}/releases/download/v{version}/{filename}"
        with urlopen(url, timeout=120) as response:
            archive = response.read(128 * 1024 * 1024 + 1)
        if len(archive) > 128 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != CHECKSUMS[name, arch]:
            raise RuntimeError(f"Official release archive checksum mismatch: {filename}")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            members = [entry for entry in package.getmembers() if entry.name in (name, "./" + name) and entry.isfile()]
            if len(members) != 1:
                raise RuntimeError(f"Expected exactly one executable in {filename}")
            binary = package.extractfile(members[0]).read()
        tool_path = destination / name
        tool_path.write_bytes(binary)
        tool_path.chmod(0o755)
        manifest["tools"][name] = {"version": version, "archive_sha256": CHECKSUMS[name, arch],
                                  "binary_sha256": hashlib.sha256(binary).hexdigest(), "url": url}
        print(f"Installed verified {name} {version} for Linux {arch}", flush=True)
    # Targets may run on the other CPU family: keep a verified syft for each so the worker can copy the right one.
    for target_arch in ("amd64", "arm64"):
        version = VERSIONS["syft"]
        filename = f"syft_{version}_linux_{target_arch}.tar.gz"
        url = f"https://github.com/anchore/syft/releases/download/v{version}/{filename}"
        with urlopen(url, timeout=120) as response:
            archive = response.read(128 * 1024 * 1024 + 1)
        if len(archive) > 128 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != CHECKSUMS["syft", target_arch]:
            raise RuntimeError(f"Official release archive checksum mismatch: {filename}")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            members = [entry for entry in package.getmembers() if entry.name in ("syft", "./syft") and entry.isfile()]
            if len(members) != 1:
                raise RuntimeError(f"Expected exactly one executable in {filename}")
            binary = package.extractfile(members[0]).read()
        tool_path = destination / f"syft-{target_arch}"
        tool_path.write_bytes(binary)
        tool_path.chmod(0o755)
        manifest["remote_syft"][target_arch] = {"version": version, "archive_sha256": CHECKSUMS["syft", target_arch],
                                                "binary_sha256": hashlib.sha256(binary).hexdigest(), "url": url}
        print(f"Installed verified syft {version} for remote Linux {target_arch}", flush=True)
    # Second scanner for cross-checking: Trivy reads the same SPDX file. Aqua names the archives by CPU word size.
    trivy_arch = {"amd64": "64bit", "arm64": "ARM64"}[arch]
    filename = f"trivy_{TRIVY_VERSION}_Linux-{trivy_arch}.tar.gz"
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{filename}"
    with urlopen(url, timeout=120) as response:
        archive = response.read(128 * 1024 * 1024 + 1)
    if len(archive) > 128 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != TRIVY_CHECKSUMS[arch]:
        raise RuntimeError(f"Official release archive checksum mismatch: {filename}")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        members = [entry for entry in package.getmembers() if entry.name in ("trivy", "./trivy") and entry.isfile()]
        if len(members) != 1:
            raise RuntimeError(f"Expected exactly one executable in {filename}")
        binary = package.extractfile(members[0]).read()
    tool_path = destination / "trivy"
    tool_path.write_bytes(binary)
    tool_path.chmod(0o755)
    manifest["tools"]["trivy"] = {"version": TRIVY_VERSION, "archive_sha256": TRIVY_CHECKSUMS[arch],
                                 "binary_sha256": hashlib.sha256(binary).hexdigest(), "url": url}
    print(f"Installed verified trivy {TRIVY_VERSION} for Linux {arch}", flush=True)
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path("/opt/analysis-tools"))
    install(parser.parse_args().destination)
