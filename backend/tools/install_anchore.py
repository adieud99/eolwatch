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


VERSIONS = {"syft": "1.51.1", "grype": "0.118.0"}
# https://github.com/anchore/{tool}/releases/download/v{version}/{tool}_{version}_checksums.txt
CHECKSUMS = {
    ("syft", "amd64"): "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3",
    ("syft", "arm64"): "a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f",
    ("grype", "amd64"): "1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2",
    ("grype", "arm64"): "32aceeb8ee837244775fcb522372c8b3a47914986385f3148f4ee2c930482a84",
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
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path("/opt/analysis-tools"))
    install(parser.parse_args().destination)
