#!/usr/bin/env python3
"""Install pinned Anchore binaries under ignored project runtime; verify SHA-256."""
from pathlib import Path
import hashlib
import io
import platform
import tarfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1] / 'infrastructure/local-vm/runtime/tools'
VERSIONS = {'syft': '1.51.1', 'grype': '0.118.0'}


def install(name, system, arch):
    version = VERSIONS[name]
    filename = f'{name}_{version}_{system}_{arch}.tar.gz'
    base = f'https://github.com/anchore/{name}/releases/download/v{version}/'
    destination = ROOT / f'{system}_{arch}' / name
    with urlopen(base + f'{name}_{version}_checksums.txt', timeout=60) as response:
        checksums = response.read().decode()
    expected = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip('*') == filename)
    print(f'Downloading {filename}', flush=True)
    with urlopen(base + filename, timeout=120) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != expected:
        raise RuntimeError(f'Checksum mismatch: {filename}')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        member = next(m for m in tar.getmembers() if m.name in (name, './' + name) and m.isfile())
        binary = tar.extractfile(member).read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(binary)
    destination.chmod(0o755)
    print(f'Installed {destination} (archive SHA-256 {expected})', flush=True)


if __name__ == '__main__':
    system = platform.system().lower()
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    for name in VERSIONS:
        install(name, system, arch)
    if (system, arch) != ('linux', 'arm64'):
        install('syft', 'linux', 'arm64')
