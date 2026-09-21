#!/usr/bin/env python3
"""Install a pinned baseline/fixed demo venv on either allowlisted local lab VM.

Only ~/eolwatch-demo is managed. No sudo, OS package changes, or exposed HTTP
listener. Package wheels are verified against hashes from the official PyPI API.
The helper pip wheel stays outside the scanned venv.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
from urllib.request import urlopen

PROJECT = Path(__file__).resolve().parents[1]
RUNTIME = PROJECT / "infrastructure/local-vm/runtime"
TARGETS = {"LAB-VM-01": (12223, "10.77.0.21"), "LAB-VM-02": (12224, "10.77.0.22")}
VERSIONS = {"baseline": "3.1.4", "fixed": "3.1.6"}


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, timeout=180, **kwargs)


def wheel(package, version, destination):
    with urlopen(f"https://pypi.org/pypi/{package}/{version}/json", timeout=30) as response:
        release = json.load(response)
    choices = [item for item in release["urls"] if item["filename"].endswith(".whl") and (
        item["filename"].endswith("py3-none-any.whl") or
        ("cp312-cp312" in item["filename"] and "manylinux2014_aarch64" in item["filename"]))]
    if len(choices) != 1:
        raise RuntimeError(f"Expected exactly one supported wheel: {package} {version}")
    metadata = choices[0]
    if not metadata["url"].startswith("https://files.pythonhosted.org/"):
        raise RuntimeError("Unexpected package download host")
    path = destination / metadata["filename"]
    expected = metadata["digests"]["sha256"]
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        with urlopen(metadata["url"], timeout=60) as response:
            content = response.read()
        if hashlib.sha256(content).hexdigest() != expected:
            raise RuntimeError(f"Wheel checksum mismatch: {path.name}")
        path.write_bytes(content)
    return path, {"package": package, "version": version, "file": path.name, "sha256": expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset_tag", choices=TARGETS)
    parser.add_argument("state", choices=VERSIONS)
    args = parser.parse_args()
    port, ip = TARGETS[args.asset_tag]
    work = RUNTIME / "demo-app" / args.asset_tag
    work.mkdir(parents=True, exist_ok=True)
    common = ["-i", str(RUNTIME / "id_ed25519"), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
              "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]
    source = run(["ssh", *common, "-p", "12222", "eolwatch@127.0.0.1",
                  "cat /opt/eolwatch/secrets/known_hosts"], capture_output=True, text=True).stdout
    lines = []
    for line in source.splitlines():
        parts = line.split()
        if len(parts) >= 3 and ip in parts[0].split(","):
            lines.append(f"[127.0.0.1]:{port} {parts[1]} {parts[2]}")
    if not lines:
        raise RuntimeError("No previously trusted target SSH host key")
    trusted = work / "known_hosts"
    trusted.write_text("\n".join(lines) + "\n")
    common += ["-o", "UserKnownHostsFile=" + str(trusted)]
    ssh = ["ssh", *common, "-p", str(port), "eolwatch@127.0.0.1"]
    check = "uname -sm; python3 -c 'import sys; print(str(sys.version_info.major)+\".\"+str(sys.version_info.minor))'; ip -4 -o address show"
    identity = run([*ssh, check], capture_output=True, text=True).stdout
    if not identity.startswith("Linux aarch64\n3.12\n") or f" {ip}/" not in identity:
        raise RuntimeError("Expected allowlisted Linux arm64 Python3.12 lab VM")
    wheels = work / "wheels"
    wheels.mkdir(exist_ok=True)
    packages = [wheel(name, version, wheels) for name, version in
                (("pip", "25.2"), ("Jinja2", VERSIONS[args.state]), ("MarkupSafe", "3.0.3"))]
    # A marker prevents accidentally taking over an existing unrelated directory.
    prepare = """set -eu
for managed in eolwatch-demo eolwatch-demo/.eolwatch-managed eolwatch-demo/.venv eolwatch-demo/wheels eolwatch-demo/app.py eolwatch-demo/app.pid eolwatch-demo/app.log eolwatch-demo/health.json eolwatch-demo/install-manifest.json; do
  if test -L "$HOME/$managed"; then echo 'Refusing symlink in managed demo paths' >&2; exit 1; fi
done
if test -d "$HOME/eolwatch-demo" && ! test -f "$HOME/eolwatch-demo/.eolwatch-managed"; then
  echo 'Refusing unmanaged existing demo directory' >&2; exit 1
fi
mkdir -p "$HOME/eolwatch-demo/wheels"
touch "$HOME/eolwatch-demo/.eolwatch-managed"
"""
    for local, _metadata in packages:
        path = '"$HOME/eolwatch-demo/wheels/"' + shlex.quote(local.name)
        prepare += "if test -L " + path + "; then echo 'Refusing symlink at wheel destination' >&2; exit 1; fi\n"
    run([*ssh, "sh -s"], input=prepare, text=True)
    for local in [PROJECT / "samples/demo-python-app/app.py", *(item[0] for item in packages)]:
        remote = "eolwatch-demo/" + ("" if local.name == "app.py" else "wheels/") + local.name
        run(["scp", *common, "-P", str(port), str(local), "eolwatch@127.0.0.1:" + remote])
    manifest = {"asset_tag": args.asset_tag, "target_ip": ip, "state": args.state, "status": "prepared",
                "jinja2": VERSIONS[args.state], "wheels": [item[1] for item in packages],
                "app_sha256": hashlib.sha256((PROJECT / "samples/demo-python-app/app.py").read_bytes()).hexdigest()}
    manifest_file = work / (args.state + "-install.json")
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n")
    checks = "\n".join(item[1]["sha256"] + "  wheels/" + item[0].name for item in packages)
    verify = """set -eu
cd "$HOME/eolwatch-demo"
printf '%s\\n' CHECKSUMS | sha256sum -c -
""".replace("CHECKSUMS", shlex.quote(checks))
    run([*ssh, "sh -s"], input=verify, text=True)
    # Stop the previous process before replacing dependencies. A running process
    # must not combine old imported code with newly installed package metadata.
    stop = '''import os, signal, time
from pathlib import Path
root = Path.home() / "eolwatch-demo"
command = [str(root / ".venv/bin/python"), str(root / "app.py")]
pid_file = root / "app.pid"
if pid_file.exists():
    pid = int(pid_file.read_text())
    if pid <= 1: raise SystemExit("Invalid demo PID; refusing to stop it")
    proc = Path("/proc") / str(pid) / "cmdline"
    try: actual = proc.read_bytes().rstrip(b"\\0").split(b"\\0")
    except FileNotFoundError: actual = None
    if actual and actual != [b""]:
        if actual != [item.encode() for item in command]:
            raise SystemExit("PID no longer belongs to this demo app; refusing to stop it")
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
        for _ in range(50):
            try: remaining = proc.read_bytes()
            except FileNotFoundError: break
            if not remaining: break
            time.sleep(0.1)
        else: raise SystemExit("Demo process did not stop")
    pid_file.unlink(missing_ok=True)
(root / "health.json").unlink(missing_ok=True)
(root / "install-manifest.json").unlink(missing_ok=True)
'''
    run([*ssh, "python3 -"], input=stop, text=True)
    install = """set -eu
cd "$HOME/eolwatch-demo"
# Rebuild this marker-owned venv so earlier dependencies cannot survive a reset.
python3 -m venv --without-pip --clear .venv
PYTHONPATH="$PWD/wheels/PIP_WHEEL" .venv/bin/python -m pip --isolated install --no-index --no-deps --no-cache-dir --force-reinstall "$PWD/wheels/JINJA_WHEEL" "$PWD/wheels/MARKUPSAFE_WHEEL"
.venv/bin/python -c 'from importlib.metadata import distributions, version; from jinja2.sandbox import SandboxedEnvironment; assert {d.metadata["Name"].lower(): d.version for d in distributions()} == {"jinja2": "JINJA_VERSION", "markupsafe": "3.0.3"}; assert SandboxedEnvironment(autoescape=True).from_string("{{ value }}").render(value="<ok>")=="&lt;ok&gt;"; print("Jinja2="+version("Jinja2")); print("render=ok")'
""".replace("PIP_WHEEL", packages[0][0].name).replace("JINJA_WHEEL", packages[1][0].name).replace("MARKUPSAFE_WHEEL", packages[2][0].name).replace("JINJA_VERSION", VERSIONS[args.state])
    run([*ssh, "sh -s"], input=install, text=True)
    start = '''import json, subprocess, time
from pathlib import Path
from urllib.request import urlopen
root = Path.home() / "eolwatch-demo"
command = [str(root / ".venv/bin/python"), str(root / "app.py")]
pid_file = root / "app.pid"
with (root / "app.log").open("ab") as log:
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                               start_new_session=True, cwd=root)
pid_file.write_text(str(process.pid))
try:
    for _ in range(50):
        if process.poll() is not None: raise SystemExit("Demo app exited; check ~/eolwatch-demo/app.log")
        try:
            with urlopen("http://127.0.0.1:19090/health", timeout=1) as response:
                health = json.load(response)
            if health != {"status": "ok", "jinja2": EXPECTED_VERSION}:
                raise SystemExit("Demo app reported an unexpected installed version")
            (root / "health.json").write_text(json.dumps(health) + "\\n")
            print(json.dumps(health))
            break
        except OSError: time.sleep(0.1)
    else: raise SystemExit("Demo app health check timed out")
except BaseException:
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
    pid_file.unlink(missing_ok=True)
    raise
'''.replace("EXPECTED_VERSION", repr(VERSIONS[args.state]))
    run([*ssh, "python3 -"], input=start, text=True)
    manifest.update(status="installed", installed_at=datetime.now(timezone.utc).isoformat())
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n")
    run([*ssh, "python3 -c " + shlex.quote(
        'import pathlib,sys; (pathlib.Path.home()/"eolwatch-demo/install-manifest.json").write_text(sys.stdin.read())')],
        input=json.dumps(manifest, indent=2) + "\n", text=True)
    print(f"Installed {args.asset_tag}: Jinja2 {VERSIONS[args.state]} ({args.state}); {manifest_file}")
    print("Web analysis scope: 데모 앱 · Python")


if __name__ == "__main__":
    main()
