#!/usr/bin/env python3
"""Analyze installed Ubuntu packages in an allowlisted local VM using Syft and Grype.

Artifacts and failures are retained under ignored infrastructure/local-vm/runtime.
No OS packages are installed or updated. Only the pinned Syft executable is copied
to the target's ~/.local/eolwatch-tools directory. This is an OS-package scan;
application dependencies, container images, and other catalogers are out of scope.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import uuid


PROJECT = Path(__file__).resolve().parents[1]
RUNTIME = PROJECT / "infrastructure/local-vm/runtime"
TARGETS = {"LAB-VM-01": (12223, "10.77.0.21"), "LAB-VM-02": (12224, "10.77.0.22")}
SCOPE = "ubuntu-dpkg-installed"
EXCLUSIONS = ["./proc/**", "./sys/**", "./dev/**", "./run/**"]
SYFT_CONFIG = {"file": {"metadata": {"selection": "none"}},
               "relationships": {"package-file-ownership": False}}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(destination, data, *, compact=False):
    destination.write_text(json.dumps(data, ensure_ascii=False, indent=None if compact else 2,
                                      separators=(",", ":") if compact else None) + "\n", encoding="utf-8")


def sha256(file):
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Run:
    def __init__(self, args):
        self.args = args
        self.directory = args.output_dir.resolve() / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + args.asset_tag + "-" + uuid.uuid4().hex[:8]
        )
        self.directory.mkdir(parents=True, mode=0o700)
        self.manifest = {
            "status": "running", "started_at": timestamp(), "asset_tag": args.asset_tag,
            "target_ip": TARGETS[args.asset_tag][1], "scan_scope": SCOPE,
            "scope_description": "Installed Ubuntu packages from dpkg-db-cataloger only; excludes application dependencies and container images.",
            "exclusions": EXCLUSIONS, "syft_config": SYFT_CONFIG, "commands": [], "artifacts": {},
        }
        self.save()

    def save(self):
        write_json(self.directory / "manifest.json", self.manifest)

    def command(self, stage, argv, *, output=None, timeout=60, env=None):
        destination = self.directory / (output or stage + ".stdout.log")
        error_file = self.directory / (stage + ".stderr.log")
        entry = {"stage": stage, "argv": [str(arg) for arg in argv], "started_at": timestamp(),
                 "stdout": destination.name, "stderr": error_file.name, "timeout_seconds": timeout}
        self.manifest["commands"].append(entry)
        self.save()
        started = time.monotonic()
        print(f"[{stage}]", flush=True)
        try:
            with destination.open("wb") as stdout, error_file.open("wb") as stderr:
                process = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, env=env, check=False)
            entry["returncode"] = process.returncode
            if process.returncode:
                raise RuntimeError(f"{stage} failed (exit {process.returncode}); see {error_file}")
        except subprocess.TimeoutExpired:
            entry["timed_out"] = True
            raise RuntimeError(f"{stage} timed out after {timeout}s; see {error_file}") from None
        finally:
            entry["duration_seconds"] = round(time.monotonic() - started, 2)
            self.save()
        return destination

    def artifact(self, name, file):
        self.manifest["artifacts"][name] = {"path": file.name, "sha256": sha256(file), "bytes": file.stat().st_size}
        self.save()


def ssh_options(args, port, known_hosts=None):
    options = ["-i", str(args.ssh_key.resolve()), "-p", str(port), "-o", "StrictHostKeyChecking=yes",
               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
               "-o", "ServerAliveCountMax=2"]
    if known_hosts:
        options.extend(["-o", "UserKnownHostsFile=" + str(known_hosts)])
    return options


def trusted_target_hosts(run):
    args = run.args
    if args.known_hosts:
        return args.known_hosts.resolve()
    # The controller is already trusted by the existing lab deployment. Read its
    # pinned target keys over that verified connection, never trust ssh-keyscan.
    source = run.command("read-trusted-target-hosts", ["ssh", *ssh_options(args, 12222),
                         "eolwatch@127.0.0.1", "cat /opt/eolwatch/secrets/known_hosts"])
    lines = []
    for line in source.read_text().splitlines():
        parts = line.split()
        if len(parts) < 3 or line.startswith("#"):
            continue
        for port, ip in TARGETS.values():
            if ip in parts[0].split(","):
                lines.append(f"[127.0.0.1]:{port} {parts[1]} {parts[2]}")
    expected_port = TARGETS[args.asset_tag][0]
    if not any(line.startswith(f"[127.0.0.1]:{expected_port} ") for line in lines):
        raise RuntimeError("Trusted controller has no host key for this target; provide --known-hosts with a verified key.")
    destination = run.directory / "target_known_hosts"
    destination.write_text("\n".join(lines) + "\n")
    run.manifest["ssh_trust_source"] = "Existing trusted controller /opt/eolwatch/secrets/known_hosts"
    run.save()
    return destination


def api_request(base, endpoint, *, payload=None, token=None):
    headers = {"Accept": "application/json"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, separators=(",", ":")).encode()
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(base + endpoint, data=body, headers=headers)
    try:
        with urlopen(request, timeout=120) as response:
            return json.load(response)
    except HTTPError as error:
        # Auth payloads, tokens, or reflected request bodies must not reach logs.
        raise RuntimeError(f"API {endpoint} returned HTTP {error.code}") from None
    except URLError:
        raise RuntimeError(f"API {endpoint} could not be reached") from None


def upload(run, bundle):
    base = run.args.api_url.rstrip("/")
    parsed = urlsplit(base)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("Use an API URL without credentials, query, or fragment.")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise RuntimeError("API credentials require HTTPS, except for a loopback API URL.")
    username = os.environ.get("EOLWATCH_USERNAME", "admin")
    password = os.environ.get("EOLWATCH_PASSWORD")
    if password is None:
        if not sys.stdin.isatty():
            raise RuntimeError("Set EOLWATCH_PASSWORD for upload, or use --no-upload.")
        password = getpass.getpass("EOLWatch password: ")
    auth = api_request(base, "/api/auth/login", payload={"username": username, "password": password})
    token = auth["access_token"]
    assets = api_request(base, "/api/assets", token=token)
    candidates = [asset for asset in assets if asset.get("asset_tag") == run.args.asset_tag]
    if len(candidates) != 1:
        raise RuntimeError("Expected exactly one API asset matching the selected asset tag.")
    asset = candidates[0]
    if asset.get("ip_address") != TARGETS[run.args.asset_tag][1]:
        raise RuntimeError("Asset IP does not match the allowlisted analysis target; refusing import.")
    bundle["asset_id"] = asset["id"]
    write_json(run.directory / "import-bundle.json", bundle, compact=True)
    run.artifact("import_bundle", run.directory / "import-bundle.json")
    result = api_request(base, "/api/analyses/import", payload=bundle, token=token)
    result_file = run.directory / "import-result.json"
    write_json(result_file, result)
    run.artifact("import_result", result_file)
    run.manifest["asset_id"] = asset["id"]


def upload_existing(run):
    """Keep each retry separate and verify the original saved analysis bundle."""
    source_directory = run.args.upload_existing_dir.resolve()
    source_manifest = json.loads((source_directory / "manifest.json").read_text())
    if (source_manifest.get("asset_tag") != run.args.asset_tag
            or source_manifest.get("target_ip") != TARGETS[run.args.asset_tag][1]
            or source_manifest.get("scan_scope") != SCOPE):
        raise RuntimeError("Saved analysis identity/scope does not match the selected allowlisted target.")
    source_bundle = source_directory / "import-bundle.json"
    expected_hash = source_manifest.get("artifacts", {}).get("import_bundle", {}).get("sha256")
    if not expected_hash or sha256(source_bundle) != expected_hash:
        raise RuntimeError("Saved import bundle checksum does not match its original run manifest.")
    bundle = json.loads(source_bundle.read_text())
    if bundle.get("scan_scope") != SCOPE or not isinstance(bundle.get("sbom"), dict) or not isinstance(bundle.get("report"), dict):
        raise RuntimeError("Saved import bundle is incomplete or has an unexpected scope.")
    bundle.pop("asset_id", None)  # Always resolve and verify the asset against the current API.
    for key in ("package_count", "match_count", "unique_vulnerability_count", "tools", "distro", "grype_db",
                "catalogers", "scan_warning_count", "syft_config", "grype_input_sha256"):
        if key in source_manifest:
            run.manifest[key] = source_manifest[key]
    run.manifest["reused_analysis_manifest"] = str(source_directory / "manifest.json")
    run.manifest["reused_bundle_sha256"] = expected_hash
    bundle_file = run.directory / "import-bundle.json"
    write_json(bundle_file, bundle, compact=True)
    run.artifact("import_bundle", bundle_file)
    upload(run, bundle)
    run.manifest["status"] = "imported"


def analyze(run):
    args = run.args
    for binary in (args.syft, args.grype, args.target_syft):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f"Missing executable: {binary}. Run scripts/install-analysis-tools.py first.")
    run.manifest["tools"] = {"syft": {"path": str(args.syft), "sha256": sha256(args.syft)},
                             "grype": {"path": str(args.grype), "sha256": sha256(args.grype)},
                             "target_syft": {"path": str(args.target_syft), "sha256": sha256(args.target_syft)}}
    known_hosts = trusted_target_hosts(run)
    port = TARGETS[args.asset_tag][0]
    ssh = ["ssh", *ssh_options(args, port, known_hosts), "eolwatch@127.0.0.1"]
    architecture = run.command("target-architecture", ssh + ["uname -sm"])
    if architecture.read_text().strip() != "Linux aarch64":
        raise RuntimeError("This lab runner requires the expected Linux aarch64 VM.")
    target_directory = "/home/eolwatch/.local/eolwatch-tools"
    target_binary = target_directory + "/syft"
    target_config = target_directory + "/analysis-config.yaml"
    run.command("prepare-target-tool-directory", ssh + [shlex.join(["mkdir", "-p", target_directory])])
    config_command = shlex.join(["printf", "%s\\n", json.dumps(SYFT_CONFIG)]) + " > " + shlex.quote(target_config)
    run.command("prepare-target-config", ssh + [config_command])
    scp_options = ssh_options(args, port, known_hosts)
    scp_options[scp_options.index("-p")] = "-P"
    run.command("copy-syft", ["scp", *scp_options, str(args.target_syft.resolve()),
                             "eolwatch@127.0.0.1:" + target_binary], timeout=120)
    run.command("chmod-syft", ssh + [shlex.join(["chmod", "0755", target_binary])])
    digest = run.command("verify-target-syft", ssh + [shlex.join(["sha256sum", target_binary])])
    if digest.read_text().split()[0] != sha256(args.target_syft):
        raise RuntimeError("Copied target Syft binary checksum does not match verified project binary.")
    for name, argv in (("syft", [str(args.syft), "version", "-o", "json"]),
                       ("grype", [str(args.grype), "version", "-o", "json"]),
                       ("target-syft", ssh + [shlex.join([target_binary, "version", "-o", "json"])])):
        run.command(name + "-version", argv)
    # An explicit cataloger list limits this run to dpkg-managed OS packages.
    remote = ["timeout", "--kill-after=10s", f"{args.scan_timeout}s", "env", "SYFT_CHECK_FOR_APP_UPDATE=false",
              target_binary, "scan", "dir:/", "--config", target_config, "--override-default-catalogers",
              "dpkg-db-cataloger", "--select-catalogers=-file", "--parallelism", "1", "--source-name", args.asset_tag, "-o", "syft-json"]
    for exclude in EXCLUSIONS:
        remote.extend(["--exclude", exclude])
    raw_file = run.command("syft-scan", ssh + [shlex.join(remote)], output="sbom.syft.json", timeout=args.scan_timeout + 30)
    raw = json.loads(raw_file.read_text())
    if not raw.get("artifacts"):
        raise RuntimeError("Syft returned no installed packages; refusing an empty successful analysis.")
    catalogers = raw.get("descriptor", {}).get("configuration", {}).get("catalogers", {}).get("used", [])
    if catalogers != ["dpkg-db-cataloger"] or any(package.get("type") != "deb" for package in raw["artifacts"]):
        raise RuntimeError("Syft result does not match the declared dpkg-only analysis scope.")
    distro = raw.get("distro") or {}
    if distro.get("id") != "ubuntu" or not distro.get("versionID"):
        raise RuntimeError("Expected Ubuntu distribution identity in the actual target SBOM.")
    run.artifact("syft_sbom", raw_file)
    run.manifest["distro"] = distro
    run.manifest["package_count"] = len(raw["artifacts"])
    run.manifest["catalogers"] = catalogers
    run.manifest["scan_warning_count"] = (run.directory / "syft-scan.stderr.log").read_text().count(" WARN ")
    # Do not inherit registry credentials or unrelated tool settings into the
    # report's embedded configuration. Preserve OS, proxy and certificate setup.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("SYFT_", "GRYPE_", "EOLWATCH_"))}
    env.update(SYFT_CHECK_FOR_APP_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false",
               GRYPE_DB_CACHE_DIR=str((RUNTIME / "grype-db").resolve()),
               GRYPE_CACHE_DIR=str((RUNTIME / "grype-cache").resolve()))
    host_config = run.directory / "analysis-empty.yaml"
    host_config.write_text("{}\n")
    spdx_file = run.command("syft-convert-spdx", [str(args.syft), "convert", str(raw_file), "--config", str(host_config),
                            "-o", "spdx-json@2.3"], output="sbom.spdx.json", timeout=120, env=env)
    sbom = json.loads(spdx_file.read_text())
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise RuntimeError("Syft did not generate the required SPDX 2.3 JSON.")
    run.artifact("spdx_sbom", spdx_file)
    run.manifest["grype_input_sha256"] = sha256(spdx_file)
    # SPDX drops some Syft metadata. Preserve the actual OS identity explicitly
    # for Grype's distribution-specific matching, while scanning this exact SPDX.
    distro_argument = "ubuntu:" + distro["versionID"]
    report_file = run.command("grype-scan", [str(args.grype), "sbom:" + str(spdx_file), "--config", str(host_config),
                              "--distro", distro_argument, "--by-cve", "-o", "json"],
                              output="grype.json", timeout=args.grype_timeout, env=env)
    report = json.loads(report_file.read_text())
    if not isinstance(report.get("matches"), list) or report.get("descriptor", {}).get("name") != "grype":
        raise RuntimeError("Unexpected Grype JSON report shape.")
    run.artifact("grype_report", report_file)
    bundle = {"sbom": sbom, "report": report, "scan_scope": SCOPE}
    write_json(run.directory / "import-bundle.json", bundle, compact=True)
    run.artifact("import_bundle", run.directory / "import-bundle.json")
    run.manifest["match_count"] = len(report["matches"])
    run.manifest["unique_vulnerability_count"] = len({match["vulnerability"]["id"] for match in report["matches"]})
    run.manifest["grype_db"] = report.get("descriptor", {}).get("db")
    run.save()
    if args.no_upload:
        run.manifest["status"] = "analyzed_not_uploaded"
    else:
        upload(run, bundle)
        run.manifest["status"] = "imported"


def main():
    machine = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
    host_tools = RUNTIME / "tools" / (platform.system().lower() + "_" + machine)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--asset-tag", choices=TARGETS, default="LAB-VM-01")
    parser.add_argument("--no-upload", action="store_true", help="Save artifacts without logging into the API")
    parser.add_argument("--upload-existing-dir", type=Path,
                        help="Upload a verified saved run directory without copying tools or rescanning; retry has its own manifest")
    parser.add_argument("--api-url", default=os.environ.get("EOLWATCH_URL", "http://127.0.0.1:18080"))
    parser.add_argument("--ssh-key", type=Path, default=RUNTIME / "id_ed25519")
    parser.add_argument("--known-hosts", type=Path, help="Verified SSH keys for forwarded target ports; default: read from trusted controller")
    parser.add_argument("--syft", type=Path, default=host_tools / "syft")
    parser.add_argument("--grype", type=Path, default=host_tools / "grype")
    parser.add_argument("--target-syft", type=Path, default=RUNTIME / "tools/linux_arm64/syft")
    parser.add_argument("--output-dir", type=Path, default=RUNTIME / "analyses")
    parser.add_argument("--scan-timeout", type=int, default=300)
    parser.add_argument("--grype-timeout", type=int, default=900, help="Includes initial vulnerability DB download (seconds)")
    args = parser.parse_args()
    if args.scan_timeout < 1 or args.grype_timeout < 1:
        parser.error("Timeouts must be positive.")
    if args.no_upload and args.upload_existing_dir:
        parser.error("--upload-existing-dir cannot be combined with --no-upload.")
    run = Run(args)
    print(f"Artifacts: {run.directory}", flush=True)
    try:
        if args.upload_existing_dir:
            upload_existing(run)
        else:
            analyze(run)
    except (Exception, KeyboardInterrupt) as error:
        run.manifest["status"] = "failed"
        run.manifest["error"] = str(error) if not isinstance(error, KeyboardInterrupt) else "Interrupted"
        print(f"Analysis failed: {run.manifest['error']}", file=sys.stderr)
        return_code = 1
    else:
        print(f"{run.manifest['status']}: {run.manifest['package_count']} packages, {run.manifest['match_count']} findings", flush=True)
        return_code = 0
    finally:
        run.manifest["finished_at"] = timestamp()
        run.save()
    return return_code


if __name__ == "__main__":
    sys.exit(main())
