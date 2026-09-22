from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from app.services import analysis_executor as executor


class LeaseLost(RuntimeError):
    pass


def test_local_timeout_reaps_process_and_preserves_output(tmp_path):
    run = executor._Run({"id": 7}, tmp_path, lambda _stage: None)
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        run.local("slow", [sys.executable, "-u", "-c", "import time; print('started'); time.sleep(30)"],
                  timeout=0.3, env=dict(os.environ))
    run.finish()
    assert failure.value.code == "TOOL_TIMEOUT"
    assert (tmp_path / "slow.stdout.log").read_text().strip() == "started"
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert manifest["commands"][0]["timed_out"]
    assert manifest["artifacts"]["slow.stdout.log"]["sha256"] == hashlib.sha256(b"started\n").hexdigest()


def test_local_fencing_propagates_same_exception_and_stops_child(tmp_path):
    reason = LeaseLost("Do not publish this detail")

    def callback(_stage):
        if (tmp_path / "pid").exists():
            raise reason

    run = executor._Run({}, tmp_path, callback)
    run.last_heartbeat = -100
    script = "import os,pathlib,time; pathlib.Path(" + repr(str(tmp_path / "pid")) + ").write_text(str(os.getpid())); time.sleep(30)"
    original = executor.HEARTBEAT_SECONDS
    executor.HEARTBEAT_SECONDS = 0
    try:
        with pytest.raises(LeaseLost) as failure:
            run.local("fenced", [sys.executable, "-c", script], 10, dict(os.environ))
    finally:
        executor.HEARTBEAT_SECONDS = original
    assert failure.value is reason
    pid = int((tmp_path / "pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


class FakeChannel:
    def __init__(self, stdout, stderr):
        self.out = list(stdout)
        self.err = list(stderr)
        self.closed = False
        self.drained = []

    def recv_ready(self):
        return bool(self.out)

    def recv(self, _count):
        self.drained.append("stdout")
        return self.out.pop(0)

    def recv_stderr_ready(self):
        return bool(self.err)

    def recv_stderr(self, _count):
        self.drained.append("stderr")
        return self.err.pop(0)

    def exit_status_ready(self):
        return not self.out and not self.err

    def recv_exit_status(self):
        assert not self.out and not self.err
        return 0

    def close(self):
        self.closed = True


def test_remote_drains_both_channels_before_exit(tmp_path):
    channel = FakeChannel([b"a", b"b", b"c"], [b"warning", b"warning2"])
    client = SimpleNamespace(exec_command=lambda *_args, **_kwargs: (None, SimpleNamespace(channel=channel), None))
    run = executor._Run({}, tmp_path, lambda _stage: None)
    output = run.remote(client, "scan", ["syft", "scan"], 10)
    assert output.read_bytes() == b"abc"
    assert (tmp_path / "scan.stderr.log").read_bytes() == b"warningwarning2"
    assert channel.drained[:4] == ["stdout", "stderr", "stdout", "stderr"]
    assert channel.closed


def test_remote_fencing_cancels_only_this_run(tmp_path, monkeypatch):
    reason = LeaseLost("fenced")
    channel = FakeChannel([b"partial"] * 10, [])
    client = SimpleNamespace(exec_command=lambda *_args, **_kwargs: (None, SimpleNamespace(channel=channel), None))
    canceled = []
    monkeypatch.setattr(executor, "_cancel_remote", lambda client, pid: canceled.append(pid))
    monkeypatch.setattr(executor, "HEARTBEAT_SECONDS", 0)

    def callback(_stage):
        if channel.drained:
            raise reason

    run = executor._Run({}, tmp_path, callback)
    with pytest.raises(LeaseLost) as failure:
        run.remote(client, "scan", ["syft", "scan"], 10, pid_file="/home/demo/unique-job.pid")
    assert failure.value is reason
    assert canceled == ["/home/demo/unique-job.pid"]
    assert channel.closed


def test_connect_requires_pinned_known_hosts_even_when_collector_is_permissive(tmp_path):
    key = tmp_path / "key"
    key.write_text("never read or print")
    settings = SimpleNamespace(ssh_private_key_path=str(key), ssh_known_hosts_path="", ssh_strict_host_key=False)
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor._connect({"ip_address": "10.77.0.21", "ssh_username": "demo"}, settings)
    assert failure.value.code == "SSH_TRUST_MISSING"


@pytest.fixture
def mocked_pipeline(tmp_path, monkeypatch):
    settings = SimpleNamespace(analysis_collect_timeout_seconds=300, analysis_scan_timeout_seconds=900,
                               analysis_cache_dir=str(tmp_path / "cache"))
    state = {"raw": {"artifacts": [{"type": "deb", "name": "openssl"}],
                     "descriptor": {"configuration": {"catalogers": {"used": ["dpkg-db-cataloger"]}}},
                     "distro": {"id": "ubuntu", "versionID": "24.04"}},
             "sbom": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "openssl", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-24.04"}]}]},
             "report": {"descriptor": {"name": "grype", "db": {"built": "fixture"}}, "matches": []},
             "local_commands": [], "remote_commands": [], "closed": False, "stages": []}

    def close():
        state["closed"] = True

    monkeypatch.setattr(executor, "_tools", lambda *_args: (Path("/tools/syft"), Path("/tools/grype"), "Linux aarch64"))
    monkeypatch.setattr(executor, "_connect", lambda *_args: SimpleNamespace(close=close))
    # Returning no remote config avoids exercising unrelated SFTP cleanup in this fixture.
    monkeypatch.setattr(executor, "_provision", lambda *_args: ("/home/demo/syft", None, "/home/demo/job.pid"))

    def remote(self, _client, name, argv, timeout, output=None, pid_file=None):
        state["remote_commands"].append((name, argv))
        path = self.directory / (output or name + ".stdout.log")
        path.write_text("Linux aarch64\n" if name == "target-architecture" else state.get("updates", "MANAGER=none\n") if name == "package-updates" else state.get("os_release", "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n") if name == "os-release" else json.dumps(state["raw"]))
        return path

    def local(self, name, argv, timeout, env, output=None):
        state["local_commands"].append((name, argv))
        path = self.directory / (output or name + ".stdout.log")
        result = state["sbom"] if name == "syft-convert-spdx" else state["report"] if name == "grype-scan" else {}
        path.write_text(json.dumps(result))
        return path

    monkeypatch.setattr(executor._Run, "remote", remote)
    monkeypatch.setattr(executor._Run, "local", local)
    return settings, state


def test_pipeline_scans_exact_spdx_and_records_hashes(tmp_path, mocked_pipeline):
    settings, state = mocked_pipeline
    directory = tmp_path / "job"
    result = executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21"}, directory, settings, state["stages"].append)
    assert {k: v for k, v in result.items() if k != "package_updates"} == {"sbom": state["sbom"], "report": state["report"], "scan_scope": "ubuntu-dpkg-installed"}
    assert result["package_updates"]["manager"] is None and result["package_updates"]["packages"] == {}
    assert state["stages"] == ["COLLECTING", "SCANNING", "IMPORTING"]
    grype = next(argv for name, argv in state["local_commands"] if name == "grype-scan")
    assert "sbom:" + str(directory / "sbom.spdx.json") in grype
    assert grype[grype.index("--distro") + 1] == "ubuntu:24.04"
    assert "--by-cve" in grype
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["status"] == "ready_for_import"
    assert manifest["grype_input_sha256"] == executor._sha256(directory / "sbom.spdx.json")
    assert manifest["match_count"] == 0
    assert state["closed"]


@pytest.mark.parametrize("invalid,code", [("empty", "EMPTY_COLLECTION"), ("scope", "SCOPE_MISMATCH"),
                                         ("distro", "DISTRO_UNSUPPORTED"), ("report", "GRYPE_INVALID")])
def test_invalid_results_never_reach_import(tmp_path, mocked_pipeline, invalid, code):
    settings, state = mocked_pipeline
    if invalid == "empty":
        state["raw"]["artifacts"] = []
    elif invalid == "scope":
        state["raw"]["artifacts"][0]["type"] = "npm"
    elif invalid == "distro":
        state["raw"]["distro"]["id"] = "alpine"
    else:
        state["report"].pop("matches")
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21"}, tmp_path / "job", settings, state["stages"].append)
    assert failure.value.code == code
    assert "IMPORTING" not in state["stages"]
    manifest = json.loads((tmp_path / "job" / "manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["error_code"] == code


def test_pipeline_fencing_does_not_publish_exception_details(tmp_path, mocked_pipeline):
    settings, state = mocked_pipeline
    error = LeaseLost("secret lease token must not leak")

    def callback(stage):
        if stage == "SCANNING":
            raise error

    with pytest.raises(LeaseLost) as failure:
        executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21"}, tmp_path / "job", settings, callback)
    assert failure.value is error
    manifest = (tmp_path / "job" / "manifest.json").read_text()
    assert "secret lease token" not in manifest
    assert json.loads(manifest)["status"] == "interrupted"
    assert state["closed"]


def test_unknown_scope_fails_before_tools_or_ssh(tmp_path, mocked_pipeline):
    settings, state = mocked_pipeline
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor.execute_analysis({"id": 9, "scan_scope": "arbitrary-path"}, tmp_path / "job", settings,
                                  state["stages"].append)
    assert failure.value.code == "UNSUPPORTED_SCAN_SCOPE"
    assert state["local_commands"] == []
    assert state["remote_commands"] == []
    manifest = json.loads((tmp_path / "job" / "manifest.json").read_text())
    assert manifest["scan_scope"] == "arbitrary-path"
    assert manifest["status"] == "failed"


def test_remote_failure_message_includes_what_the_server_printed(tmp_path):
    out, err = tmp_path / "o.log", tmp_path / "e.log"
    out.write_text('Please login as the user "ubuntu" rather than the user "root".\n\n')
    err.write_text("")
    assert executor._remote_hint(out, err) == 'Please login as the user "ubuntu" rather than the user "root".'
    err.write_text("x" * 300)
    assert executor._remote_hint(out, err).endswith("…") and len(executor._remote_hint(out, err)) == 201
    (tmp_path / "missing").unlink(missing_ok=True)
    assert executor._remote_hint(tmp_path / "missing", tmp_path / "missing2") == ""


def test_remote_syft_is_picked_by_target_cpu_and_verified(tmp_path):
    tools = tmp_path / "tools"; tools.mkdir()
    local = tools / "syft"; local.write_bytes(b"local")
    other = tools / "syft-amd64"; other.write_bytes(b"amd64 binary")
    (tools / "manifest.json").write_text(json.dumps({"tools": {}, "remote_syft": {"amd64": {"version": "1.51.1", "binary_sha256": executor._sha256(other)}}}))
    run = executor._Run({"id": 1}, tmp_path / "run", lambda _stage: None)
    assert executor._remote_syft(local, "Linux x86_64\n", run) == other.resolve()
    assert run.manifest["tools"]["remote_syft"]["architecture"] == "amd64"
    with pytest.raises(executor.AnalysisExecutionError) as missing:
        executor._remote_syft(local, "Linux aarch64", run)  # no arm64 remote binary installed here
    assert missing.value.code == "TOOL_NOT_INSTALLED"
    with pytest.raises(executor.AnalysisExecutionError) as unsupported:
        executor._remote_syft(local, "Darwin arm64", run)
    assert unsupported.value.code == "TARGET_ARCHITECTURE"
    other.write_bytes(b"tampered")
    with pytest.raises(executor.AnalysisExecutionError) as tampered:
        executor._remote_syft(local, "Linux x86_64", run)
    assert tampered.value.code == "TOOL_CHECKSUM"


APT_OUTPUT = """MANAGER=apt
REFRESHED=yes
Listing...
curl/resolute-updates,resolute-security 8.18.0-1ubuntu2.5 amd64 [upgradable from: 8.18.0-1ubuntu2.1]
libssl3t64/resolute-updates,resolute-security 3.5.5-1ubuntu3.5 amd64 [upgradable from: 3.5.5-1ubuntu3]
linux-aws/resolute-updates,resolute-security 7.0.0-1012.12 amd64 [upgradable from: 7.0.0-1006.6]
"""


def test_os_scan_collects_updates_read_only_and_ships_them_to_the_importer(tmp_path, mocked_pipeline):
    settings, state = mocked_pipeline
    state["updates"] = APT_OUTPUT
    result = executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21"}, tmp_path / "job", settings, state["stages"].append)
    names = [name for name, _ in state["remote_commands"]]
    assert names.index("package-updates") > names.index("syft-scan")
    command = next(argv for name, argv in state["remote_commands"] if name == "package-updates")
    assert command[:2] == ["sh", "-c"] and "apt list --upgradable" in command[2] and "apt-get install" not in command[2] and "upgrade " not in command[2].replace("--upgradable", "")
    assert result["package_updates"]["manager"] == "apt" and set(result["package_updates"]["packages"]) == {"curl", "libssl3t64", "linux-aws"}
    manifest = json.loads((tmp_path / "job" / "manifest.json").read_text())
    assert manifest["package_updates"] == {"manager": "apt", "refreshed": True, "collected_at": result["package_updates"]["collected_at"], "package_count": 3}
    grype = next(argv for name, argv in state["local_commands"] if name == "grype-scan")
    config = Path(grype[grype.index("--config") + 1]).read_text()
    assert "using-cpes: false" in config  # OS packages are judged by distro fix data only, never by upstream CPE versions


def test_distro_comes_from_the_servers_os_release_when_syft_has_none(tmp_path, mocked_pipeline):
    settings, state = mocked_pipeline
    state["raw"]["distro"] = {}
    state["os_release"] = 'NAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\nPRETTY_NAME="Ubuntu 26.04 LTS"\n'
    executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21"}, tmp_path / "job", settings, state["stages"].append)
    grype = next(argv for name, argv in state["local_commands"] if name == "grype-scan")
    assert grype[grype.index("--distro") + 1] == "ubuntu:26.04"
    manifest = json.loads((tmp_path / "job" / "manifest.json").read_text())
    assert manifest["distro"]["id"] == "ubuntu" and manifest["distro"]["versionID"] == "26.04"
    assert executor._parse_os_release("garbage {not: os-release}") == {}


def test_os_scan_without_deb_purls_is_rejected_instead_of_matching_upstream_versions(tmp_path, mocked_pipeline):
    settings, state = mocked_pipeline
    state["sbom"] = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "openssl"}]}   # syft found no distro -> no PURLs
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21"}, tmp_path / "job", settings, state["stages"].append)
    assert failure.value.code == "PACKAGE_IDENTITY"
    assert "grype-scan" not in [name for name, _ in state["local_commands"]]
