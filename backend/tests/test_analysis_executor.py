from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

from app.services import analysis_executor as executor
from app.services.analysis_profiles import ANALYSIS_PROFILES, DEFAULT_SCAN_SCOPE, DEMO_PYTHON_SCAN_SCOPE


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
             "sbom": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "openssl"}]},
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
        path.write_text("Linux aarch64\n" if name == "target-architecture" else json.dumps(state["raw"]))
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
    assert result == {"sbom": state["sbom"], "report": state["report"], "scan_scope": "ubuntu-dpkg-installed"}
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
        state["raw"]["distro"]["id"] = "debian"
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


class FakeSftp:
    def __init__(self, home="/home/demo", exists=True, directory=True, canonical=None):
        self.home = home
        self.exists = exists
        self.directory = directory
        self.canonical = canonical
        self.checked_paths = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def get_channel(self):
        return SimpleNamespace(settimeout=lambda _timeout: None)

    def normalize(self, path):
        if path == ".":
            return self.home
        return self.canonical if self.canonical is not None else path

    def stat(self, path):
        self.checked_paths.append(path)
        if not self.exists:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=stat.S_IFDIR if self.directory else stat.S_IFREG)


def test_app_scan_directory_uses_registered_accounts_home():
    sftp = FakeSftp(home="/srv/operator")
    client = SimpleNamespace(open_sftp=lambda: sftp)
    profile = ANALYSIS_PROFILES[DEMO_PYTHON_SCAN_SCOPE]
    assert executor._scan_directory(client, profile) == "/srv/operator/eolwatch-demo/.venv"
    assert sftp.checked_paths == ["/srv/operator/eolwatch-demo/.venv"]
    # The OS profile does not require any application installation.
    assert executor._scan_directory(None, ANALYSIS_PROFILES[DEFAULT_SCAN_SCOPE]) == "/"


@pytest.mark.parametrize("sftp,code", [
    (FakeSftp(exists=False), "APP_NOT_INSTALLED"),
    (FakeSftp(directory=False), "APP_NOT_INSTALLED"),
    (FakeSftp(canonical="/etc"), "APP_PATH_OUT_OF_SCOPE"),
    (FakeSftp(home="/home/demo/../other"), "SSH_HOME"),
])
def test_app_scan_rejects_missing_and_redirected_directories(sftp, code):
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor._scan_directory(SimpleNamespace(open_sftp=lambda: sftp), ANALYSIS_PROFILES[DEMO_PYTHON_SCAN_SCOPE])
    assert failure.value.code == code


@pytest.fixture
def mocked_app_pipeline(mocked_pipeline, monkeypatch):
    settings, state = mocked_pipeline
    state["raw"] = {
        "artifacts": [{"type": "python", "name": "Jinja2", "version": "3.1.4"}],
        "descriptor": {"configuration": {"catalogers": {"used": ["python-installed-package-cataloger"]}}},
        "source": {"type": "directory", "metadata": {"path": "/home/demo/eolwatch-demo/.venv"}},
    }
    state["sbom"] = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "Jinja2", "versionInfo": "3.1.4"}]}
    monkeypatch.setattr(executor, "_connect", lambda *_args: SimpleNamespace(
        close=lambda: state.update(closed=True), open_sftp=lambda: FakeSftp()))
    return settings, state


def test_app_pipeline_scans_installed_python_only_without_os_distro(tmp_path, mocked_app_pipeline):
    settings, state = mocked_app_pipeline
    directory = tmp_path / "job"
    snapshot = {"id": 9, "ip_address": "10.77.0.21", "scan_scope": DEMO_PYTHON_SCAN_SCOPE,
                "scan_path": "/etc", "application_path": "/root"}
    result = executor.execute_analysis(snapshot, directory, settings, state["stages"].append)
    assert result["scan_scope"] == DEMO_PYTHON_SCAN_SCOPE
    scan = next(argv for name, argv in state["remote_commands"] if name == "syft-scan")
    assert scan[scan.index("scan") + 1] == "dir:/home/demo/eolwatch-demo/.venv"
    assert scan[scan.index("--override-default-catalogers") + 1] == "python-installed-package-cataloger"
    assert "python-package-cataloger" not in scan
    assert "dpkg-db-cataloger" not in scan
    grype = next(argv for name, argv in state["local_commands"] if name == "grype-scan")
    assert "sbom:" + str(directory / "sbom.spdx.json") in grype
    assert "--distro" not in grype
    assert state["stages"] == ["COLLECTING", "SCANNING", "IMPORTING"]
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["scan_scope"] == DEMO_PYTHON_SCAN_SCOPE
    assert manifest["scan_directory"] == "/home/demo/eolwatch-demo/.venv"
    assert manifest["exclusions"] == []
    assert manifest["distro"] == {}
    assert manifest["package_count"] == 1


@pytest.mark.parametrize("invalid,code", [("empty", "EMPTY_COLLECTION"), ("os", "SCOPE_MISMATCH"),
                                         ("declared", "SCOPE_MISMATCH"), ("path", "SCOPE_MISMATCH")])
def test_app_pipeline_rejects_wrong_inventory(tmp_path, mocked_app_pipeline, invalid, code):
    settings, state = mocked_app_pipeline
    if invalid == "empty":
        state["raw"]["artifacts"] = []
    elif invalid == "os":
        state["raw"]["artifacts"].append({"type": "deb", "name": "openssl"})
    elif invalid == "declared":
        state["raw"]["descriptor"]["configuration"]["catalogers"]["used"] = ["python-package-cataloger"]
    else:
        state["raw"]["source"]["metadata"]["path"] = "/etc"
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor.execute_analysis({"id": 9, "ip_address": "10.77.0.21", "scan_scope": DEMO_PYTHON_SCAN_SCOPE},
                                  tmp_path / "job", settings, state["stages"].append)
    assert failure.value.code == code
    assert "IMPORTING" not in state["stages"]


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
