"""Execute fixed OS/application package scans inside the management worker.

The registered SSH target supplies the installed package inventory. The worker
converts that inventory to SPDX and scans the exact SPDX document with Grype.
No API/database objects or credentials are written into command artifacts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import signal
import socket
import stat
import subprocess
import time
from typing import Callable
import uuid

import paramiko

from .analysis_profiles import (ANALYSIS_PROFILES, DEFAULT_SCAN_SCOPE, GIT_SCAN_SCOPE, PATH_SCAN_SCOPES, SOURCE_SCAN_SCOPES,
                                ZIP_SCAN_SCOPE, AnalysisProfile, normalize_git_ref, normalize_repository_url, normalize_target_path, scope_identity)
from .analysis_uploads import InvalidArchive, extract_upload
from . import ssh_auth
from .ai_library_reference import LibraryReferenceError, reference_libraries


SCAN_SCOPE = DEFAULT_SCAN_SCOPE
EXCLUSIONS = list(ANALYSIS_PROFILES[DEFAULT_SCAN_SCOPE].exclusions)
SYFT_CONFIG = {"file": {"metadata": {"selection": "none"}},
               "relationships": {"package-file-ownership": False},
               "package": {"search-indexed-archives": False, "search-unindexed-archives": False}}
OUTPUT_LIMIT = 256 * 1024 * 1024
LOG_LIMIT = 16 * 1024 * 1024
HEARTBEAT_SECONDS = 5


class AnalysisExecutionError(RuntimeError):
    """A classified error whose message is safe to display in the job API."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> dict:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as error:
        raise AnalysisExecutionError("INVALID_OUTPUT", "분석 도구가 올바른 JSON 결과를 생성하지 않았습니다.") from error
    if not isinstance(result, dict):
        raise AnalysisExecutionError("INVALID_OUTPUT", "분석 결과 JSON 객체가 필요합니다.")
    return result


class _Run:
    def __init__(self, asset: dict, directory: Path, callback: Callable[[str], None]):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.callback = callback
        self.stage = "COLLECTING"
        self.last_heartbeat = 0.0
        self.cleanup_confirmed = True
        self.scan_scope = asset.get("scan_scope", DEFAULT_SCAN_SCOPE)
        self.profile = asset.get("profile", self.scan_scope)
        profile = ANALYSIS_PROFILES.get(self.profile)
        self.manifest = {
            "status": "running", "started_at": _timestamp(), "scan_scope": self.scan_scope,
            "asset_id": asset.get("id"), "asset_tag": asset.get("asset_tag"),
            "target_ip": asset.get("ip_address"), "exclusions": list(profile.exclusions) if profile else [],
            "scope_description": profile.description if profile else "Unsupported scan profile.",
            "syft_config": SYFT_CONFIG, "commands": [], "artifacts": {},
            "profile": self.profile, "input_type": asset.get("input_type", "ssh"),
            "target_path": asset.get("target_path"), "upload_id": asset.get("upload_id"),
            "upload_sha256": asset.get("upload_sha256"), "upload_filename": asset.get("upload_filename"),
            "project_name": asset.get("project_name"),
            "git_url": asset.get("git_url"), "git_ref": asset.get("git_ref"),
        }
        self.save()

    def save(self) -> None:
        temporary = self.directory / "manifest.json.tmp"
        temporary.write_text(json.dumps(self.manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.directory / "manifest.json")

    def heartbeat(self, stage=None) -> None:
        now = time.monotonic()
        if stage is not None:
            self.stage = stage
        if stage is not None or now - self.last_heartbeat >= HEARTBEAT_SECONDS:
            self.callback(self.stage)  # A lost lease must propagate and abort execution.
            self.last_heartbeat = now

    def command(self, name: str, argv, timeout: int, output=None):
        stdout = self.directory / (output or name + ".stdout.log")
        stderr = self.directory / (name + ".stderr.log")
        entry = {"stage": name, "argv": argv, "started_at": _timestamp(),
                 "stdout": stdout.name, "stderr": stderr.name, "timeout_seconds": timeout}
        self.manifest["commands"].append(entry)
        self.save()
        return stdout, stderr, entry

    def local(self, name: str, argv: list, timeout: int, env: dict, output=None) -> Path:
        stdout, stderr, entry = self.command(name, argv, timeout, output)
        started = time.monotonic()
        process = None
        try:
            self.heartbeat()
            with stdout.open("wb") as out, stderr.open("wb") as err:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                           env=env, start_new_session=True)
                while process.poll() is None:
                    self.heartbeat()
                    if time.monotonic() - started > timeout:
                        entry["timed_out"] = True
                        raise AnalysisExecutionError("TOOL_TIMEOUT", f"{name} 작업이 제한 시간을 초과했습니다.")
                    if stdout.stat().st_size > OUTPUT_LIMIT or stderr.stat().st_size > LOG_LIMIT:
                        raise AnalysisExecutionError("OUTPUT_TOO_LARGE", "분석 출력이 허용 크기를 초과했습니다.")
                    time.sleep(0.2)
                entry["returncode"] = process.returncode
                if process.returncode:
                    raise AnalysisExecutionError("TOOL_FAILED", f"{name} 실행에 실패했습니다. 관리 서버의 작업 로그를 확인하세요.")
            if stdout.stat().st_size > OUTPUT_LIMIT or stderr.stat().st_size > LOG_LIMIT:
                raise AnalysisExecutionError("OUTPUT_TOO_LARGE", "분석 출력이 허용 크기를 초과했습니다.")
        except OSError as error:
            raise AnalysisExecutionError("TOOL_EXECUTION", f"{name} 도구를 실행할 수 없습니다. 워커 설치 상태를 확인하세요.") from error
        finally:
            if process is not None:
                # Clean the entire process group even if its parent exited first.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    self.cleanup_confirmed = False
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    self.cleanup_confirmed = False
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    pass
                except OSError:
                    self.cleanup_confirmed = False
                else:
                    self.cleanup_confirmed = False
            entry["duration_seconds"] = round(time.monotonic() - started, 2)
            self.save()
        return stdout

    def remote(self, client, name: str, argv: list, timeout: int, output=None, pid_file=None) -> Path:
        bounded = ["timeout", "--kill-after=5s", f"{timeout}s", *argv]
        if pid_file:
            # A unique process group permits cancellation without touching other jobs.
            command = (shlex.join(["setsid", *bounded]) + " & child=$!; printf '%s' \"$child\" > "
                       + shlex.quote(pid_file) + "; wait \"$child\"; result=$?; rm -f "
                       + shlex.quote(pid_file) + "; exit \"$result\"")
        else:
            command = shlex.join(bounded)
        stdout, stderr, entry = self.command(name, argv, timeout, output)
        channel = None
        started = time.monotonic()
        completed = False
        requested = False
        try:
            self.heartbeat()
            requested = True
            _, remote_stdout, _ = client.exec_command(command, timeout=15)
            channel = remote_stdout.channel
            totals = [0, 0]
            with stdout.open("wb") as out, stderr.open("wb") as err:
                while True:
                    self.heartbeat()
                    # Drain both streams before asking for the exit status. Large
                    # JSON reports otherwise fill SSH's receive window and hang.
                    if channel.recv_ready():
                        chunk = channel.recv(65536)
                        out.write(chunk)
                        totals[0] += len(chunk)
                    if channel.recv_stderr_ready():
                        chunk = channel.recv_stderr(65536)
                        err.write(chunk)
                        totals[1] += len(chunk)
                    if totals[0] > OUTPUT_LIMIT or totals[1] > LOG_LIMIT:
                        raise AnalysisExecutionError("OUTPUT_TOO_LARGE", "대상 서버의 분석 출력이 허용 크기를 초과했습니다.")
                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        entry["returncode"] = channel.recv_exit_status()
                        completed = entry["returncode"] >= 0
                        break
                    if time.monotonic() - started > timeout + 10:
                        entry["timed_out"] = True
                        raise AnalysisExecutionError("COLLECTION_TIMEOUT", "대상 서버의 구성요소 수집 시간이 초과되었습니다.")
                    if not channel.recv_ready() and not channel.recv_stderr_ready():
                        time.sleep(0.1)
            if entry["returncode"]:
                code = "COLLECTION_TIMEOUT" if entry["returncode"] in (124, 137) else "REMOTE_COMMAND_FAILED"
                hint = _remote_hint(stdout, stderr)
                raise AnalysisExecutionError(code, f"{name} 원격 작업에 실패했습니다." + (f" 서버 응답: {hint}" if hint else " 대상 권한과 작업 로그를 확인하세요."))
        finally:
            if not completed and requested:
                stopped = bool(channel is not None and channel.exit_status_ready()
                               and channel.recv_exit_status() >= 0)
                if not stopped and pid_file:
                    stopped = _cancel_remote(client, pid_file)
                if not stopped:
                    self.cleanup_confirmed = False
            if channel is not None:
                channel.close()
            entry["duration_seconds"] = round(time.monotonic() - started, 2)
            self.save()
        return stdout

    def finish(self) -> None:
        for artifact in self.directory.iterdir():
            if artifact.is_file() and artifact.name not in ("manifest.json", "manifest.json.tmp"):
                self.manifest["artifacts"][artifact.name] = {
                    "path": artifact.name, "sha256": _sha256(artifact), "bytes": artifact.stat().st_size,
                }
        self.manifest["finished_at"] = _timestamp()
        # Persist only after child/remote cleanup has finished. Stale cancelled
        # jobs may use this receipt, never heartbeat expiry, to release an asset.
        self.manifest["cleanup_confirmed"] = self.cleanup_confirmed
        self.save()


def _remote_hint(stdout: Path, stderr: Path, limit: int = 200) -> str:
    """First line of what the server printed, so the reason shows up in the job list (e.g. a forced-command banner)."""
    for path in (stderr, stdout):
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            line = text.splitlines()[0].strip()
            return line[:limit] + ("…" if len(line) > limit else "")
    return ""


def _cancel_remote(client, pid_file: str) -> bool:
    """Acknowledge only a stopped group with this run's unique config argument."""
    if not re.fullmatch(r'/[^\r\n]*/analysis-[0-9a-f]{32}\.pid', pid_file):
        return False
    path = shlex.quote(pid_file)
    config = shlex.quote(pid_file[:-4] + '.json')
    command = ("command -v kill >/dev/null || exit 7; test -f " + path + " || exit 2; p=$(cat " + path + "); "
               "case \"$p\" in ''|*[!0-9]*) exit 1;; esac; test \"$p\" -gt 1 || exit 1; "
               "if command kill -0 -\"$p\" 2>/dev/null; then "
               "test -r /proc/\"$p\"/cmdline || exit 3; "
               "tr '\\000' '\\n' < /proc/\"$p\"/cmdline | grep -F -x -- " + config + " >/dev/null || exit 4; "
               "command kill -KILL -\"$p\" 2>/dev/null || exit 5; n=0; "
               "while command kill -0 -\"$p\" 2>/dev/null; do n=$((n+1)); "
               "test \"$n\" -lt 30 || exit 6; sleep 0.1; done; fi; rm -f " + path)
    try:
        _, stdout, _ = client.exec_command(command, timeout=5)
        deadline = time.monotonic() + 5
        while not stdout.channel.exit_status_ready() and time.monotonic() < deadline:
            time.sleep(0.1)
        stopped = stdout.channel.exit_status_ready() and stdout.channel.recv_exit_status() == 0
        stdout.channel.close()
        return stopped
    except (OSError, paramiko.SSHException):
        return False


def _tools(settings, run: _Run):
    syft, grype = Path(settings.analysis_syft_path), Path(settings.analysis_grype_path)
    expected_arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(platform.machine())
    if platform.system() != "Linux" or not expected_arch:
        raise AnalysisExecutionError("WORKER_PLATFORM", "분석 워커는 Linux arm64 또는 amd64 환경에서 실행해야 합니다.")
    for name, path in (("syft", syft), ("grype", grype)):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise AnalysisExecutionError("TOOL_NOT_INSTALLED", f"분석 워커에 {name} 실행 파일이 없습니다. analysis-worker 이미지를 빌드하세요.")
        manifest_path = path.parent / "manifest.json"
        if not manifest_path.is_file():
            raise AnalysisExecutionError("TOOL_UNVERIFIED", "분석 도구의 설치 검증 기록이 없습니다. 워커 이미지를 다시 빌드하세요.")
        installed = _json(manifest_path).get("tools", {}).get(name, {})
        digest = _sha256(path)
        if digest != installed.get("binary_sha256"):
            raise AnalysisExecutionError("TOOL_CHECKSUM", f"{name} 실행 파일의 체크섬이 설치 기록과 다릅니다.")
        run.manifest.setdefault("tools", {})[name] = {"version": installed.get("version"), "sha256": digest}
    run.save()
    return syft.resolve(), grype.resolve(), "Linux " + expected_arch


REMOTE_ARCHITECTURES = {"Linux x86_64": "amd64", "Linux aarch64": "arm64", "Linux arm64": "arm64"}


def _remote_syft(syft: Path, architecture_line: str, run: _Run) -> Path:
    """The verified syft binary built for the target's CPU (targets need not match the worker)."""
    arch = REMOTE_ARCHITECTURES.get(architecture_line.strip())
    if not arch:
        raise AnalysisExecutionError("TARGET_ARCHITECTURE", f"대상 서버는 Linux x86_64 또는 arm64여야 합니다. 응답: {architecture_line.strip()[:60] or '없음'}")
    candidate = syft.parent / f"syft-{arch}"
    installed = _json(syft.parent / "manifest.json").get("remote_syft", {}).get(arch, {})
    if not candidate.is_file() or not installed:
        raise AnalysisExecutionError("TOOL_NOT_INSTALLED", f"대상 CPU({arch})용 syft가 워커에 없습니다. analysis-worker 이미지를 다시 빌드하세요.")
    digest = _sha256(candidate)
    if digest != installed.get("binary_sha256"):
        raise AnalysisExecutionError("TOOL_CHECKSUM", f"대상 CPU({arch})용 syft 체크섬이 설치 기록과 다릅니다.")
    run.manifest.setdefault("tools", {})["remote_syft"] = {"architecture": arch, "version": installed.get("version"), "sha256": digest}
    run.save()
    return candidate.resolve()


def _connect(asset: dict, settings):
    if not asset.get("ip_address") or not asset.get("ssh_username"):
        raise AnalysisExecutionError("TARGET_NOT_CONFIGURED", "대상 자산의 IP 주소와 SSH 계정을 설정하세요.")
    mode = ssh_auth.auth_mode(asset)
    password_mode = mode in ssh_auth.TARGET_AUTH_MODES
    if mode == ssh_auth.AUTH_PASSWORD:
        if not ssh_auth.decrypt_password(asset.get("ssh_password_encrypted")):
            raise AnalysisExecutionError("SSH_PASSWORD_MISSING", "이 서버의 SSH 비밀번호가 저장되어 있지 않습니다.")
    elif mode == ssh_auth.AUTH_PRIVATE_KEY:
        if not ssh_auth.decrypt_password(asset.get("ssh_private_key_encrypted")):
            raise AnalysisExecutionError("SSH_PRIVATE_KEY_MISSING", "이 서버의 SSH 개인키가 저장되어 있지 않습니다.")
    else:
        if not settings.ssh_private_key_path or not Path(settings.ssh_private_key_path).is_file():
            raise AnalysisExecutionError("SSH_KEY_MISSING", "관리 서버의 SSH 개인키가 설정되지 않았습니다.")
        if not settings.ssh_known_hosts_path or not Path(settings.ssh_known_hosts_path).is_file():
            raise AnalysisExecutionError("SSH_TRUST_MISSING", "관리 서버에 검증된 대상 SSH 호스트 키를 설정하세요.")
    client = paramiko.SSHClient()
    pinned = ssh_auth.PinnedHostKeyPolicy(asset.get("ssh_host_key"))
    try:
        if password_mode:
            client.set_missing_host_key_policy(pinned)
        else:
            client.load_host_keys(settings.ssh_known_hosts_path)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        timeout = settings.ssh_connect_timeout_seconds
        try:
            kwargs = ssh_auth.connect_kwargs(asset, timeout)
        except ValueError as error:
            raise AnalysisExecutionError("SSH_PRIVATE_KEY_INVALID", str(error)) from error
        client.connect(**kwargs, channel_timeout=timeout)
        client.get_transport().set_keepalive(15)
        client.eolwatch_learned_host_key = pinned.learned
        return client
    except paramiko.AuthenticationException as error:
        client.close()
        raise AnalysisExecutionError("SSH_AUTHENTICATION", "대상 서버의 SSH 비밀번호 인증에 실패했습니다." if mode == ssh_auth.AUTH_PASSWORD else "대상 서버의 SSH 키 인증에 실패했습니다.") from error
    except paramiko.BadHostKeyException as error:
        client.close()
        raise AnalysisExecutionError("SSH_HOST_KEY", "대상 서버의 SSH 호스트 키가 등록된 키와 다릅니다.") from error
    except (OSError, paramiko.SSHException) as error:
        client.close()
        raise AnalysisExecutionError("SSH_CONNECTION", "SSH 연결에 실패했습니다. IP·포트·등록된 호스트 키를 확인하세요.") from error


def _target_home(sftp) -> str:
    home = sftp.normalize(".")
    if (not isinstance(home, str) or not home.startswith("/") or any(ord(char) < 32 for char in home)
            or ".." in PurePosixPath(home).parts or str(PurePosixPath(home)) != home):
        raise AnalysisExecutionError("SSH_HOME", "대상 SSH 계정의 홈 디렉터리를 확인할 수 없습니다.")
    return home


def _scan_directory(client, profile: AnalysisProfile, target_path=None) -> str:
    if profile.relative_directory is None and target_path is None:
        return "/"
    with client.open_sftp() as sftp:
        sftp.get_channel().settimeout(15)
        directory = normalize_target_path(target_path) if target_path is not None else _target_home(sftp).rstrip("/") + "/" + profile.relative_directory
        try:
            info = sftp.stat(directory)
            canonical = sftp.normalize(directory)
        except FileNotFoundError as error:
            raise AnalysisExecutionError("APP_NOT_INSTALLED", "선택한 앱 디렉터리가 대상 서버에 없습니다.") from error
        if not stat.S_ISDIR(info.st_mode):
            raise AnalysisExecutionError("APP_NOT_INSTALLED", "분석 대상은 앱 디렉터리여야 합니다.")
        if canonical != directory:
            raise AnalysisExecutionError("APP_PATH_OUT_OF_SCOPE", "앱 경로가 다른 디렉터리로 연결됩니다. 실제 절대 경로를 지정하세요.")
        return directory


def _provision(client, syft: Path, run: _Run):
    with client.open_sftp() as sftp:
        sftp.get_channel().settimeout(15)
        home = _target_home(sftp)
        root = home.rstrip("/")
        for part in (".local", "eolwatch-tools"):
            root += "/" + part
            try:
                sftp.stat(root)
            except FileNotFoundError:
                sftp.mkdir(root, mode=0o700)
        digest = _sha256(syft)
        target = root + "/syft-" + digest[:16]
        identifier = uuid.uuid4().hex
        config = root + "/analysis-" + identifier + ".json"
        pid = root + "/analysis-" + identifier + ".pid"
        exists = run.remote(client, "existing-target-tool", ["sh", "-c",
                            "if test -x " + shlex.quote(target) + "; then sha256sum " + shlex.quote(target) + "; fi"], 10)
        if exists.read_text().split()[:1] != [digest]:
            temporary = target + "." + identifier + ".tmp"
            transfer_started = time.monotonic()

            def progress(_sent, _total):
                run.heartbeat()
                if time.monotonic() - transfer_started > 120:
                    raise AnalysisExecutionError("TOOL_TRANSFER_TIMEOUT", "대상 서버에 분석 도구를 전송하는 시간이 초과되었습니다.")

            try:
                sftp.put(str(syft), temporary, callback=progress)
                sftp.chmod(temporary, 0o755)
                # posix_rename replaces an interrupted/corrupt prior installation atomically.
                sftp.posix_rename(temporary, target)
            finally:
                try:
                    sftp.remove(temporary)
                except OSError:
                    pass
        verified = run.remote(client, "verify-target-syft", ["sha256sum", target], 10)
        if verified.read_text().split()[:1] != [digest]:
            raise AnalysisExecutionError("TARGET_TOOL_CHECKSUM", "대상 서버의 분석 도구 체크섬 검증에 실패했습니다.")
        with sftp.open(config, "w") as stream:
            stream.write(json.dumps(SYFT_CONFIG) + "\n")
        sftp.chmod(config, 0o600)
        return target, config, pid


def _clone_repository(run: _Run, snapshot: dict, settings, env: dict) -> str:
    """Shallow, read-only clone into the run directory. The token never reaches argv or the manifest."""
    try:
        url = normalize_repository_url(snapshot.get("git_url"))
        ref = normalize_git_ref(snapshot.get("git_ref"))
    except ValueError as error:
        raise AnalysisExecutionError("TARGET_INVALID", str(error)) from error
    directory = run.directory / "source"
    git_env = dict(env, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_ASKPASS="/bin/false",
                   HOME=str(run.directory), GIT_LFS_SKIP_SMUDGE="1")
    credential = None
    argv = [settings.analysis_git_path, "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "core.symlinks=false"]
    token = snapshot.get("git_token")
    if token:
        credential = run.directory / ".git-credential"
        credential.touch(mode=0o600)
        credential.write_text(f"#!/bin/sh\necho username=oauth2\necho password={shlex.quote(token)}\n", encoding="utf-8")
        credential.chmod(0o700)
        argv.extend(["-c", "credential.helper=" + str(credential)])
    argv.extend(["clone", "--depth", "1", "--no-tags", "--single-branch", "--recurse-submodules=no"])
    if ref:
        argv.extend(["--branch", ref])
    argv.extend(["--", url, str(directory)])
    try:
        run.local("git-clone", argv, settings.analysis_git_timeout_seconds, git_env)
    except AnalysisExecutionError as error:
        if error.code == "TOOL_FAILED":
            raise AnalysisExecutionError("GIT_CLONE_FAILED", "저장소를 가져오지 못했습니다. 주소·브랜치·접근 권한(비공개 저장소는 토큰)을 확인하세요.") from error
        raise
    finally:
        if credential is not None:
            credential.unlink(missing_ok=True)
    head = run.local("git-head", [settings.analysis_git_path, "-C", str(directory), "rev-parse", "HEAD"], 30, git_env)
    commit = head.read_text(encoding="utf-8", errors="replace").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AnalysisExecutionError("GIT_CLONE_FAILED", "가져온 저장소의 커밋을 확인하지 못했습니다.")
    run.manifest["git_commit"] = commit
    total = 0
    for path in directory.rglob("*"):
        if path.is_symlink():
            path.unlink()
            continue
        if path.is_file():
            total += path.stat().st_size
            if total > settings.analysis_git_max_bytes:
                raise AnalysisExecutionError("SOURCE_TOO_LARGE", "저장소 크기가 허용 한도를 초과했습니다.")
    run.save()
    return str(directory)


def _ai_library_reference(run: _Run, directory: str, asset_snapshot: dict) -> Path:
    """Syft found nothing pinned: let the AI name the libraries from imports and manifests (see ai_library_reference)."""
    from . import ai_advisor
    project_name = str(asset_snapshot.get("project_name") or asset_snapshot.get("asset_tag") or asset_snapshot.get("id"))
    started = time.monotonic()
    try:
        spdx, entry = reference_libraries(directory, project_name=project_name, complete_json=ai_advisor.complete_json)
    except LibraryReferenceError as error:
        run.manifest["ai_library_reference"] = {"status": "failed", "error_code": error.code}
        raise AnalysisExecutionError("EMPTY_COLLECTION", (
            "버전이 고정된 의존성 파일(package-lock.json·yarn.lock, requirements.txt, pom.xml, go.sum, Gemfile.lock 등)을 찾지 못했고, "
            f"AI 라이브러리 참조도 실패했습니다. {error.message} 취약점이 없다는 뜻이 아닙니다.")) from error
    entry.update(status="ok", seconds=round(time.monotonic() - started, 1))
    run.manifest["ai_library_reference"] = entry
    spdx_path = run.directory / "sbom.spdx.json"
    spdx_path.write_text(json.dumps(spdx, ensure_ascii=False, indent=1), encoding="utf-8")
    run.manifest["artifacts"]["sbom.spdx.json"] = _sha256(spdx_path)
    run.save()
    return spdx_path


def _environment(settings) -> dict:
    # Do not pass database/password/registry credentials into scanners or their reports.
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR",
               "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    cache = Path(settings.analysis_cache_dir).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    env.update(SYFT_CHECK_FOR_APP_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false",
               GRYPE_DB_CACHE_DIR=str(cache / "grype-db"), GRYPE_CACHE_DIR=str(cache / "grype"))
    return env


def execute_analysis(asset_snapshot: dict, output_dir: Path, settings, stage_callback: Callable[[str], None]) -> dict:
    """Return validated analysis payloads; caller owns the import transaction.

    stage_callback is invoked on stage transitions and every five seconds while
    tools run. Its exceptions propagate unchanged, allowing a worker lease to
    fence a run that is no longer owned by this process.
    """
    run = _Run(asset_snapshot, output_dir, stage_callback)
    client = None
    remote_config = None
    try:
        run.heartbeat("COLLECTING")
        profile = ANALYSIS_PROFILES.get(run.profile)
        if profile is None:
            raise AnalysisExecutionError("UNSUPPORTED_SCAN_SCOPE", "지원하지 않는 분석 범위입니다.")
        if run.profile in PATH_SCAN_SCOPES or run.profile in SOURCE_SCAN_SCOPES:
            try:
                expected_scope = scope_identity(run.profile, asset_snapshot.get('target_path'), asset_snapshot.get('project_name'))
            except ValueError as error:
                raise AnalysisExecutionError("TARGET_INVALID", str(error)) from error
            if run.scan_scope != expected_scope:
                raise AnalysisExecutionError("SCOPE_MISMATCH", "분석 대상과 저장된 분석 범위가 일치하지 않습니다.")
        syft, grype, expected_architecture = _tools(settings, run)
        env = _environment(settings)
        for name, tool in (("syft", syft), ("grype", grype)):
            run.local(name + "-version", [str(tool), "version", "-o", "json"], 20, env)
        scan_options = ["--select-catalogers=-file", "--parallelism", "1", "--source-name",
                        str(asset_snapshot.get("project_name") or asset_snapshot.get("asset_tag") or asset_snapshot.get("id")),
                        "-o", "syft-json"]
        if profile.cataloger:
            scan_options.extend(["--override-default-catalogers", profile.cataloger])
        for exclude in profile.exclusions:
            scan_options.extend(["--exclude", exclude])
        if run.profile in SOURCE_SCAN_SCOPES:
            if run.profile == GIT_SCAN_SCOPE:
                directory = _clone_repository(run, asset_snapshot, settings, env)
            else:
                try:
                    directory = str(extract_upload(asset_snapshot, run.directory / "source", settings, run.heartbeat))
                except InvalidArchive as error:
                    raise AnalysisExecutionError("INVALID_SOURCE_ARCHIVE", str(error)) from error
            config_path = run.directory / "source-syft.json"
            config_path.write_text(json.dumps(SYFT_CONFIG), encoding="utf-8")
            raw_path = run.local("syft-scan", [str(syft), "scan", "dir:" + directory,
                                 "--config", str(config_path), *scan_options],
                                 settings.analysis_collect_timeout_seconds, env, output="sbom.syft.json")
        else:
            client = _connect(asset_snapshot, settings)
            architecture = run.remote(client, "target-architecture", ["uname", "-sm"], 10)
            architecture_line = architecture.read_text().strip()
            remote_syft = syft if architecture_line == expected_architecture else _remote_syft(syft, architecture_line, run)
            run.manifest["target_architecture"] = architecture_line
            if run.profile in PATH_SCAN_SCOPES:
                directory = _scan_directory(client, profile, asset_snapshot.get('target_path'))
            else:
                directory = _scan_directory(client, profile)
            target, remote_config, pid_file = _provision(client, remote_syft, run)
            remote = ["env", "SYFT_CHECK_FOR_APP_UPDATE=false", target, "scan", "dir:" + directory,
                      "--config", remote_config, *scan_options]
            raw_path = run.remote(client, "syft-scan", remote, settings.analysis_collect_timeout_seconds,
                                  output="sbom.syft.json", pid_file=pid_file)
        run.manifest["scan_directory"] = directory
        raw = _json(raw_path)
        packages = raw.get("artifacts")
        catalogers = raw.get("descriptor", {}).get("configuration", {}).get("catalogers", {}).get("used", [])
        ai_reference = False
        if not isinstance(packages, list) or not packages:
            if run.profile in SOURCE_SCAN_SCOPES and getattr(settings, "ai_pipeline", True):
                spdx_path = _ai_library_reference(run, directory, asset_snapshot)
                ai_reference = True
                packages = []
            elif run.profile in SOURCE_SCAN_SCOPES:
                raise AnalysisExecutionError("EMPTY_COLLECTION", "버전이 고정된 의존성 파일(package-lock.json·yarn.lock, requirements.txt, pom.xml, go.sum, Gemfile.lock 등)을 찾지 못했습니다. package.json·build.gradle만으로는 구성요소를 확정할 수 없어 결과를 저장하지 않습니다. 취약점이 없다는 뜻이 아닙니다.")
            else:
                raise AnalysisExecutionError("EMPTY_COLLECTION", "설치 패키지가 수집되지 않았습니다. 빈 결과는 정상 분석으로 저장하지 않습니다.")
        if not ai_reference and (any(not isinstance(package, dict) for package in packages)
                or profile.cataloger and (catalogers != [profile.cataloger]
                    or any(package.get("type") != profile.package_type for package in packages))):
            raise AnalysisExecutionError("SCOPE_MISMATCH", "수집 결과의 구성요소 또는 수집 도구가 선택한 분석 범위와 일치하지 않습니다.")
        distro = raw.get("distro") or {}
        if run.profile == DEFAULT_SCAN_SCOPE and (distro.get("id") != "ubuntu"
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", str(distro.get("versionID", "")))):
            raise AnalysisExecutionError("DISTRO_UNSUPPORTED", "현재 분석은 배포판 버전을 식별할 수 있는 Ubuntu 서버를 지원합니다.")
        if not ai_reference and (profile.relative_directory is not None or run.profile in PATH_SCAN_SCOPES or run.profile in SOURCE_SCAN_SCOPES) and raw.get("source", {}).get("metadata", {}).get("path") != directory:
            raise AnalysisExecutionError("SCOPE_MISMATCH", "수집 결과의 경로가 선택한 앱 디렉터리와 다릅니다.")
        run.manifest.update(distro=distro, package_count=len(packages), catalogers=catalogers)
        run.heartbeat("SCANNING")
        config = run.directory / "analysis-empty.yaml"
        config.write_text("{}\n", encoding="utf-8")
        if not ai_reference:
            spdx_path = run.local("syft-convert-spdx", [str(syft), "convert", str(raw_path), "--config", str(config),
                                 "-o", "spdx-json@2.3"], 120, env, output="sbom.spdx.json")
        sbom = _json(spdx_path)
        if sbom.get("spdxVersion") != "SPDX-2.3" or not sbom.get("packages"):
            raise AnalysisExecutionError("SPDX_INVALID", "SPDX 2.3 구성요소 목록 생성에 실패했습니다.")
        run.manifest["grype_input_sha256"] = _sha256(spdx_path)
        grype_arguments = [str(grype), "sbom:" + str(spdx_path), "--config", str(config)]
        if run.profile == DEFAULT_SCAN_SCOPE:
            grype_arguments.extend(["--distro", "ubuntu:" + distro["versionID"]])
        grype_arguments.extend(["--by-cve", "-o", "json"])
        report_path = run.local("grype-scan", grype_arguments,
                               settings.analysis_scan_timeout_seconds, env, output="grype.json")
        report = _json(report_path)
        if not isinstance(report.get("matches"), list) or report.get("descriptor", {}).get("name") != "grype":
            raise AnalysisExecutionError("GRYPE_INVALID", "Grype 취약점 분석 결과 형식이 올바르지 않습니다.")
        run.manifest.update(match_count=len(report["matches"]), grype_db=report.get("descriptor", {}).get("db"))
        run.heartbeat("IMPORTING")
        run.manifest["status"] = "ready_for_import"
        result = {"sbom": sbom, "report": report, "scan_scope": run.scan_scope}
        if run.manifest.get("git_commit"):
            result["git_commit"] = run.manifest["git_commit"]
        learned = getattr(client, "eolwatch_learned_host_key", None) if client is not None else None
        if learned:
            result["learned_host_key"] = learned
        return result
    except AnalysisExecutionError as error:
        run.manifest.update(status="failed", error_code=error.code, error=error.message)
        raise
    except (paramiko.SSHException, socket.timeout, OSError) as error:
        failure = AnalysisExecutionError("EXECUTION_IO", "분석 실행 중 연결 또는 파일 처리에 실패했습니다. 관리 서버 작업 로그를 확인하세요.")
        run.manifest.update(status="failed", error_code=failure.code, error=failure.message)
        raise failure from error
    except BaseException as error:
        # Preserve lease/shutdown exceptions, but never put their arbitrary text in artifacts.
        run.manifest.update(status="interrupted", error_code=type(error).__name__, error="분석 실행이 중단되었습니다.")
        raise
    finally:
        if client is not None:
            if remote_config:
                try:
                    with client.open_sftp() as sftp:
                        sftp.get_channel().settimeout(5)
                        sftp.remove(remote_config)
                except (OSError, paramiko.SSHException):
                    pass
            client.close()
        run.finish()
