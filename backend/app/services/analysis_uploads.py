"""Content-addressed source uploads and bounded extraction, without executing source files."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Callable, Optional
from uuid import uuid4
import zipfile

from fastapi import HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from .analysis_profiles import normalize_project_name


class InvalidArchive(ValueError):
    pass


# Dependency manifests and lock files Syft reads on its own; a single such file
# may be uploaded instead of a whole source tree and is wrapped into a ZIP.
MANIFEST_NAMES = frozenset({
    "requirements.txt", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "go.mod", "go.sum", "gemfile.lock", "cargo.lock", "composer.lock", "packages.lock.json",
    "package.resolved", "pubspec.lock", "mix.lock", "conanfile.txt", "conan.lock",
})
MANIFEST_PATTERNS = (re.compile(r"requirements[\w.-]*\.txt"), re.compile(r"[\w.-]+\.csproj"), re.compile(r"[\w.-]+\.deps\.json"))
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def is_manifest_filename(filename: str) -> bool:
    name = filename.casefold()
    return name in MANIFEST_NAMES or any(pattern.fullmatch(name) for pattern in MANIFEST_PATTERNS)


def wrap_manifest(source: Path, filename: str, destination: Path) -> None:
    """Store a lone dependency file as a one-entry ZIP so the ZIP pipeline applies unchanged."""
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(source, arcname=filename)


def archive_path(settings, sha256: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise InvalidArchive("업로드 원본 해시가 올바르지 않습니다.")
    return Path(settings.analysis_uploads_dir).resolve() / (sha256 + ".zip")


def _entries(archive: zipfile.ZipFile, settings):
    entries = archive.infolist()
    if not entries or len(entries) > settings.analysis_zip_max_entries:
        raise InvalidArchive("ZIP이 비어 있거나 허용된 파일 수를 초과했습니다.")
    names, files, total = set(), set(), 0
    for entry in entries:
        name = entry.filename
        path = PurePosixPath(name)
        if (not name or name.startswith("/") or "\\" in name or ":" in name
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))
                or len(path.parts) > 40 or len(name) > 1000):
            raise InvalidArchive("ZIP에 허용되지 않는 파일 경로가 있습니다.")
        normalized = path.as_posix().casefold()
        if normalized in names:
            raise InvalidArchive("ZIP에 중복 파일 경로가 있습니다.")
        names.add(normalized)
        mode = stat.S_IFMT(entry.external_attr >> 16)
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise InvalidArchive("ZIP의 심볼릭 링크와 특수 파일은 허용되지 않습니다.")
        if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise InvalidArchive("암호화 ZIP 또는 지원하지 않는 압축 방식입니다.")
        if entry.file_size > settings.analysis_zip_max_file_bytes:
            raise InvalidArchive("ZIP 내부 파일이 허용 크기를 초과했습니다.")
        total += entry.file_size
        if total > settings.analysis_zip_max_unpacked_bytes:
            raise InvalidArchive("ZIP 압축 해제 크기가 허용 한도를 초과했습니다.")
        if entry.file_size > max(1, entry.compress_size) * settings.analysis_zip_max_ratio:
            raise InvalidArchive("ZIP의 압축률이 허용 한도를 초과했습니다.")
        if not entry.is_dir():
            files.add(normalized)
    for name in names:
        if any(parent.as_posix() in files for parent in PurePosixPath(name).parents if parent.as_posix() != "."):
            raise InvalidArchive("ZIP의 파일과 디렉터리 경로가 충돌합니다.")
    if not files:
        raise InvalidArchive("ZIP에 분석할 파일이 없습니다.")
    return entries


def validate_archive(path: Path, settings) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            _entries(archive, settings)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as error:
        raise InvalidArchive("유효한 소스 ZIP 파일이 필요합니다.") from error


def _persist_upload(db: Session, asset_id: int, temporary: Path, sha256: str, size: int,
                    filename: str, project_name: str, settings) -> models.AnalysisUpload:
    # The lock, registration and commit stay in one synchronous worker call.
    # No event-loop await may occur while this request owns the asset row lock.
    try:
        if not db.scalar(select(models.Asset).where(models.Asset.id == asset_id).with_for_update()):
            raise HTTPException(status_code=404, detail="연결할 자산이 없습니다")
        validate_archive(temporary, settings)
        destination = archive_path(settings, sha256)
        try:
            os.link(temporary, destination)
            destination.chmod(0o400)
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file() or hashlib.sha256(destination.read_bytes()).hexdigest() != sha256:
                raise HTTPException(status_code=409, detail="보관된 업로드 원본이 변경되었습니다. 저장소를 확인하세요.")
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        record = db.scalar(select(models.AnalysisUpload).where(
            models.AnalysisUpload.asset_id == asset_id,
            models.AnalysisUpload.project_name == project_name,
            models.AnalysisUpload.sha256 == sha256,
        ).order_by(models.AnalysisUpload.created_at, models.AnalysisUpload.id).limit(1))
        if record is None:
            record = models.AnalysisUpload(id=str(uuid4()), asset_id=asset_id, sha256=sha256,
                filename=filename, project_name=project_name, size_bytes=size)
            db.add(record)
        db.commit()
        return record
    except Exception:
        db.rollback()
        raise


async def save_upload(db: Session, asset_id: int, file: UploadFile, project_name: str, settings) -> models.AnalysisUpload:
    try:
        project_name = normalize_project_name(project_name)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    root = Path(settings.analysis_uploads_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=root)
    temporary = Path(temporary_name)
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(descriptor, "wb") as stream:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > settings.analysis_upload_max_bytes:
                    raise HTTPException(status_code=413, detail="소스 ZIP이 허용 크기를 초과했습니다.")
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            await run_in_threadpool(os.fsync, stream.fileno())
        # Close the asynchronous upload before acquiring the database lock.
        await file.close()
        filename = (file.filename or "source.zip").replace("\\", "/").split("/")[-1]
        filename = "".join(c for c in filename if ord(c) >= 32 and ord(c) != 127)[:255] or "source.zip"
        with temporary.open("rb") as stream:
            magic = stream.read(4)
        if size and not magic.startswith(ZIP_MAGIC):
            if not is_manifest_filename(filename):
                raise InvalidArchive("소스 ZIP 또는 지원하는 의존성 파일(requirements.txt, package-lock.json, pom.xml 등)을 선택하세요.")
            wrapped = Path(tempfile.mkstemp(prefix=".manifest-", dir=root)[1])
            try:
                await run_in_threadpool(wrap_manifest, temporary, filename, wrapped)
                temporary.unlink(missing_ok=True)
                temporary = wrapped
                digest, size = hashlib.sha256(temporary.read_bytes()), temporary.stat().st_size
            except BaseException:
                wrapped.unlink(missing_ok=True)
                raise
        return await run_in_threadpool(_persist_upload, db, asset_id, temporary, digest.hexdigest(),
                                       size, filename, project_name, settings)
    except InvalidArchive as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    finally:
        temporary.unlink(missing_ok=True)
        await file.close()


def extract_upload(snapshot: dict, directory: Path, settings, heartbeat: Optional[Callable] = None) -> Path:
    source = archive_path(settings, snapshot.get("upload_sha256", ""))
    if source.is_symlink() or not source.is_file():
        raise InvalidArchive("보관된 업로드 원본을 찾을 수 없습니다.")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > settings.analysis_upload_max_bytes:
                raise InvalidArchive("보관된 업로드 크기가 허용 한도를 초과했습니다.")
            digest.update(chunk)
            if heartbeat:
                heartbeat()
    if digest.hexdigest() != snapshot["upload_sha256"] or size != snapshot.get("upload_size_bytes"):
        raise InvalidArchive("보관된 업로드 원본의 해시 또는 크기가 변경되었습니다.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    total = 0
    try:
        with zipfile.ZipFile(source) as archive:
            for entry in _entries(archive, settings):
                destination = directory.joinpath(*PurePosixPath(entry.filename).parts)
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                count = 0
                with archive.open(entry) as incoming, destination.open("xb") as outgoing:
                    while True:
                        chunk = incoming.read(65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        total += len(chunk)
                        if count > settings.analysis_zip_max_file_bytes or total > settings.analysis_zip_max_unpacked_bytes:
                            raise InvalidArchive("ZIP 실제 압축 해제 크기가 허용 한도를 초과했습니다.")
                        outgoing.write(chunk)
                        if heartbeat:
                            heartbeat()
                if count != entry.file_size:
                    raise InvalidArchive("ZIP 내부 파일 크기가 선언된 크기와 다릅니다.")
                destination.chmod(0o400)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as error:
        raise InvalidArchive("ZIP 압축 해제 중 원본 손상이 확인되었습니다.") from error
    return directory
