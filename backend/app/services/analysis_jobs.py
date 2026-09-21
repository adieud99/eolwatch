"""Durable analysis queue. Requests enqueue; the worker owns tool execution."""
from __future__ import annotations

from datetime import timedelta
import json
import logging
from pathlib import Path
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..config import get_settings
from ..db import SessionLocal
from .analysis import import_analysis
from .analysis_profiles import (DEFAULT_SCAN_SCOPE, GIT_SCAN_SCOPE, PATH_SCAN_SCOPES, ZIP_SCAN_SCOPE, normalize_git_ref,
                                normalize_repository_url, normalize_target_path, scope_identity)

logger = logging.getLogger(__name__)
RUNNING = ('COLLECTING', 'SCANNING', 'IMPORTING')
ACTIVE = ('QUEUED', *RUNNING, 'CANCEL_REQUESTED')
SNAPSHOT_FIELDS = ('id', 'asset_tag', 'name', 'ip_address', 'ssh_port', 'ssh_username', 'ssh_auth', 'ssh_password_encrypted', 'ssh_private_key_encrypted', 'ssh_host_key')
TARGET_FIELDS = ('ip_address', 'ssh_port', 'ssh_username', 'ssh_auth')


class JobLeaseLost(RuntimeError):
    """An interrupted/stale worker may no longer change this job."""


class JobCancellationRequested(JobLeaseLost):
    """The owner must stop tools and acknowledge cleanup before releasing its asset."""


def cancel_analysis(db: Session, job_id: int, _attempt: int = 0) -> models.AnalysisJob:
    # This same row is locked for result import. Whichever transaction wins
    # determines whether a result is committed or cancellation prevents import.
    job = db.scalar(select(models.AnalysisJob).where(models.AnalysisJob.id == job_id).with_for_update())
    if job is None:
        raise HTTPException(status_code=404, detail='취소할 분석 작업이 없습니다.')
    if job.status in ('CANCEL_REQUESTED', 'CANCELLED'):
        return job
    if job.status not in ACTIVE:
        raise HTTPException(status_code=409, detail='이미 종료된 분석 작업은 취소할 수 없습니다.')
    previous_status = job.status
    values = {'status': 'CANCEL_REQUESTED', 'error_code': None, 'error_message': None}
    if previous_status == 'QUEUED':
        values.update(status='CANCELLED', active_asset_id=None, worker_token=None,
                      finished_at=models.utcnow(), error_code='USER_CANCELLED',
                      error_message='사용자가 분석을 취소했습니다.')
    result = db.execute(update(models.AnalysisJob).where(
        models.AnalysisJob.id == job_id, models.AnalysisJob.status == previous_status,
    ).values(**values))
    if result.rowcount != 1:
        db.rollback()
        # SQLite has no SELECT FOR UPDATE; retry its compare-and-swap against
        # the newly committed state instead of overwriting a successful job.
        if _attempt >= 3:
            raise HTTPException(status_code=409, detail='분석 상태가 변경되고 있습니다. 상태를 확인하고 취소를 다시 요청하세요.')
        return cancel_analysis(db, job_id, _attempt + 1)
    db.commit()
    db.refresh(job)
    return job


def _cleanup_confirmed(job: models.AnalysisJob) -> bool:
    if not job.worker_token:
        return False
    directory = Path(get_settings().analysis_artifacts_dir) / f'job-{job.id}-{job.worker_token}'
    marker = directory / 'manifest.json'
    if directory.is_symlink() or marker.is_symlink():
        return False
    try:
        if marker.stat().st_size > 1024 * 1024:
            return False
        manifest = json.loads(marker.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return (isinstance(manifest, dict) and manifest.get('asset_id') == job.asset_id
            and manifest.get('cleanup_confirmed') is True and bool(manifest.get('finished_at')))


def _acknowledge_cancellation(db: Session, job: models.AnalysisJob, *, no_execution=False) -> bool:
    if job.status != 'CANCEL_REQUESTED':
        return False
    if not no_execution and not _cleanup_confirmed(job):
        db.execute(update(models.AnalysisJob).where(
            models.AnalysisJob.id == job.id, models.AnalysisJob.status == 'CANCEL_REQUESTED',
            models.AnalysisJob.worker_token == job.worker_token,
        ).values(error_code='CANCEL_CLEANUP_REQUIRED',
                 error_message='분석 프로세스 정리를 확인하지 못해 자산 잠금을 유지합니다. 관리자가 작업 로그와 워커 상태를 확인해야 합니다.'))
        return False
    now = models.utcnow()
    result = db.execute(update(models.AnalysisJob).where(
        models.AnalysisJob.id == job.id, models.AnalysisJob.status == 'CANCEL_REQUESTED',
        models.AnalysisJob.worker_token == job.worker_token,
    ).values(status='CANCELLED', active_asset_id=None, worker_token=None, finished_at=now,
             heartbeat_at=now, error_code='USER_CANCELLED', error_message='사용자가 분석을 취소했습니다.'))
    return result.rowcount == 1


def _finish_cancellation(job_id: int, token: str, *, no_execution=False) -> bool:
    with SessionLocal() as db:
        job = db.scalar(select(models.AnalysisJob).where(
            models.AnalysisJob.id == job_id, models.AnalysisJob.worker_token == token,
        ).with_for_update())
        if not job or job.status != 'CANCEL_REQUESTED':
            return False
        _acknowledge_cancellation(db, job, no_execution=no_execution)
        db.commit()
        return True


def execute_analysis(*args, **kwargs):
    # Load the tool executor only in the worker, not during API startup.
    from .analysis_executor import execute_analysis as execute
    return execute(*args, **kwargs)


def analysis_snapshot(db: Session, asset_id: int, scan_scope: str = DEFAULT_SCAN_SCOPE,
                      target_path: Optional[str] = None, upload_id: Optional[str] = None,
                      git: Optional[dict] = None) -> dict:
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail='분석할 자산이 없습니다')
    snapshot = {name: getattr(asset, name) for name in SNAPSHOT_FIELDS}
    if scan_scope == GIT_SCAN_SCOPE:
        git = git or {}
        try:
            snapshot.update(input_type='git', profile=GIT_SCAN_SCOPE, project_name=git.get('project_name'),
                            git_url=normalize_repository_url(git.get('repository_url')), git_ref=normalize_git_ref(git.get('ref')))
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        if git.get('access_token'):
            # Used once by the worker for the clone, then removed from the stored snapshot.
            snapshot['git_token'] = git['access_token']
    elif scan_scope == ZIP_SCAN_SCOPE:
        upload = db.get(models.AnalysisUpload, upload_id) if upload_id else None
        if not upload or upload.asset_id != asset_id:
            raise HTTPException(status_code=422, detail='동일 자산에 보관된 소스 ZIP이 필요합니다')
        snapshot.update(input_type='zip', profile=ZIP_SCAN_SCOPE, upload_id=upload.id,
                        upload_sha256=upload.sha256, upload_filename=upload.filename,
                        upload_size_bytes=upload.size_bytes, project_name=upload.project_name)
    elif not asset.monitored or not asset.ip_address or not asset.ssh_username:
        raise HTTPException(status_code=422, detail='모니터링 사용, IP 주소, SSH 계정을 설정한 자산만 분석할 수 있습니다')
    else:
        snapshot.update(input_type='ssh', profile=scan_scope)
    try:
        snapshot['scan_scope'] = scope_identity(scan_scope, target_path, snapshot.get('project_name'))
        if scan_scope in PATH_SCAN_SCOPES:
            snapshot['target_path'] = normalize_target_path(target_path)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return snapshot


def enqueue_analysis(db: Session, asset_id: int, retry_of_id: Optional[int] = None,
                     scan_scope: str = DEFAULT_SCAN_SCOPE, target_path: Optional[str] = None,
                     upload_id: Optional[str] = None, git: Optional[dict] = None, *, commit: bool = True) -> models.AnalysisJob:
    if retry_of_id is not None:
        previous = db.get(models.AnalysisJob, retry_of_id)
        if not previous:
            raise HTTPException(status_code=404, detail='재시도할 작업이 없습니다')
        if previous.asset_id != asset_id or previous.status != 'FAILED':
            raise HTTPException(status_code=409, detail='실패한 동일 자산의 작업만 재시도할 수 있습니다')
        scan_scope = previous.asset_snapshot.get('profile', previous.asset_snapshot.get('scan_scope', DEFAULT_SCAN_SCOPE))
        target_path = previous.asset_snapshot.get('target_path')
        upload_id = previous.asset_snapshot.get('upload_id')
        if previous.asset_snapshot.get('input_type') == 'git':
            git = {'repository_url': previous.asset_snapshot.get('git_url'), 'ref': previous.asset_snapshot.get('git_ref'),
                   'project_name': previous.asset_snapshot.get('project_name'), 'access_token': (git or {}).get('access_token')}
    snapshot = analysis_snapshot(db, asset_id, scan_scope, target_path, upload_id, git)
    identity = snapshot['scan_scope']
    if retry_of_id is not None and snapshot.get('input_type') == 'zip':
        if any(snapshot.get(key) != previous.asset_snapshot.get(key)
               for key in ('upload_sha256', 'upload_size_bytes', 'project_name')):
            raise HTTPException(status_code=409, detail='재시도할 업로드 원본 정보가 변경되었습니다')
    existing = db.scalar(select(models.AnalysisJob).where(models.AnalysisJob.active_asset_id == asset_id))
    if existing:
        if existing.status == 'CANCEL_REQUESTED':
            raise HTTPException(status_code=409, detail='이 자산의 취소 요청을 정리하고 있습니다. 취소 완료 후 다시 요청하세요.')
        if (existing.asset_snapshot.get('scan_scope', DEFAULT_SCAN_SCOPE) != identity
                or existing.asset_snapshot.get('upload_sha256') != snapshot.get('upload_sha256')):
            raise HTTPException(status_code=409, detail='이 자산의 다른 범위 분석이 진행 중입니다. 완료 후 요청하세요.')
        return existing
    job = models.AnalysisJob(
        asset_id=asset_id, active_asset_id=asset_id, status='QUEUED',
        asset_snapshot=snapshot,
        retry_of_id=retry_of_id,
    )
    db.add(job)
    try:
        if commit:
            db.commit()
        else:
            db.flush()
    except IntegrityError:
        # Another request may have won the unique active-asset constraint.
        if not commit:
            raise
        db.rollback()
        existing = db.scalar(select(models.AnalysisJob).where(models.AnalysisJob.active_asset_id == asset_id))
        if existing:
            if existing.status == 'CANCEL_REQUESTED':
                raise HTTPException(status_code=409, detail='이 자산의 취소 요청을 정리하고 있습니다. 취소 완료 후 다시 요청하세요.')
            if (existing.asset_snapshot.get('scan_scope', DEFAULT_SCAN_SCOPE) != identity
                    or existing.asset_snapshot.get('upload_sha256') != snapshot.get('upload_sha256')):
                raise HTTPException(status_code=409, detail='이 자산의 다른 범위 분석이 진행 중입니다. 완료 후 요청하세요.')
            return existing
        raise HTTPException(status_code=409, detail='분석 요청이 충돌했습니다. 자산 상태를 확인하세요') from None
    db.refresh(job)
    return job


def recover_stale_jobs(db: Session) -> int:
    now = models.utcnow()
    cutoff = now - timedelta(seconds=max(60, get_settings().analysis_job_lease_seconds))
    result = db.execute(update(models.AnalysisJob).where(
        models.AnalysisJob.status.in_(RUNNING), models.AnalysisJob.heartbeat_at < cutoff,
    ).values(status='FAILED', active_asset_id=None, worker_token=None, finished_at=now,
             error_code='WORKER_INTERRUPTED', error_message='분석 작업의 실행 확인이 끊겼습니다. 작업을 재시도하세요.'))
    recovered = result.rowcount
    cancelled = db.scalars(select(models.AnalysisJob).where(
        models.AnalysisJob.status == 'CANCEL_REQUESTED', models.AnalysisJob.heartbeat_at < cutoff,
    ).with_for_update(skip_locked=True)).all()
    for job in cancelled:
        # Heartbeat expiry alone is not evidence that the tool process stopped.
        # A worker that died after cleanup but before DB commit can be recovered.
        recovered += int(_acknowledge_cancellation(db, job))
    return recovered


def claim_next_analysis_job(db: Session):
    recover_stale_jobs(db)
    job = db.scalar(select(models.AnalysisJob).where(models.AnalysisJob.status == 'QUEUED')
                    .order_by(models.AnalysisJob.id).with_for_update(skip_locked=True).limit(1))
    if not job:
        db.commit()
        return None
    token, now = str(uuid4()), models.utcnow()
    claimed = db.execute(update(models.AnalysisJob).where(
        models.AnalysisJob.id == job.id, models.AnalysisJob.status == 'QUEUED',
    ).values(status='COLLECTING', worker_token=token, started_at=now, heartbeat_at=now))
    if claimed.rowcount != 1:
        db.rollback()
        return None
    result = (job.id, token, dict(job.asset_snapshot))
    db.commit()
    return result


def set_job_stage(job_id: int, token: str, stage: str) -> None:
    if stage not in RUNNING:
        raise ValueError('Unknown analysis stage')
    with SessionLocal() as db:
        result = db.execute(update(models.AnalysisJob).where(
            models.AnalysisJob.id == job_id, models.AnalysisJob.worker_token == token,
            models.AnalysisJob.status.in_(RUNNING),
        ).values(status=stage, heartbeat_at=models.utcnow()))
        if result.rowcount != 1:
            db.rollback()
            job = db.get(models.AnalysisJob, job_id)
            if job and job.worker_token == token and job.status == 'CANCEL_REQUESTED':
                raise JobCancellationRequested('Analysis cancellation requested')
            raise JobLeaseLost('Analysis worker no longer owns this job')
        db.commit()


def _check_target(db: Session, snapshot: dict) -> None:
    asset = db.get(models.Asset, snapshot['id'])
    if snapshot.get('input_type') == 'zip':
        upload = db.get(models.AnalysisUpload, snapshot.get('upload_id'))
        if not asset or not upload or upload.asset_id != asset.id or upload.sha256 != snapshot.get('upload_sha256'):
            raise HTTPException(status_code=409, detail='분석 자산 또는 보관된 업로드 원본 정보가 변경됐습니다.')
        return
    if snapshot.get('input_type') == 'git':
        if not asset:
            raise HTTPException(status_code=409, detail='분석 대상이 삭제됐습니다.')
        return
    if not asset or not asset.monitored or any(getattr(asset, key) != snapshot[key] for key in TARGET_FIELDS):
        raise HTTPException(status_code=409, detail='요청 후 분석 대상의 접속 정보가 변경됐습니다. 다시 요청하세요.')


def _finalize_git_snapshot(job_id: int, token: str, snapshot: dict) -> None:
    """Drop the one-time access token from the stored snapshot and keep the resolved commit."""
    stored = {key: value for key, value in snapshot.items() if key != 'git_token'}
    with SessionLocal() as db:
        db.execute(update(models.AnalysisJob).where(
            models.AnalysisJob.id == job_id, models.AnalysisJob.worker_token == token,
        ).values(asset_snapshot=stored))
        db.commit()
    snapshot.pop('git_token', None)


def _fail_job(job_id: int, token: str, error: Exception) -> None:
    code = getattr(error, 'code', 'ANALYSIS_FAILED')
    if isinstance(error, HTTPException):
        code, message = 'RESULT_REJECTED', str(error.detail)
    elif hasattr(error, 'message'):
        message = str(error.message)
    else:
        message = '분석 처리 중 오류가 발생했습니다. 관리자에게 작업 번호를 전달하고 재시도하세요.'
    with SessionLocal() as db:
        job = db.scalar(select(models.AnalysisJob).where(
            models.AnalysisJob.id == job_id, models.AnalysisJob.worker_token == token,
        ).with_for_update())
        if job and job.status == 'CANCEL_REQUESTED':
            _acknowledge_cancellation(db, job)
            db.commit()
            return
        db.execute(update(models.AnalysisJob).where(
            models.AnalysisJob.id == job_id, models.AnalysisJob.worker_token == token,
            models.AnalysisJob.status.in_(RUNNING),
        ).values(status='FAILED', active_asset_id=None, worker_token=None,
                 error_code=str(code)[:80], error_message=message[:2000], finished_at=models.utcnow()))
        db.commit()


def process_next_analysis_job() -> Optional[int]:
    with SessionLocal() as db:
        claimed = claim_next_analysis_job(db)
    if claimed is None:
        return None
    job_id, token, snapshot = claimed
    execution_started = False
    try:
        with SessionLocal() as db:
            _check_target(db, snapshot)
        settings = get_settings()
        output_dir = Path(settings.analysis_artifacts_dir) / f'job-{job_id}-{token}'
        set_job_stage(job_id, token, 'COLLECTING')
        execution_started = True
        bundle = None
        try:
            bundle = execute_analysis(snapshot, output_dir, settings, lambda stage: set_job_stage(job_id, token, stage))
        finally:
            if snapshot.get('input_type') == 'git':
                if bundle and bundle.get('git_commit'):
                    snapshot['git_commit'] = bundle['git_commit']
                _finalize_git_snapshot(job_id, token, snapshot)
        set_job_stage(job_id, token, 'IMPORTING')
        with SessionLocal() as db:
            # A conditional write also acquires SQLite's writer lock, closing
            # the gap between reading status and the first evidence INSERT.
            ownership = db.execute(update(models.AnalysisJob).where(
                models.AnalysisJob.id == job_id, models.AnalysisJob.worker_token == token,
                models.AnalysisJob.status.in_(RUNNING),
            ).values(heartbeat_at=models.utcnow()))
            job = db.scalar(select(models.AnalysisJob).where(models.AnalysisJob.id == job_id).with_for_update())
            if job and job.worker_token == token and job.status == 'CANCEL_REQUESTED':
                raise JobCancellationRequested('Analysis cancellation requested')
            if ownership.rowcount != 1 or not job or job.worker_token != token or job.status not in RUNNING:
                raise JobLeaseLost('Analysis worker no longer owns this job')
            _check_target(db, snapshot)
            payload = schemas.AnalysisImport(asset_id=job.asset_id, sbom=bundle['sbom'], report=bundle['report'],
                                            scan_scope=bundle['scan_scope'], package_updates=bundle.get('package_updates'))
            run = import_analysis(db, payload, commit=False)
            if bundle.get('learned_host_key'):
                target = db.get(models.Asset, job.asset_id)
                if target is not None and not target.ssh_host_key:
                    target.ssh_host_key = bundle['learned_host_key']
            job.analysis_run_id = run.id
            job.status = 'SUCCESS'
            job.active_asset_id = None
            job.worker_token = None
            job.finished_at = models.utcnow()
            job.heartbeat_at = job.finished_at
            db.commit()
    except JobCancellationRequested:
        _finish_cancellation(job_id, token, no_execution=not execution_started)
    except JobLeaseLost:
        logger.warning('Analysis job %s no longer belongs to this worker', job_id)
    except Exception as exc:
        if not _finish_cancellation(job_id, token, no_execution=not execution_started):
            logger.exception('Analysis job %s failed', job_id)
            _fail_job(job_id, token, exc)
    return job_id
