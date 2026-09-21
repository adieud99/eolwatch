"""등록 서버(자산) 관리. SSH 접속 정보와 식별 정보만 다룬다."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..config import get_settings
from ..db import get_db
from ..services import ssh_auth


router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_read(db: Session, asset: models.Asset) -> schemas.AssetRead:
    sbom_count = db.scalar(select(func.count(models.SbomDocument.id)).where(models.SbomDocument.asset_id == asset.id)) or 0
    # Open CVEs on the asset's *latest* run per scan scope, counted once per CVE: summing every historical
    # link would show 70,000 for a server scanned twice with 35,000 links each.
    latest_runs = db.execute(
        select(func.max(models.AnalysisRun.id))
        .join(models.SbomDocument, models.SbomDocument.id == models.AnalysisRun.sbom_id)
        .where(models.SbomDocument.asset_id == asset.id)
        .group_by(models.AnalysisRun.scan_scope)
    ).scalars().all()
    link = models.ComponentVulnerability
    findings = db.execute(
        select(models.Vulnerability.osv_id, func.max(func.upper(func.coalesce(link.finding_severity, models.Vulnerability.severity, "UNKNOWN"))))
        .join(link, link.vulnerability_id == models.Vulnerability.id)
        .where(link.analysis_run_id.in_(latest_runs), link.vex_status.in_(("AFFECTED", "UNDER_INVESTIGATION")))
        .group_by(models.Vulnerability.osv_id)
    ).all() if latest_runs else []
    vulnerability_counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for _cve, severity in findings:
        level = str(severity or "UNKNOWN")
        vulnerability_counts[level if level in vulnerability_counts else "UNKNOWN"] += 1
    values = {column.name: getattr(asset, column.name) for column in models.Asset.__table__.columns
              if column.name not in ("ssh_password_encrypted", "ssh_private_key_encrypted", "ssh_host_key")}
    return schemas.AssetRead(
        **values,
        has_password=bool(asset.ssh_password_encrypted),
        has_private_key=bool(asset.ssh_private_key_encrypted),
        ssh_host_key_fingerprint=ssh_auth.host_key_fingerprint(asset.ssh_host_key),
        sbom_count=sbom_count,
        vulnerability_counts=vulnerability_counts,
        vulnerability_count=sum(vulnerability_counts.values()),
    )


@router.get("", response_model=list[schemas.AssetRead])
def list_assets(
    q: Optional[str] = Query(default=None, max_length=100),
    asset_type: Optional[schemas.AssetType] = None,
    db: Session = Depends(get_db),
):
    query = select(models.Asset).order_by(models.Asset.asset_tag)
    if q:
        pattern = f"%{q}%"
        query = query.where(or_(
            models.Asset.asset_tag.ilike(pattern),
            models.Asset.name.ilike(pattern),
            models.Asset.ip_address.ilike(pattern),
            models.Asset.ssh_username.ilike(pattern),
        ))
    if asset_type:
        query = query.where(models.Asset.asset_type == asset_type)
    return [_asset_read(db, asset) for asset in db.scalars(query).all()]


@router.post("", response_model=schemas.AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: schemas.AssetCreate, db: Session = Depends(get_db)):
    values = payload.model_dump()
    password = values.pop("ssh_password", None)
    private_key = values.pop("ssh_private_key", None)
    asset = models.Asset(**values)
    _apply_credentials(asset, password, private_key)
    db.add(asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 자산번호입니다")
    db.refresh(asset)
    return _asset_read(db, asset)


@router.get("/{asset_id}", response_model=schemas.AssetRead)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    return _asset_read(db, asset)


@router.get("/{asset_id}/timeline")
def get_asset_timeline(asset_id: int, db: Session = Depends(get_db)):
    if not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    events: list[dict[str, Any]] = []
    for job in db.scalars(select(models.AnalysisJob).where(models.AnalysisJob.asset_id == asset_id)).all():
        events.append({"type": "ANALYSIS", "at": job.finished_at or job.started_at or job.requested_at, "title": f"분석 작업 #{job.id} {job.status}", "detail": job.error_message or "분석 작업 이력"})
    for job in db.scalars(select(models.CollectionJob).where(models.CollectionJob.asset_id == asset_id)).all():
        events.append({"type": "CHECK", "at": job.finished_at or job.started_at, "title": f"SSH 점검 #{job.id} {job.status}", "detail": job.failure_message or "인프라 상태 점검 이력"})
    for sbom in db.scalars(select(models.SbomDocument).where(models.SbomDocument.asset_id == asset_id)).all():
        events.append({"type": "SBOM", "at": sbom.imported_at, "title": f"SBOM #{sbom.id} 저장", "detail": f"{sbom.component_count}개 구성요소 · {sbom.dependency_count}개 의존관계"})
    action_rows = db.execute(
        select(models.VulnerabilityAction, models.Vulnerability, models.Component)
        .join(models.ComponentVulnerability, models.ComponentVulnerability.id == models.VulnerabilityAction.link_id)
        .join(models.Vulnerability, models.Vulnerability.id == models.ComponentVulnerability.vulnerability_id)
        .join(models.Component, models.Component.id == models.ComponentVulnerability.component_id)
        .join(models.SbomDocument, models.SbomDocument.id == models.Component.sbom_id)
        .where(models.SbomDocument.asset_id == asset_id)
    ).all()
    for action, vulnerability, component in action_rows:
        cve = next((alias for alias in vulnerability.aliases if str(alias).startswith("CVE-")), vulnerability.osv_id)
        events.append({"type": "ACTION", "at": action.created_at, "title": f"{cve} 조치 {action.to_status}", "detail": action.detail or f"{component.name} · {action.actor_username}"})
    return sorted(events, key=lambda item: item["at"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)


@router.patch("/{asset_id}", response_model=schemas.AssetRead)
def update_asset(asset_id: int, payload: schemas.AssetUpdate, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    values = payload.model_dump(exclude_unset=True)
    password = values.pop("ssh_password", None)
    private_key = values.pop("ssh_private_key", None)
    reset_host_key = values.pop("reset_host_key", None)
    connection_fields = {"ip_address", "ssh_port", "ssh_username", "monitored", "asset_tag", "name", "ssh_auth"}
    changed_fields = {key for key, value in values.items() if value != getattr(asset, key)}
    if password or private_key or reset_host_key:
        changed_fields.add("ssh_auth")
    if changed_fields & connection_fields:
        active_analysis = db.scalar(select(models.AnalysisJob.id).where(models.AnalysisJob.asset_id == asset_id, models.AnalysisJob.active_asset_id.is_not(None)).limit(1))
        active_collection = db.scalar(select(models.CollectionJob.id).where(models.CollectionJob.asset_id == asset_id, models.CollectionJob.status.in_(("PENDING", "RUNNING"))).limit(1))
        if active_analysis or active_collection:
            raise HTTPException(status_code=409, detail="분석 또는 SSH 점검 중에는 자산 식별정보와 연결 설정을 변경할 수 없습니다")
    for key, value in values.items():
        setattr(asset, key, value)
    _apply_credentials(asset, password, private_key)
    if reset_host_key or ("ip_address" in changed_fields) or ("ssh_port" in changed_fields):
        asset.ssh_host_key = None
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 자산번호입니다")
    db.refresh(asset)
    return _asset_read(db, asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, purge: bool = Query(False), db: Session = Depends(get_db)):
    """Delete a target. Without `purge` the target must have no history; with `purge` every scan,
    check, SBOM, CVE link, remediation action, upload and AI summary of the target is removed too."""
    asset = db.scalar(select(models.Asset).where(models.Asset.id == asset_id).with_for_update())
    if not asset:
        raise HTTPException(status_code=404, detail="대상이 없습니다")
    if not purge:
        for model in (models.AnalysisJob, models.CollectionJob, models.SbomDocument, models.AnalysisUpload, models.AnalysisSchedule):
            if db.scalar(select(model.asset_id).where(model.asset_id == asset_id).limit(1)) is not None:
                raise HTTPException(status_code=409, detail="검사·점검·결과 이력이 있는 대상입니다. 이력까지 지우려면 '이력 포함 삭제'를 선택하세요")
    else:
        if db.scalar(select(models.AnalysisJob.id).where(models.AnalysisJob.asset_id == asset_id, models.AnalysisJob.active_asset_id.is_not(None)).limit(1)):
            raise HTTPException(status_code=409, detail="진행 중인 검사가 있습니다. 취소가 끝난 뒤 삭제하세요")
        _purge_history(db, asset_id)
    db.delete(asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="대상에 연결된 이력이 있어 삭제할 수 없습니다")


def _apply_credentials(asset: models.Asset, password, private_key) -> None:
    """Store what the chosen auth mode needs, drop what it does not, and validate before saving."""
    if password:
        asset.ssh_password_encrypted = ssh_auth.encrypt_password(password)
    if private_key:
        try:
            ssh_auth.load_private_key(private_key, password or ssh_auth.decrypt_password(asset.ssh_password_encrypted))
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        asset.ssh_private_key_encrypted = ssh_auth.encrypt_password(private_key.strip())
    if asset.ssh_auth == "password":
        asset.ssh_private_key_encrypted = None
        if not asset.ssh_password_encrypted:
            raise HTTPException(status_code=422, detail="비밀번호 인증을 고르면 SSH 비밀번호를 입력해야 합니다")
    elif asset.ssh_auth == "private_key":
        if not asset.ssh_private_key_encrypted:
            raise HTTPException(status_code=422, detail="개인키 인증을 고르면 개인키 내용을 붙여넣어야 합니다")
        if not private_key and password:
            # a new passphrase for the stored key must still open it
            try:
                ssh_auth.load_private_key(ssh_auth.decrypt_password(asset.ssh_private_key_encrypted) or "", password)
            except ValueError as error:
                raise HTTPException(status_code=422, detail=str(error)) from error
    else:
        asset.ssh_password_encrypted = None
        asset.ssh_private_key_encrypted = None


def _purge_history(db: Session, asset_id: int) -> None:
    from sqlalchemy import delete
    from ..services.analysis_uploads import archive_path
    sbom_ids = list(db.scalars(select(models.SbomDocument.id).where(models.SbomDocument.asset_id == asset_id)))
    run_ids = list(db.scalars(select(models.AnalysisRun.id).where(models.AnalysisRun.sbom_id.in_(sbom_ids)))) if sbom_ids else []
    job_ids = list(db.scalars(select(models.CollectionJob.id).where(models.CollectionJob.asset_id == asset_id)))
    component_ids = list(db.scalars(select(models.Component.id).where(models.Component.sbom_id.in_(sbom_ids)))) if sbom_ids else []
    link_ids = list(db.scalars(select(models.ComponentVulnerability.id).where(models.ComponentVulnerability.component_id.in_(component_ids)))) if component_ids else []
    if link_ids:
        db.execute(delete(models.VulnerabilityAction).where(models.VulnerabilityAction.link_id.in_(link_ids)))
        db.execute(delete(models.ComponentVulnerability).where(models.ComponentVulnerability.id.in_(link_ids)))
    if run_ids:
        db.execute(delete(models.AiSummary).where(models.AiSummary.kind == "analysis", models.AiSummary.target_id.in_(run_ids)))
        db.execute(delete(models.AnalysisRun).where(models.AnalysisRun.id.in_(run_ids)))
    if sbom_ids:
        db.execute(delete(models.DependencyEdge).where(models.DependencyEdge.sbom_id.in_(sbom_ids)))
        db.execute(delete(models.Component).where(models.Component.sbom_id.in_(sbom_ids)))
        db.execute(delete(models.SbomDocument).where(models.SbomDocument.id.in_(sbom_ids)))
    db.execute(delete(models.AnalysisSchedule).where(models.AnalysisSchedule.asset_id == asset_id))
    db.execute(delete(models.AnalysisJob).where(models.AnalysisJob.asset_id == asset_id))
    uploads = list(db.scalars(select(models.AnalysisUpload).where(models.AnalysisUpload.asset_id == asset_id)))
    for upload in uploads:
        db.delete(upload)
    db.flush()
    settings = get_settings()
    for upload in uploads:
        still_used = db.scalar(select(models.AnalysisUpload.id).where(models.AnalysisUpload.sha256 == upload.sha256).limit(1))
        if still_used is None:
            try:
                archive_path(settings, upload.sha256).unlink(missing_ok=True)
            except (OSError, ValueError):
                pass
    if job_ids:
        db.execute(delete(models.AiSummary).where(models.AiSummary.kind == "check", models.AiSummary.target_id.in_(job_ids)))
        db.execute(delete(models.CheckResult).where(models.CheckResult.collection_job_id.in_(job_ids)))
        db.execute(delete(models.CollectionJob).where(models.CollectionJob.id.in_(job_ids)))