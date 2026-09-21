"""등록 서버(자산) 관리. SSH 접속 정보와 식별 정보만 다룬다."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db


router = APIRouter(prefix="/assets", tags=["assets"])


def _asset_read(db: Session, asset: models.Asset) -> schemas.AssetRead:
    sbom_count = db.scalar(select(func.count(models.SbomDocument.id)).where(models.SbomDocument.asset_id == asset.id)) or 0
    findings = db.execute(
        select(models.Vulnerability.severity, models.ComponentVulnerability.vex_status)
        .join(models.ComponentVulnerability, models.ComponentVulnerability.vulnerability_id == models.Vulnerability.id)
        .join(models.Component, models.Component.id == models.ComponentVulnerability.component_id)
        .join(models.SbomDocument, models.SbomDocument.id == models.Component.sbom_id)
        .where(models.SbomDocument.asset_id == asset.id)
    ).all()
    vulnerability_counts = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for severity, vex_status in findings:
        if vex_status not in ("AFFECTED", "UNDER_INVESTIGATION"):
            continue
        level = str(severity or "UNKNOWN").upper()
        vulnerability_counts[level if level in vulnerability_counts else "UNKNOWN"] += 1
    values = {column.name: getattr(asset, column.name) for column in models.Asset.__table__.columns}
    return schemas.AssetRead(
        **values,
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
    asset = models.Asset(**payload.model_dump())
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
    connection_fields = {"ip_address", "ssh_port", "ssh_username", "monitored", "asset_tag", "name"}
    changed_fields = {key for key, value in values.items() if value != getattr(asset, key)}
    if changed_fields & connection_fields:
        active_analysis = db.scalar(select(models.AnalysisJob.id).where(models.AnalysisJob.asset_id == asset_id, models.AnalysisJob.active_asset_id.is_not(None)).limit(1))
        active_collection = db.scalar(select(models.CollectionJob.id).where(models.CollectionJob.asset_id == asset_id, models.CollectionJob.status.in_(("PENDING", "RUNNING"))).limit(1))
        if active_analysis or active_collection:
            raise HTTPException(status_code=409, detail="분석 또는 SSH 점검 중에는 자산 식별정보와 연결 설정을 변경할 수 없습니다")
    for key, value in values.items():
        setattr(asset, key, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 자산번호입니다")
    db.refresh(asset)
    return _asset_read(db, asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.scalar(select(models.Asset).where(models.Asset.id == asset_id).with_for_update())
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    for model in (models.AnalysisJob, models.CollectionJob, models.SbomDocument, models.AnalysisUpload, models.AnalysisSchedule):
        if db.scalar(select(model.asset_id).where(model.asset_id == asset_id).limit(1)) is not None:
            raise HTTPException(status_code=409, detail="분석·점검·SBOM 이력이 있는 자산은 삭제할 수 없습니다. 이력을 보존하려면 모니터링을 해제하세요")
    db.delete(asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="자산에 연결된 이력이 있어 삭제할 수 없습니다")
