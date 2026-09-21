from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk


router = APIRouter(prefix="/assets", tags=["assets"])


CSV_OPTIONAL_FIELDS = {
    "site_id",
    "model_release_id",
    "manufacturer",
    "model",
    "serial_number",
    "site",
    "building",
    "floor",
    "room",
    "rack",
    "rack_position",
    "ip_address",
    "ssh_username",
    "introduced_on",
    "purchase_date",
    "purchase_price",
    "power_watts",
    "power_source",
    "warranty_end_date",
    "owner_name",
    "owner_department",
    "support_end_date",
    "lifecycle_source_url",
}


def _csv_payload(row: dict[str, str]) -> dict[str, Any]:
    values: dict[str, Any] = {key.strip(): (value or "").strip() for key, value in row.items() if key}
    for key in CSV_OPTIONAL_FIELDS:
        if not values.get(key):
            values[key] = None
    for key in ("site_id", "model_release_id", "ssh_port"):
        if values.get(key):
            values[key] = int(values[key])
    values.setdefault("operational_status", "ACTIVE")
    values.setdefault("service_criticality", "STANDARD")
    values["monitored"] = str(values.get("monitored", "false")).lower() in {"1", "true", "yes", "y", "예"}
    return values


def _asset_read(db: Session, asset: models.Asset) -> schemas.AssetRead:
    model_end_date = None
    if asset.model_release:
        model_end_date = asset.model_release.security_end_date or asset.model_release.support_end_date or asset.model_release.eol_date
    risk_level, days_left = lifecycle_risk(model_end_date or asset.support_end_date)
    software_count = db.scalar(select(func.count(models.Deployment.id)).where(models.Deployment.asset_id == asset.id)) or 0
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
    vulnerability_count = sum(vulnerability_counts.values())
    severity_score = min(60, vulnerability_counts["CRITICAL"] * 20 + vulnerability_counts["HIGH"] * 8 + vulnerability_counts["MEDIUM"] * 3 + vulnerability_counts["LOW"])
    lifecycle_score = 0 if days_left is None else 25 if days_left < 0 else 20 if days_left <= 90 else 15 if days_left <= 180 else 8 if days_left <= 365 else 0
    criticality_score = {"CRITICAL": 10, "HIGH": 7, "STANDARD": 3, "LOW": 0}.get(asset.service_criticality, 3)
    status_score = 5 if asset.operational_status in ("REPAIR", "RETIRING") else 0
    risk_score = min(100, severity_score + lifecycle_score + criticality_score + status_score)
    priority_level = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"
    values = {column.name: getattr(asset, column.name) for column in models.Asset.__table__.columns}
    return schemas.AssetRead(
        **values,
        risk_level=risk_level,
        days_left=days_left,
        software_count=software_count,
        sbom_count=sbom_count,
        vulnerability_counts=vulnerability_counts,
        vulnerability_count=vulnerability_count,
        risk_score=risk_score,
        priority_level=priority_level,
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
            models.Asset.model.ilike(pattern),
            models.Asset.serial_number.ilike(pattern),
            models.Asset.ip_address.ilike(pattern),
            models.Asset.site.ilike(pattern),
            models.Asset.building.ilike(pattern),
            models.Asset.rack.ilike(pattern),
            models.Asset.owner_name.ilike(pattern),
        ))
    if asset_type:
        query = query.where(models.Asset.asset_type == asset_type)
    return [_asset_read(db, asset) for asset in db.scalars(query).all()]


@router.post("/import-csv", response_model=schemas.AssetCsvImportResult)
async def import_assets_csv(file: UploadFile = File(), db: Session = Depends(get_db)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=422, detail="CSV 파일만 업로드할 수 있습니다")
    try:
        content = (await file.read()).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="CSV 파일은 UTF-8 인코딩이어야 합니다") from exc
    reader = csv.DictReader(io.StringIO(content))
    required = {"asset_tag", "name", "asset_type"}
    if not reader.fieldnames or not required.issubset({name.strip() for name in reader.fieldnames if name}):
        raise HTTPException(status_code=422, detail="필수 열은 asset_tag, name, asset_type입니다")

    errors: list[schemas.CsvRowError] = []
    created = 0
    total = 0
    for row_number, row in enumerate(reader, start=2):
        if not any((value or "").strip() for value in row.values()):
            continue
        total += 1
        try:
            payload = schemas.AssetCreate.model_validate(_csv_payload(row))
            if payload.site_id and not db.get(models.Site, payload.site_id):
                raise ValueError("사이트가 없습니다")
            if payload.model_release_id and not db.get(models.ProductRelease, payload.model_release_id):
                raise ValueError("장비 모델 릴리스가 없습니다")
            values = payload.model_dump()
            if values.get("lifecycle_source_url"):
                values["lifecycle_source_url"] = str(values["lifecycle_source_url"])
            db.add(models.Asset(**values))
            db.commit()
            created += 1
        except (ValidationError, ValueError, IntegrityError) as exc:
            db.rollback()
            if isinstance(exc, ValidationError):
                message = "; ".join(error["msg"] for error in exc.errors())
            elif isinstance(exc, IntegrityError):
                message = "이미 사용 중인 자산번호이거나 참조 값이 올바르지 않습니다"
            else:
                message = str(exc)
            errors.append(schemas.CsvRowError(row=row_number, asset_tag=row.get("asset_tag") or None, message=message))
    return schemas.AssetCsvImportResult(total_rows=total, created=created, failed=len(errors), errors=errors)


@router.post("", response_model=schemas.AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: schemas.AssetCreate, db: Session = Depends(get_db)):
    values = payload.model_dump()
    if payload.site_id and not db.get(models.Site, payload.site_id):
        raise HTTPException(status_code=404, detail="사이트가 없습니다")
    if payload.model_release_id and not db.get(models.ProductRelease, payload.model_release_id):
        raise HTTPException(status_code=404, detail="장비 모델 릴리스가 없습니다")
    if values.get("lifecycle_source_url"):
        values["lifecycle_source_url"] = str(values["lifecycle_source_url"])
    asset = models.Asset(**values)
    db.add(asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 자산번호입니다")
    db.refresh(asset)
    return _asset_read(db, asset)


@router.get("/deadline-alerts")
def list_asset_deadline_alerts_static(days: int = Query(default=90, ge=1, le=3650), db: Session = Depends(get_db)):
    today = datetime.now(timezone.utc).date()
    alerts: list[dict[str, Any]] = []
    for asset in db.scalars(select(models.Asset).order_by(models.Asset.asset_tag)).all():
        for kind, value in (("EOL", asset.support_end_date), ("WARRANTY", asset.warranty_end_date)):
            if value is None:
                continue
            remaining = (value - today).days
            if remaining <= days:
                alerts.append({"asset_id": asset.id, "asset_tag": asset.asset_tag, "asset_name": asset.name, "kind": kind, "date": value, "days_left": remaining})
        contracts = db.scalars(select(models.Contract).join(models.ContractAsset, models.ContractAsset.contract_id == models.Contract.id).where(models.ContractAsset.asset_id == asset.id)).all()
        for contract in contracts:
            remaining = (contract.end_date - today).days
            if remaining <= days:
                alerts.append({"asset_id": asset.id, "asset_tag": asset.asset_tag, "asset_name": asset.name, "kind": "CONTRACT", "date": contract.end_date, "days_left": remaining, "reference": contract.contract_no})
        due_rows = db.execute(
            select(models.ComponentVulnerability, models.Vulnerability)
            .join(models.Component, models.Component.id == models.ComponentVulnerability.component_id)
            .join(models.SbomDocument, models.SbomDocument.id == models.Component.sbom_id)
            .join(models.Vulnerability, models.Vulnerability.id == models.ComponentVulnerability.vulnerability_id)
            .where(models.SbomDocument.asset_id == asset.id, models.ComponentVulnerability.due_date.is_not(None), models.ComponentVulnerability.vex_status.in_(("AFFECTED", "UNDER_INVESTIGATION")))
        ).all()
        for finding, vulnerability in due_rows:
            remaining = (finding.due_date - today).days
            if remaining <= days:
                cve = next((alias for alias in vulnerability.aliases if str(alias).startswith("CVE-")), vulnerability.osv_id)
                alerts.append({"asset_id": asset.id, "asset_tag": asset.asset_tag, "asset_name": asset.name, "kind": "CVE", "date": finding.due_date, "days_left": remaining, "reference": cve})
    return sorted(alerts, key=lambda item: (item["days_left"], item["asset_tag"]))


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


@router.post("/{asset_id}/risk-snapshots")
def create_risk_snapshot(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    current = _asset_read(db, asset)
    factors = {
        "vulnerability_counts": current.vulnerability_counts,
        "lifecycle_days_left": current.days_left,
        "service_criticality": asset.service_criticality,
        "operational_status": asset.operational_status,
    }
    snapshot = models.AssetRiskSnapshot(asset_id=asset_id, score=current.risk_score, priority_level=current.priority_level, factors=factors)
    db.add(snapshot); db.commit(); db.refresh(snapshot)
    return {"id": snapshot.id, "asset_id": asset_id, "score": snapshot.score, "priority_level": snapshot.priority_level, "factors": snapshot.factors, "calculated_at": snapshot.calculated_at}


@router.get("/{asset_id}/risk-snapshots")
def list_risk_snapshots(asset_id: int, db: Session = Depends(get_db)):
    if not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    return [{"id": item.id, "asset_id": item.asset_id, "score": item.score, "priority_level": item.priority_level, "factors": item.factors, "calculated_at": item.calculated_at} for item in db.scalars(select(models.AssetRiskSnapshot).where(models.AssetRiskSnapshot.asset_id == asset_id).order_by(models.AssetRiskSnapshot.calculated_at.desc()).limit(50)).all()]


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
    if values.get("site_id") and not db.get(models.Site, values["site_id"]):
        raise HTTPException(status_code=404, detail="사이트가 없습니다")
    if values.get("model_release_id") and not db.get(models.ProductRelease, values["model_release_id"]):
        raise HTTPException(status_code=404, detail="장비 모델 릴리스가 없습니다")
    if "site_id" in changed_fields:
        contract_customers = set(db.scalars(select(models.Contract.customer_id).join(models.ContractAsset).where(models.ContractAsset.asset_id == asset_id)).all())
        target_site = db.get(models.Site, values["site_id"]) if values["site_id"] else None
        if contract_customers and (not target_site or contract_customers != {target_site.customer_id}):
            raise HTTPException(status_code=409, detail="연결된 계약의 고객사와 같은 고객사의 사이트를 선택하세요. 계약 자산 연결을 먼저 수정할 수 있습니다")
    if values.get("lifecycle_source_url"):
        values["lifecycle_source_url"] = str(values["lifecycle_source_url"])
    if values.get("support_end_date", asset.support_end_date) and not values.get("lifecycle_source_url", asset.lifecycle_source_url):
        raise HTTPException(status_code=422, detail="지원종료일에는 근거 URL이 필요합니다")
    for key, value in values.items():
        setattr(asset, key, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 자산번호이거나 연결 정보가 올바르지 않습니다")
    db.refresh(asset)
    return _asset_read(db, asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.scalar(select(models.Asset).where(models.Asset.id == asset_id).with_for_update())
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    for model in (models.AnalysisJob, models.CollectionJob, models.SbomDocument, models.Deployment, models.ContractAsset):
        if db.scalar(select(model.asset_id).where(model.asset_id == asset_id).limit(1)) is not None:
            raise HTTPException(status_code=409, detail="분석·점검·SBOM 이력 또는 설치·계약 연결이 있는 자산은 삭제할 수 없습니다. 이력을 보존하려면 모니터링을 해제하세요")
    db.delete(asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="자산에 연결된 이력이 있어 삭제할 수 없습니다")
