from __future__ import annotations

import csv
import io
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
    "ip_address",
    "ssh_username",
    "introduced_on",
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
    values["monitored"] = str(values.get("monitored", "false")).lower() in {"1", "true", "yes", "y", "예"}
    return values


def _asset_read(db: Session, asset: models.Asset) -> schemas.AssetRead:
    model_end_date = None
    if asset.model_release:
        model_end_date = asset.model_release.security_end_date or asset.model_release.support_end_date or asset.model_release.eol_date
    risk_level, days_left = lifecycle_risk(model_end_date or asset.support_end_date)
    software_count = db.scalar(select(func.count(models.Deployment.id)).where(models.Deployment.asset_id == asset.id)) or 0
    sbom_count = db.scalar(select(func.count(models.SbomDocument.id)).where(models.SbomDocument.asset_id == asset.id)) or 0
    values = {column.name: getattr(asset, column.name) for column in models.Asset.__table__.columns}
    return schemas.AssetRead(
        **values,
        risk_level=risk_level,
        days_left=days_left,
        software_count=software_count,
        sbom_count=sbom_count,
    )


@router.get("", response_model=list[schemas.AssetRead])
def list_assets(
    q: Optional[str] = Query(default=None, max_length=100),
    asset_type: Optional[schemas.AssetType] = None,
    db: Session = Depends(get_db),
):
    query = select(models.Asset).order_by(models.Asset.asset_tag)
    if q:
        query = query.where(or_(models.Asset.asset_tag.ilike(f"%{q}%"), models.Asset.name.ilike(f"%{q}%")))
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


@router.get("/{asset_id}", response_model=schemas.AssetRead)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    return _asset_read(db, asset)


@router.patch("/{asset_id}", response_model=schemas.AssetRead)
def update_asset(asset_id: int, payload: schemas.AssetUpdate, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    values = payload.model_dump(exclude_unset=True)
    if values.get("site_id") and not db.get(models.Site, values["site_id"]):
        raise HTTPException(status_code=404, detail="사이트가 없습니다")
    if values.get("model_release_id") and not db.get(models.ProductRelease, values["model_release_id"]):
        raise HTTPException(status_code=404, detail="장비 모델 릴리스가 없습니다")
    if values.get("lifecycle_source_url"):
        values["lifecycle_source_url"] = str(values["lifecycle_source_url"])
    for key, value in values.items():
        setattr(asset, key, value)
    if asset.support_end_date and not asset.lifecycle_source_url:
        raise HTTPException(status_code=422, detail="지원종료일에는 근거 URL이 필요합니다")
    db.commit()
    db.refresh(asset)
    return _asset_read(db, asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    db.delete(asset)
    db.commit()
