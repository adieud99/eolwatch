from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk


router = APIRouter(prefix="/assets", tags=["assets"])


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
