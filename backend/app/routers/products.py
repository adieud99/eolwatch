from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk


router = APIRouter(prefix="/products", tags=["product lifecycle"])


def _read(db: Session, item: models.ProductRelease) -> schemas.ProductReleaseRead:
    end_date = item.security_end_date or item.support_end_date or item.eol_date
    risk, days = lifecycle_risk(end_date)
    return schemas.ProductReleaseRead(
        id=item.id,
        product_type=item.product_type,
        vendor=item.vendor,
        name=item.name,
        version=item.version,
        purl=item.purl,
        cpe=item.cpe,
        eol_date=item.eol_date,
        support_end_date=item.support_end_date,
        security_end_date=item.security_end_date,
        lifecycle_source_url=item.lifecycle_source_url,
        verified_at=item.verified_at,
        risk_level=risk,
        days_left=days,
        deployment_count=db.scalar(select(func.count(models.Deployment.id)).where(models.Deployment.software_product_id == item.id)) or 0,
        component_occurrence_count=db.scalar(select(func.count(models.Component.id)).where(models.Component.product_release_id == item.id)) or 0,
    )


@router.get("", response_model=list[schemas.ProductReleaseRead])
def list_products(q: Optional[str] = Query(default=None, max_length=100), product_type: Optional[schemas.ProductType] = None,
                  limit: Optional[int] = Query(default=None, ge=1, le=200), offset: int = Query(default=0, ge=0),
                  db: Session = Depends(get_db)):
    query = select(models.ProductRelease).order_by(models.ProductRelease.vendor, models.ProductRelease.name, models.ProductRelease.version, models.ProductRelease.id)
    if q:
        query = query.where(or_(*(column.ilike(f"%{q}%") for column in (models.ProductRelease.name, models.ProductRelease.vendor, models.ProductRelease.version, models.ProductRelease.purl, models.ProductRelease.cpe))))
    if product_type:
        query = query.where(models.ProductRelease.product_type == product_type)
    query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return [_read(db, item) for item in db.scalars(query).all()]


@router.get("/{product_id}", response_model=schemas.ProductReleaseRead)
def get_product(product_id: int, db: Session = Depends(get_db)):
    item = db.get(models.ProductRelease, product_id)
    if not item:
        raise HTTPException(status_code=404, detail="제품 릴리스가 없습니다")
    return _read(db, item)


@router.patch("/{product_id}", response_model=schemas.ProductReleaseRead)
def update_product(product_id: int, payload: schemas.ProductReleaseUpdate, db: Session = Depends(get_db)):
    item = db.get(models.ProductRelease, product_id)
    if not item:
        raise HTTPException(status_code=404, detail="제품 릴리스가 없습니다")
    values = payload.model_dump(exclude_unset=True)
    if values.get("lifecycle_source_url"):
        values["lifecycle_source_url"] = str(values["lifecycle_source_url"])
    dates = [values.get(key, getattr(item, key)) for key in ("eol_date", "support_end_date", "security_end_date")]
    if any(dates) and not values.get("lifecycle_source_url", item.lifecycle_source_url):
        raise HTTPException(status_code=422, detail="수명주기 날짜에는 공식 근거 URL이 필요합니다")
    lifecycle_changed = any(values[key] != getattr(item, key) for key in
                            set(values) & {"eol_date", "support_end_date", "security_end_date", "lifecycle_source_url"})
    for key, value in values.items():
        setattr(item, key, value)
    # Backward-compatible field: this is the manual edit time, not proof that
    # an external policy was fetched or independently verified.
    if lifecycle_changed:
        item.verified_at = datetime.now(timezone.utc) if any(dates) else None
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="동일한 제품 식별정보가 이미 사용 중입니다")
    db.refresh(item)
    return _read(db, item)


@router.get("/{product_id}/impact")
def product_impact(product_id: int, db: Session = Depends(get_db)):
    item = db.get(models.ProductRelease, product_id)
    if not item:
        raise HTTPException(status_code=404, detail="제품 릴리스가 없습니다")
    direct_asset_ids = set(db.scalars(select(models.Deployment.asset_id).where(models.Deployment.software_product_id == product_id)).all())
    sbom_asset_ids = set(
        db.scalars(
            select(models.SbomDocument.asset_id)
            .join(models.Component, models.Component.sbom_id == models.SbomDocument.id)
            .where(models.Component.product_release_id == product_id, models.SbomDocument.asset_id.is_not(None))
        ).all()
    )
    model_asset_ids = set(db.scalars(select(models.Asset.id).where(models.Asset.model_release_id == product_id)).all())
    asset_ids = direct_asset_ids | sbom_asset_ids | model_asset_ids
    assets = db.scalars(select(models.Asset).where(models.Asset.id.in_(asset_ids)).order_by(models.Asset.asset_tag)).all() if asset_ids else []
    return {
        "product": {"id": item.id, "name": item.name, "version": item.version, "purl": item.purl},
        "affected_assets": [{"id": asset.id, "asset_tag": asset.asset_tag, "name": asset.name, "ip_address": asset.ip_address} for asset in assets],
        "asset_count": len(assets),
    }
