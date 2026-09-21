from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk


router = APIRouter(prefix="/software", tags=["software"])


def _read(item: models.SoftwareProduct) -> schemas.SoftwareRead:
    end_date = item.security_end_date or item.support_end_date or item.eol_date
    risk_level, days_left = lifecycle_risk(end_date)
    return schemas.SoftwareRead(
        id=item.id,
        product_type=item.product_type,
        name=item.name,
        vendor=item.vendor,
        version=item.version,
        purl=item.purl,
        cpe=item.cpe,
        support_end_date=end_date,
        lifecycle_source_url=item.lifecycle_source_url,
        risk_level=risk_level,
        days_left=days_left,
        asset_ids=[deployment.asset_id for deployment in item.deployments],
    )


@router.get("", response_model=list[schemas.SoftwareRead])
def list_software(db: Session = Depends(get_db)):
    query = (
        select(models.SoftwareProduct)
        .where(models.SoftwareProduct.product_type != "HARDWARE_MODEL")
        .options(selectinload(models.SoftwareProduct.deployments))
        .order_by(models.SoftwareProduct.name)
    )
    return [_read(item) for item in db.scalars(query).all()]


@router.post("", response_model=schemas.SoftwareRead, status_code=status.HTTP_201_CREATED)
def create_software(payload: schemas.SoftwareCreate, db: Session = Depends(get_db)):
    if payload.support_end_date and not payload.lifecycle_source_url:
        raise HTTPException(status_code=422, detail="지원종료일에는 근거 URL이 필요합니다")
    if payload.asset_id and not db.get(models.Asset, payload.asset_id):
        raise HTTPException(status_code=404, detail="연결할 자산이 없습니다")
    values = payload.model_dump(exclude={"asset_id", "environment"})
    if values.get("lifecycle_source_url"):
        values["lifecycle_source_url"] = str(values["lifecycle_source_url"])
    item = models.SoftwareProduct(**values)
    db.add(item)
    try:
        db.flush()
        if payload.asset_id:
            db.add(models.Deployment(asset_id=payload.asset_id, software_product_id=item.id, environment=payload.environment))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="같은 공급사·이름·버전의 소프트웨어가 이미 있습니다")
    query = select(models.SoftwareProduct).options(selectinload(models.SoftwareProduct.deployments)).where(models.SoftwareProduct.id == item.id)
    return _read(db.scalar(query))


@router.post("/{software_id}/deployments/{asset_id}", status_code=status.HTTP_201_CREATED)
def connect_to_asset(software_id: int, asset_id: int, environment: str = "production", db: Session = Depends(get_db)):
    if not db.get(models.SoftwareProduct, software_id):
        raise HTTPException(status_code=404, detail="소프트웨어가 없습니다")
    if not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="자산이 없습니다")
    db.add(models.Deployment(asset_id=asset_id, software_product_id=software_id, environment=environment))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 연결되어 있습니다")
    return {"software_product_id": software_id, "asset_id": asset_id, "environment": environment}
