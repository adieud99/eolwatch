from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db


router = APIRouter(tags=["organization"])


@router.get("/customers", response_model=list[schemas.CustomerRead])
def list_customers(db: Session = Depends(get_db)):
    result = []
    for customer in db.scalars(select(models.Customer).order_by(models.Customer.name)).all():
        site_count = db.scalar(select(func.count(models.Site.id)).where(models.Site.customer_id == customer.id)) or 0
        asset_count = db.scalar(
            select(func.count(models.Asset.id)).join(models.Site, models.Asset.site_id == models.Site.id).where(models.Site.customer_id == customer.id)
        ) or 0
        result.append(
            schemas.CustomerRead(
                id=customer.id,
                customer_code=customer.customer_code,
                name=customer.name,
                status=customer.status,
                site_count=site_count,
                asset_count=asset_count,
                created_at=customer.created_at,
            )
        )
    return result


@router.post("/customers", response_model=schemas.CustomerRead, status_code=status.HTTP_201_CREATED)
def create_customer(payload: schemas.CustomerCreate, db: Session = Depends(get_db)):
    item = models.Customer(**payload.model_dump())
    db.add(item)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 고객사 코드입니다")
    db.refresh(item)
    return schemas.CustomerRead(**payload.model_dump(), id=item.id, status=item.status, created_at=item.created_at)


@router.get("/sites", response_model=list[schemas.SiteRead])
def list_sites(customer_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = select(models.Site, models.Customer.name).join(models.Customer).order_by(models.Customer.name, models.Site.name)
    if customer_id:
        query = query.where(models.Site.customer_id == customer_id)
    result = []
    for site, customer_name in db.execute(query).all():
        count = db.scalar(select(func.count(models.Asset.id)).where(models.Asset.site_id == site.id)) or 0
        result.append(
            schemas.SiteRead(
                id=site.id,
                customer_id=site.customer_id,
                site_code=site.site_code,
                name=site.name,
                address=site.address,
                timezone=site.timezone,
                customer_name=customer_name,
                asset_count=count,
            )
        )
    return result


@router.post("/sites", response_model=schemas.SiteRead, status_code=status.HTTP_201_CREATED)
def create_site(payload: schemas.SiteCreate, db: Session = Depends(get_db)):
    customer = db.get(models.Customer, payload.customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="고객사가 없습니다")
    item = models.Site(**payload.model_dump())
    db.add(item)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="고객사 안에서 이미 사용 중인 사이트 코드입니다")
    db.refresh(item)
    count = db.scalar(select(func.count(models.Asset.id)).where(models.Asset.site_id == item.id)) or 0
    return schemas.SiteRead(**payload.model_dump(), id=item.id, customer_name=customer.name, asset_count=count)
