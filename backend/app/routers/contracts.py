from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk


router = APIRouter(prefix="/contracts", tags=["maintenance contracts"])


def _read(item: models.Contract) -> schemas.ContractRead:
    risk, days = lifecycle_risk(item.end_date)
    return schemas.ContractRead(
        id=item.id,
        customer_id=item.customer_id,
        customer_name=item.customer.name,
        contract_no=item.contract_no,
        provider=item.provider,
        start_date=item.start_date,
        end_date=item.end_date,
        annual_cost=float(item.annual_cost) if item.annual_cost is not None else None,
        service_level=item.service_level,
        asset_ids=[link.asset_id for link in item.assets],
        risk_level=risk,
        days_left=days,
    )


@router.get("", response_model=list[schemas.ContractRead])
def list_contracts(db: Session = Depends(get_db)):
    query = (
        select(models.Contract)
        .options(selectinload(models.Contract.assets), selectinload(models.Contract.customer))
        .order_by(models.Contract.end_date)
    )
    return [_read(item) for item in db.scalars(query).all()]


@router.post("", response_model=schemas.ContractRead, status_code=status.HTTP_201_CREATED)
def create_contract(payload: schemas.ContractCreate, db: Session = Depends(get_db)):
    if payload.end_date < payload.start_date:
        raise HTTPException(status_code=422, detail="계약 종료일은 시작일보다 빠를 수 없습니다")
    if not db.get(models.Customer, payload.customer_id):
        raise HTTPException(status_code=404, detail="고객사가 없습니다")
    assets = db.scalars(select(models.Asset).where(models.Asset.id.in_(payload.asset_ids))).all() if payload.asset_ids else []
    if len(assets) != len(set(payload.asset_ids)):
        raise HTTPException(status_code=404, detail="계약에 연결할 자산 중 일부가 없습니다")
    item = models.Contract(**payload.model_dump(exclude={"asset_ids"}))
    db.add(item)
    try:
        db.flush()
        for asset_id in set(payload.asset_ids):
            db.add(models.ContractAsset(contract_id=item.id, asset_id=asset_id))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 계약번호입니다")
    query = (
        select(models.Contract)
        .where(models.Contract.id == item.id)
        .options(selectinload(models.Contract.assets), selectinload(models.Contract.customer))
    )
    return _read(db.scalar(query))
