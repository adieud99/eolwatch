from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
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
def list_contracts(q: Optional[str] = Query(default=None, max_length=100), customer_id: Optional[int] = Query(default=None, ge=1),
                   limit: Optional[int] = Query(default=None, ge=1, le=200), offset: int = Query(default=0, ge=0),
                   db: Session = Depends(get_db)):
    query = (
        select(models.Contract)
        .options(selectinload(models.Contract.assets), selectinload(models.Contract.customer))
        .order_by(models.Contract.end_date, models.Contract.id)
    )
    if q:
        query = query.join(models.Contract.customer).where(or_(models.Contract.contract_no.ilike(f"%{q}%"), models.Contract.provider.ilike(f"%{q}%"), models.Customer.name.ilike(f"%{q}%")))
    if customer_id is not None:
        query = query.where(models.Contract.customer_id == customer_id)
    query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return [_read(item) for item in db.scalars(query).all()]


def _validate(db: Session, values: dict, asset_ids: list[int]):
    if values["end_date"] < values["start_date"]:
        raise HTTPException(status_code=422, detail="계약 종료일은 시작일보다 빠를 수 없습니다")
    if not db.get(models.Customer, values["customer_id"]):
        raise HTTPException(status_code=404, detail="고객사가 없습니다")
    assets = db.scalars(select(models.Asset).options(selectinload(models.Asset.site_record)).where(models.Asset.id.in_(asset_ids))).all() if asset_ids else []
    if len(assets) != len(set(asset_ids)):
        raise HTTPException(status_code=404, detail="계약에 연결할 자산 중 일부가 없습니다")
    if any(not asset.site_record or asset.site_record.customer_id != values["customer_id"] for asset in assets):
        raise HTTPException(status_code=422, detail="계약 자산은 선택한 고객사의 사이트에 연결되어 있어야 합니다")


def _get(db: Session, contract_id: int):
    item = db.scalar(select(models.Contract).where(models.Contract.id == contract_id).options(selectinload(models.Contract.assets), selectinload(models.Contract.customer)).execution_options(populate_existing=True))
    if not item:
        raise HTTPException(status_code=404, detail="계약이 없습니다")
    return item


@router.get("/{contract_id}", response_model=schemas.ContractRead)
def get_contract(contract_id: int, db: Session = Depends(get_db)):
    return _read(_get(db, contract_id))


@router.post("", response_model=schemas.ContractRead, status_code=status.HTTP_201_CREATED)
def create_contract(payload: schemas.ContractCreate, db: Session = Depends(get_db)):
    values = payload.model_dump(exclude={"asset_ids"})
    _validate(db, values, payload.asset_ids)
    item = models.Contract(**values)
    db.add(item)
    try:
        db.flush()
        for asset_id in set(payload.asset_ids):
            db.add(models.ContractAsset(contract_id=item.id, asset_id=asset_id))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 계약번호입니다")
    return _read(_get(db, item.id))


@router.patch("/{contract_id}", response_model=schemas.ContractRead)
def update_contract(contract_id: int, payload: schemas.ContractUpdate, db: Session = Depends(get_db)):
    item = _get(db, contract_id)
    changes = payload.model_dump(exclude_unset=True)
    asset_ids = changes.pop("asset_ids", [link.asset_id for link in item.assets])
    values = {key: changes.get(key, getattr(item, key)) for key in ("customer_id", "contract_no", "provider", "start_date", "end_date", "annual_cost", "service_level")}
    _validate(db, values, asset_ids)
    for key, value in changes.items():
        setattr(item, key, value)
    if "asset_ids" in payload.model_fields_set:
        by_id = {link.asset_id: link for link in item.assets}
        item.assets = [by_id.get(asset_id) or models.ContractAsset(asset_id=asset_id) for asset_id in sorted(set(asset_ids))]
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 계약번호이거나 자산 연결이 변경되었습니다")
    return _read(_get(db, item.id))
