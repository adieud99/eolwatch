from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk
from ..services.sbom import import_cyclonedx


router = APIRouter(prefix="/sboms", tags=["sboms"])


def _component_identity(item: models.Component) -> str:
    if item.purl:
        package = item.purl.split("?", 1)[0].split("#", 1)[0]
        return package.rsplit("@", 1)[0].lower()
    if item.cpe:
        return item.cpe.lower()
    return f"{item.supplier or ''}:{item.group_name or ''}:{item.name}".lower()


def _diff_item(identity: str, before: Optional[models.Component], after: Optional[models.Component]) -> schemas.SbomDiffItem:
    item = after or before
    return schemas.SbomDiffItem(
        identity=identity,
        name=item.name,
        before_version=before.version if before else None,
        after_version=after.version if after else None,
        purl=item.purl,
    )


@router.get("", response_model=list[schemas.SbomRead])
def list_sboms(db: Session = Depends(get_db)):
    return db.scalars(select(models.SbomDocument).order_by(models.SbomDocument.imported_at.desc())).all()


@router.post("/import", response_model=schemas.SbomRead, status_code=status.HTTP_201_CREATED)
def import_sbom(
    document: dict[str, Any] = Body(),
    asset_id: Optional[int] = Query(default=None),
    software_product_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
):
    try:
        return import_cyclonedx(db, document, asset_id, software_product_id)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="같은 일련번호와 버전의 SBOM이 이미 있습니다")


@router.get("/{base_sbom_id}/compare/{target_sbom_id}", response_model=schemas.SbomDiffRead)
def compare_sboms(base_sbom_id: int, target_sbom_id: int, db: Session = Depends(get_db)):
    if not db.get(models.SbomDocument, base_sbom_id) or not db.get(models.SbomDocument, target_sbom_id):
        raise HTTPException(status_code=404, detail="비교할 SBOM이 없습니다")
    base_items = {
        _component_identity(item): item
        for item in db.scalars(select(models.Component).where(models.Component.sbom_id == base_sbom_id)).all()
    }
    target_items = {
        _component_identity(item): item
        for item in db.scalars(select(models.Component).where(models.Component.sbom_id == target_sbom_id)).all()
    }
    added = [_diff_item(key, None, target_items[key]) for key in sorted(target_items.keys() - base_items.keys())]
    removed = [_diff_item(key, base_items[key], None) for key in sorted(base_items.keys() - target_items.keys())]
    changed = []
    unchanged = 0
    for key in sorted(base_items.keys() & target_items.keys()):
        before, after = base_items[key], target_items[key]
        before_signature = (before.version, before.supplier, before.licenses, before.hashes)
        after_signature = (after.version, after.supplier, after.licenses, after.hashes)
        if before_signature != after_signature:
            changed.append(_diff_item(key, before, after))
        else:
            unchanged += 1
    return schemas.SbomDiffRead(
        base_sbom_id=base_sbom_id,
        target_sbom_id=target_sbom_id,
        added=added,
        removed=removed,
        changed=changed,
        unchanged_count=unchanged,
    )


@router.get("/{sbom_id}/components", response_model=list[schemas.ComponentRead])
def list_components(sbom_id: int, q: Optional[str] = None, db: Session = Depends(get_db)):
    if not db.get(models.SbomDocument, sbom_id):
        raise HTTPException(status_code=404, detail="SBOM이 없습니다")
    query = select(models.Component).where(models.Component.sbom_id == sbom_id).order_by(models.Component.name)
    if q:
        query = query.where(models.Component.name.ilike(f"%{q}%"))
    result = []
    for item in db.scalars(query).all():
        risk_level, days_left = lifecycle_risk(item.support_end_date)
        result.append(
            schemas.ComponentRead(
                id=item.id,
                bom_ref=item.bom_ref,
                component_type=item.component_type,
                group_name=item.group_name,
                name=item.name,
                version=item.version,
                supplier=item.supplier,
                purl=item.purl,
                cpe=item.cpe,
                licenses=item.licenses,
                support_end_date=item.support_end_date,
                risk_level=risk_level,
                days_left=days_left,
            )
        )
    return result


@router.patch("/components/{component_id}/lifecycle", response_model=schemas.ComponentRead)
def update_component_lifecycle(component_id: int, payload: schemas.ComponentLifecycleUpdate, db: Session = Depends(get_db)):
    item = db.get(models.Component, component_id)
    if not item:
        raise HTTPException(status_code=404, detail="구성요소가 없습니다")
    item.support_end_date = payload.support_end_date
    item.lifecycle_source_url = str(payload.lifecycle_source_url)
    if item.product_release:
        item.product_release.support_end_date = payload.support_end_date
        item.product_release.lifecycle_source_url = str(payload.lifecycle_source_url)
    db.commit()
    db.refresh(item)
    risk_level, days_left = lifecycle_risk(item.support_end_date)
    return schemas.ComponentRead(
        id=item.id,
        bom_ref=item.bom_ref,
        component_type=item.component_type,
        group_name=item.group_name,
        name=item.name,
        version=item.version,
        supplier=item.supplier,
        purl=item.purl,
        cpe=item.cpe,
        licenses=item.licenses,
        support_end_date=item.support_end_date,
        risk_level=risk_level,
        days_left=days_left,
    )
