"""Explicit local product → public support cycle preview and application."""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session, defer

from .. import models
from ..db import get_db
from ..services import lifecycle_catalog as service
from ..services.risk import lifecycle_risk
from .auth import current_user


router = APIRouter(prefix="/lifecycle-catalog", tags=["public lifecycle catalog"], dependencies=[Depends(current_user)])


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_slug: Optional[str] = Field(default=None, min_length=1, max_length=120, pattern=r"^[a-z0-9][a-z0-9-]*$")


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    product_id: int = Field(ge=1)
    product_slug: str = Field(min_length=1, max_length=120, pattern=r"^[a-z0-9][a-z0-9-]*$")
    release_cycle: str = Field(min_length=1, max_length=100)
    expected_product_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def admin(user=Depends(current_user)):
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다")
    return user


def product_read(item):
    risk, days = lifecycle_risk(item.security_end_date or item.support_end_date or item.eol_date)
    return {"id": item.id, "name": item.name, "version": item.version, "vendor": item.vendor,
            "purl": item.purl, "cpe": item.cpe, "product_type": item.product_type,
            **service.lifecycle_values(item), "manual_updated_at": item.verified_at,
            "risk_level": risk, "days_left": days}


def application_read(item):
    return {"id": item.id, "product_id": item.product_release_id, "applied_by_id": item.applied_by_id,
            **{key: getattr(item, key) for key in ("product_slug", "release_cycle", "source_url", "policy_url",
               "source_sha256", "provider_generated_at", "provider_last_modified", "fetched_at", "applied_at",
               "previous_values", "applied_values")}}


@router.get("/local-products")
def local_products(q: str = Query(default="", max_length=200), limit: int = Query(default=20, ge=1, le=100),
                   offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    filters = []
    if q.strip():
        filters.append(or_(*(field.icontains(q.strip(), autoescape=True) for field in
                            (models.ProductRelease.name, models.ProductRelease.vendor, models.ProductRelease.version,
                             models.ProductRelease.purl, models.ProductRelease.cpe))))
    total = db.scalar(select(func.count(models.ProductRelease.id)).where(*filters)) or 0
    rows = db.scalars(select(models.ProductRelease).where(*filters).order_by(models.ProductRelease.name, models.ProductRelease.id)
                      .offset(offset).limit(limit)).all()
    ids = [item.id for item in rows]
    latest_ids = select(func.max(models.LifecycleCatalogApplication.id)).where(
        models.LifecycleCatalogApplication.product_release_id.in_(ids)).group_by(models.LifecycleCatalogApplication.product_release_id)
    latest = {item.product_release_id: item for item in db.scalars(select(models.LifecycleCatalogApplication)
              .options(defer(models.LifecycleCatalogApplication.source_document)).where(models.LifecycleCatalogApplication.id.in_(latest_ids)))} if ids else {}
    return {"items": [{**product_read(item), "latest_application": application_read(latest[item.id]) if item.id in latest else None}
                       for item in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/products")
def public_products(q: str = Query(default="", max_length=100), limit: int = Query(default=50, ge=1, le=200),
                    offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    row = service.cached(db)
    products = service.payload(row) or []
    needle = q.strip().casefold()
    items = [item for item in products if not needle or needle in item["name"].casefold() or needle in item["label"].casefold()]
    return {"items": [{key: item.get(key) for key in ("name", "label", "category")} for item in items[offset:offset + limit]],
            "total": len(items), "limit": limit, "offset": offset, "cache": service.cache_read(row)}


@router.get("/products/{product_slug}")
def public_product(product_slug: str, db: Session = Depends(get_db)):
    if not service.SLUG.fullmatch(product_slug):
        raise HTTPException(status_code=422, detail="공개 제품 식별자가 올바르지 않습니다")
    row = service.cached(db, product_slug)
    data = service.payload(row)
    return {"product": {key: value for key, value in data.items() if key != "releases"} if data else None,
            "releases": data["releases"] if data else [], "cache": service.cache_read(row)}


@router.post("/refresh")
def refresh(payload: RefreshRequest, db: Session = Depends(get_db), _user=Depends(admin)):
    try:
        row = service.refresh(db, payload.product_slug)
    except service.CatalogError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if row.last_error:
        raise HTTPException(status_code=502, detail=row.last_error)
    return {"cache": service.cache_read(row)}


def read_proposal(db, product_id, slug, cycle, lock=False):
    # Lock ordering is cache → product for both refresh and application.
    row = service.cached(db, slug, lock=lock)
    query = select(models.ProductRelease).where(models.ProductRelease.id == product_id)
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    product = db.scalar(query)
    if product is None:
        raise HTTPException(status_code=404, detail="제품 릴리스가 없습니다")
    try:
        result = service.proposal(product, row, cycle)
    except service.CatalogError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    result["product"] = product_read(product)
    return product, row, result


@router.get("/preview/{product_id}")
def preview(product_id: int, product_slug: str = Query(min_length=1, max_length=120, pattern=r"^[a-z0-9][a-z0-9-]*$"),
            release_cycle: str = Query(min_length=1, max_length=100), db: Session = Depends(get_db)):
    return read_proposal(db, product_id, product_slug, release_cycle)[2]


@router.post("/apply")
def apply(payload: ApplyRequest, db: Session = Depends(get_db), user=Depends(admin)):
    product, row, proposed = read_proposal(db, payload.product_id, payload.product_slug, payload.release_cycle, lock=True)
    if (payload.expected_product_revision != proposed["expected_product_revision"]
            or payload.expected_catalog_sha256 != proposed["expected_catalog_sha256"]):
        db.rollback()
        raise HTTPException(status_code=409, detail="미리보기 이후 제품 또는 공개 일정이 변경됐습니다. 다시 비교하세요.")
    if not proposed["can_apply"]:
        raise HTTPException(status_code=422, detail=proposed["blocked_reason"])
    cache_claim = db.execute(update(models.LifecycleCatalogCache).where(
        models.LifecycleCatalogCache.id == row.id,
        models.LifecycleCatalogCache.content_sha256 == payload.expected_catalog_sha256,
        models.LifecycleCatalogCache.last_checked_at == row.last_checked_at,
        models.LifecycleCatalogCache.last_error.is_(None),
    ).values(last_checked_at=row.last_checked_at).execution_options(synchronize_session=False))
    if cache_claim.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="공개 자료가 동시에 변경됐습니다. 최신 자료로 다시 비교하세요.")
    before = proposed["before"]
    after = proposed["after"]
    # Portable compare-and-set also protects databases without row locks.
    checks = [models.ProductRelease.id == product.id]
    for key in (*service.LIFECYCLE_FIELDS, "product_type", "vendor", "name", "version", "purl", "cpe"):
        value = getattr(product, key)
        column = getattr(models.ProductRelease, key)
        checks.append(column.is_(None) if value is None else column == value)
    changed = db.execute(update(models.ProductRelease).where(*checks).values(
        security_end_date=date.fromisoformat(after["security_end_date"]), lifecycle_source_url=after["lifecycle_source_url"])
        .execution_options(synchronize_session=False))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="제품이 동시에 변경됐습니다. 최신 값으로 다시 비교하세요.")
    # Keep the exact original UTF-8 response and its SHA with each application.
    data = service.payload(row)
    links = data.get("links") if isinstance(data.get("links"), dict) else {}
    record = models.LifecycleCatalogApplication(
        product_release_id=product.id, applied_by_id=user.id, product_slug=payload.product_slug,
        release_cycle=payload.release_cycle, source_url=row.source_url,
        policy_url=service.valid_url(links.get("releasePolicy")), source_sha256=row.content_sha256,
        source_document=row.raw_document, provider_generated_at=row.provider_generated_at,
        provider_last_modified=row.provider_last_modified, fetched_at=row.fetched_at,
        applied_at=datetime.now(timezone.utc), previous_values=before, applied_values=after,
    )
    db.add(record)
    db.commit()
    db.refresh(product)
    db.refresh(record)
    return {"application": application_read(record), "product": product_read(product)}


@router.get("/applications")
def applications(product_id: int = Query(ge=1), limit: int = Query(default=10, ge=1, le=100),
                 offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    if db.get(models.ProductRelease, product_id) is None:
        raise HTTPException(status_code=404, detail="제품 릴리스가 없습니다")
    where = models.LifecycleCatalogApplication.product_release_id == product_id
    count = db.scalar(select(func.count(models.LifecycleCatalogApplication.id)).where(where)) or 0
    rows = db.scalars(select(models.LifecycleCatalogApplication).options(defer(models.LifecycleCatalogApplication.source_document))
                      .where(where).order_by(models.LifecycleCatalogApplication.id.desc()).limit(limit).offset(offset))
    return {"items": [application_read(item) for item in rows], "total": count, "limit": limit, "offset": offset}
