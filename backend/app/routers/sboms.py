from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased, defer, joinedload
from fastapi.responses import JSONResponse

from .. import models, schemas
from ..db import get_db
from ..services.risk import lifecycle_risk
from ..services.sbom import import_sbom as import_sbom_document
from ..services.component_lifecycle import effective_component_lifecycle


router = APIRouter(prefix="/sboms", tags=["sboms"])


def _document(db, sbom_id):
    document = db.scalar(select(models.SbomDocument).options(
        defer(models.SbomDocument.raw_document), joinedload(models.SbomDocument.asset)
    ).where(models.SbomDocument.id == sbom_id))
    if document is None:
        raise HTTPException(status_code=404, detail="SBOM이 없습니다")
    return document


def _read_component(item):
    end_date, source_url, origin = effective_component_lifecycle(item)
    risk, days = lifecycle_risk(end_date)
    return schemas.ComponentRead(
        id=item.id, bom_ref=item.bom_ref, component_type=item.component_type,
        group_name=item.group_name, name=item.name, version=item.version,
        supplier=item.supplier, purl=item.purl, cpe=item.cpe, licenses=item.licenses,
        support_end_date=end_date, lifecycle_source_url=source_url,
        risk_level=risk, days_left=days, product_release_id=item.product_release_id,
        hashes=item.hashes or [], lifecycle_origin=origin,
        override_support_end_date=item.support_end_date,
    )


@router.get("/{sbom_id}/detail")
def sbom_detail(sbom_id: int, db: Session = Depends(get_db)):
    document = _document(db, sbom_id)
    result = schemas.SbomRead.model_validate(document).model_dump(mode="json")
    result["asset"] = {"id": document.asset.id, "asset_tag": document.asset.asset_tag,
                       "name": document.asset.name} if document.asset else None
    result["analysis_ids"] = list(db.scalars(select(models.AnalysisRun.id).where(
        models.AnalysisRun.sbom_id == sbom_id).order_by(models.AnalysisRun.id.desc())))
    return result


@router.get("/{sbom_id}/raw")
def raw_sbom(sbom_id: int, db: Session = Depends(get_db)):
    document = _document(db, sbom_id)
    return JSONResponse(document.raw_document, headers={
        "Content-Disposition": f'attachment; filename="eolwatch-sbom-{sbom_id}.json"',
        "Cache-Control": "no-store",
    })


@router.get("/{sbom_id}/component-page")
def component_page(sbom_id: int, q: str = Query(default="", max_length=200),
                   limit: int = Query(default=50, ge=1, le=200),
                   offset: int = Query(default=0, ge=0), db: Session = Depends(get_db)):
    _document(db, sbom_id)
    filters = [models.Component.sbom_id == sbom_id]
    if q.strip():
        value = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        filters.append(or_(*[column.ilike(value, escape="\\") for column in (
            models.Component.name, models.Component.version, models.Component.purl,
            models.Component.cpe, models.Component.supplier,
        )]))
    total = db.scalar(select(func.count(models.Component.id)).where(*filters))
    items = db.scalars(select(models.Component).options(joinedload(models.Component.product_release))
                       .where(*filters).order_by(models.Component.name, models.Component.id).limit(limit).offset(offset)).all()
    return {"items": [_read_component(item) for item in items], "total": total, "limit": limit, "offset": offset}


@router.get("/{sbom_id}/dependencies")
def dependency_page(sbom_id: int, component_id: Optional[int] = None,
                    direction: str = Query(default="both", pattern="^(both|outgoing|incoming)$"),
                    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
                    db: Session = Depends(get_db)):
    _document(db, sbom_id)
    edge = models.DependencyEdge
    filters = [edge.sbom_id == sbom_id]
    if component_id is not None:
        component = db.get(models.Component, component_id)
        if not component or component.sbom_id != sbom_id:
            raise HTTPException(status_code=404, detail="이 SBOM의 구성요소가 아닙니다")
        outgoing, incoming = edge.source_ref == component.bom_ref, edge.target_ref == component.bom_ref
        filters.append(outgoing if direction == "outgoing" else incoming if direction == "incoming" else or_(outgoing, incoming))
    total = db.scalar(select(func.count(edge.id)).where(*filters))
    source, target = aliased(models.Component), aliased(models.Component)
    rows = db.execute(select(edge, source, target).outerjoin(source, and_(source.sbom_id == edge.sbom_id, source.bom_ref == edge.source_ref))
                      .outerjoin(target, and_(target.sbom_id == edge.sbom_id, target.bom_ref == edge.target_ref))
                      .where(*filters).order_by(edge.id).limit(limit).offset(offset)).all()
    def endpoint(component, ref):
        return {"id": component.id if component else None, "ref": ref,
                "name": component.name if component else ref, "version": component.version if component else None,
                "purl": component.purl if component else None}
    return {"items": [{"id": row.id, "source": endpoint(before, row.source_ref), "target": endpoint(after, row.target_ref)}
                      for row, before, after in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/{sbom_id}/components/{component_id}", response_model=schemas.ComponentRead)
def get_component(sbom_id: int, component_id: int, db: Session = Depends(get_db)):
    item = db.scalar(select(models.Component).options(joinedload(models.Component.product_release)).where(
        models.Component.id == component_id, models.Component.sbom_id == sbom_id))
    if not item:
        raise HTTPException(status_code=404, detail="이 SBOM의 구성요소가 아닙니다")
    return _read_component(item)


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
    return db.scalars(select(models.SbomDocument).options(defer(models.SbomDocument.raw_document)).order_by(models.SbomDocument.imported_at.desc())).all()


@router.post("/import", response_model=schemas.SbomRead, status_code=status.HTTP_201_CREATED)
def import_sbom(
    document: dict[str, Any] = Body(),
    asset_id: Optional[int] = Query(default=None),
    software_product_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
):
    try:
        return import_sbom_document(db, document, asset_id, software_product_id)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="같은 일련번호와 버전의 SBOM이 이미 있습니다")


@router.get("/{base_sbom_id}/compare/{target_sbom_id}", response_model=schemas.SbomDiffRead)
def compare_sboms(base_sbom_id: int, target_sbom_id: int, db: Session = Depends(get_db)):
    from collections import defaultdict, deque
    import json
    from packageurl import PackageURL
    from packaging.utils import canonicalize_name

    # Comparison uses normalized component records; do not load large raw SBOMs.
    for document_id in {base_sbom_id, target_sbom_id}:
        if db.scalar(select(models.SbomDocument.id).where(models.SbomDocument.id == document_id)) is None:
            raise HTTPException(status_code=404, detail="비교할 SBOM이 없습니다")

    versions = {}

    def identity(item):
        versions[item.id] = item.version
        if item.purl:
            try:
                package = PackageURL.from_string(item.purl)
                versions[item.id] = item.version or package.version
                # Preserve namespace, qualifiers and subpath; '@' can be an npm
                # scope, and Maven/Go identifiers can be case-sensitive.
                name = canonicalize_name(package.name) if package.type == "pypi" else package.name
                return PackageURL(type=package.type, namespace=package.namespace, name=name,
                                  qualifiers=package.qualifiers, subpath=package.subpath).to_string()
            except (ValueError, TypeError):
                return "invalid-purl:" + item.purl
        return _component_identity(item)

    def grouped(document_id):
        result = defaultdict(list)
        for item in db.scalars(select(models.Component).where(models.Component.sbom_id == document_id)
                               .order_by(models.Component.id)).all():
            result[identity(item)].append(item)
        return result

    def signature(item):
        return (versions[item.id], item.supplier,
                json.dumps(item.licenses, sort_keys=True, ensure_ascii=False),
                json.dumps(item.hashes, sort_keys=True, ensure_ascii=False))

    def diff_item(key, before, after):
        result = _diff_item(key, before, after)
        result.before_version = versions[before.id] if before else None
        result.after_version = versions[after.id] if after else None
        return result

    base_items, target_items = grouped(base_sbom_id), grouped(target_sbom_id)
    added, removed, changed = [], [], []
    unchanged = 0
    for key in sorted(base_items.keys() | target_items.keys()):
        before, after = base_items.get(key, []), target_items.get(key, [])
        exact = defaultdict(deque)
        for item in before:
            exact[signature(item)].append(item)
        consumed = set()
        remaining_after = []
        # Match a multiset, not a dictionary: two copies of the same version
        # are two occurrences and must not overwrite one another.
        for item in after:
            candidates = exact[signature(item)]
            if candidates:
                consumed.add(candidates.popleft().id)
                unchanged += 1
            else:
                remaining_after.append(item)
        remaining_before = [item for item in before if item.id not in consumed]

        # A retained version with different supplier/license/hash is a metadata
        # change. Match exact versions before considering a version transition.
        before_by_version, after_by_version = defaultdict(deque), defaultdict(deque)
        for item in remaining_before:
            before_by_version[versions[item.id]].append(item)
        for item in remaining_after:
            after_by_version[versions[item.id]].append(item)
        for version in sorted(before_by_version.keys() & after_by_version.keys(), key=lambda value: (value is not None, value or "")):
            old, new = before_by_version[version], after_by_version[version]
            while old and new:
                changed.append(diff_item(key, old.popleft(), new.popleft()))
        remaining_before = [item for items in before_by_version.values() for item in items]
        remaining_after = [item for items in after_by_version.values() for item in items]

        # Preserve the existing single-version before/after API. If multiple
        # versions remain on either side, their correspondence is unknown: show
        # every removal/addition instead of inventing version-to-version pairs.
        if len({versions[item.id] for item in remaining_before}) == 1 and len({versions[item.id] for item in remaining_after}) == 1:
            paired = min(len(remaining_before), len(remaining_after))
            changed.extend(diff_item(key, old, new) for old, new in zip(remaining_before[:paired], remaining_after[:paired]))
            remaining_before = remaining_before[paired:]
            remaining_after = remaining_after[paired:]
        removed.extend(diff_item(key, item, None) for item in remaining_before)
        added.extend(diff_item(key, None, item) for item in remaining_after)
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
    _document(db, sbom_id)
    query = select(models.Component).options(joinedload(models.Component.product_release)).where(models.Component.sbom_id == sbom_id).order_by(models.Component.name, models.Component.id)
    if q:
        query = query.where(models.Component.name.ilike(f"%{q}%"))
    return [_read_component(item) for item in db.scalars(query).all()]


@router.patch("/components/{component_id}/lifecycle", response_model=schemas.ComponentRead)
def update_component_lifecycle(component_id: int, payload: schemas.ComponentLifecycleUpdate, db: Session = Depends(get_db)):
    item = db.get(models.Component, component_id)
    if not item:
        raise HTTPException(status_code=404, detail="구성요소가 없습니다")
    item.support_end_date = payload.support_end_date
    item.lifecycle_source_url = str(payload.lifecycle_source_url) if payload.support_end_date and payload.lifecycle_source_url else None
    db.commit()
    db.refresh(item)
    return _read_component(item)
