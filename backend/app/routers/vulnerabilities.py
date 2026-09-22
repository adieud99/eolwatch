from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models, schemas
from ..db import get_db
from ..services.vulnerability_actions import action_history, read_link, record_action
from .auth import current_user


router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities and VEX"])


def _read(link: models.ComponentVulnerability) -> schemas.VulnerabilityRead:
    component = link.component
    vulnerability = link.vulnerability
    asset = component.sbom.asset if component.sbom else None
    return schemas.VulnerabilityRead(
        link_id=link.id,
        component_id=component.id,
        component_name=component.name,
        component_version=component.version,
        sbom_id=component.sbom_id,
        asset_tag=asset.asset_tag if asset else None,
        asset_name=asset.name if asset else None,
        cve_id=vulnerability.osv_id,
        summary=vulnerability.summary,
        severity=link.finding_severity or vulnerability.severity,
        aliases=vulnerability.aliases,
        fixed_version=link.fixed_version,
        fixed_versions=link.fixed_versions or [],
        fix_check=link.fix_check,
        finding_source=link.finding_source or "OSV",
        analysis_run_id=link.analysis_run_id,
        vex_status=link.vex_status,
        justification=link.justification,
        response=link.response,
        detail=link.detail,
        review_revision=link.review_revision,
        modified_at=vulnerability.modified_at,
    )


@router.get("", response_model=list[schemas.VulnerabilityRead])
def list_vulnerabilities(sbom_id: Optional[int] = None, vex_status: Optional[str] = None, db: Session = Depends(get_db)):
    query = (
        select(models.ComponentVulnerability)
        .join(models.Component)
        .options(
            joinedload(models.ComponentVulnerability.component),
            joinedload(models.ComponentVulnerability.component)
            .joinedload(models.Component.sbom)
            .defer(models.SbomDocument.raw_document)
            .joinedload(models.SbomDocument.asset),
            joinedload(models.ComponentVulnerability.vulnerability),
        )
        .order_by(models.ComponentVulnerability.updated_at.desc())
    )
    if sbom_id:
        query = query.where(models.Component.sbom_id == sbom_id)
    if vex_status:
        query = query.where(models.ComponentVulnerability.vex_status == vex_status)
    return [_read(item) for item in db.scalars(query).unique().all()]


@router.patch("/{link_id}/vex", response_model=schemas.VulnerabilityRead)
def update_vex(link_id: int, payload: schemas.VexUpdate, request: Request,
               user: models.User = Depends(current_user), db: Session = Depends(get_db)):
    return _read(record_action(db, link_id, user, payload.model_dump(exclude_unset=True), legacy=True,
                              request_method="PATCH", request_path=request.url.path,
                              request_ip=request.client.host if request.client else None))


@router.post("/{link_id}/actions", response_model=schemas.VulnerabilityRead)
def create_action(link_id: int, payload: schemas.VulnerabilityActionCreate, request: Request,
                  user: models.User = Depends(current_user), db: Session = Depends(get_db)):
    return _read(record_action(db, link_id, user, payload.model_dump(exclude_unset=True),
                              request_path=request.url.path,
                              request_ip=request.client.host if request.client else None))


@router.get("/{link_id}", response_model=schemas.VulnerabilityRead)
def get_vulnerability(link_id: int, user: models.User = Depends(current_user), db: Session = Depends(get_db)):
    return _read(read_link(db, link_id))


@router.get("/{link_id}/actions", response_model=schemas.VulnerabilityActionPage)
def list_actions(link_id: int, limit: int = Query(default=100, ge=1, le=100),
                 before_id: Optional[int] = Query(default=None, ge=1),
                 user: models.User = Depends(current_user), db: Session = Depends(get_db)):
    return action_history(db, link_id, limit, before_id)
