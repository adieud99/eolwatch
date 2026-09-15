from __future__ import annotations

import httpx
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .. import models, schemas
from ..db import get_db
from ..services.vulnerabilities import scan_sbom


router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities and VEX"])


def _read(link: models.ComponentVulnerability) -> schemas.VulnerabilityRead:
    component = link.component
    vulnerability = link.vulnerability
    return schemas.VulnerabilityRead(
        link_id=link.id,
        component_id=component.id,
        component_name=component.name,
        component_version=component.version,
        sbom_id=component.sbom_id,
        osv_id=vulnerability.osv_id,
        summary=vulnerability.summary,
        severity=vulnerability.severity,
        aliases=vulnerability.aliases,
        vex_status=link.vex_status,
        justification=link.justification,
        response=link.response,
        detail=link.detail,
        modified_at=vulnerability.modified_at,
    )


@router.get("", response_model=list[schemas.VulnerabilityRead])
def list_vulnerabilities(sbom_id: Optional[int] = None, vex_status: Optional[str] = None, db: Session = Depends(get_db)):
    query = (
        select(models.ComponentVulnerability)
        .join(models.Component)
        .options(
            joinedload(models.ComponentVulnerability.component),
            joinedload(models.ComponentVulnerability.vulnerability),
        )
        .order_by(models.ComponentVulnerability.updated_at.desc())
    )
    if sbom_id:
        query = query.where(models.Component.sbom_id == sbom_id)
    if vex_status:
        query = query.where(models.ComponentVulnerability.vex_status == vex_status)
    return [_read(item) for item in db.scalars(query).unique().all()]


@router.post("/scan/sbom/{sbom_id}", response_model=schemas.VulnerabilityScanResult)
def scan_sbom_vulnerabilities(sbom_id: int, db: Session = Depends(get_db)):
    if not db.get(models.SbomDocument, sbom_id):
        raise HTTPException(status_code=404, detail="SBOM이 없습니다")
    try:
        return scan_sbom(db, sbom_id)
    except (httpx.HTTPError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=f"OSV 조회에 실패했습니다: {exc}") from exc


@router.patch("/{link_id}/vex", response_model=schemas.VulnerabilityRead)
def update_vex(link_id: int, payload: schemas.VexUpdate, db: Session = Depends(get_db)):
    query = (
        select(models.ComponentVulnerability)
        .where(models.ComponentVulnerability.id == link_id)
        .options(
            joinedload(models.ComponentVulnerability.component),
            joinedload(models.ComponentVulnerability.vulnerability),
        )
    )
    link = db.scalar(query)
    if not link:
        raise HTTPException(status_code=404, detail="취약점 연결 정보가 없습니다")
    link.vex_status = payload.status
    link.justification = payload.justification
    link.response = payload.response
    link.detail = payload.detail
    db.commit()
    db.refresh(link)
    return _read(link)
