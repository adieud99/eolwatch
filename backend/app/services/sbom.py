from __future__ import annotations

from datetime import datetime
from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4

from fastapi import HTTPException
from jsonschema import validators
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import models


SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}
CYCLONEDX_TYPE_MAP = {
    "operating-system": "OS",
    "firmware": "FIRMWARE",
    "library": "LIBRARY",
    "framework": "MIDDLEWARE",
    "application": "APPLICATION",
    "container": "APPLICATION",
    "platform": "MIDDLEWARE",
    "device": "HARDWARE_MODEL",
    "device-driver": "AGENT",
    "file": "LIBRARY",
}


@lru_cache
def _schema(version: str) -> dict[str, Any]:
    path = Path(__file__).parents[1] / "resources" / "cyclonedx" / f"bom-{version}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate_cyclonedx_schema(document: dict[str, Any], version: str) -> None:
    schema = _schema(version)
    validator_class = validators.validator_for(schema)
    validator_class.check_schema(schema)
    errors = sorted(validator_class(schema).iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    details = []
    for error in errors[:10]:
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        details.append({"path": location, "message": error.message})
    raise HTTPException(
        status_code=422,
        detail={"message": "CycloneDX 공식 JSON Schema 검증에 실패했습니다", "errors": details},
    )


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _supplier(component: dict[str, Any]) -> Optional[str]:
    supplier = component.get("supplier") or component.get("manufacturer")
    if isinstance(supplier, dict):
        return supplier.get("name")
    return supplier if isinstance(supplier, str) else None


def _license_values(component: dict[str, Any]) -> list[Any]:
    result: list[Any] = []
    for item in component.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        license_data = item.get("license")
        if isinstance(license_data, dict):
            result.append(license_data.get("id") or license_data.get("name"))
        elif item.get("expression"):
            result.append(item["expression"])
    return [item for item in result if item]


def _flatten_components(components: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for component in components:
        flattened.append(component)
        children = component.get("components") or []
        if isinstance(children, list):
            flattened.extend(_flatten_components(children))
    return flattened


def _normalize_product(db: Session, item: dict[str, Any]) -> models.ProductRelease:
    purl = item.get("purl")
    cpe = item.get("cpe")
    supplier = _supplier(item)
    name = item.get("name") or "이름 없음"
    version = str(item.get("version") or "UNKNOWN")
    product_type = CYCLONEDX_TYPE_MAP.get(item.get("type", "library"), "LIBRARY")

    query = select(models.ProductRelease)
    if purl or cpe:
        query = query.where(or_(models.ProductRelease.purl == purl if purl else False, models.ProductRelease.cpe == cpe if cpe else False))
    else:
        query = query.where(
            models.ProductRelease.product_type == product_type,
            models.ProductRelease.vendor == supplier,
            models.ProductRelease.name == name,
            models.ProductRelease.version == version,
        )
    existing = db.scalar(query.limit(1))
    if existing:
        return existing
    product = models.ProductRelease(
        product_type=product_type,
        vendor=supplier,
        name=name,
        version=version,
        purl=purl,
        cpe=cpe,
    )
    db.add(product)
    db.flush()
    return product


def inspect_quality(document: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    """프로젝트 품질 프로파일. 공식 적합성 인증을 대신하지 않는다."""
    metadata = document.get("metadata") or {}
    components = _flatten_components(document.get("components") or [])
    dependencies = document.get("dependencies") or []
    checks = {
        "document_serial_number": bool(document.get("serialNumber")),
        "document_timestamp": bool(metadata.get("timestamp")),
        "document_author_or_tool": bool(metadata.get("authors") or metadata.get("tools")),
        "component_names": bool(components) and all(c.get("name") for c in components),
        "component_versions": bool(components) and all(c.get("version") for c in components),
        "component_suppliers": bool(components) and all(_supplier(c) for c in components),
        "component_unique_ids": bool(components)
        and all(c.get("bom-ref") or c.get("purl") or c.get("cpe") for c in components),
        "dependency_relationships": bool(dependencies),
        "license_information": bool(components) and all(c.get("licenses") for c in components),
    }
    passed = sum(checks.values())
    score = round(passed / len(checks) * 100, 1)
    missing = [key for key, value in checks.items() if not value]
    return score, {"profile": "EOLWatch SBOM quality profile v1", "checks": checks, "missing": missing}


def import_cyclonedx(
    db: Session,
    document: dict[str, Any],
    asset_id: Optional[int] = None,
    software_product_id: Optional[int] = None,
) -> models.SbomDocument:
    if document.get("bomFormat") != "CycloneDX":
        raise HTTPException(status_code=422, detail="현재 CycloneDX JSON SBOM만 가져올 수 있습니다")
    spec_version = str(document.get("specVersion", ""))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise HTTPException(status_code=422, detail=f"지원하는 CycloneDX 버전은 {sorted(SUPPORTED_SPEC_VERSIONS)}입니다")
    validate_cyclonedx_schema(document, spec_version)
    if asset_id and not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="연결할 자산이 없습니다")
    if software_product_id and not db.get(models.SoftwareProduct, software_product_id):
        raise HTTPException(status_code=404, detail="연결할 소프트웨어가 없습니다")

    raw_components = _flatten_components(document.get("components") or [])
    raw_dependencies = document.get("dependencies") or []
    score, details = inspect_quality(document)
    sbom = models.SbomDocument(
        serial_number=document.get("serialNumber") or f"urn:uuid:{uuid4()}",
        bom_format="CycloneDX",
        spec_version=spec_version,
        document_version=int(document.get("version", 1)),
        generated_at=_parse_timestamp((document.get("metadata") or {}).get("timestamp")),
        asset_id=asset_id,
        software_product_id=software_product_id,
        component_count=len(raw_components),
        dependency_count=sum(len(d.get("dependsOn") or []) for d in raw_dependencies if isinstance(d, dict)),
        quality_score=score,
        quality_details=details,
        raw_document=document,
    )
    db.add(sbom)
    db.flush()

    used_refs: set[str] = set()
    for index, item in enumerate(raw_components):
        fallback_ref = f"component:{index}:{item.get('name', 'unknown')}:{item.get('version', 'unknown')}"
        bom_ref = str(item.get("bom-ref") or item.get("purl") or item.get("cpe") or fallback_ref)
        if bom_ref in used_refs:
            bom_ref = f"{bom_ref}#{index}"
        used_refs.add(bom_ref)
        product = _normalize_product(db, item)
        db.add(
            models.Component(
                sbom_id=sbom.id,
                product_release_id=product.id,
                bom_ref=bom_ref,
                component_type=item.get("type", "library"),
                group_name=item.get("group"),
                name=item.get("name") or "이름 없음",
                version=item.get("version"),
                supplier=_supplier(item),
                purl=item.get("purl"),
                cpe=item.get("cpe"),
                licenses=_license_values(item),
                hashes=item.get("hashes") or [],
            )
        )
    for dependency in raw_dependencies:
        source_ref = dependency.get("ref") if isinstance(dependency, dict) else None
        if not source_ref:
            continue
        for target_ref in dependency.get("dependsOn") or []:
            db.add(models.DependencyEdge(sbom_id=sbom.id, source_ref=source_ref, target_ref=target_ref))

    db.commit()
    db.refresh(sbom)
    return sbom
