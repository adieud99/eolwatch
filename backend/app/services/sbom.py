from __future__ import annotations

from datetime import datetime
from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Iterable, Optional
from uuid import uuid4

from fastapi import HTTPException
from jsonschema import validators
from packageurl import PackageURL
from packaging.version import InvalidVersion, Version
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import models


SUPPORTED_SPEC_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}
SUPPORTED_SPDX_VERSIONS = {"SPDX-2.3"}
INSTALL_QUALIFIERS = {"distro", "arch"}
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
SPDX_TYPE_MAP = {
    "APPLICATION": "APPLICATION",
    "CONTAINER": "APPLICATION",
    "DEVICE": "HARDWARE_MODEL",
    "FIRMWARE": "FIRMWARE",
    "FRAMEWORK": "MIDDLEWARE",
    "LIBRARY": "LIBRARY",
    "OPERATING_SYSTEM": "OS",
}


@lru_cache
def _schema(version: str) -> dict[str, Any]:
    path = Path(__file__).parents[1] / "resources" / "cyclonedx" / f"bom-{version}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache
def _spdx_schema() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "resources" / "spdx" / "spdx-2.3.schema.json"
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


def validate_spdx_schema(document: dict[str, Any]) -> None:
    schema = _spdx_schema()
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
        detail={"message": "SPDX 2.3 공식 JSON Schema 검증에 실패했습니다", "errors": details},
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
    raw_purl = item.get("purl")
    cpe = item.get("cpe")
    supplier = _supplier(item)
    name = item.get("name") or "이름 없음"
    version = str(item.get("version") or "UNKNOWN")
    raw_type = str(item.get("type", "library"))
    product_type = CYCLONEDX_TYPE_MAP.get(raw_type, raw_type.upper() if raw_type.upper() in set(SPDX_TYPE_MAP.values()) else "LIBRARY")

    def fail(message):
        raise HTTPException(status_code=422, detail=f"제품 연결을 확인하세요: {name} {version}. {message}")

    def canonical(value, installed):
        try:
            parsed = PackageURL.from_string(value)
            installed = None if installed in {None, "UNKNOWN", "N/A", ""} else str(installed)
            if parsed.version and installed and parsed.version != installed:
                # Only a documented ecosystem comparator may equate two spellings.
                if parsed.type != "pypi" or Version(parsed.version) != Version(installed):
                    fail("PURL 버전과 구성요소 버전이 다릅니다.")
            effective = parsed.version or installed
            # The same OS package version seen on two releases (distro=ubuntu-24.04 vs 26.04) or two CPU
            # architectures is one product: those qualifiers describe where it was installed, not what it is.
            qualifiers = {k: v for k, v in (parsed.qualifiers or {}).items() if k not in INSTALL_QUALIFIERS} or None
            parsed = parsed._replace(qualifiers=qualifiers)
            return parsed._replace(version=effective).to_string(), effective, parsed._replace(version=None).to_string()
        except (ValueError, TypeError, AttributeError, InvalidVersion):
            fail("PURL 형식 또는 버전이 올바르지 않습니다.")

    purl = raw_purl
    unversioned = None
    if raw_purl:
        purl, embedded_version, unversioned = canonical(raw_purl, item.get("version"))
        supplied_version = item.get("version")
        version = str((supplied_version if supplied_version not in {None, "", "UNKNOWN", "N/A"} else None)
                      or embedded_version or "UNKNOWN")
        if len(purl) > 500:
            fail("정규화된 제품 PURL이 500자를 초과합니다.")
    identity = (
        (models.ProductRelease.product_type == product_type)
        & (models.ProductRelease.vendor == supplier)
        & (models.ProductRelease.name == name)
        & (models.ProductRelease.version == version)
    )
    # Legacy PURLs may have no version or a different qualifier ordering. The
    # exact human identity is only a candidate, never permission to merge IDs.
    candidates = db.scalars(select(models.ProductRelease).where(or_(
        identity,
        models.ProductRelease.purl.in_([purl, raw_purl, unversioned]) if purl else False,
        models.ProductRelease.cpe == cpe if cpe else False,
    ))).all()
    matches = []
    for existing in candidates:
        same_purl = bool(purl and existing.purl and canonical(existing.purl, existing.version)[0] == purl)
        same_cpe = bool(cpe and existing.cpe == cpe)
        if same_cpe and existing.product_type != product_type:
            fail("같은 CPE에 서로 다른 제품 유형이 연결돼 있습니다.")
        if same_cpe and existing.version != version:
            fail("같은 CPE가 서로 다른 버전을 가리킵니다. 버전별 식별자가 필요합니다.")
        if same_purl or same_cpe:
            if same_purl and cpe and existing.cpe and cpe != existing.cpe:
                fail("PURL과 CPE가 서로 다른 제품을 가리킵니다.")
            if same_cpe and purl and existing.purl and not same_purl:
                fail("PURL과 CPE가 서로 다른 제품을 가리킵니다.")
            if same_cpe and purl and not existing.purl:
                parsed = PackageURL.from_string(purl)
                if parsed.type in {"deb", "rpm", "apk"} or parsed.qualifiers:
                    fail("배포판·한정자가 있는 패키지는 CPE만으로 공통 지원일을 상속할 수 없습니다.")
            matches.append(existing)
        elif not purl and not cpe:
            matches.append(existing)
        elif (existing.product_type, existing.vendor, existing.name, existing.version) == (product_type, supplier, name, version):
            # A missing identifier can be enriched, but distinct known package
            # ecosystems/namespaces must not share a product identity accidentally.
            if existing.purl or existing.cpe:
                fail("동일한 제품 이름·버전에 충돌하는 식별정보가 있습니다.")
            matches.append(existing)
    if len(matches) > 1:
        if purl and cpe:
            fail("PURL과 CPE가 서로 다른 제품을 가리키거나 중복 연결돼 있습니다.")
        fail("여러 제품이 식별정보에 일치합니다. 기존 연결을 먼저 확인하세요.")
    if matches:
        existing = matches[0]
        if purl and not existing.purl:
            existing.purl = purl
        if cpe and not existing.cpe:
            existing.cpe = cpe
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


def _spdx_supplier(value: Any) -> Optional[str]:
    if not isinstance(value, str) or value in {"NOASSERTION", "NONE"}:
        return None
    for prefix in ("Organization: ", "Person: ", "Tool: "):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _spdx_external_ref(package: dict[str, Any], *types: str) -> Optional[str]:
    expected = {item.lower() for item in types}
    for reference in package.get("externalRefs") or []:
        if str(reference.get("referenceType", "")).lower() in expected:
            return reference.get("referenceLocator")
    return None


def _spdx_component(package: dict[str, Any]) -> dict[str, Any]:
    licenses = []
    for key in ("licenseDeclared", "licenseConcluded"):
        value = package.get(key)
        if value and value not in {"NOASSERTION", "NONE"} and value not in licenses:
            licenses.append(value)
    return {
        "bom-ref": package.get("SPDXID"),
        "type": SPDX_TYPE_MAP.get(str(package.get("primaryPackagePurpose", "LIBRARY")).upper(), "LIBRARY"),
        "name": package.get("name"),
        "version": package.get("versionInfo"),
        "supplier": _spdx_supplier(package.get("supplier") or package.get("originator")),
        "purl": _spdx_external_ref(package, "purl"),
        "cpe": _spdx_external_ref(package, "cpe22Type", "cpe23Type"),
        "licenses": licenses,
        "hashes": package.get("checksums") or [],
    }


def inspect_spdx_quality(document: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    packages = document.get("packages") or []
    creation = document.get("creationInfo") or {}
    checks = {
        "document_namespace": bool(document.get("documentNamespace")),
        "document_timestamp": bool(creation.get("created")),
        "document_creator": bool(creation.get("creators")),
        "package_names": bool(packages) and all(item.get("name") for item in packages),
        "package_versions": bool(packages) and all(item.get("versionInfo") for item in packages),
        "package_suppliers": bool(packages) and all(_spdx_supplier(item.get("supplier") or item.get("originator")) for item in packages),
        "package_identifiers": bool(packages)
        and all(_spdx_external_ref(item, "purl", "cpe22Type", "cpe23Type") for item in packages),
        "dependency_relationships": bool(document.get("relationships")),
        "license_information": bool(packages)
        and all((item.get("licenseDeclared") or item.get("licenseConcluded")) not in {None, "NOASSERTION", "NONE"} for item in packages),
    }
    score = round(sum(checks.values()) / len(checks) * 100, 1)
    return score, {
        "profile": "EOLWatch SPDX infrastructure SBOM quality profile v2",
        "checks": checks,
        "missing": [key for key, value in checks.items() if not value],
    }


def import_cyclonedx(
    db: Session,
    document: dict[str, Any],
    asset_id: Optional[int] = None,
) -> models.SbomDocument:
    if document.get("bomFormat") != "CycloneDX":
        raise HTTPException(status_code=422, detail="현재 CycloneDX JSON SBOM만 가져올 수 있습니다")
    spec_version = str(document.get("specVersion", ""))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise HTTPException(status_code=422, detail=f"지원하는 CycloneDX 버전은 {sorted(SUPPORTED_SPEC_VERSIONS)}입니다")
    validate_cyclonedx_schema(document, spec_version)
    if asset_id and not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="연결할 자산이 없습니다")

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


def import_spdx(
    db: Session,
    document: dict[str, Any],
    asset_id: Optional[int] = None,
    commit: bool = True,
) -> models.SbomDocument:
    spec_version = str(document.get("spdxVersion", ""))
    if spec_version not in SUPPORTED_SPDX_VERSIONS:
        raise HTTPException(status_code=422, detail="지원하는 SPDX 버전은 SPDX-2.3입니다")
    validate_spdx_schema(document)
    if asset_id and not db.get(models.Asset, asset_id):
        raise HTTPException(status_code=404, detail="연결할 자산이 없습니다")

    packages = document.get("packages") or []
    relationships = document.get("relationships") or []
    components = [_spdx_component(item) for item in packages]
    score, details = inspect_spdx_quality(document)
    dependency_types = {"DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY"}
    package_refs = {item.get("SPDXID") for item in packages}
    # File ownership stays in the original SPDX. The searchable graph represents packages.
    package_relationships = [item for item in relationships
                             if item.get("relationshipType") in dependency_types
                             and item.get("spdxElementId") in package_refs
                             and item.get("relatedSpdxElement") in package_refs]
    dependency_count = len(package_relationships)
    sbom = models.SbomDocument(
        serial_number=document.get("documentNamespace") or f"https://eolwatch.local/spdx/{uuid4()}",
        bom_format="SPDX",
        spec_version="2.3",
        document_version=1,
        generated_at=_parse_timestamp((document.get("creationInfo") or {}).get("created")),
        asset_id=asset_id,
        component_count=len(components),
        dependency_count=dependency_count,
        quality_score=score,
        quality_details=details,
        raw_document=document,
    )
    db.add(sbom)
    db.flush()

    used_refs: set[str] = set()
    for index, item in enumerate(components):
        fallback_ref = f"SPDXRef-Package-{index}"
        bom_ref = str(item.get("bom-ref") or item.get("purl") or item.get("cpe") or fallback_ref)
        if bom_ref in used_refs:
            bom_ref = f"{bom_ref}-{index}"
        used_refs.add(bom_ref)
        product = _normalize_product(db, item)
        db.add(
            models.Component(
                sbom_id=sbom.id,
                product_release_id=product.id,
                bom_ref=bom_ref,
                component_type=item.get("type", "LIBRARY").lower(),
                name=item.get("name") or "이름 없음",
                version=item.get("version"),
                supplier=_supplier(item),
                purl=item.get("purl"),
                cpe=item.get("cpe"),
                licenses=item.get("licenses") or [],
                hashes=item.get("hashes") or [],
            )
        )

    for relationship in package_relationships:
        relationship_type = relationship.get("relationshipType")
        if relationship_type not in dependency_types:
            continue
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        if relationship_type in {"DEPENDENCY_OF", "CONTAINED_BY"}:
            source, target = target, source
        if source and target:
            db.add(models.DependencyEdge(sbom_id=sbom.id, source_ref=source, target_ref=target))

    if commit:
        db.commit()
        db.refresh(sbom)
    else:
        db.flush()
    return sbom


def import_sbom(
    db: Session,
    document: dict[str, Any],
    asset_id: Optional[int] = None,
) -> models.SbomDocument:
    if document.get("spdxVersion"):
        return import_spdx(db, document, asset_id)
    if document.get("bomFormat") == "CycloneDX":
        return import_cyclonedx(db, document, asset_id)
    raise HTTPException(status_code=422, detail="SPDX 2.3 또는 CycloneDX JSON SBOM만 가져올 수 있습니다")
