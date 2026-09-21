"""Exercise imported scanner evidence without running tools or querying CVE services."""

from copy import deepcopy
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

# Keep app initialization consistent with test_api; requests below use a separate DB.
os.environ["DATABASE_URL"] = "sqlite:////tmp/eolwatch-test.db"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import main, middleware, models
from app.db import Base, get_db


@pytest.fixture
def analysis_db(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'analysis.db'}", connect_args={"check_same_thread": False}
    )
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(main, "SessionLocal", factory)
    monkeypatch.setattr(middleware, "SessionLocal", factory)

    def isolated_db():
        with factory() as db:
            yield db

    previous_overrides = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[get_db] = isolated_db
    try:
        yield factory
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(previous_overrides)
        engine.dispose()


@pytest.fixture
def client(analysis_db):
    with TestClient(main.app) as test_client:
        response = test_client.post(
            "/api/auth/login", json={"username": "admin", "password": "Eolwatch!2026"}
        )
        assert response.status_code == 200, response.text
        test_client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
        yield test_client


@pytest.fixture
def bundle(client):
    asset = client.post(
        "/api/assets",
        json={"asset_tag": "ANALYSIS-SRV-01", "name": "분석 대상 서버", "asset_type": "server"},
    )
    assert asset.status_code == 201, asset.text
    sample = Path(__file__).parents[2] / "samples" / "spdx-2.3-blackduck-compatible.json"
    sbom = json.loads(sample.read_text(encoding="utf-8"))
    sbom["documentNamespace"] = f"https://eolwatch.local/spdx/test/{uuid4()}"
    sbom["creationInfo"]["creators"] = ["Tool: syft-test-fixture-1.0"]
    return {
        "asset_id": asset.json()["id"],
        "scan_scope": "test server /opt/application",
        "sbom": sbom,
        "report": {
            "descriptor": {
                "name": "grype",
                "version": "test-fixture-1.0",
                "db": {"built": "2026-09-15T00:00:00Z", "schemaVersion": 6},
            },
            "source": {"type": "sbom", "target": "test.spdx.json"},
            "matches": [
                {
                    "artifact": {"name": "Jinja2", "version": "2.4.1", "purl": "pkg:pypi/jinja2@2.4.1"},
                    "vulnerability": {
                        "id": "CVE-2026-12345",
                        "severity": "High",
                        "description": "Synthetic test finding, not a real advisory.",
                        "urls": ["https://example.test/advisories/CVE-2026-12345"],
                        "fix": {"state": "fixed", "versions": ["2.11.3"]},
                    },
                    "relatedVulnerabilities": [],
                }
            ],
            "extraEvidence": {"preserve": "original report fields"},
        },
    }


def row_count(factory, model):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(model))


def test_import_preserves_evidence_and_connects_cve_to_asset(client, bundle):
    response = client.post("/api/analyses/import", json=bundle)
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["scanner"] == "Grype"
    assert run["scanner_version"] == "test-fixture-1.0"
    assert run["generator"] == "Tool: syft-test-fixture-1.0"
    assert run["scan_scope"] == bundle["scan_scope"]
    assert run["database_info"] == bundle["report"]["descriptor"]["db"]
    assert (run["component_count"], run["match_count"], run["cve_count"], run["link_count"]) == (1, 1, 1, 1)
    assert run["asset_tag"] == "ANALYSIS-SRV-01"
    assert client.get("/api/analyses").json() == [run]
    assert client.get(f"/api/analyses/{run['id']}/bundle").json() == bundle

    findings = client.get(f"/api/vulnerabilities?sbom_id={run['sbom_id']}")
    assert findings.status_code == 200, findings.text
    assert len(findings.json()) == 1
    finding = findings.json()[0]
    assert finding["asset_tag"] == "ANALYSIS-SRV-01"
    assert finding["component_name"] == "Jinja2"
    assert finding["component_version"] == "2.4.1"
    assert finding["cve_id"] == "CVE-2026-12345"
    assert finding["severity"] == "HIGH"
    assert finding["finding_source"] == "Grype"
    assert finding["analysis_run_id"] == run["id"]
    assert finding["fixed_version"] == "2.11.3"
    assert finding["fixed_versions"] == ["2.11.3"]
    assert finding["vex_status"] == "AFFECTED"


def test_reimport_is_idempotent(client, bundle, analysis_db):
    first = client.post("/api/analyses/import", json=bundle)
    second = client.post("/api/analyses/import", json=deepcopy(bundle))
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    for model in (models.SbomDocument, models.AnalysisRun, models.Component, models.Vulnerability, models.ComponentVulnerability):
        assert row_count(analysis_db, model) == 1


def test_cve_aliases_merge_matches_without_recommending_one_fixed_branch(client, bundle):
    match = bundle["report"]["matches"][0]
    match["vulnerability"]["id"] = "GHSA-test-fixture-only"
    match["vulnerability"]["severity"] = "Low"
    match["vulnerability"]["fix"]["versions"] = ["3.0.4", "2.11.3", "3.0.4"]
    match["relatedVulnerabilities"] = [{"id": "CVE-2026-12345"}, {"id": "CVE-2026-12345"}]
    duplicate = deepcopy(match)
    duplicate["vulnerability"]["id"] = "CVE-2026-12345"
    duplicate["vulnerability"]["severity"] = "High"
    duplicate["vulnerability"]["fix"]["versions"] = ["3.0.4"]
    non_cve = deepcopy(match)
    non_cve["relatedVulnerabilities"] = []
    bundle["report"]["matches"].extend([duplicate, non_cve])

    response = client.post("/api/analyses/import", json=bundle)
    assert response.status_code == 200, response.text
    run = response.json()
    assert (run["match_count"], run["cve_count"], run["link_count"], run["ignored_non_cve"]) == (3, 1, 1, 1)
    findings = client.get(f"/api/vulnerabilities?sbom_id={run['sbom_id']}").json()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["cve_id"] == "CVE-2026-12345"
    assert "GHSA-test-fixture-only" in finding["aliases"]
    assert finding["severity"] == "HIGH"
    assert finding["fixed_versions"] == ["2.11.3", "3.0.4"]
    assert finding["fixed_version"] is None


@pytest.mark.parametrize("non_cve", [False, True])
def test_mismatched_report_rolls_back_all_imported_rows(client, bundle, analysis_db, non_cve):
    # A valid first row ensures rejection occurs after creating SBOM, product and CVE rows.
    mismatched = deepcopy(bundle["report"]["matches"][0])
    mismatched["artifact"]["purl"] = "pkg:pypi/jinja2@9.9.9"
    if non_cve:
        mismatched["vulnerability"]["id"] = "GHSA-test-unmapped"
    bundle["report"]["matches"].append(mismatched)
    response = client.post("/api/analyses/import", json=bundle)
    assert response.status_code == 422, response.text
    for model in (models.SbomDocument, models.AnalysisRun, models.Component, models.ProductRelease, models.Vulnerability, models.ComponentVulnerability):
        assert row_count(analysis_db, model) == 0, model.__name__
    assert row_count(analysis_db, models.Asset) == 1


def test_missing_matches_is_not_treated_as_zero_findings(client, bundle, analysis_db):
    del bundle["report"]["matches"]
    response = client.post("/api/analyses/import", json=bundle)
    assert response.status_code == 422, response.text
    assert row_count(analysis_db, models.SbomDocument) == 0
    assert row_count(analysis_db, models.AnalysisRun) == 0


def test_explicit_zero_matches_still_records_completed_analysis(client, bundle, analysis_db):
    bundle["report"]["matches"] = []
    response = client.post("/api/analyses/import", json=bundle)
    assert response.status_code == 200, response.text
    run = response.json()
    assert (run["component_count"], run["match_count"], run["cve_count"], run["link_count"], run["ignored_non_cve"]) == (1, 0, 0, 0, 0)
    assert row_count(analysis_db, models.AnalysisRun) == 1
    assert row_count(analysis_db, models.SbomDocument) == 1
    assert client.get(f"/api/vulnerabilities?sbom_id={run['sbom_id']}").json() == []
    assert client.get(f"/api/analyses/{run['id']}/bundle").json() == bundle


def test_spdx_file_ownership_is_preserved_without_becoming_package_dependencies(client, bundle, analysis_db):
    document = bundle["sbom"]
    document["packages"].append({
        "SPDXID": "SPDXRef-Package-DemoApp",
        "name": "demo-app",
        "versionInfo": "1.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:generic/demo-app@1.0",
        }],
    })
    document["files"] = [
        {
            "SPDXID": "SPDXRef-File-App",
            "fileName": "./app.py",
            "checksums": [{"algorithm": "SHA1", "checksumValue": "a" * 40}],
        },
        {
            "SPDXID": "SPDXRef-File-Jinja2",
            "fileName": "./site-packages/jinja2/__init__.py",
            "checksums": [{"algorithm": "SHA1", "checksumValue": "b" * 40}],
        },
    ]
    document["relationships"].extend([
        {
            "spdxElementId": "SPDXRef-Package-DemoApp",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Package-Jinja2",
        },
        {
            "spdxElementId": "SPDXRef-Package-DemoApp",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-File-App",
        },
        {
            "spdxElementId": "SPDXRef-File-Jinja2",
            "relationshipType": "CONTAINED_BY",
            "relatedSpdxElement": "SPDXRef-Package-Jinja2",
        },
    ])

    response = client.post("/api/analyses/import", json=bundle)
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["component_count"] == 2
    sboms = client.get("/api/sboms").json()
    assert len(sboms) == 1
    assert sboms[0]["dependency_count"] == 1
    assert client.get(f"/api/analyses/{run['id']}/bundle").json()["sbom"] == document
    with analysis_db() as db:
        edges = db.scalars(select(models.DependencyEdge).where(models.DependencyEdge.sbom_id == run["sbom_id"])).all()
        assert [(edge.source_ref, edge.target_ref) for edge in edges] == [
            ("SPDXRef-Package-DemoApp", "SPDXRef-Package-Jinja2")
        ]


@pytest.mark.parametrize("conflict", ["asset", "sbom_content"])
def test_sbom_namespace_cannot_be_reused_for_other_asset_or_content(client, bundle, analysis_db, conflict):
    original = client.post("/api/analyses/import", json=bundle)
    assert original.status_code == 200, original.text
    changed = deepcopy(bundle)
    if conflict == "asset":
        asset = client.post("/api/assets", json={"asset_tag": "ANALYSIS-SRV-02", "name": "다른 서버", "asset_type": "server"})
        assert asset.status_code == 201, asset.text
        changed["asset_id"] = asset.json()["id"]
    else:
        changed["sbom"]["name"] = "different SBOM with same namespace"
    response = client.post("/api/analyses/import", json=changed)
    assert response.status_code == 409, response.text
    assert row_count(analysis_db, models.AnalysisRun) == 1
    assert row_count(analysis_db, models.SbomDocument) == 1
    assert client.get(f"/api/analyses/{original.json()['id']}/bundle").json() == bundle


def test_viewer_can_read_analysis_but_cannot_import(client, bundle, analysis_db):
    imported = client.post("/api/analyses/import", json=bundle)
    assert imported.status_code == 200, imported.text
    user = client.post("/api/auth/users", json={"username": "analysis-viewer", "password": "Viewer!2026", "role": "VIEWER"})
    assert user.status_code == 201, user.text
    login = client.post("/api/auth/login", json={"username": "analysis-viewer", "password": "Viewer!2026"})
    assert login.status_code == 200, login.text
    client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
    assert client.get("/api/analyses").status_code == 200
    assert client.get(f"/api/analyses/{imported.json()['id']}/bundle").status_code == 200
    assert client.post("/api/analyses/import", json=bundle).status_code == 403
    assert row_count(analysis_db, models.AnalysisRun) == 1
    client.headers.pop("Authorization")
    assert client.get("/api/analyses").status_code == 401
