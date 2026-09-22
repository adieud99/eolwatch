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


def test_runs_split_fixable_and_kernel_cves_and_work_list_filters_them(client, bundle):
    """A kernel source package carries thousands of tracked CVEs; the actionable number is what has a fix outside it."""
    kernel_package = dict(bundle["sbom"]["packages"][0], SPDXID="SPDXRef-Package-kernel", name="linux-image-6.8.0-1-aws", versionInfo="6.8.0-1",
                          externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                         "referenceLocator": "pkg:deb/ubuntu/linux-image-6.8.0-1-aws@6.8.0-1?arch=amd64&distro=ubuntu-24.04&upstream=linux%406.8.0-1"}])
    bundle["sbom"]["packages"].append(kernel_package)
    bundle["sbom"]["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-kernel"})
    kernel_artifact = {"name": "linux-image-6.8.0-1-aws", "version": "6.8.0-1", "purl": kernel_package["externalRefs"][0]["referenceLocator"]}
    bundle["report"]["matches"] += [
        {"artifact": kernel_artifact, "vulnerability": {"id": "CVE-2026-20001", "severity": "Medium", "fix": {"state": "fixed", "versions": ["6.8.0-2"]}}, "relatedVulnerabilities": []},
        {"artifact": kernel_artifact, "vulnerability": {"id": "CVE-2026-20002", "severity": "Medium", "fix": {"state": "not-fixed", "versions": []}}, "relatedVulnerabilities": []},
    ]
    imported = client.post("/api/analyses/import", json=bundle)
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert (body["cve_count"], body["fixable_cve_count"], body["kernel_cve_count"], body["kernel_fixable_cve_count"]) == (3, 2, 2, 1)
    listed = next(run for run in client.get("/api/analyses").json() if run["id"] == body["id"])
    assert (listed["fixable_cve_count"], listed["kernel_cve_count"], listed["kernel_fixable_cve_count"]) == (2, 2, 1)
    sbom_id = body["sbom_id"]
    def cves(**params):
        page = client.get("/api/vulnerability-work", params={"sbom_id": sbom_id, "status": "ALL", **params})
        assert page.status_code == 200, page.text
        return sorted(item["cve_id"] for item in page.json()["items"])
    assert cves() == ["CVE-2026-12345", "CVE-2026-20001", "CVE-2026-20002"]
    assert cves(fix="FIXED") == ["CVE-2026-12345", "CVE-2026-20001"]
    assert cves(fix="UNFIXED") == ["CVE-2026-20002"]
    assert cves(kernel="false") == ["CVE-2026-12345"]
    assert cves(fix="FIXED", kernel="false") == ["CVE-2026-12345"]
    # folded per component: the kernel package is one row with two CVEs, not two rows
    groups = client.get("/api/vulnerability-work/components", params={"sbom_id": sbom_id, "status": "ALL"})
    assert groups.status_code == 200, groups.text
    page = groups.json()
    assert page["total"] == 2 and [(g["component_name"], g["cve_count"], g["max_severity"]) for g in page["items"]] == [("Jinja2", 1, "HIGH"), ("linux-image-6.8.0-1-aws", 2, "MEDIUM")]
    kernel_row = page["items"][1]
    assert kernel_row["fixed_versions"] == ["6.8.0-2"] and kernel_row["open_count"] == 2 and kernel_row["asset_tag"] == "ANALYSIS-SRV-01"
    assert cves(component_id=kernel_row["component_id"]) == ["CVE-2026-20001", "CVE-2026-20002"]
    assert cves(component_id=kernel_row["component_id"], fix="FIXED") == ["CVE-2026-20001"]
    assert client.get("/api/vulnerability-work/components", params={"sbom_id": sbom_id, "status": "ALL", "kernel": "false"}).json()["total"] == 1


def test_import_records_the_package_managers_verdict_per_finding(client, bundle):
    """grype says Jinja2 is fixed in 2.11.3; whether the repository really offers it is recorded on the link and the run."""
    bundle["package_updates"] = {"manager": "apt", "refreshed": True, "collected_at": "2026-09-21T09:00:00Z",
                                 "packages": {"Jinja2": {"candidate": "2.11.3", "installed": "2.4.1"}}}
    kernel = dict(bundle["sbom"]["packages"][0], SPDXID="SPDXRef-Package-k", name="linux-image-6.8.0-1-aws", versionInfo="6.8.0-1",
                  externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:deb/ubuntu/linux-image-6.8.0-1-aws@6.8.0-1?upstream=linux%406.8.0-1"}])
    bundle["sbom"]["packages"].append(kernel)
    bundle["sbom"]["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-k"})
    bundle["report"]["matches"].append({"artifact": {"name": kernel["name"], "version": "6.8.0-1", "purl": kernel["externalRefs"][0]["referenceLocator"]},
                                        "vulnerability": {"id": "CVE-2026-30001", "severity": "High", "fix": {"state": "fixed", "versions": ["6.8.0-2"]}}, "relatedVulnerabilities": []})
    imported = client.post("/api/analyses/import", json=bundle)
    assert imported.status_code == 200, imported.text
    body = imported.json()
    # the kernel CVE is fixable but gets no apt verdict (apt upgrades linux-aws, not the versioned image), so it is not "suspect"
    assert body["verified_fixable_cve_count"] == 1 and body["suspect_cve_count"] == 0 and body["kernel_fixable_cve_count"] == 1
    assert body["package_updates"] == {"manager": "apt", "refreshed": True, "collected_at": "2026-09-21T09:00:00Z", "package_count": 1}
    item = client.get("/api/vulnerability-work", params={"sbom_id": body["sbom_id"], "status": "ALL"}).json()["items"][0]
    assert item["fix_check"] == "UPDATE_AVAILABLE"
    group = client.get("/api/vulnerability-work/components", params={"sbom_id": body["sbom_id"], "status": "ALL"}).json()["items"][0]
    assert group["update_available_count"] == 1 and group["no_update_count"] == 0
    # same report, but apt has nothing to upgrade: the finding is flagged as suspect
    bundle["package_updates"]["packages"] = {}
    bundle["sbom"]["documentNamespace"] = bundle["sbom"]["documentNamespace"] + "-2"
    bundle["report"]["descriptor"]["version"] = "test-fixture-1.1"
    second = client.post("/api/analyses/import", json=bundle).json()
    assert second["verified_fixable_cve_count"] == 0 and second["suspect_cve_count"] == 1
    kernel_items = [i for i in client.get("/api/vulnerability-work", params={"sbom_id": second["sbom_id"], "status": "ALL"}).json()["items"] if i["component_name"].startswith("linux-image")]
    assert kernel_items and all(i["fix_check"] is None for i in kernel_items)
    # no package manager data at all: nothing is claimed either way
    del bundle["package_updates"]
    bundle["sbom"]["documentNamespace"] = bundle["sbom"]["documentNamespace"] + "-3"
    bundle["report"]["descriptor"]["version"] = "test-fixture-1.2"
    third = client.post("/api/analyses/import", json=bundle).json()
    assert third["verified_fixable_cve_count"] == 0 and third["suspect_cve_count"] == 0 and third["package_updates"] is None


def test_earlier_runs_keep_their_counts_when_the_same_sbom_is_imported_again(client, bundle):
    first = client.post("/api/analyses/import", json=bundle).json()
    assert first["fixable_cve_count"] == 1
    bundle["report"]["descriptor"]["version"] = "test-fixture-2.0"   # new run, same SBOM: links get re-pointed
    second = client.post("/api/analyses/import", json=bundle).json()
    assert second["id"] != first["id"] and second["fixable_cve_count"] == 1
    listed = {run["id"]: run for run in client.get("/api/analyses").json()}
    assert listed[first["id"]]["fixable_cve_count"] == 1 and listed[first["id"]]["cve_count"] == 1


def test_same_os_package_on_two_ubuntu_releases_is_one_product(client, bundle):
    """srv-han (26.04) and srv-na (24.04) both ship libsort-naturally-perl 1.03-4: same CPE, PURLs differing only in distro=."""
    def package(distro):
        return dict(bundle["sbom"]["packages"][0], SPDXID="SPDXRef-Package-perl", name="libsort-naturally-perl", versionInfo="1.03-4",
                    externalRefs=[{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                   "referenceLocator": f"pkg:deb/ubuntu/libsort-naturally-perl@1.03-4?arch=all&distro=ubuntu-{distro}"},
                                  {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                                   "referenceLocator": "cpe:2.3:a:libsort-naturally-perl:libsort-naturally-perl:1.03-4:*:*:*:*:*:*:*"}])
    bundle["sbom"]["packages"].append(package("26.04"))
    bundle["sbom"]["relationships"].append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-perl"})
    first = client.post("/api/analyses/import", json=bundle)
    assert first.status_code == 200, first.text
    other = client.post("/api/assets", json={"asset_tag": "ANALYSIS-SRV-02", "name": "다른 릴리스 서버", "asset_type": "server"}).json()["id"]
    bundle["asset_id"] = other
    bundle["sbom"]["documentNamespace"] = bundle["sbom"]["documentNamespace"] + "-2404"
    bundle["sbom"]["packages"][-1] = package("24.04")
    second = client.post("/api/analyses/import", json=bundle)
    assert second.status_code == 200, second.text
