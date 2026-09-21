"""OSV refresh can add findings without discarding a saved Grype baseline/review."""
from copy import deepcopy
from datetime import date

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app import models
from app.db import Base
from app.services.analysis import digest
from app.services.vulnerabilities import scan_sbom
from app.services.vulnerability_actions import record_action


@pytest.fixture
def provenance_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'provenance.db'}")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)() as db:
        user = models.User(username="reviewer", password_hash="unused-test-hash", role="ADMIN", active=True)
        asset = models.Asset(asset_tag="PROVENANCE-01", name="원본 검증 서버", asset_type="server")
        db.add_all([user, asset]); db.flush()
        sbom = models.SbomDocument(serial_number="provenance-fixture", bom_format="SPDX", spec_version="2.3",
                                   asset_id=asset.id, component_count=1, raw_document={"original": "SBOM evidence"})
        db.add(sbom); db.flush()
        component = models.Component(sbom_id=sbom.id, bom_ref="pkg-demo", name="demo", version="1.0",
                                     purl="pkg:pypi/demo@1.0")
        vulnerability = models.Vulnerability(osv_id="CVE-2026-12345", summary="Original Grype summary", severity="HIGH")
        raw_report = {"descriptor": {"name": "grype", "version": "fixture"}, "matches": [{"original": True}]}
        run = models.AnalysisRun(sbom_id=sbom.id,
                                 report_sha256=digest({"asset_id": asset.id, "sbom": sbom.raw_document, "report": raw_report}),
                                 sbom_sha256=digest(sbom.raw_document), scanner="Grype", scanner_version="fixture",
                                 generator="Tool: syft-fixture", scan_scope="demo-python-venv", match_count=1,
                                 cve_count=1, link_count=1, ignored_non_cve=0, database_info={"built": "fixture"}, raw_report=raw_report)
        db.add_all([component, vulnerability, run]); db.flush()
        link = models.ComponentVulnerability(component_id=component.id, vulnerability_id=vulnerability.id,
                                             analysis_run_id=run.id, finding_source="GRYPE", finding_severity="HIGH",
                                             fixed_version="2.0", fixed_versions=["2.0"])
        db.add(link); db.commit()
        yield db, user, link, run
    engine.dispose()


def _osv(cve, fixed="999.0"):
    return {"id": cve, "summary": "A later OSV response", "aliases": [],
            "database_specific": {"severity": "LOW"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def test_osv_refresh_keeps_grype_origin_reviews_and_raw_but_adds_new_link(provenance_db, monkeypatch):
    db, user, link, run = provenance_db
    record_action(db, link.id, user, {"expected_revision": 0, "status": "UNDER_INVESTIGATION",
                                    "detail": "설치 환경 확인 중", "assignee_id": user.id,
                                    "due_date": date(2026, 10, 1), "justification": "reviewing", "response": "update"})
    columns = list(models.ComponentVulnerability.__table__.columns)
    original_link = deepcopy(dict(db.execute(select(*columns).where(models.ComponentVulnerability.id == link.id)).mappings().one()))
    original_raw = deepcopy((run.raw_report, run.sbom.raw_document, run.report_sha256, run.sbom_sha256))
    original_action = deepcopy(db.scalar(select(models.VulnerabilityAction)).after_state)
    calls = []

    def query(queries):
        calls.append(queries)
        return [{"vulns": [_osv("CVE-2026-12345"), _osv("CVE-2026-12346", "3.0")]}]

    monkeypatch.setattr("app.services.vulnerabilities.query_osv", query)
    result = scan_sbom(db, link.component.sbom_id)
    current_link = dict(db.execute(select(*columns).where(models.ComponentVulnerability.id == link.id)).mappings().one())
    assert current_link == original_link
    assert (run.raw_report, run.sbom.raw_document, run.report_sha256, run.sbom_sha256) == original_raw
    assert db.scalar(select(models.VulnerabilityAction)).after_state == original_action
    assert link.vulnerability.summary == "Original Grype summary"
    assert calls == [[{"package": {"purl": "pkg:pypi/demo@1.0"}}]]
    assert result["vulnerability_links"] == 2
    assert result["unique_vulnerabilities"] == 2
    added = db.scalar(select(models.ComponentVulnerability).join(models.Vulnerability).where(
        models.Vulnerability.osv_id == "CVE-2026-12346"))
    assert added.finding_source == "OSV"
    assert added.analysis_run_id is None
    assert added.fixed_versions == ["3.0"]
    assert added.review_revision == 0
    assert added.vex_status == "AFFECTED"


def test_osv_origin_can_refresh_without_resetting_review(provenance_db, monkeypatch):
    db, user, link, _run = provenance_db
    link.analysis_run_id = None
    link.finding_source = "OSV"
    db.commit()
    record_action(db, link.id, user, {"expected_revision": 0, "status": "NOT_AFFECTED", "detail": "수동 영향 검토 결과"})
    monkeypatch.setattr("app.services.vulnerabilities.query_osv", lambda _queries: [{"vulns": [_osv("CVE-2026-12345", "4.0")]}])
    scan_sbom(db, link.component.sbom_id)
    db.refresh(link)
    assert link.finding_source == "OSV"
    assert link.analysis_run_id is None
    assert link.fixed_versions == ["4.0"]
    assert link.vex_status == "NOT_AFFECTED"
    assert link.detail == "수동 영향 검토 결과"
    assert link.review_revision == 1
