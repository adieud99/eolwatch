"""Latest analysis metadata stays separate from historical mutable VEX counts."""

from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/eolwatch-test.db")

from app import models
from app.db import Base
from app.routers.dashboard import latest_analysis_overview, summary


NOW = datetime(2026, 9, 15, 8, tzinfo=timezone.utc)
APP = "demo-python-venv"
OS = "ubuntu-dpkg-installed"


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([models.Asset(id=i, asset_tag=f"VM-{i}", name=f"Server {i}", asset_type="vm") for i in (1, 2, 3)])
        session.commit()
        yield session
    engine.dispose()


def run(db, identity, asset_id=1, scope=APP, count=3, at=NOW):
    sbom = models.SbomDocument(id=identity, serial_number=f"sbom-{identity}", spec_version="2.3", asset_id=asset_id, component_count=1, raw_document={"packages": ["original-sbom"]})
    record = models.AnalysisRun(id=identity, sbom=sbom, report_sha256=f"{identity:064x}", sbom_sha256="a" * 64, scanner="grype", scanner_version="1", generator="syft", scan_scope=scope, match_count=count, cve_count=count, link_count=count, ignored_non_cve=0, raw_report={"matches": ["original-evidence"]}, imported_at=at)
    db.add(record); db.flush()
    return record


def job(db, identity, status, asset_id=1, scope=APP, at=NOW + timedelta(hours=1)):
    record = models.AnalysisJob(id=identity, asset_id=asset_id, asset_snapshot={"scan_scope": scope, "ssh_username": "private-collector"}, status=status, requested_at=at)
    db.add(record); db.flush()
    return record


def test_latest_success_per_asset_and_scope_uses_time_then_id_includes_zero(db):
    run(db, 1, count=3)
    run(db, 2, count=0, at=NOW + timedelta(minutes=1))
    run(db, 3, scope=OS, count=3216)
    run(db, 4, asset_id=2, count=7)
    run(db, 5, asset_id=None, count=100)
    run(db, 6, count=99, at=NOW - timedelta(days=1))
    run(db, 7, asset_id=2, count=2)
    db.commit()
    rows = {(item.asset_id, item.scan_scope): item for item in latest_analysis_overview(db)}
    assert set(rows) == {(1, APP), (1, OS), (2, APP)}
    assert rows[(1, APP)].analysis_run_id == 2
    assert rows[(1, APP)].cve_count == 0
    assert rows[(1, OS)].cve_count == 3216
    assert rows[(2, APP)].analysis_run_id == 7
    assert rows[(2, APP)].cve_count == 2


@pytest.mark.parametrize("status", ["QUEUED", "COLLECTING", "SCANNING", "IMPORTING", "FAILED"])
def test_pending_or_failed_new_attempt_preserves_dated_last_success(db, status):
    success = run(db, 1, count=0)
    attempt = job(db, 2, status)
    job(db, 3, "FAILED", asset_id=3, scope=OS)
    db.commit()
    rows = {(item.asset_id, item.scan_scope): item for item in latest_analysis_overview(db)}
    app = rows[(1, APP)]
    assert app.analysis_run_id == success.id and app.sbom_id == success.sbom_id
    assert app.cve_count == 0 and app.last_success_at
    assert app.latest_attempt_status == status
    assert app.latest_attempt_id == attempt.id
    assert app.latest_attempt_is_newer
    assert rows[(3, OS)].analysis_run_id is None
    assert rows[(3, OS)].cve_count is None
    assert rows[(3, OS)].latest_attempt_status == "FAILED"


def test_latest_job_uses_request_time_and_id_and_legacy_os_scope(db):
    run(db, 1, scope=OS, at=NOW + timedelta(hours=2))
    old = job(db, 10, "FAILED", scope=OS, at=NOW - timedelta(hours=1))
    old.asset_snapshot = {"ssh_username": "private-collector"}
    first = job(db, 11, "FAILED", scope=OS, at=NOW)
    second = job(db, 12, "SUCCESS", scope=OS, at=NOW)
    second.analysis_run_id = 1
    db.commit()
    row = latest_analysis_overview(db)[0]
    assert row.latest_attempt_id == second.id
    assert row.latest_attempt_status == "SUCCESS"
    assert not row.latest_attempt_is_newer
    assert "private-collector" not in row.model_dump_json()


def test_vex_changes_affect_historical_open_count_but_not_run_count_or_history(db):
    historical = run(db, 1, count=1)
    latest = run(db, 2, count=0, at=NOW + timedelta(minutes=1))
    component = models.Component(sbom_id=historical.sbom_id, bom_ref="pkg", name="jinja2", version="3.1.4")
    vulnerability = models.Vulnerability(osv_id="CVE-2025-27516")
    db.add_all([component, vulnerability]); db.flush()
    link = models.ComponentVulnerability(component_id=component.id, vulnerability_id=vulnerability.id, vex_status="AFFECTED", analysis_run_id=historical.id)
    db.add(link); db.commit()
    before = summary(db)
    assert before.open_cves == 1
    # The open finding sits on the superseded SBOM, so the current-inventory view is clean.
    assert before.current_open_cves == 0 and before.current_affected_assets == 0
    assert before.affected_assets == 1
    assert before.latest_analyses[0].cve_count == 0
    link.vex_status = "FIXED"; db.commit()
    after = summary(db)
    assert after.open_cves == 0
    assert after.latest_analyses[0].analysis_run_id == latest.id
    assert after.latest_analyses[0].cve_count == 0
    assert db.scalars(select(models.AnalysisRun).order_by(models.AnalysisRun.id)).all() == [historical, latest]
    assert historical.cve_count == 1
    assert historical.raw_report == {"matches": ["original-evidence"]}


def test_latest_overview_does_not_fetch_large_raw_evidence(db):
    run(db, 1); job(db, 1, "SUCCESS"); db.commit()
    statements = []
    def record_query(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    event.listen(db.bind, "before_cursor_execute", record_query)
    try:
        assert latest_analysis_overview(db)[0].cve_count == 3
    finally:
        event.remove(db.bind, "before_cursor_execute", record_query)
    assert statements
    assert all("raw_report" not in statement and "raw_document" not in statement for statement in statements)
