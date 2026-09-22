"""Verify durable web analysis jobs using isolated DBs and no external scanners."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

os.environ["DATABASE_URL"] = "sqlite:////tmp/eolwatch-test.db"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import main, middleware, models
from app.db import Base, get_db


@pytest.fixture
def jobs_db(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'analysis-jobs.db'}",
        connect_args={"check_same_thread": False},
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
def client(jobs_db):
    with TestClient(main.app) as test_client:
        response = test_client.post(
            "/api/auth/login", json={"username": "admin", "password": "Eolwatch!2026"}
        )
        assert response.status_code == 200, response.text
        test_client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"
        yield test_client


@pytest.fixture
def target(client):
    response = client.post(
        "/api/assets",
        json={
            "asset_tag": "QUEUED-SRV-01",
            "name": "웹 분석 대상",
            "asset_type": "server",
            "monitored": True,
            "ip_address": "192.0.2.10",
            "ssh_port": 2222,
            "ssh_username": "scanner",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def enqueue(client, target):
    response = client.post(f"/api/analyses/assets/{target['id']}/jobs")
    assert response.status_code == 202, response.text
    return response.json()


def count_rows(factory, model):
    with factory() as db:
        return db.scalar(select(func.count()).select_from(model))


def finish_job(factory, job_id, status="FAILED"):
    with factory() as db:
        job = db.get(models.AnalysisJob, job_id)
        job.status = status
        job.active_asset_id = None
        job.finished_at = datetime.now(timezone.utc)
        job.error_code = "TEST_FAILURE" if status == "FAILED" else None
        job.error_message = "Synthetic test failure" if status == "FAILED" else None
        db.commit()


def test_enqueue_is_durable_and_active_requests_share_one_job(client, target, jobs_db):
    first = enqueue(client, target)
    second = enqueue(client, target)
    assert first == second
    assert first["asset_id"] == target["id"]
    assert first["asset_tag"] == target["asset_tag"]
    assert first["asset_name"] == target["name"]
    assert first["status"] == "QUEUED"
    assert first["requested_at"]
    for field in ("started_at", "finished_at", "error_code", "error_message", "analysis_run_id", "sbom_id", "retry_of_id"):
        assert first[field] is None
    assert {"worker_token", "active_asset_id", "ssh_key", "ssh_private_key", "token"}.isdisjoint(first)
    assert client.get("/api/analyses/jobs").json() == [first]
    assert count_rows(jobs_db, models.AnalysisJob) == 1
    with jobs_db() as db:
        assert db.get(models.AnalysisJob, first["id"]).active_asset_id == target["id"]
    assert count_rows(jobs_db, models.AnalysisRun) == 0


def test_explicit_os_scope_is_saved_and_retry_preserves_it(client, target, jobs_db):
    response = client.post(f"/api/analyses/assets/{target['id']}/jobs", json={"scan_scope": "ubuntu-dpkg-installed"})
    assert response.status_code == 202, response.text
    first = response.json()
    assert first['scan_scope'] == 'ubuntu-dpkg-installed' and first['input_type'] == 'ssh'
    with jobs_db() as db:
        assert db.get(models.AnalysisJob, first['id']).asset_snapshot['scan_scope'] == 'ubuntu-dpkg-installed'
    assert client.post(f"/api/analyses/assets/{target['id']}/jobs").json()['id'] == first['id']
    finish_job(jobs_db, first['id'])
    retry = client.post(f"/api/analyses/jobs/{first['id']}/retry")
    assert retry.status_code == 202, retry.text
    assert retry.json()['scan_scope'] == 'ubuntu-dpkg-installed'
    assert retry.json()['retry_of_id'] == first['id']


@pytest.mark.parametrize('payload', [{'scan_scope': 'dir:/etc'}, {'scan_scope': 'ssh-project-directory', 'target_path': '/srv/app'},
                                     {'scan_scope': 'demo-python-venv'}, {'scan_scope': 'ubuntu-dpkg-installed', 'target_path': '/etc'}])
def test_scope_does_not_allow_other_profiles_or_directories(client, target, jobs_db, payload):
    response = client.post(f"/api/analyses/assets/{target['id']}/jobs", json=payload)
    assert response.status_code == 422
    assert count_rows(jobs_db, models.AnalysisJob) == 0


@pytest.mark.parametrize("missing", ["monitored", "ip_address", "ssh_username"])
def test_target_must_be_configured_before_it_can_be_queued(client, target, jobs_db, missing):
    with jobs_db() as db:
        asset = db.get(models.Asset, target["id"])
        setattr(asset, missing, False if missing == "monitored" else None)
        db.commit()
    response = client.post(f"/api/analyses/assets/{target['id']}/jobs")
    assert response.status_code == 422, response.text
    assert count_rows(jobs_db, models.AnalysisJob) == 0


def test_missing_target_and_retry_have_clear_not_found_responses(client, jobs_db):
    assert client.post("/api/analyses/assets/999999/jobs").status_code == 404
    assert client.post("/api/analyses/jobs/999999/retry").status_code == 404
    assert count_rows(jobs_db, models.AnalysisJob) == 0


@pytest.mark.parametrize("field", ["ssh_private_key", "token", "scan_command"])
def test_request_does_not_accept_credentials_or_commands(client, target, jobs_db, field):
    response = client.post(
        f"/api/analyses/assets/{target['id']}/jobs", json={field: "forbidden-input"}
    )
    assert response.status_code == 422, response.text
    assert count_rows(jobs_db, models.AnalysisJob) == 0


def test_retry_creates_new_history_and_finished_jobs_allow_a_new_request(client, target, jobs_db):
    first = enqueue(client, target)
    assert client.post(f"/api/analyses/jobs/{first['id']}/retry").status_code == 409
    finish_job(jobs_db, first["id"])

    response = client.post(f"/api/analyses/jobs/{first['id']}/retry")
    assert response.status_code == 202, response.text
    retry = response.json()
    assert retry["id"] != first["id"]
    assert retry["retry_of_id"] == first["id"]
    assert retry["status"] == "QUEUED"
    assert retry["error_code"] is None
    assert client.post(f"/api/analyses/jobs/{first['id']}/retry").json()["id"] == retry["id"]
    assert enqueue(client, target)["id"] == retry["id"]

    history = client.get("/api/analyses/jobs").json()
    original = next(job for job in history if job["id"] == first["id"])
    assert original["status"] == "FAILED"
    assert original["error_code"] == "TEST_FAILURE"
    assert original["finished_at"]

    finish_job(jobs_db, retry["id"], status="SUCCESS")
    assert client.post(f"/api/analyses/jobs/{retry['id']}/retry").status_code == 409
    fresh = enqueue(client, target)
    assert fresh["id"] not in {first["id"], retry["id"]}
    assert fresh["retry_of_id"] is None
    assert count_rows(jobs_db, models.AnalysisJob) == 3


def test_viewer_can_follow_jobs_but_only_admin_can_enqueue_or_retry(client, target, jobs_db):
    job = enqueue(client, target)
    finish_job(jobs_db, job["id"])
    response = client.post(
        "/api/auth/users",
        json={"username": "jobs-viewer", "password": "Viewer!2026", "role": "VIEWER"},
    )
    assert response.status_code == 201, response.text
    login = client.post(
        "/api/auth/login", json={"username": "jobs-viewer", "password": "Viewer!2026"}
    )
    assert login.status_code == 200, login.text
    client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
    assert client.get("/api/analyses/jobs").status_code == 200
    assert client.post(f"/api/analyses/assets/{target['id']}/jobs").status_code == 403
    assert client.post(f"/api/analyses/jobs/{job['id']}/retry").status_code == 403
    assert count_rows(jobs_db, models.AnalysisJob) == 1
    client.headers.pop("Authorization")
    assert client.get("/api/analyses/jobs").status_code == 401
    assert client.post(f"/api/analyses/assets/{target['id']}/jobs").status_code == 401


@pytest.fixture
def scan_bundle(target):
    sample = Path(__file__).parents[2] / "samples" / "spdx-2.3-blackduck-compatible.json"
    sbom = json.loads(sample.read_text(encoding="utf-8"))
    sbom["documentNamespace"] = f"https://eolwatch.local/spdx/jobs-test/{uuid4()}"
    sbom["creationInfo"]["creators"] = ["Tool: syft-job-test-fixture"]
    return {
        "sbom": sbom,
        "scan_scope": "test dpkg package inventory",
        "report": {
            "descriptor": {"name": "grype", "version": "job-test-fixture", "db": {}},
            "source": {"type": "sbom", "target": "synthetic.spdx.json"},
            "matches": [{
                "artifact": {"name": "Jinja2", "version": "2.4.1", "purl": "pkg:pypi/jinja2@2.4.1"},
                "vulnerability": {
                    "id": "CVE-2026-12345", "severity": "High",
                    "description": "Synthetic finding used only by this test.",
                    "fix": {"state": "fixed", "versions": ["2.11.3"]},
                },
                "relatedVulnerabilities": [],
            }],
        },
    }


@pytest.fixture
def worker(jobs_db, monkeypatch, tmp_path):
    from app.config import get_settings
    from app.services import analysis_jobs

    settings = get_settings().model_copy(update={
        "analysis_artifacts_dir": str(tmp_path / "artifacts"),
        "analysis_cache_dir": str(tmp_path / "cache"),
        "analysis_job_lease_seconds": 180,
    })
    monkeypatch.setattr(analysis_jobs, "SessionLocal", jobs_db)
    monkeypatch.setattr(analysis_jobs, "get_settings", lambda: settings)
    return analysis_jobs


def test_worker_publishes_stages_and_links_saved_results(client, target, jobs_db, worker, scan_bundle, monkeypatch):
    queued = enqueue(client, target)
    stages = []

    def execute(snapshot, output_dir, settings, stage_callback):
        assert snapshot["id"] == target["id"]
        assert snapshot["ip_address"] == "192.0.2.10"
        assert snapshot["ssh_username"] == "scanner"
        assert snapshot["ssh_port"] == 2222
        assert Path(output_dir).is_relative_to(Path(settings.analysis_artifacts_dir))
        for stage in ("COLLECTING", "SCANNING", "IMPORTING"):
            stage_callback(stage)
            # Separate session proves progress is visible to a polling web request.
            with jobs_db() as db:
                running = db.get(models.AnalysisJob, queued["id"])
                assert running.status == stage
                assert running.started_at is not None
                assert running.heartbeat_at is not None
                assert running.active_asset_id == target["id"]
                assert running.finished_at is None
            stages.append(stage)
        return deepcopy(scan_bundle)

    monkeypatch.setattr(worker, "execute_analysis", execute)
    assert worker.process_next_analysis_job() == queued["id"]
    assert stages == ["COLLECTING", "SCANNING", "IMPORTING"]
    job = client.get("/api/analyses/jobs").json()[0]
    assert job["status"] == "SUCCESS"
    assert job["started_at"] and job["finished_at"]
    assert job["error_code"] is None
    assert job["error_message"] is None
    run = client.get("/api/analyses").json()[0]
    assert job["analysis_run_id"] == run["id"]
    assert job["sbom_id"] == run["sbom_id"]
    assert (run["component_count"], run["cve_count"], run["link_count"]) == (1, 1, 1)
    finding = client.get(f"/api/vulnerabilities?sbom_id={job['sbom_id']}").json()[0]
    assert finding["asset_tag"] == target["asset_tag"]
    assert finding["cve_id"] == "CVE-2026-12345"
    with jobs_db() as db:
        assert db.get(models.AnalysisJob, job["id"]).active_asset_id is None
    assert worker.process_next_analysis_job() is None
    assert enqueue(client, target)["id"] != queued["id"]


def test_executor_failure_is_persisted_and_allows_retry(client, target, jobs_db, worker, monkeypatch):
    queued = enqueue(client, target)

    def fail(snapshot, output_dir, settings, stage_callback):
        stage_callback("SCANNING")
        raise RuntimeError("private-key-do-not-expose")

    monkeypatch.setattr(worker, "execute_analysis", fail)
    assert worker.process_next_analysis_job() == queued["id"]
    job = client.get("/api/analyses/jobs").json()[0]
    assert job["status"] == "FAILED"
    assert job["started_at"] and job["finished_at"]
    assert job["error_code"]
    assert job["error_message"]
    assert "private-key-do-not-expose" not in json.dumps(job)
    assert job["analysis_run_id"] is None
    assert job["sbom_id"] is None
    assert count_rows(jobs_db, models.AnalysisRun) == 0
    assert count_rows(jobs_db, models.SbomDocument) == 0
    with jobs_db() as db:
        assert db.get(models.AnalysisJob, queued["id"]).active_asset_id is None
    retry = client.post(f"/api/analyses/jobs/{queued['id']}/retry")
    assert retry.status_code == 202, retry.text
    assert retry.json()["retry_of_id"] == queued["id"]


def test_invalid_scan_bundle_rolls_back_partial_evidence_and_fails_job(client, target, jobs_db, worker, scan_bundle, monkeypatch):
    queued = enqueue(client, target)
    mismatch = deepcopy(scan_bundle["report"]["matches"][0])
    mismatch["artifact"]["purl"] = "pkg:pypi/jinja2@9.9.9"
    scan_bundle["report"]["matches"].append(mismatch)
    monkeypatch.setattr(worker, "execute_analysis", lambda *args, **kwargs: deepcopy(scan_bundle))

    assert worker.process_next_analysis_job() == queued["id"]
    job = client.get("/api/analyses/jobs").json()[0]
    assert job["status"] == "FAILED"
    assert job["error_code"]
    assert job["finished_at"]
    assert job["analysis_run_id"] is None
    assert job["sbom_id"] is None
    for model in (models.SbomDocument, models.AnalysisRun, models.Component, models.ProductRelease, models.Vulnerability, models.ComponentVulnerability):
        assert count_rows(jobs_db, model) == 0, model.__name__
    assert count_rows(jobs_db, models.AnalysisJob) == 1
    assert count_rows(jobs_db, models.Asset) == 1
    assert enqueue(client, target)["id"] != queued["id"]


@pytest.mark.parametrize("when", ["before_execution", "during_execution"])
def test_changed_target_cannot_receive_results_from_old_connection(client, target, jobs_db, worker, scan_bundle, monkeypatch, when):
    queued = enqueue(client, target)
    executed = []

    def change_target():
        with jobs_db() as db:
            db.get(models.Asset, target["id"]).ip_address = "192.0.2.11"
            db.commit()

    def execute(snapshot, output_dir, settings, stage_callback):
        executed.append(snapshot["ip_address"])
        change_target()
        return deepcopy(scan_bundle)

    if when == "before_execution":
        change_target()
    monkeypatch.setattr(worker, "execute_analysis", execute)
    assert worker.process_next_analysis_job() == queued["id"]
    assert executed == ([] if when == "before_execution" else ["192.0.2.10"])
    job = client.get("/api/analyses/jobs").json()[0]
    assert job["status"] == "FAILED"
    assert job["analysis_run_id"] is None
    assert job["sbom_id"] is None
    assert count_rows(jobs_db, models.AnalysisRun) == 0
    assert count_rows(jobs_db, models.SbomDocument) == 0
    retry = client.post(f"/api/analyses/jobs/{queued['id']}/retry")
    assert retry.status_code == 202, retry.text
    with jobs_db() as db:
        assert db.get(models.AnalysisJob, retry.json()["id"]).asset_snapshot["ip_address"] == "192.0.2.11"


def test_stale_worker_is_failed_without_touching_queued_jobs(client, target, jobs_db, worker):
    queued = enqueue(client, target)
    with jobs_db() as db:
        claimed = worker.claim_next_analysis_job(db)
    assert claimed is not None
    assert claimed[0] == queued["id"]
    assert claimed[1]
    with jobs_db() as db:
        # Another worker cannot claim a running job.
        assert worker.claim_next_analysis_job(db) is None
        running = db.get(models.AnalysisJob, queued["id"])
        assert running.status == "COLLECTING"
        running.heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        db.commit()
    with jobs_db() as db:
        assert worker.recover_stale_jobs(db) == 1
        db.commit()
    failed = client.get("/api/analyses/jobs").json()[0]
    assert failed["status"] == "FAILED"
    assert failed["finished_at"]
    assert failed["error_code"]
    assert failed["analysis_run_id"] is None
    retry = client.post(f"/api/analyses/jobs/{queued['id']}/retry")
    assert retry.status_code == 202, retry.text
    with jobs_db() as db:
        assert worker.recover_stale_jobs(db) == 0
        db.commit()
        db.expire_all()
        assert db.get(models.AnalysisJob, retry.json()["id"]).status == "QUEUED"
    with pytest.raises(worker.JobLeaseLost):
        worker.set_job_stage(queued["id"], claimed[1], "SCANNING")
