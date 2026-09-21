"""Cancellation and scheduler fairness, with isolated DBs and owned test processes."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import sys
import subprocess
from threading import Event
import time
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import middleware, models, schemas
from app.config import Settings
from app.db import Base, get_db
from app.routers import analyses, analysis_controls
from app.services import analysis_jobs as jobs, analysis_executor as executor, analysis_schedules as schedules
from app.services.auth import create_access_token


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///' + str(tmp_path / 'controls.db'), connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    settings = Settings(analysis_artifacts_dir=str(tmp_path / 'artifacts'), analysis_job_lease_seconds=60)
    for module in (jobs, schedules, middleware):
        monkeypatch.setattr(module, 'SessionLocal', factory)
    monkeypatch.setattr(jobs, 'get_settings', lambda: settings)
    app = FastAPI()
    app.middleware('http')(middleware.authenticate_and_audit)
    app.include_router(analysis_controls.router, prefix='/api')
    app.include_router(analyses.router, prefix='/api')

    def get_session():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = get_session
    with factory() as db:
        admin = models.User(username='cancel-admin', password_hash='unused', role='ADMIN')
        viewer = models.User(username='cancel-viewer', password_hash='unused', role='VIEWER')
        db.add_all([admin, viewer]); db.commit()
        admin_token = create_access_token(admin)[0]
        viewer_token = create_access_token(viewer)[0]
    with TestClient(app) as client:
        client.headers['Authorization'] = 'Bearer ' + admin_token
        yield SimpleNamespace(db=factory, settings=settings, client=client, viewer_token=viewer_token)
    engine.dispose()


def asset(env, number):
    with env.db() as db:
        item = models.Asset(asset_tag=f'CANCEL-{number}', name=f'Target {number}', asset_type='server',
                            monitored=True, ip_address='192.0.2.10', ssh_username='scan', ssh_port=22)
        db.add(item); db.commit()
        return item.id


def new_job(env, number=1, status='QUEUED'):
    asset_id = asset(env, number)
    with env.db() as db:
        job = jobs.enqueue_analysis(db, asset_id)
        if status != 'QUEUED':
            job.status = status
            job.started_at = models.utcnow()
            job.heartbeat_at = models.utcnow()
            job.worker_token = str(uuid4()) if status in (*jobs.RUNNING, 'CANCEL_REQUESTED') else None
            if status not in jobs.ACTIVE:
                job.active_asset_id = None
                job.finished_at = models.utcnow()
            db.commit()
        return job.id, asset_id


def receipt(env, job_id, confirmed=True, wrong_asset=False):
    with env.db() as db:
        job = db.get(models.AnalysisJob, job_id)
        directory = Path(env.settings.analysis_artifacts_dir) / f'job-{job.id}-{job.worker_token}'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'manifest.json').write_text(json.dumps({'asset_id': job.asset_id + int(wrong_asset),
            'finished_at': models.utcnow().isoformat(), 'cleanup_confirmed': confirmed}))


def test_queued_cancel_is_immediate_idempotent_audited_and_never_claimed(env):
    job_id, asset_id = new_job(env)
    path = f'/api/analyses/jobs/{job_id}/cancel'
    first = env.client.post(path)
    assert first.status_code == 200
    assert first.json()['status'] == 'CANCELLED'
    assert first.json()['started_at'] is None
    assert first.json()['finished_at']
    assert env.client.post(path).json() == first.json()
    with env.db() as db:
        assert jobs.claim_next_analysis_job(db) is None
        assert db.get(models.AnalysisJob, job_id).active_asset_id is None
        assert db.scalar(select(models.AuditLog).where(models.AuditLog.path == path)).username == 'cancel-admin'
        assert jobs.enqueue_analysis(db, asset_id).id != job_id


@pytest.mark.parametrize('status', ['COLLECTING', 'SCANNING', 'IMPORTING'])
def test_running_cancel_keeps_owner_and_exclusion_until_cleanup(env, status):
    job_id, asset_id = new_job(env, status=status)
    with env.db() as db:
        token = db.get(models.AnalysisJob, job_id).worker_token
    response = env.client.post(f'/api/analyses/jobs/{job_id}/cancel')
    assert response.status_code == 200
    assert response.json()['status'] == 'CANCEL_REQUESTED'
    assert response.json()['finished_at'] is None
    assert env.client.post(f'/api/analyses/jobs/{job_id}/cancel').json()['status'] == 'CANCEL_REQUESTED'
    with env.db() as db:
        job = db.get(models.AnalysisJob, job_id)
        assert job.worker_token == token and job.active_asset_id == asset_id
        with pytest.raises(HTTPException) as error:
            jobs.enqueue_analysis(db, asset_id)
        assert error.value.status_code == 409
    with pytest.raises(jobs.JobCancellationRequested):
        jobs.set_job_stage(job_id, token, status)


@pytest.mark.parametrize('status', ['SUCCESS', 'FAILED'])
def test_completed_jobs_are_not_rewritten_by_cancel(env, status):
    job_id, _ = new_job(env, status=status)
    assert env.client.post(f'/api/analyses/jobs/{job_id}/cancel').status_code == 409
    with env.db() as db:
        assert db.get(models.AnalysisJob, job_id).status == status


def test_cancel_authorization_and_missing_job(env):
    assert env.client.post('/api/analyses/jobs/99999/cancel').status_code == 404
    job_id, _ = new_job(env)
    env.client.headers['Authorization'] = 'Bearer ' + env.viewer_token
    assert env.client.get('/api/analyses/jobs/active').status_code == 200
    assert env.client.post(f'/api/analyses/jobs/{job_id}/cancel').status_code == 403
    env.client.headers.pop('Authorization')
    assert env.client.post(f'/api/analyses/jobs/{job_id}/cancel').status_code == 401


def test_active_tracking_includes_old_jobs_and_cancellation_beyond_history_limit(env):
    oldest, _ = new_job(env, status='CANCEL_REQUESTED')
    for number in range(2, 112):
        new_job(env, number)
    for number in range(112, 222):
        new_job(env, number, 'SUCCESS')
    response = env.client.get('/api/analyses/jobs/active')
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 111 and rows[0]['id'] == oldest
    assert rows[0]['status'] == 'CANCEL_REQUESTED'
    assert all(row['status'] in jobs.ACTIVE for row in rows)


@pytest.mark.parametrize('proof', ['missing', 'unconfirmed', 'wrong-asset', 'confirmed'])
def test_stale_cancel_requires_positive_cleanup_receipt(env, proof):
    job_id, asset_id = new_job(env, status='CANCEL_REQUESTED')
    if proof != 'missing':
        receipt(env, job_id, confirmed=proof != 'unconfirmed', wrong_asset=proof == 'wrong-asset')
    with env.db() as db:
        job = db.get(models.AnalysisJob, job_id)
        job.heartbeat_at = models.utcnow() - timedelta(minutes=10)
        token = job.worker_token
        db.commit()
        assert jobs.recover_stale_jobs(db) == int(proof == 'confirmed')
        db.commit(); db.expire_all()
        job = db.get(models.AnalysisJob, job_id)
        if proof == 'confirmed':
            assert job.status == 'CANCELLED' and job.active_asset_id is None
            assert job.worker_token is None
        else:
            assert job.status == 'CANCEL_REQUESTED' and job.active_asset_id == asset_id
            assert job.worker_token == token and job.error_code == 'CANCEL_CLEANUP_REQUIRED'


def test_worker_cancel_stops_owned_process_before_releasing_asset(env, monkeypatch):
    job_id, asset_id = new_job(env)
    cleanup_reached, allow_receipt = Event(), Event()
    pid_path = Path(env.settings.analysis_artifacts_dir) / 'owned-test.pid'
    monkeypatch.setattr(executor, 'HEARTBEAT_SECONDS', 0.01)

    def execute(snapshot, directory, settings, callback):
        run = executor._Run(snapshot, directory, callback)
        try:
            code = 'import os,pathlib,time; pathlib.Path(' + repr(str(pid_path)) + ').write_text(str(os.getpid())); time.sleep(30)'
            run.local('cancel-test', [sys.executable, '-c', code], 10, dict(os.environ))
        finally:
            cleanup_reached.set()
            assert allow_receipt.wait(5)
            run.finish()

    monkeypatch.setattr(jobs, 'execute_analysis', execute)
    monkeypatch.setattr(jobs, 'import_analysis', lambda *_args, **_kwargs: pytest.fail('Cancelled work must not import'))
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(jobs.process_next_analysis_job)
        deadline = time.monotonic() + 5
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_path.exists()
        try:
            assert env.client.post(f'/api/analyses/jobs/{job_id}/cancel').json()['status'] == 'CANCEL_REQUESTED'
            assert cleanup_reached.wait(5)
            with pytest.raises(ProcessLookupError):
                os.kill(int(pid_path.read_text()), 0)
            with env.db() as db:
                assert db.get(models.AnalysisJob, job_id).active_asset_id == asset_id
        finally:
            allow_receipt.set()
        assert future.result(timeout=5) == job_id
    with env.db() as db:
        job = db.get(models.AnalysisJob, job_id)
        assert job.status == 'CANCELLED' and job.active_asset_id is None
        assert db.scalar(select(func.count()).select_from(models.AnalysisRun)) == 0


def test_cancel_after_tools_finish_prevents_import(env, monkeypatch):
    job_id, _ = new_job(env)

    def execute(snapshot, directory, settings, callback):
        run = executor._Run(snapshot, directory, callback); run.finish()
        with env.db() as db:
            jobs.cancel_analysis(db, job_id)
        return {}

    monkeypatch.setattr(jobs, 'execute_analysis', execute)
    monkeypatch.setattr(jobs, 'import_analysis', lambda *_args, **_kwargs: pytest.fail('Cancellation won before import'))
    assert jobs.process_next_analysis_job() == job_id
    with env.db() as db:
        assert db.get(models.AnalysisJob, job_id).status == 'CANCELLED'


def test_cancel_before_executor_needs_no_process_receipt(env, monkeypatch):
    job_id, _ = new_job(env)
    check_target = jobs._check_target

    def check(db, snapshot):
        check_target(db, snapshot)
        with env.db() as other:
            jobs.cancel_analysis(other, job_id)

    monkeypatch.setattr(jobs, '_check_target', check)
    monkeypatch.setattr(jobs, 'execute_analysis', lambda *_args: pytest.fail('No tool may start'))
    assert jobs.process_next_analysis_job() == job_id
    with env.db() as db:
        assert db.get(models.AnalysisJob, job_id).status == 'CANCELLED'


def test_remote_channel_closed_without_exit_status_is_not_cleanup_proof(tmp_path, monkeypatch):
    channel = SimpleNamespace(recv_ready=lambda: False, recv_stderr_ready=lambda: False,
        exit_status_ready=lambda: True, recv_exit_status=lambda: -1, close=lambda: None)
    client = SimpleNamespace(exec_command=lambda *_args, **_kwargs: (None, SimpleNamespace(channel=channel), None))
    monkeypatch.setattr(executor, '_cancel_remote', lambda *_args: False)
    run = executor._Run({'id': 1}, tmp_path, lambda _stage: None)
    with pytest.raises(executor.AnalysisExecutionError):
        run.remote(client, 'lost-connection', ['syft', 'scan'], 1,
                   pid_file='/home/scan/analysis-' + 'a' * 32 + '.pid')
    run.finish()
    assert json.loads((tmp_path / 'manifest.json').read_text())['cleanup_confirmed'] is False


def test_import_transaction_winning_race_returns_success_and_rejects_cancel(env, monkeypatch):
    job_id, _ = new_job(env)
    import_entered, allow_import, cancel_started = Event(), Event(), Event()
    sbom = json.loads((Path(__file__).parents[2] / 'samples/spdx-2.3-blackduck-compatible.json').read_text())
    sbom['documentNamespace'] = 'https://eolwatch.local/spdx/cancel-race/' + str(uuid4())
    bundle = {'sbom': sbom, 'scan_scope': 'ubuntu-dpkg-installed',
              'report': {'descriptor': {'name': 'grype', 'version': 'cancel-test', 'db': {}},
                         'source': {'type': 'sbom'}, 'matches': []}}
    actual_import = jobs.import_analysis

    def execute(snapshot, directory, settings, callback):
        run = executor._Run(snapshot, directory, callback); run.finish()
        return bundle

    def importing(*args, **kwargs):
        import_entered.set()
        assert allow_import.wait(5)
        return actual_import(*args, **kwargs)

    def cancel():
        cancel_started.set()
        return env.client.post(f'/api/analyses/jobs/{job_id}/cancel')

    monkeypatch.setattr(jobs, 'execute_analysis', execute)
    monkeypatch.setattr(jobs, 'import_analysis', importing)
    with ThreadPoolExecutor(max_workers=2) as pool:
        running = pool.submit(jobs.process_next_analysis_job)
        try:
            assert import_entered.wait(5)
            cancelling = pool.submit(cancel)
            assert cancel_started.wait(5)
            time.sleep(0.05)
        finally:
            allow_import.set()
        assert running.result(timeout=5) == job_id
        assert cancelling.result(timeout=5).status_code == 409
    with env.db() as db:
        job = db.get(models.AnalysisJob, job_id)
        assert job.status == 'SUCCESS' and job.analysis_run_id
        assert db.scalar(select(func.count()).select_from(models.AnalysisRun)) == 1


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Remote targets use Linux /proc for process identity')
@pytest.mark.parametrize('matching_identity', [True, False])
def test_remote_cleanup_checks_identity_and_confirms_process_exit(tmp_path, matching_identity):
    pid_file = tmp_path / ('analysis-' + uuid4().hex + '.pid')
    config = str(pid_file.with_suffix('.json'))
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)',
                                config if matching_identity else config + '.different-run'], start_new_session=True)
    pid_file.write_text(str(process.pid))

    def execute(command, **kwargs):
        result = subprocess.run(command, shell=True, capture_output=True, timeout=7)
        channel = SimpleNamespace(exit_status_ready=lambda: True, recv_exit_status=lambda: result.returncode,
                                  close=lambda: None)
        return None, SimpleNamespace(channel=channel), None

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            if matching_identity:
                reaped = pool.submit(process.wait, timeout=7)
            assert executor._cancel_remote(SimpleNamespace(exec_command=execute), str(pid_file)) is matching_identity
            if matching_identity:
                assert reaped.result(timeout=2) == -9
            else:
                assert process.poll() is None
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
        process.wait(timeout=5)


def test_scheduler_progresses_past_fifty_blocked_due_targets(env):
    due = models.utcnow() - timedelta(hours=1)
    for number in range(1, 52):
        if number <= 50:
            _, asset_id = new_job(env, number)
        else:
            asset_id = asset(env, number)
        with env.db() as db:
            db.add(models.AnalysisSchedule(asset_id=asset_id,
                input_spec={'scan_scope': 'ssh-python-environment', 'target_path': '/srv/app'},
                scan_scope='ssh-python-environment:/srv/app', interval_minutes=5,
                enabled=True, next_run_at=due))
            db.commit()
    assert schedules.enqueue_due_schedules() == 0
    assert schedules.enqueue_due_schedules() == 1
    with env.db() as db:
        last = db.scalar(select(models.AnalysisSchedule).order_by(models.AnalysisSchedule.id.desc()))
        assert last.last_job_id is not None
        assert db.get(models.AnalysisJob, last.last_job_id).asset_id == last.asset_id
        blocked = db.scalars(select(models.AnalysisSchedule).where(models.AnalysisSchedule.id != last.id)).all()
        assert all(item.last_error and item.last_job_id is None for item in blocked)
        assert all(item.next_run_at.replace(tzinfo=None) == due.replace(tzinfo=None) for item in blocked)


def test_cancelled_active_job_does_not_consume_scheduled_occurrence(env):
    job_id, asset_id = new_job(env, status='CANCEL_REQUESTED')
    with env.db() as db:
        schedule = models.AnalysisSchedule(asset_id=asset_id, input_spec={'scan_scope': 'ubuntu-dpkg-installed', 'target_path': None},
            scan_scope='ubuntu-dpkg-installed', interval_minutes=5, enabled=True,
            next_run_at=models.utcnow() - timedelta(minutes=1))
        db.add(schedule); db.commit()
        schedule_id = schedule.id
    assert schedules.enqueue_due_schedules() == 0
    with env.db() as db:
        schedule = db.get(models.AnalysisSchedule, schedule_id)
        assert schedule.last_job_id is None and schedule.last_error
    receipt(env, job_id)
    with env.db() as db:
        job = db.get(models.AnalysisJob, job_id)
        assert jobs._acknowledge_cancellation(db, job)
        db.commit()
    assert schedules.enqueue_due_schedules() == 1
