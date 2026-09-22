"""Real archive/DB/API paths; scanner execution is mocked explicitly."""
from __future__ import annotations

from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import hashlib
from io import BytesIO
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import zipfile
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import main, middleware, models
from app.config import Settings
from app.db import Base, get_db
from app.services import analysis_executor as executor, analysis_jobs as jobs, analysis_schedules as schedules
from app.services.analysis_profiles import (ANALYSIS_PROFILES, SSH_PROJECT_SCAN_SCOPE, SSH_PYTHON_SCAN_SCOPE,
                                            ZIP_SCAN_SCOPE, normalize_target_path, scope_identity)
from app.services.analysis_uploads import InvalidArchive, archive_path, extract_upload, validate_archive
from app.routers import analyses


def source_zip(name='requirements.txt', content=b'Jinja2==3.1.4\n', *, compression=zipfile.ZIP_STORED):
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=compression) as archive:
        archive.writestr(name, content)
    return stream.getvalue()


@pytest.fixture
def settings(tmp_path):
    return Settings(analysis_uploads_dir=str(tmp_path / 'uploads'), analysis_artifacts_dir=str(tmp_path / 'artifacts'),
                    analysis_cache_dir=str(tmp_path / 'cache'))


@pytest.fixture
def factory(tmp_path, monkeypatch, settings):
    engine = create_engine('sqlite:///' + str(tmp_path / 'inputs.db'), connect_args={'check_same_thread': False})
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    for module in (main, middleware, jobs, schedules):
        monkeypatch.setattr(module, 'SessionLocal', factory)
    monkeypatch.setattr(main, 'engine', engine)
    monkeypatch.setattr(jobs, 'get_settings', lambda: settings)
    monkeypatch.setattr(analyses, 'get_settings', lambda: settings)
    def isolated_db():
        with factory() as db:
            yield db
    before = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[get_db] = isolated_db
    yield factory
    main.app.dependency_overrides.clear()
    main.app.dependency_overrides.update(before)
    engine.dispose()


@pytest.fixture
def client(factory):
    with TestClient(main.app) as client:
        response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'Eolwatch!2026'})
        assert response.status_code == 200
        client.headers['Authorization'] = 'Bearer ' + response.json()['access_token']
        yield client


@pytest.fixture
def asset(client):
    response = client.post('/api/assets', json={'asset_tag': 'PROJECT-01', 'name': '앱 분석 대상', 'asset_type': 'server',
        'monitored': True, 'ip_address': '192.0.2.30', 'ssh_username': 'operator'})
    assert response.status_code == 201, response.text
    return response.json()['id']


def complete_job(factory, job_id, status='FAILED'):
    with factory() as db:
        job = db.get(models.AnalysisJob, job_id)
        job.status, job.active_asset_id = status, None
        db.commit()


def test_paths_normalize_identity_and_retries_preserve_target(client, factory, asset):
    request = {'scan_scope': SSH_PROJECT_SCAN_SCOPE, 'target_path': '/srv/apps/./billing/'}
    response = client.post(f'/api/analyses/assets/{asset}/jobs', json=request)
    assert response.status_code == 202, response.text
    first = response.json()
    assert first['scan_scope'] == SSH_PROJECT_SCAN_SCOPE + ':/srv/apps/billing'
    assert first['target_path'] == '/srv/apps/billing'
    assert first['profile'] == SSH_PROJECT_SCAN_SCOPE
    assert client.post(f'/api/analyses/assets/{asset}/jobs', json=request).json()['id'] == first['id']
    request['target_path'] = '/srv/apps/payments'
    assert client.post(f'/api/analyses/assets/{asset}/jobs', json=request).status_code == 409
    complete_job(factory, first['id'])
    retry = client.post(f"/api/analyses/jobs/{first['id']}/retry")
    assert retry.status_code == 202, retry.text
    assert retry.json()['target_path'] == '/srv/apps/billing'
    assert retry.json()['scan_scope'] == first['scan_scope']


@pytest.mark.parametrize('path', [None, '', 'relative/project', '/', '/srv/../etc', '//srv/project', '/srv/app\nother'])
def test_bad_project_paths_rejected_before_enqueue(client, factory, asset, path):
    response = client.post(f'/api/analyses/assets/{asset}/jobs', json={'scan_scope': SSH_PROJECT_SCAN_SCOPE, 'target_path': path})
    assert response.status_code == 422
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(models.AnalysisJob)) == 0


def test_zip_upload_needs_no_ssh_and_survives_session_restart(client, factory, settings):
    response = client.post('/api/assets', json={'asset_tag': 'ZIP-01', 'name': '소스 프로젝트', 'asset_type': 'server'})
    asset_id = response.json()['id']
    archive = source_zip()
    response = client.post(f'/api/analyses/assets/{asset_id}/uploads',
        data={'project_name': 'billing-app'}, files={'file': ('billing.zip', archive, 'application/zip')})
    assert response.status_code == 202, response.text
    job = response.json()
    assert job['input_type'] == 'zip'
    assert job['upload_sha256'] == hashlib.sha256(archive).hexdigest()
    assert job['scan_scope'] == 'source-zip:billing-app'
    assert archive_path(settings, job['upload_sha256']).read_bytes() == archive
    with factory() as db:
        persisted = db.get(models.AnalysisJob, job['id'])
        snapshot = persisted.asset_snapshot.copy()
        assert db.get(models.AnalysisUpload, job['upload_id']).project_name == 'billing-app'
        jobs._check_target(db, snapshot)
    extracted = extract_upload(snapshot, Path(settings.analysis_artifacts_dir) / 'fresh-worker-source', settings)
    assert (extracted / 'requirements.txt').read_text() == 'Jinja2==3.1.4\n'
    complete_job(factory, job['id'])
    retry = client.post(f"/api/analyses/jobs/{job['id']}/retry")
    assert retry.status_code == 202, retry.text
    assert retry.json()['upload_id'] == job['upload_id']
    assert retry.json()['upload_sha256'] == job['upload_sha256']


@pytest.mark.parametrize('name', ['../escape', '/tmp/escape', 'C:/escape', 'a\\b', 'a/../../escape', 'a//b', './escape'])
def test_zip_traversal_never_creates_job(client, factory, settings, asset, name):
    response = client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': 'project'},
        files={'file': ('bad.zip', source_zip(name), 'application/zip')})
    assert response.status_code == 422, response.text
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(models.AnalysisJob)) == 0
        assert db.scalar(select(func.count()).select_from(models.AnalysisUpload)) == 0
    assert not list(Path(settings.analysis_uploads_dir).glob('*.zip'))


@pytest.mark.parametrize('kind', ['symlink', 'ratio', 'entry-count', 'file-size', 'total-size', 'duplicate', 'parent-file'])
def test_archive_rejects_links_bombs_and_conflicting_paths(tmp_path, settings, kind):
    path = tmp_path / 'bad.zip'
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        if kind == 'symlink':
            entry = zipfile.ZipInfo('link')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, '/etc/passwd')
        elif kind == 'ratio':
            archive.writestr('large.txt', b'0' * 100000)
        elif kind == 'entry-count':
            settings.analysis_zip_max_entries = 1
            archive.writestr('a', 'first'); archive.writestr('b', 'second')
        elif kind == 'file-size':
            settings.analysis_zip_max_file_bytes = 3
            archive.writestr('a', '1234')
        elif kind == 'total-size':
            settings.analysis_zip_max_unpacked_bytes = 5
            archive.writestr('a', '123'); archive.writestr('b', '123')
        elif kind == 'duplicate':
            archive.writestr('A.txt', 'first'); archive.writestr('a.txt', 'second')
        else:
            archive.writestr('a', 'file'); archive.writestr('a/b', 'child')
    with pytest.raises(InvalidArchive):
        validate_archive(path, settings)


def test_upload_size_limit_returns_413(client, asset, settings):
    settings.analysis_upload_max_bytes = 10
    response = client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': 'project'},
        files={'file': ('source.zip', source_zip(), 'application/zip')})
    assert response.status_code == 413


def test_mutated_upload_cannot_be_retried_as_different_input(client, factory, settings, asset):
    response = client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': 'project'},
        files={'file': ('source.zip', source_zip(), 'application/zip')})
    job = response.json()
    with factory() as db:
        snapshot = db.get(models.AnalysisJob, job['id']).asset_snapshot.copy()
    path = archive_path(settings, job['upload_sha256'])
    path.chmod(0o600); path.write_bytes(source_zip(content=b'Jinja2==3.1.6\n'))
    with pytest.raises(InvalidArchive, match='해시'):
        extract_upload(snapshot, Path(settings.analysis_artifacts_dir) / 'bad-source', settings)


def test_schedule_is_durable_coalesces_missed_runs_and_can_pause(client, factory, asset):
    request = {'asset_id': asset, 'scan_scope': SSH_PROJECT_SCAN_SCOPE, 'target_path': '/srv/project', 'interval_minutes': 5}
    response = client.post('/api/analyses/schedules', json=request)
    assert response.status_code == 201, response.text
    schedule_id = response.json()['id']
    assert client.post('/api/analyses/schedules', json=request).status_code == 409
    with factory() as db:
        schedule = db.get(models.AnalysisSchedule, schedule_id)
        schedule.next_run_at = models.utcnow() - timedelta(hours=2)
        db.commit()
    assert schedules.enqueue_due_schedules() == 1
    assert schedules.enqueue_due_schedules() == 0
    listed = client.get('/api/analyses/schedules').json()[0]
    assert listed['last_job_id'] is not None
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(models.AnalysisJob)) == 1
    paused = client.patch(f'/api/analyses/schedules/{schedule_id}', json={'enabled': False})

    assert paused.status_code == 200
    with factory() as db:
        db.get(models.AnalysisSchedule, schedule_id).next_run_at = models.utcnow() - timedelta(minutes=1)
        db.commit()
    assert schedules.enqueue_due_schedules() == 0
    assert client.patch(f'/api/analyses/schedules/{schedule_id}', json={'enabled': True, 'interval_minutes': 10}).json()['interval_minutes'] == 10
    assert client.patch(f'/api/analyses/schedules/{schedule_id}', json={'enabled': None}).status_code == 422
    # deleting frees the (asset, scope, path) slot for a new schedule
    assert client.delete(f'/api/analyses/schedules/{schedule_id}').status_code == 204
    assert client.get('/api/analyses/schedules').json() == [] and client.delete(f'/api/analyses/schedules/{schedule_id}').status_code == 404
    assert client.post('/api/analyses/schedules', json=request).status_code == 201


def test_busy_other_scope_keeps_schedule_due_until_asset_is_free(client, factory, asset):
    active = client.post(f'/api/analyses/assets/{asset}/jobs').json()
    response = client.post('/api/analyses/schedules', json={'asset_id': asset, 'scan_scope': SSH_PYTHON_SCAN_SCOPE,
        'target_path': '/srv/venv', 'interval_minutes': 5})
    schedule_id = response.json()['id']
    with factory() as db:
        db.get(models.AnalysisSchedule, schedule_id).next_run_at = models.utcnow() - timedelta(minutes=1)
        db.commit()
    assert schedules.enqueue_due_schedules() == 0
    assert client.get('/api/analyses/schedules').json()[0]['last_error']
    complete_job(factory, active['id'])
    assert schedules.enqueue_due_schedules() == 1
    listed = client.get('/api/analyses/schedules').json()[0]
    assert listed['last_error'] is None
    with factory() as db:
        assert db.get(models.AnalysisJob, listed['last_job_id']).asset_snapshot['target_path'] == '/srv/venv'


def test_due_same_scope_reuses_active_job(client, factory, asset):
    active = client.post(f'/api/analyses/assets/{asset}/jobs').json()
    response = client.post('/api/analyses/schedules', json={'asset_id': asset, 'interval_minutes': 5})
    with factory() as db:
        db.get(models.AnalysisSchedule, response.json()['id']).next_run_at = models.utcnow() - timedelta(minutes=1)
        db.commit()
    assert schedules.enqueue_due_schedules() == 1
    assert client.get('/api/analyses/schedules').json()[0]['last_job_id'] == active['id']
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(models.AnalysisJob)) == 1


def test_zip_pipeline_uses_source_directory_and_exact_spdx(client, factory, settings, asset, monkeypatch):
    response = client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': 'web-api'},
        files={'file': ('source.zip', source_zip(), 'application/zip')})
    with factory() as db:
        snapshot = db.get(models.AnalysisJob, response.json()['id']).asset_snapshot.copy()
    monkeypatch.setattr(executor, '_tools', lambda *_args: (Path('/tools/syft'), Path('/tools/grype'), 'Linux aarch64'))
    def no_ssh(*_args):
        raise AssertionError('ZIP analysis must not access SSH')
    monkeypatch.setattr(executor, '_connect', no_ssh)
    commands = []
    def local(self, name, argv, timeout, env, output=None):
        commands.append((name, argv))
        path = self.directory / (output or name + '.stdout.log')
        if name == 'syft-scan':
            document = {'artifacts': [{'name': 'Jinja2', 'version': '3.1.4', 'type': 'python'}],
                        'source': {'metadata': {'path': str(self.directory / 'source')}},
                        'descriptor': {'configuration': {'catalogers': {'used': ['python-package-cataloger']}}}}
        elif name == 'syft-convert-spdx':
            document = {'spdxVersion': 'SPDX-2.3', 'packages': [{'name': 'Jinja2', 'versionInfo': '3.1.4'}]}
        elif name == 'grype-scan':
            document = {'descriptor': {'name': 'grype'}, 'matches': []}
        else:
            document = {}
        path.write_text(json.dumps(document))
        return path
    monkeypatch.setattr(executor._Run, 'local', local)
    output = Path(settings.analysis_artifacts_dir) / 'mock-worker'
    bundle = executor.execute_analysis(snapshot, output, settings, lambda _stage: None)
    assert bundle['scan_scope'] == 'source-zip:web-api'
    scan = next(argv for name, argv in commands if name == 'syft-scan')
    assert 'dir:' + str(output / 'source') in scan
    assert '--override-default-catalogers' not in scan  # Syft directory defaults include lockfiles.
    grype = next(argv for name, argv in commands if name == 'grype-scan')
    assert 'sbom:' + str(output / 'sbom.spdx.json') in grype
    manifest = json.loads((output / 'manifest.json').read_text())
    assert manifest['upload_sha256'] == snapshot['upload_sha256']
    assert manifest['grype_input_sha256'] == hashlib.sha256((output / 'sbom.spdx.json').read_bytes()).hexdigest()


def test_ssh_path_is_data_and_canonical_redirect_is_rejected():
    dangerous = '/srv/app; touch SHOULD_NOT_EXIST'
    assert normalize_target_path(dangerous) == dangerous
    assert scope_identity(SSH_PROJECT_SCAN_SCOPE, dangerous).endswith(dangerous)
    class Sftp:
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def get_channel(self): return SimpleNamespace(settimeout=lambda _seconds: None)
        def stat(self, _path): return SimpleNamespace(st_mode=stat.S_IFDIR)
        def normalize(self, _path): return '/srv/different'
    client = SimpleNamespace(open_sftp=lambda: Sftp())
    with pytest.raises(executor.AnalysisExecutionError) as error:
        executor._scan_directory(client, ANALYSIS_PROFILES[SSH_PROJECT_SCAN_SCOPE], dangerous)
    assert error.value.code == 'APP_PATH_OUT_OF_SCOPE'


def test_two_schedule_workers_claim_one_occurrence(client, factory, asset):
    created = client.post('/api/analyses/schedules', json={'asset_id': asset, 'interval_minutes': 5}).json()
    with factory() as db:
        db.get(models.AnalysisSchedule, created['id']).next_run_at = models.utcnow() - timedelta(minutes=1)
        db.commit()
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = [pool.submit(schedules.enqueue_due_schedules) for _ in range(2)]
        assert sum(attempt.result() for attempt in attempts) == 1
    with factory() as db:
        assert db.scalar(select(func.count()).select_from(models.AnalysisJob)) == 1


def test_zip_job_worker_imports_and_api_returns_completed_result(client, factory, settings, monkeypatch):
    asset_id = client.post('/api/assets', json={'asset_tag': 'WORKER-ZIP', 'name': 'ZIP 프로젝트', 'asset_type': 'server'}).json()['id']
    job = client.post(f'/api/analyses/assets/{asset_id}/uploads', data={'project_name': 'service'},
        files={'file': ('source.zip', source_zip(), 'application/zip')}).json()
    def execute(snapshot, directory, _settings, callback):
        assert snapshot['upload_sha256'] == job['upload_sha256']
        extract_upload(snapshot, directory / 'source', settings, lambda: callback('COLLECTING'))
        callback('SCANNING')
        document = json.loads((Path(__file__).parents[2] / 'samples' / 'spdx-2.3-blackduck-compatible.json').read_text())
        document['documentNamespace'] = 'https://eolwatch.test/upload/' + str(uuid4())
        return {'scan_scope': snapshot['scan_scope'], 'sbom': document,
            'report': {'descriptor': {'name': 'grype', 'version': 'mock-test', 'db': {}},
                       'source': {'type': 'sbom'}, 'matches': []}}
    monkeypatch.setattr(jobs, 'execute_analysis', execute)
    assert jobs.process_next_analysis_job() == job['id']
    finished = next(item for item in client.get('/api/analyses/jobs').json() if item['id'] == job['id'])
    assert finished['status'] == 'SUCCESS'
    assert finished['sbom_id'] is not None and finished['analysis_run_id'] is not None
    run = next(item for item in client.get('/api/analyses').json() if item['id'] == finished['analysis_run_id'])
    assert run['scan_scope'] == 'source-zip:service'
    assert client.get(f"/api/analyses/{run['id']}/bundle").json()['sbom']['packages']


def test_analysis_comparison_rejects_two_paths_on_same_asset(client, asset):
    ids = []
    for target_path in ('/srv/first-project', '/srv/second-project'):
        document = json.loads((Path(__file__).parents[2] / 'samples' / 'spdx-2.3-blackduck-compatible.json').read_text())
        document['documentNamespace'] = 'https://eolwatch.test/path/' + str(uuid4())
        response = client.post('/api/analyses/import', json={'asset_id': asset,
            'scan_scope': scope_identity(SSH_PROJECT_SCAN_SCOPE, target_path), 'sbom': document,
            'report': {'descriptor': {'name': 'grype', 'version': 'mock-test'}, 'source': {'type': 'sbom'}, 'matches': []}})
        assert response.status_code == 200, response.text
        ids.append(response.json()['id'])
    comparison = client.get(f'/api/analyses/{ids[0]}/compare/{ids[1]}')
    assert comparison.status_code == 409
    assert '범위' in comparison.json()['detail']


# ---- dependency-file uploads and Git repository scans ----

def test_dependency_manifest_upload_is_wrapped_and_scanned_as_source_zip(client, factory, settings, asset, monkeypatch):
    from app.routers import analysis_history
    monkeypatch.setattr(analysis_history, 'get_settings', lambda: settings)
    response = client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': 'billing-api'},
        files={'file': ('requirements.txt', b'Jinja2==3.1.4\nrequests==2.31.0\n', 'text/plain')})
    assert response.status_code == 202, response.text
    job = response.json()
    assert job['scan_scope'] == 'source-zip:billing-api' and job['upload_filename'] == 'requirements.txt'
    stored = archive_path(settings, job['upload_sha256'])
    with zipfile.ZipFile(stored) as archive:
        assert archive.namelist() == ['requirements.txt']
        assert archive.read('requirements.txt') == b'Jinja2==3.1.4\nrequests==2.31.0\n'
    validate_archive(stored, settings)
    download = client.get(f"/api/analyses/uploads/{job['upload_id']}/raw")
    assert download.status_code == 200 and "requirements.txt.zip" in download.headers['content-disposition']
    assert not list(Path(settings.analysis_uploads_dir).glob('.manifest-*'))


@pytest.mark.parametrize('filename', ['notes.md', 'app.py', 'archive.tar.gz'])
def test_unknown_plain_file_is_rejected_without_storing(client, settings, asset, filename):
    response = client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': 'project'},
        files={'file': (filename, b'not a zip', 'application/octet-stream')})
    assert response.status_code == 422
    assert '의존성 파일' in response.json()['detail']
    assert not list(Path(settings.analysis_uploads_dir).glob('*'))


@pytest.mark.parametrize('payload,fragment', [
    ({'repository_url': 'http://github.com/org/repo', 'project_name': 'p'}, 'https://'),
    ({'repository_url': 'https://user:token@github.com/org/repo', 'project_name': 'p'}, '계정 정보'),
    ({'repository_url': 'https://github.com/org/repo', 'ref': '--upload-pack=evil', 'project_name': 'p'}, '브랜치'),
    ({'repository_url': 'https://github.com/org/../repo', 'project_name': 'p'}, 'https://'),
])
def test_git_request_rejects_unsafe_urls_and_refs(client, asset, payload, fragment):
    response = client.post(f'/api/analyses/assets/{asset}/git', json=payload)
    assert response.status_code == 422
    assert fragment in json.dumps(response.json(), ensure_ascii=False)


def test_git_scan_queues_without_ssh_and_hides_the_token(client, factory, asset):
    response = client.post(f'/api/analyses/assets/{asset}/git', json={
        'repository_url': 'https://github.com/example/orders-api.git', 'ref': 'release/1.2',
        'project_name': 'orders-api', 'access_token': 'ghp_secret'})
    assert response.status_code == 202, response.text
    job = response.json()
    assert job['input_type'] == 'git' and job['scan_scope'] == 'source-git:orders-api'
    assert job['git_url'] == 'https://github.com/example/orders-api.git' and job['git_ref'] == 'release/1.2'
    assert 'ghp_secret' not in response.text
    with factory() as db:
        snapshot = db.get(models.AnalysisJob, job['id']).asset_snapshot
    assert snapshot['git_token'] == 'ghp_secret' and snapshot['profile'] == 'source-git'
    listed = client.get('/api/analyses/jobs').json()
    assert 'ghp_secret' not in json.dumps(listed)
    projects = client.get('/api/analyses/projects').json()['items']
    assert projects[0]['scan_scope'] == 'source-git:orders-api' and projects[0]['project_name'] == 'orders-api'
    assert projects[0]['upload_count'] == 0


def test_git_worker_scrubs_token_and_records_commit(client, factory, settings, monkeypatch, asset):
    job = client.post(f'/api/analyses/assets/{asset}/git', json={
        'repository_url': 'https://github.com/example/orders-api', 'project_name': 'orders-api', 'access_token': 'tok'}).json()
    seen = {}
    def execute(snapshot, directory, _settings, callback):
        seen['token'] = snapshot.get('git_token')
        callback('SCANNING')
        document = json.loads((Path(__file__).parents[2] / 'samples' / 'spdx-2.3-blackduck-compatible.json').read_text())
        document['documentNamespace'] = 'https://eolwatch.test/git/' + str(uuid4())
        return {'scan_scope': snapshot['scan_scope'], 'sbom': document, 'git_commit': 'a' * 40,
                'report': {'descriptor': {'name': 'grype', 'version': 'mock-test', 'db': {}}, 'source': {'type': 'sbom'}, 'matches': []}}
    monkeypatch.setattr(jobs, 'execute_analysis', execute)
    assert jobs.process_next_analysis_job() == job['id']
    assert seen['token'] == 'tok'
    finished = client.get(f"/api/analyses/jobs/{job['id']}").json()
    assert finished['status'] == 'SUCCESS' and finished['git_commit'] == 'a' * 40
    with factory() as db:
        snapshot = db.get(models.AnalysisJob, job['id']).asset_snapshot
    assert 'git_token' not in snapshot and snapshot['git_commit'] == 'a' * 40


def test_git_failure_still_scrubs_token_and_retry_keeps_repository(client, factory, monkeypatch, asset):
    job = client.post(f'/api/analyses/assets/{asset}/git', json={
        'repository_url': 'https://gitlab.example.com/team/app', 'ref': 'main', 'project_name': 'app', 'access_token': 'tok'}).json()
    def execute(*_args):
        raise executor.AnalysisExecutionError('GIT_CLONE_FAILED', '저장소를 가져오지 못했습니다.')
    monkeypatch.setattr(jobs, 'execute_analysis', execute)
    assert jobs.process_next_analysis_job() == job['id']
    failed = client.get(f"/api/analyses/jobs/{job['id']}").json()
    assert failed['status'] == 'FAILED' and failed['error_code'] == 'GIT_CLONE_FAILED'
    with factory() as db:
        assert 'git_token' not in db.get(models.AnalysisJob, job['id']).asset_snapshot
    retry = client.post(f"/api/analyses/jobs/{job['id']}/retry")
    assert retry.status_code == 202, retry.text
    assert retry.json()['git_url'] == 'https://gitlab.example.com/team/app' and retry.json()['git_ref'] == 'main'
    assert retry.json()['scan_scope'] == 'source-git:app'


def test_git_pipeline_clones_shallow_without_token_in_argv(client, factory, settings, asset, monkeypatch):
    response = client.post(f'/api/analyses/assets/{asset}/git', json={
        'repository_url': 'https://github.com/example/web-api', 'ref': 'v2', 'project_name': 'web-api', 'access_token': 'secret-token'})
    with factory() as db:
        snapshot = db.get(models.AnalysisJob, response.json()['id']).asset_snapshot.copy()
    monkeypatch.setattr(executor, '_tools', lambda *_args: (Path('/tools/syft'), Path('/tools/grype'), 'Linux aarch64'))
    monkeypatch.setattr(executor, '_connect', lambda *_args: (_ for _ in ()).throw(AssertionError('no SSH')))
    commands, credential_seen = [], {}
    def local(self, name, argv, timeout, env, output=None):
        commands.append((name, argv, env))
        path = self.directory / (output or name + '.stdout.log')
        if name == 'git-clone':
            helper = [value for value in argv if value.startswith('credential.helper=') and value != 'credential.helper=']
            credential_seen['helper'] = Path(helper[0].split('=', 1)[1]).read_text() if helper else None
            (self.directory / 'source').mkdir()
            (self.directory / 'source' / 'requirements.txt').write_text('Jinja2==3.1.4\n')
            path.write_text('')
        elif name == 'git-head':
            path.write_text('b' * 40 + '\n')
        elif name == 'syft-scan':
            path.write_text(json.dumps({'artifacts': [{'name': 'Jinja2', 'version': '3.1.4', 'type': 'python'}],
                'source': {'metadata': {'path': str(self.directory / 'source')}},
                'descriptor': {'configuration': {'catalogers': {'used': ['python-package-cataloger']}}}}))
        elif name == 'syft-convert-spdx':
            path.write_text(json.dumps({'spdxVersion': 'SPDX-2.3', 'packages': [{'name': 'Jinja2', 'versionInfo': '3.1.4'}]}))
        elif name == 'grype-scan':
            path.write_text(json.dumps({'descriptor': {'name': 'grype'}, 'matches': []}))
        else:
            path.write_text('{}')
        return path
    monkeypatch.setattr(executor._Run, 'local', local)
    output = Path(settings.analysis_artifacts_dir) / 'mock-git-worker'
    bundle = executor.execute_analysis(snapshot, output, settings, lambda _stage: None)
    assert bundle['scan_scope'] == 'source-git:web-api' and bundle['git_commit'] == 'b' * 40
    clone = next(argv for name, argv, _env in commands if name == 'git-clone')
    assert clone[:1] == ['git'] and '--depth' in clone and clone[clone.index('--branch') + 1] == 'v2'
    assert clone[-2:] == ['https://github.com/example/web-api', str(output / 'source')]
    assert all('secret-token' not in value for value in clone)
    assert 'password=secret-token' in credential_seen['helper']
    assert not (output / '.git-credential').exists()
    env = next(env for name, _argv, env in commands if name == 'git-clone')
    assert env['GIT_TERMINAL_PROMPT'] == '0'
    manifest = json.loads((output / 'manifest.json').read_text())
    assert manifest['git_commit'] == 'b' * 40 and manifest['git_url'] == 'https://github.com/example/web-api'
    assert 'secret-token' not in (output / 'manifest.json').read_text()
    scan = next(argv for name, argv, _env in commands if name == 'syft-scan')
    assert 'dir:' + str(output / 'source') in scan
