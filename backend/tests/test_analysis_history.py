"""History beyond 100 rows, source reuse and storage integrity over real DB/API paths."""
from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import tempfile
import threading

import pytest
from fastapi import UploadFile
from sqlalchemy import event, func, select

from app import models
from app.routers import analysis_history
from app.routers import analyses
from test_analysis_inputs import factory, client, settings, asset, source_zip, complete_job


@pytest.fixture(autouse=True)
def history_settings(monkeypatch, settings):
    monkeypatch.setattr(analysis_history, 'get_settings', lambda: settings)


def add_run(db, identity, asset_id, scope='source-zip:sample', at=None):
    sbom = models.SbomDocument(serial_number=f'history-{identity}', spec_version='2.3', asset_id=asset_id,
        component_count=1, raw_document={'large_original': 'do-not-read'})
    run = models.AnalysisRun(id=identity, sbom=sbom, report_sha256=f'{identity:064x}', sbom_sha256='a' * 64,
        scanner='grype', scanner_version='test', generator='syft', scan_scope=scope,
        match_count=0, cve_count=0, link_count=0, ignored_non_cve=0,
        raw_report={'large_original': 'do-not-read'}, imported_at=at or datetime(2026, 9, 15, tzinfo=timezone.utc) + timedelta(seconds=identity))
    db.add(run)
    return run


def test_all_250_results_page_without_raw_json_and_old_candidates(client, factory, asset):
    with factory() as db:
        for i in range(1, 251):
            add_run(db, i, asset)
        add_run(db, 251, asset, scope='other')
        db.commit()
    statements = []
    engine = factory.kw['bind']
    def record(_conn, _cursor, statement, *_):
        statements.append(statement.lower())
    event.listen(engine, 'before_cursor_execute', record)
    try:
        ids = []
        for offset in range(0, 250, 50):
            result = client.get('/api/analyses/history', params={'asset_id': asset, 'scan_scope': 'source-zip:sample', 'limit': 50, 'offset': offset})
            assert result.status_code == 200, result.text
            body = result.json()
            assert body['total'] == 250
            ids.extend(row['id'] for row in body['items'])
        assert ids == list(range(250, 0, -1))
        result = client.get('/api/analyses/runs/1/candidates?offset=200&limit=100')
        assert result.status_code == 200, result.text
        assert result.json()['base']['id'] == 1
        assert result.json()['total'] == 249
        assert result.json()['items'][-1]['id'] == 2
        assert client.get('/api/analyses/runs/1').json()['id'] == 1
        assert not any('raw_report' in sql or 'raw_document' in sql for sql in statements)
    finally:
        event.remove(engine, 'before_cursor_execute', record)
    assert client.get('/api/analyses/1/bundle').json()['report']['large_original'] == 'do-not-read'


def test_job_history_filters_and_single_old_job(client, factory, asset):
    with factory() as db:
        for i in range(1, 251):
            db.add(models.AnalysisJob(id=i, asset_id=asset, status='FAILED' if i % 2 else 'CANCELLED',
                asset_snapshot={'asset_tag': 'PROJECT-01', 'name': 'history', 'scan_scope': 'source-zip:sample'},
                requested_at=datetime(2026, 9, 15, tzinfo=timezone.utc) + timedelta(seconds=i)))
        db.commit()
    result = client.get('/api/analyses/job-history?status=FAILED&limit=100&offset=100')
    assert result.status_code == 200, result.text
    assert result.json()['total'] == 125
    assert result.json()['items'][-1]['id'] == 1
    assert client.get('/api/analyses/jobs/1').json()['id'] == 1
    assert client.get('/api/analyses/jobs/999').status_code == 404
    assert client.get('/api/analyses/job-history?status=INVENTED').status_code == 422


def test_date_filters_follow_business_day_and_literal_search(client, factory, asset):
    with factory() as db:
        for i, at in enumerate(('2026-09-15T14:59:59+00:00', '2026-09-15T15:00:00+00:00', '2026-09-16T14:59:59+00:00', '2026-09-16T15:00:00+00:00'), 1):
            add_run(db, i, asset, scope='source-zip:100%_project', at=datetime.fromisoformat(at))
        db.commit()
    result = client.get('/api/analyses/history?date_from=2026-09-16&date_to=2026-09-16')
    assert [row['id'] for row in result.json()['items']] == [3, 2]
    assert client.get('/api/analyses/history', params={'q': '%_'}).json()['total'] == 4
    assert client.get('/api/analyses/history', params={'q': '10_%'}).json()['total'] == 0
    assert client.get('/api/analyses/history?date_from=2026-09-17&date_to=2026-09-16').status_code == 422
    assert client.get('/api/analyses/history?limit=101').status_code == 422
    assert client.get('/api/analyses/history?date_from=0001-01-01').status_code == 422
    assert client.get('/api/analyses/history?date_to=9999-12-31').status_code == 422


def put_source(client, asset, name='sample', payload=None):
    return client.post(f'/api/analyses/assets/{asset}/uploads', data={'project_name': name},
        files={'file': ('프로젝트.zip', payload or source_zip(), 'application/zip')})


def test_saved_source_dedup_download_and_successful_replay(client, factory, settings, asset):
    first = put_source(client, asset).json()
    second = put_source(client, asset).json()
    assert first['id'] == second['id'] and first['upload_id'] == second['upload_id']
    assert client.get('/api/analyses/uploads').json()['total'] == 1
    result = client.get(f"/api/analyses/uploads/{first['upload_id']}/raw")
    assert result.status_code == 200
    assert result.content == source_zip()
    assert result.headers['x-content-sha256'] == hashlib.sha256(source_zip()).hexdigest()
    assert "filename*=UTF-8''" in result.headers['content-disposition']
    complete_job(factory, first['id'], status='SUCCESS')
    replay = client.post(f"/api/analyses/uploads/{first['upload_id']}/jobs")
    assert replay.status_code == 202, replay.text
    assert replay.json()['id'] != first['id']
    assert replay.json()['upload_id'] == first['upload_id']
    assert replay.json()['upload_sha256'] == first['upload_sha256']


def test_busy_asset_preserves_discoverable_source_instead_of_orphan(client, factory, asset):
    first = put_source(client, asset).json()
    blocked = put_source(client, asset, name='next-project', payload=source_zip(content=b'Jinja2==3.1.6\n'))
    assert blocked.status_code == 409
    assert '보관했습니다' in blocked.json()['detail']
    sources = client.get('/api/analyses/uploads').json()
    assert sources['total'] == 2
    new = next(row for row in sources['items'] if row['project_name'] == 'next-project')
    assert new['job_count'] == 0 and new['storage_status'] == 'AVAILABLE'
    storage = client.get('/api/analyses/storage').json()
    assert storage['unreferenced_files'] == 0 and storage['referenced_files'] == 2
    complete_job(factory, first['id'])
    assert client.post(f"/api/analyses/uploads/{new['id']}/jobs").status_code == 202


def test_upload_lock_and_queue_waits_leave_event_loop_responsive(factory, asset, monkeypatch):
    """Model a blocked PG row lock; its release requires another async request.

    The old synchronous SELECT FOR UPDATE inside save_upload deadlocked this
    coroutine until the timeout, even though unrelated async work could release it.
    """
    registration_waiting, release_registration = threading.Event(), threading.Event()
    queue_waiting, release_queue = threading.Event(), threading.Event()
    engine = factory.kw['bind']
    original_queue = analyses._queue_upload

    def block_registration(_conn, _cursor, _statement, _parameters, context, _many):
        statement = getattr(getattr(context, 'compiled', None), 'statement', None)
        if getattr(statement, '_for_update_arg', None) is not None:
            registration_waiting.set()
            assert release_registration.wait(2), 'Asset lock wait blocked the event loop'

    def block_queue(*args):
        queue_waiting.set()
        assert release_queue.wait(2), 'Queue transaction blocked the event loop'
        return original_queue(*args)

    monkeypatch.setattr(analyses, '_queue_upload', block_queue)
    event.listen(engine, 'before_cursor_execute', block_registration)

    async def execute():
        content = source_zip(content=b'x' * (2 * 1024 * 1024))
        disk_file = tempfile.SpooledTemporaryFile(max_size=1024)
        disk_file.write(content); disk_file.seek(0)
        upload_file = UploadFile(file=disk_file, filename='concurrent.zip')
        with factory() as db:
            task = asyncio.create_task(analyses.upload_source(asset, upload_file, 'concurrent-project', db))
            try:
                for waiting, release in ((registration_waiting, release_registration), (queue_waiting, release_queue)):
                    while not waiting.is_set() and not task.done():
                        await asyncio.sleep(0.005)
                    assert not task.done(), 'The upload failed before other async work could advance'
                    release.set()
                result = await task
                assert result.status == 'QUEUED'
                assert result.upload_sha256 == hashlib.sha256(content).hexdigest()
                assert db.get(models.AnalysisUpload, result.upload_id) is not None
            finally:
                release_registration.set(); release_queue.set()
                if not task.done():
                    await task
        assert disk_file.closed

    try:
        asyncio.run(execute())
    finally:
        event.remove(engine, 'before_cursor_execute', block_registration)


def test_project_groups_separate_assets_scopes_versions_and_use_latest_time(client, factory, asset):
    first = put_source(client, asset).json()
    complete_job(factory, first['id'])
    assert put_source(client, asset, payload=source_zip(content=b'Jinja2==3.1.6\n')).status_code == 202
    other = client.post('/api/assets', json={'asset_tag': 'PROJECT-02', 'name': 'same name other asset', 'asset_type': 'server'}).json()['id']
    assert put_source(client, other).status_code == 202
    with factory() as db:
        add_run(db, 1, asset, at=datetime(2026, 9, 16, tzinfo=timezone.utc))
        add_run(db, 2, asset, at=datetime(2026, 9, 15, tzinfo=timezone.utc))
        db.commit()
    result = client.get('/api/analyses/projects').json()
    assert result['total'] == 2
    row = next(row for row in result['items'] if row['asset_id'] == asset)
    assert row['upload_count'] == 2 and row['analysis_count'] == 2 and row['job_count'] == 2
    assert row['latest_analysis']['id'] == 1
    assert client.get('/api/analyses/projects', params={'asset_id': other}).json()['total'] == 1
    assert client.get('/api/analyses/uploads', params={'asset_id': other, 'scan_scope': 'source-zip:sample'}).json()['total'] == 1


@pytest.mark.parametrize('damage', ['missing', 'same-size', 'size', 'symlink'])
def test_damaged_snapshot_cannot_download_or_replay(client, factory, settings, asset, damage, tmp_path):
    first = put_source(client, asset).json()
    complete_job(factory, first['id'])
    path = analysis_history.archive_path(settings, first['upload_sha256'])
    if damage == 'missing':
        path.unlink()
    elif damage == 'symlink':
        path.unlink(); target = tmp_path / 'outside.zip'; target.write_bytes(source_zip()); path.symlink_to(target)
    else:
        path.chmod(0o600); path.write_bytes(b'x' * (len(source_zip()) if damage == 'same-size' else 3))
    for method, suffix in ((client.get, 'raw'), (client.post, 'jobs')):
        result = method(f"/api/analyses/uploads/{first['upload_id']}/{suffix}")
        assert result.status_code == 409, result.text
    with factory() as db:
        assert db.scalar(select(func.count(models.AnalysisJob.id))) == 1


def test_viewer_reads_history_sources_but_cannot_replay_or_see_storage(client, factory, asset):
    first = put_source(client, asset).json()
    complete_job(factory, first['id'])
    response = client.post('/api/auth/users', json={'username': 'history-viewer', 'password': 'HistoryViewer!2026', 'role': 'VIEWER'})
    assert response.status_code == 201
    login = client.post('/api/auth/login', json={'username': 'history-viewer', 'password': 'HistoryViewer!2026'}).json()
    client.headers['Authorization'] = 'Bearer ' + login['access_token']
    assert client.get('/api/analyses/projects').status_code == 200
    assert client.get('/api/analyses/uploads').status_code == 200
    assert client.get(f"/api/analyses/uploads/{first['upload_id']}/raw").status_code == 200
    assert client.get('/api/analyses/storage').status_code == 403
    assert client.post(f"/api/analyses/uploads/{first['upload_id']}/jobs").status_code == 403
