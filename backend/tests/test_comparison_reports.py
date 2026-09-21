"""Report exports retain evidence, enforce access, and never change findings."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

os.environ['DATABASE_URL'] = 'sqlite:////tmp/eolwatch-test.db'

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import main, middleware, models, schemas
from app.db import Base, get_db
from app.services.analysis import digest, import_analysis


@pytest.fixture
def report_env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'reports.db'}", connect_args={'check_same_thread': False})
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, 'engine', engine)
    monkeypatch.setattr(main, 'SessionLocal', factory)
    monkeypatch.setattr(middleware, 'SessionLocal', factory)
    def isolated_db():
        with factory() as db:
            yield db
    original = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[get_db] = isolated_db
    try:
        with TestClient(main.app) as client:
            login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'Eolwatch!2026'})
            assert login.status_code == 200
            client.headers['Authorization'] = 'Bearer ' + login.json()['access_token']
            yield client, factory
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(original)
        engine.dispose()


def add_pair(factory, *, count=3, verified=True):
    with factory() as db:
        asset = models.Asset(asset_tag='REPORT-01', name='분석 대상 서버', asset_type='server')
        db.add(asset)
        db.flush()
        source = json.loads((Path(__file__).parents[2] / 'samples/spdx-2.3-blackduck-compatible.json').read_text())
        runs = []
        for index, version in enumerate(('3.1.4', '3.1.6')):
            sbom = deepcopy(source)
            sbom['documentNamespace'] = f'https://eolwatch.test/reports/{uuid4()}'
            sbom['creationInfo']['creators'] = ['Tool: syft-fixture']
            package = sbom['packages'][0]
            package.update(name='jinja2', versionInfo=version)
            package['externalRefs'][0]['referenceLocator'] = f'pkg:pypi/jinja2@{version}'
            report = {
                'descriptor': {'name': 'grype', 'version': 'fixture', 'db': {
                    'status': {'built': '2026-09-15T00:00:00Z', 'schemaVersion': 'v6', 'valid': True},
                    'not_for_report': 'scanner-private-sentinel',
                }},
                'source': {'type': 'sbom', 'target': 'fixture.spdx.json'},
                'matches': [{
                    'artifact': {'name': 'jinja2', 'version': version, 'purl': f'pkg:pypi/jinja2@{version}'},
                    'vulnerability': {'id': f'CVE-2026-{10000 + n}', 'severity': 'Medium',
                                      'fix': {'state': 'fixed', 'versions': ['3.1.6']}},
                } for n in range(count)] if index == 0 else [],
            }
            run = import_analysis(db, schemas.AnalysisImport(asset_id=asset.id, sbom=sbom, report=report,
                                                             scan_scope='demo-python-venv'), commit=False)
            run.imported_at = datetime(2026, 9, 15, tzinfo=timezone.utc) + timedelta(seconds=index)
            if verified:
                db.add(models.AnalysisJob(asset_id=asset.id, asset_snapshot={
                    'asset_tag': asset.asset_tag, 'name': asset.name, 'scan_scope': run.scan_scope,
                    'ssh_private_key': 'private-key-sentinel',
                }, status='SUCCESS', analysis_run_id=run.id, worker_token='private-worker-token',
                    requested_at=run.imported_at, started_at=run.imported_at, finished_at=run.imported_at))
            runs.append(run.id)
        db.commit()
        return runs


def url(pair, extension='json'):
    return f'/api/reports/analyses/{pair[0]}/compare/{pair[1]}.{extension}'


def test_json_exports_complete_findings_and_verifiable_hashes_without_mutations(report_env):
    client, factory = report_env
    pair = add_pair(factory, count=121)
    with factory() as db:
        counts = {model: db.scalar(select(func.count()).select_from(model)) for model in
                  (models.AuditLog, models.AnalysisRun, models.AnalysisJob, models.ComponentVulnerability)}
        asset = db.scalar(select(models.Asset))
        asset.asset_tag, asset.name = 'RENAMED-01', '바뀐 자산명'
        link = db.scalar(select(models.ComponentVulnerability).limit(1))
        link.vex_status = 'NOT_AFFECTED'
        db.commit()
    response = client.get(url(pair))
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    assert 'attachment;' in response.headers['content-disposition']
    assert f'eolwatch-analysis-{pair[0]}-{pair[1]}.json' in response.headers['content-disposition']
    report = response.json()
    assert report['report_version'] == 1 and report['generated_at']
    assert len(report['findings']) == 121
    assert report['summary']['no_longer_detected'] == 121
    assert report['findings_sha256'] == digest(report['findings'])
    assert report['base']['asset_tag'] == 'REPORT-01'
    assert report['base']['asset_name'] == '분석 대상 서버'
    assert report['base']['asset_identity_source'] == 'job_snapshot'
    for side in ('base', 'target'):
        item = report[side]
        bundle = client.get(report['raw_evidence'][side + '_bundle_path']).json()
        assert item['sbom_sha256'] == digest(bundle['sbom'])
        assert item['bundle_sha256'] == digest({key: bundle[key] for key in report['hash_format']['bundle_fields']})
        assert item['jobs'][0]['status'] == 'SUCCESS'
        assert item['database_info']['status']['built'] == '2026-09-15T00:00:00Z'
    assert all(text not in response.text for text in
               ('private-key-sentinel', 'private-worker-token', 'scanner-private-sentinel'))
    assert any('자동 판정' in text for text in report['limitations'])
    with factory() as db:
        for model, count in counts.items():
            assert db.scalar(select(func.count()).select_from(model)) == count
        assert db.scalar(select(models.ComponentVulnerability).limit(1)).vex_status == 'NOT_AFFECTED'


@pytest.mark.parametrize('extension', ['json', 'pdf'])
def test_exports_require_login_and_allow_read_only_viewers(report_env, extension):
    client, factory = report_env
    pair = add_pair(factory)
    created = client.post('/api/auth/users', json={'username': 'report-viewer', 'password': 'Viewer!2026', 'role': 'VIEWER'})
    assert created.status_code == 201
    login = client.post('/api/auth/login', json={'username': 'report-viewer', 'password': 'Viewer!2026'})
    client.headers['Authorization'] = 'Bearer ' + login.json()['access_token']
    response = client.get(url(pair, extension))
    assert response.status_code == 200, response.text[:200]
    if extension == 'pdf':
        assert response.headers['content-type'] == 'application/pdf'
        assert response.content.startswith(b'%PDF-')
        # Portable Korean text requires embedded TrueType outlines and Unicode mapping.
        assert b'/FontFile2' in response.content
        assert b'/ToUnicode' in response.content
    client.headers.pop('Authorization')
    assert client.get(url(pair, extension)).status_code == 401


@pytest.mark.parametrize('extension', ['json', 'pdf'])
def test_both_formats_keep_comparison_guards(report_env, extension):
    client, factory = report_env
    pair = add_pair(factory)
    assert client.get(url([pair[1], pair[0]], extension)).status_code == 409
    assert client.get(url([pair[0], pair[0]], extension)).status_code == 409
    assert client.get(url([pair[0], 99999], extension)).status_code == 404
    with factory() as db:
        db.get(models.AnalysisRun, pair[1]).scan_scope = 'different-scope'
        db.commit()
    assert client.get(url(pair, extension)).status_code == 409


@pytest.mark.parametrize('extension', ['json', 'pdf'])
def test_changed_raw_evidence_cannot_be_exported_with_old_hash(report_env, extension):
    client, factory = report_env
    pair = add_pair(factory)
    with factory() as db:
        run = db.get(models.AnalysisRun, pair[0])
        run.raw_report = {**run.raw_report, 'modified_after_import': True}
        db.commit()
    response = client.get(url(pair, extension))
    assert response.status_code == 409
    assert 'SHA-256' in response.json()['detail']


def test_manual_import_warnings_are_exported_and_database_metadata_is_optional(report_env):
    client, factory = report_env
    pair = add_pair(factory, verified=False)
    with factory() as db:
        for run_id in pair:
            run = db.get(models.AnalysisRun, run_id)
            report = deepcopy(run.raw_report)
            report['descriptor']['db'] = {'status': 'metadata-unavailable'}
            run.raw_report = report
            run.report_sha256 = digest({'asset_id': run.sbom.asset_id, 'sbom': run.sbom.raw_document, 'report': report})
        db.commit()
    response = client.get(url(pair))
    assert response.status_code == 200, response.text
    report = response.json()
    assert not report['comparable'] and report['warnings']
    assert len(report['findings']) == 3
    assert report['base']['jobs'] == []
    assert report['base']['asset_identity_source'] == 'current_asset_record'
    assert report['base']['database_info']['status']['built'] is None
