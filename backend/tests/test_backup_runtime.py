"""Exercise backup publication, failure cleanup, restoration fencing and retention without Docker."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest


SCRIPT = Path(__file__).parents[2] / 'scripts' / 'backup-runtime.py'
spec = importlib.util.spec_from_file_location('backup_runtime', SCRIPT)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class FakeRuntime:
    project_id = 'a' * 64

    def __init__(self, fail=None):
        self.fail = fail
        self.content = b'immutable original ZIP bytes for the stub'
        self.sha = hashlib.sha256(self.content).hexdigest()
        self.metadata = {'tables': {'analysis_runs': {'rows': 3, 'sha256': 'b' * 64}},
                         'uploads': [{'sha256': self.sha, 'size_bytes': len(self.content)}]}
        self.calls = []

    @contextmanager
    def snapshot(self):
        self.calls.append('snapshot-open')
        try:
            yield '00000003-000000AA-1', self.metadata
        finally:
            self.calls.append('snapshot-close')

    def dump(self, destination, snapshot_id):
        assert snapshot_id == '00000003-000000AA-1'
        assert self.calls[-1] == 'snapshot-open'
        self.calls.append('dump')
        destination.write_bytes(b'PGDMP-stub-custom-format')
        if self.fail == 'dump':
            raise backup.BackupError('Stub dump failed.')

    def copy_uploads(self, destination, uploads):
        assert self.calls[-1] == 'snapshot-close'
        self.calls.append('uploads')
        assert uploads == self.metadata['uploads']
        with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(self.sha + '.zip', self.content if self.fail != 'corrupt-upload' else b'changed')
        if self.fail == 'uploads':
            raise backup.BackupError('Stub volume copy failed.')

    def verify_restore(self, directory, metadata):
        self.calls.append('restore')
        assert not (directory / 'COMPLETE').exists()
        assert metadata == self.metadata
        backup.verify_upload_archive(directory / 'uploads.zip', metadata['uploads'])
        if self.fail == 'restore':
            raise backup.BackupError('Stub verification restore failed.')


@pytest.fixture
def runtime(tmp_path):
    compose = tmp_path / 'compose with spaces; $(not-a-command)'
    compose.mkdir()
    (compose / 'docker-compose.prod.yml').write_text('services: {}\n')
    return backup.ComposeRuntime(compose, 'docker-compose.prod.yml', '/usr/local/bin/docker')


def test_success_publishes_private_atomic_backup_and_checksums(tmp_path):
    runtime = FakeRuntime()
    root = tmp_path / 'backups'
    destination = backup.create_backup(runtime, root, verify_restore=True)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert {path.name for path in destination.iterdir()} == backup.BACKUP_FILES
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in destination.iterdir())
    assert not list(root.glob('.partial-*'))
    marker = json.loads((destination / 'COMPLETE').read_text())
    manifest = json.loads((destination / 'manifest.json').read_text())
    assert marker['manifest_sha256'] == backup.sha256_file(destination / 'manifest.json')
    assert manifest['restore_verified'] is True
    assert manifest['database'] == runtime.metadata
    for name, details in manifest['files'].items():
        assert backup.sha256_file(destination / name) == details['sha256']
        assert (destination / name).stat().st_size == details['bytes']
    assert runtime.calls == ['snapshot-open', 'dump', 'snapshot-close', 'uploads', 'restore']


@pytest.mark.parametrize('failure', ['dump', 'uploads', 'corrupt-upload', 'restore'])
def test_failure_removes_partial_without_pruning_previous_backups(tmp_path, failure):
    root = tmp_path / 'backups'
    previous = [backup.create_backup(FakeRuntime(), root, keep=10) for _ in range(3)]
    before = {path.name: backup.sha256_file(path / 'manifest.json') for path in previous}
    with pytest.raises(backup.BackupError):
        backup.create_backup(FakeRuntime(fail=failure), root, verify_restore=True, keep=1)
    assert not list(root.glob('.partial-*'))
    assert {path.name for path in root.iterdir()} == set(before)
    assert {path.name: backup.sha256_file(path / 'manifest.json') for path in previous} == before


def test_retention_keeps_seven_and_never_deletes_unmanaged_or_other_projects(tmp_path):
    root = tmp_path / 'backups'
    created = [backup.create_backup(FakeRuntime(), root, keep=20) for _ in range(8)]
    other = FakeRuntime(); other.project_id = 'c' * 64
    foreign = backup.create_backup(other, root, keep=20)
    unmanaged = root / 'eolwatch-runtime-20000101T000000Z-000000000000'
    unmanaged.mkdir(); (unmanaged / 'important.txt').write_text('keep')
    partial = root / '.partial-eolwatch-runtime-do-not-touch'
    partial.mkdir(); (partial / 'note').write_text('keep')
    outside = tmp_path / 'outside'; outside.mkdir(); (outside / 'keep').write_text('keep')
    link = root / 'eolwatch-runtime-20000101T000000Z-111111111111'
    link.symlink_to(outside, target_is_directory=True)
    newest = backup.create_backup(FakeRuntime(), root, keep=7)
    remaining = {path for path in root.iterdir() if backup.managed_backup(path, FakeRuntime.project_id)}
    assert len(remaining) == 7 and newest in remaining
    assert not created[0].exists() and not created[1].exists()
    assert unmanaged.exists() and partial.exists() and link.is_symlink() and foreign.exists()
    assert (outside / 'keep').read_text() == 'keep'


def test_unknown_file_inside_old_backup_prevents_retention_deletion(tmp_path):
    root = tmp_path / 'backups'
    first = backup.create_backup(FakeRuntime(), root)
    (first / 'user-file').write_text('do not delete')
    backup.create_backup(FakeRuntime(), root, keep=1)
    assert (first / 'user-file').read_text() == 'do not delete'


@pytest.mark.parametrize('kind', ['traversal', 'absolute', 'symlink', 'duplicate', 'compressed', 'wrong-hash'])
def test_upload_archive_verification_rejects_unsafe_entries(tmp_path, kind):
    content = b'original bytes'
    sha = hashlib.sha256(content).hexdigest()
    path = tmp_path / 'uploads.zip'
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED if kind == 'compressed' else zipfile.ZIP_STORED) as archive:
        name = '../' + sha + '.zip' if kind == 'traversal' else '/' + sha + '.zip' if kind == 'absolute' else sha + '.zip'
        if kind == 'symlink':
            info = zipfile.ZipInfo(name); info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, content)
        else:
            archive.writestr(name, content if kind != 'wrong-hash' else b'different data')
        if kind == 'duplicate':
            with pytest.warns(UserWarning):
                archive.writestr(name, content)
    with pytest.raises(backup.BackupError):
        backup.verify_upload_archive(path, [{'sha256': sha, 'size_bytes': len(content)}])
    assert not (tmp_path / (sha + '.zip')).exists()


def test_restore_failure_always_drops_only_unique_verification_database(tmp_path, runtime, monkeypatch):
    folder = tmp_path / 'backup'; folder.mkdir(); (folder / 'database.dump').write_bytes(b'dump')
    calls = []
    def run(argv, label, **kwargs):
        calls.append((argv, label))
        if label == 'PostgreSQL verification restore':
            assert kwargs['source'].read() == b'dump'
            raise backup.BackupError('Stub restore failed.')
        return b''
    monkeypatch.setattr(runtime, 'run', run)
    with pytest.raises(backup.BackupError, match='Stub restore'):
        runtime.verify_restore(folder, {'tables': {}, 'uploads': []})
    assert [label for _, label in calls] == ['Verification database create', 'PostgreSQL verification restore', 'Verification database drop']
    created, dropped = calls[0][0][-1], calls[-1][0][-1]
    assert created == dropped and backup.TEMP_DATABASE.fullmatch(created)
    assert calls[1][0][-1] == created
    assert created != 'eolwatch'
    with pytest.raises(backup.BackupError):
        runtime.temporary_database('drop', 'eolwatch')
    with pytest.raises(backup.BackupError):
        runtime.temporary_database('drop', 'eolwatch_verify_name; DROP DATABASE eolwatch')


def test_uncertain_database_create_still_attempts_safe_cleanup(tmp_path, runtime, monkeypatch):
    calls = []
    def run(argv, label, **kwargs):
        calls.append(label)
        if label == 'Verification database create':
            raise backup.BackupError('Connection lost during creation.')
    monkeypatch.setattr(runtime, 'run', run)
    with pytest.raises(backup.BackupError, match='Connection lost'):
        runtime.verify_restore(tmp_path, {})
    assert calls == ['Verification database create', 'Verification database drop']


@pytest.mark.parametrize('matches', [True, False])
def test_restore_compares_table_hashes_and_upload_references(tmp_path, runtime, monkeypatch, matches):
    fake = FakeRuntime()
    folder = tmp_path / 'restore'; folder.mkdir(); (folder / 'database.dump').write_bytes(b'dump')
    fake.calls.append('snapshot-close')
    fake.copy_uploads(folder / 'uploads.zip', fake.metadata['uploads'])
    calls = []
    def run(argv, label, **kwargs):
        calls.append(label)
        if label == 'Restored database inspection':
            value = json.loads(json.dumps(fake.metadata))
            if not matches:
                value['tables']['analysis_runs']['sha256'] = 'f' * 64
            return json.dumps(value).encode()
        return b''
    monkeypatch.setattr(runtime, 'run', run)
    if matches:
        runtime.verify_restore(folder, fake.metadata)
    else:
        with pytest.raises(backup.BackupError, match='row counts or content checksums'):
            runtime.verify_restore(folder, fake.metadata)
    assert calls[-1] == 'Verification database drop'


def test_subprocess_failure_does_not_publish_secret_stderr(runtime, monkeypatch):
    captured = []
    def run(argv, **kwargs):
        captured.append((argv, kwargs))
        assert kwargs['stderr'] is subprocess.DEVNULL
        assert 'shell' not in kwargs
        return SimpleNamespace(returncode=9, stdout=b'', stderr=b'postgresql://secret-user:password@db/eolwatch')
    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(backup.BackupError) as error:
        runtime.run(runtime.command('db', 'sh', '-c', backup.DUMP_PROGRAM, 'eolwatch-backup', '00000003-000000AA-1'), 'PostgreSQL dump')
    assert str(error.value) == 'PostgreSQL dump failed (exit 9).'
    assert captured[0][0][3] == str(runtime.compose_dir)


def test_snapshot_session_stays_alive_until_context_exits(runtime, monkeypatch):
    metadata = {'snapshot': '00000003-000000AA-1', 'tables': {}, 'uploads': []}
    script = 'import sys; print(' + repr(json.dumps(metadata)) + ', flush=True); sys.stdin.buffer.read(1)'
    monkeypatch.setattr(runtime, 'command', lambda *_args: [sys.executable, '-c', script])
    with runtime.snapshot() as (snapshot_id, value):
        assert snapshot_id == metadata['snapshot']
        assert value == {'tables': {}, 'uploads': []}


def test_cron_install_preserves_existing_entries_and_is_idempotent(runtime, tmp_path, monkeypatch):
    root = tmp_path / "backups % literal';$(name)"
    original = 'MAILTO=operator\n12 4 * * * /usr/local/bin/existing-task\n'
    stored, calls = {'value': original}, []
    def run(argv, **kwargs):
        calls.append(argv)
        if argv == ['crontab', '-l']:
            return SimpleNamespace(returncode=0, stdout=stored['value'].encode(), stderr=b'')
        assert argv == ['crontab', '-'] and 'shell' not in kwargs
        stored['value'] = kwargs['input'].decode()
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    monkeypatch.setattr(subprocess, 'run', run)
    backup.install_schedule(runtime, root, verify_restore=True)
    once = stored['value']
    backup.install_schedule(runtime, root, verify_restore=True)
    assert stored['value'] == once
    assert once.startswith(original)
    assert once.count('20 3 * * *') == 1
    assert '\\%' in once and '--verify-restore' in once
    assert calls == [['crontab', '-l'], ['crontab', '-'], ['crontab', '-l'], ['crontab', '-']]


def test_malformed_managed_cron_block_is_preserved(runtime, tmp_path):
    original = '# BEGIN EOLWatch runtime backup ' + runtime.project_id[:16] + '\n3 2 * * * preserve-this\n'
    with pytest.raises(backup.BackupError, match='incomplete'):
        backup.cron_text(original, runtime, tmp_path, keep=7, verify_restore=False)


def test_default_cli_does_not_install_cron(runtime, tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(backup, 'create_backup', lambda *_args, **_kwargs: called.append('backup') or tmp_path / 'completed')
    monkeypatch.setattr(backup, 'install_schedule', lambda *_args, **_kwargs: called.append('cron'))
    assert backup.main(['--compose-dir', str(runtime.compose_dir), '--docker-command', runtime.docker_command]) == 0
    assert called == ['backup']
