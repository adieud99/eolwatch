#!/usr/bin/env python3
"""Back up a Compose PostgreSQL snapshot and its immutable source ZIPs.

The controller needs only Python's standard library and the Docker Compose CLI.
Database connections use the API container's existing configuration. Credentials
are never copied to the controller, command arguments, or diagnostic output.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from uuid import uuid4
import zipfile


FORMAT = "eolwatch-runtime-backup-v1"
BACKUP_NAME = re.compile(r"eolwatch-runtime-\d{8}T\d{6}Z-[0-9a-f]{12}\Z")
UPLOAD_NAME = re.compile(r"([0-9a-f]{64})\.zip\Z")
TEMP_DATABASE = re.compile(r"eolwatch_verify_[0-9a-f]{32}\Z")
BACKUP_FILES = frozenset(("database.dump", "uploads.zip", "manifest.json", "COMPLETE"))
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024 * 1024

# These are fixed programs, not templates. Every variable input is a separate
# argument or JSON on stdin. No database/password/environment values are printed.
DATABASE_PROGRAM = r'''
import hashlib, json, os, re, sys
import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

url = make_url(os.environ["DATABASE_URL"])
mode = sys.argv[1]
target = sys.argv[2] if len(sys.argv) > 2 else None
if mode not in {"snapshot", "inspect", "create", "drop"}:
    raise SystemExit(2)
if mode != "snapshot" and (not re.fullmatch(r"eolwatch_verify_[0-9a-f]{32}", target or "") or target == url.database):
    raise SystemExit(2)
database = url.database if mode == "snapshot" else target if mode == "inspect" else "postgres"
connection = psycopg.connect(host=url.host, port=url.port or 5432, user=url.username,
    password=url.password, dbname=database, connect_timeout=15,
    autocommit=mode in {"create", "drop"})
try:
    if mode == "create":
        connection.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(target)))
    elif mode == "drop":
        connection.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(target)))
    else:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        connection.execute("SET LOCAL timezone TO 'UTC'")
        connection.execute("SET LOCAL idle_in_transaction_session_timeout TO '20min'")
        snapshot = connection.execute("SELECT pg_export_snapshot()").fetchone()[0] if mode == "snapshot" else None
        tables = connection.execute("""SELECT c.oid, c.relname FROM pg_class c
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname""").fetchall()
        result = {"tables": {}, "uploads": []}
        for oid, name in tables:
            keys = connection.execute("""SELECT a.attname FROM pg_index i
                CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, n)
                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                WHERE i.indrelid=%s AND i.indisprimary ORDER BY k.n""", (oid,)).fetchall()
            order = sql.SQL(', ').join(sql.Identifier(key[0]) for key in keys) if keys else sql.SQL('to_jsonb(t)::text COLLATE "C"')
            statement = sql.SQL("SELECT to_jsonb(t)::text FROM {} AS t ORDER BY {}").format(sql.Identifier('public', name), order)
            digest, count = hashlib.sha256(), 0
            with connection.cursor(name="backup_rows") as cursor:
                cursor.execute(statement)
                for row in cursor:
                    encoded = row[0].encode('utf-8')
                    digest.update(len(encoded).to_bytes(8, 'big'))
                    digest.update(encoded)
                    count += 1
            result['tables'][name] = {'rows': count, 'sha256': digest.hexdigest()}
        uploads = connection.execute("SELECT DISTINCT sha256, size_bytes FROM analysis_uploads ORDER BY sha256, size_bytes").fetchall() if 'analysis_uploads' in result['tables'] else []
        result['uploads'] = [{'sha256': sha, 'size_bytes': size} for sha, size in uploads]
        if snapshot is not None:
            result['snapshot'] = snapshot
        print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
        if mode == "snapshot":
            sys.stdin.buffer.read(1)  # Keep the exported snapshot alive until pg_dump finishes.
finally:
    connection.close()
'''

UPLOAD_PROGRAM = r'''
import hashlib, json, os, pathlib, re, stat, sys, zipfile
requested = json.load(sys.stdin)
root = pathlib.Path(os.environ.get('ANALYSIS_UPLOADS_DIR', '/var/lib/eolwatch/uploads')).resolve()
seen = set()
with zipfile.ZipFile(sys.stdout.buffer, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
    for item in requested:
        sha, size = item['sha256'], item['size_bytes']
        if not re.fullmatch(r'[0-9a-f]{64}', sha) or type(size) is not int or not 0 <= size <= 1024*1024*1024 or sha in seen:
            raise SystemExit(2)
        seen.add(sha)
        name = sha + '.zip'
        path = root / name
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size:
                raise SystemExit(3)
            digest, copied = hashlib.sha256(), 0
            entry = zipfile.ZipInfo(name)
            entry.external_attr = (stat.S_IFREG | 0o400) << 16
            with archive.open(entry, 'w', force_zip64=True) as destination:
                for chunk in iter(lambda: source.read(1024*1024), b''):
                    copied += len(chunk)
                    if copied > size:
                        raise SystemExit(3)
                    digest.update(chunk)
                    destination.write(chunk)
            if copied != size or digest.hexdigest() != sha:
                raise SystemExit(3)
'''

DUMP_PROGRAM = 'exec pg_dump --no-password --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --format=custom --snapshot="$1"'
RESTORE_PROGRAM = 'exec pg_restore --no-password --username="$POSTGRES_USER" --dbname="$1" --exit-on-error --no-owner --no-privileges --single-transaction'


class BackupError(RuntimeError):
    """Only messages safe for cron logs or terminal output belong here."""


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def upload_index(items):
    if not isinstance(items, list):
        raise BackupError('Invalid source upload metadata.')
    result = {}
    for item in items:
        if not isinstance(item, dict):
            raise BackupError('Invalid source upload metadata.')
        sha, size = item.get('sha256'), item.get('size_bytes')
        if (not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha)
                or type(size) is not int or not 0 <= size <= MAX_SOURCE_BYTES or sha in result):
            raise BackupError('Invalid or conflicting source upload metadata.')
        result[sha] = size
    return result


def verify_upload_archive(path, uploads):
    """Inspect and hash entries without ever extracting untrusted archive paths."""
    expected = upload_index(uploads)
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) != len(expected):
                raise BackupError('Source archive entry count does not match the database snapshot.')
            seen = set()
            for entry in entries:
                match = UPLOAD_NAME.fullmatch(entry.filename)
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if (not match or entry.filename != entry.orig_filename or entry.is_dir()
                        or mode not in (0, stat.S_IFREG) or entry.flag_bits & 1
                        or entry.compress_type != zipfile.ZIP_STORED):
                    raise BackupError('Source archive contains an unsafe entry.')
                sha = match.group(1)
                if sha not in expected or sha in seen or entry.file_size != expected[sha]:
                    raise BackupError('Source archive does not match the database snapshot.')
                seen.add(sha)
                digest, size = hashlib.sha256(), 0
                with archive.open(entry) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        size += len(chunk)
                        if size > expected[sha]:
                            raise BackupError('Source archive exceeds its recorded size.')
                        digest.update(chunk)
                if size != expected[sha] or digest.hexdigest() != sha:
                    raise BackupError('Source archive checksum verification failed.')
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, KeyError) as error:
        if isinstance(error, BackupError):
            raise
        raise BackupError('Source archive is damaged or unsupported.') from error


class ComposeRuntime:
    def __init__(self, compose_dir, compose_file, docker_command='docker'):
        self.compose_dir = Path(compose_dir).resolve()
        file = Path(compose_file)
        self.compose_file = (self.compose_dir / file).resolve() if not file.is_absolute() else file.resolve()
        for value in (str(self.compose_dir), str(self.compose_file), docker_command):
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise BackupError('Paths and executable names must not contain control characters.')
        if not self.compose_dir.is_dir() or not self.compose_file.is_file():
            raise BackupError('Compose directory or configuration file is missing.')
        self.docker_command = docker_command
        self.prefix = [docker_command, 'compose', '--project-directory', str(self.compose_dir), '-f', str(self.compose_file)]
        self.project_id = hashlib.sha256((str(self.compose_dir) + '\0' + str(self.compose_file)).encode()).hexdigest()

    def command(self, service, *arguments):
        return [*self.prefix, 'exec', '-T', service, *arguments]

    def run(self, argv, label, *, output=None, source=None, data=None, timeout=900):
        try:
            result = subprocess.run(argv, cwd=self.compose_dir, stdin=source, input=data,
                stdout=output if output is not None else subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise BackupError(label + ' timed out.') from error
        except OSError as error:
            raise BackupError(label + ' could not start.') from error
        if result.returncode != 0:
            raise BackupError(label + ' failed (exit ' + str(result.returncode) + ').')
        return result.stdout

    @contextmanager
    def snapshot(self):
        process = None
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(self.command('api', 'python', '-c', DATABASE_PROGRAM, 'snapshot'),
                cwd=self.compose_dir, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline, buffer = time.monotonic() + 900, bytearray()
            while b'\n' not in buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise BackupError('Database snapshot metadata timed out.')
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    raise BackupError('Database snapshot session ended unexpectedly.')
                buffer.extend(block)
                if len(buffer) > MAX_METADATA_BYTES:
                    raise BackupError('Database snapshot metadata exceeds the supported limit.')
            try:
                metadata = json.loads(bytes(buffer).split(b'\n', 1)[0])
            except (ValueError, UnicodeError) as error:
                raise BackupError('Database snapshot metadata is invalid.') from error
            snapshot_id = metadata.pop('snapshot', None)
            if not isinstance(snapshot_id, str) or not re.fullmatch(r'[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9A-Fa-f]+', snapshot_id):
                raise BackupError('Database snapshot identifier is invalid.')
            upload_index(metadata.get('uploads'))
            yield snapshot_id, metadata
        except OSError as error:
            raise BackupError('Database snapshot process could not start or communicate.') from error
        finally:
            selector.close()
            if process is not None:
                if process.stdin is not None:
                    process.stdin.close()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()

    def dump(self, destination, snapshot_id):
        with destination.open('xb') as output:
            self.run(self.command('db', 'sh', '-c', DUMP_PROGRAM, 'eolwatch-backup', snapshot_id), 'PostgreSQL dump', output=output)
            output.flush()
            os.fsync(output.fileno())
        if destination.stat().st_size == 0:
            raise BackupError('PostgreSQL dump is empty.')

    def copy_uploads(self, destination, uploads):
        with destination.open('xb') as output:
            self.run(self.command('api', 'python', '-c', UPLOAD_PROGRAM), 'Source upload backup',
                     output=output, data=json_bytes(uploads))
            output.flush()
            os.fsync(output.fileno())

    def temporary_database(self, action, name):
        if action not in ('create', 'drop') or not TEMP_DATABASE.fullmatch(name):
            raise BackupError('Only a uniquely named verification database can be created or dropped.')
        self.run(self.command('api', 'python', '-c', DATABASE_PROGRAM, action, name), 'Verification database ' + action, timeout=120)

    def verify_restore(self, backup, expected):
        name = 'eolwatch_verify_' + uuid4().hex
        attempted = False
        try:
            attempted = True
            self.temporary_database('create', name)
            with (backup / 'database.dump').open('rb') as source:
                self.run(self.command('db', 'sh', '-c', RESTORE_PROGRAM, 'eolwatch-verify', name),
                         'PostgreSQL verification restore', source=source)
            encoded = self.run(self.command('api', 'python', '-c', DATABASE_PROGRAM, 'inspect', name), 'Restored database inspection')
            try:
                restored = json.loads(encoded)
            except (ValueError, UnicodeError) as error:
                raise BackupError('Restored database metadata is invalid.') from error
            if restored != expected:
                raise BackupError('Restored database row counts or content checksums do not match the snapshot.')
            verify_upload_archive(backup / 'uploads.zip', restored['uploads'])
        finally:
            if attempted:
                try:
                    self.temporary_database('drop', name)
                except BackupError as error:
                    raise BackupError('Could not remove verification database ' + name + '; manual cleanup is required.') from error


def managed_backup(path, project_id):
    if path.is_symlink() or not path.is_dir() or not BACKUP_NAME.fullmatch(path.name):
        return False
    try:
        entries = list(path.iterdir())
        if {entry.name for entry in entries} != BACKUP_FILES or any(entry.is_symlink() or not entry.is_file() for entry in entries):
            return False
        if (path / 'COMPLETE').stat().st_size > 4096 or (path / 'manifest.json').stat().st_size > MAX_METADATA_BYTES:
            return False
        marker = json.loads((path / 'COMPLETE').read_text())
        manifest = json.loads((path / 'manifest.json').read_text())
        datetime.fromisoformat(manifest['created_at'])
        return (marker.get('format') == FORMAT and manifest.get('format') == FORMAT
                and marker.get('manifest_sha256') == sha256_file(path / 'manifest.json')
                and manifest.get('backup_name') == path.name and manifest.get('project_id') == project_id)
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return False


def retain_backups(root, project_id, keep=7, protected_name=None):
    if keep < 1:
        raise BackupError('Retention must preserve at least one completed backup.')
    def creation_key(path):
        timestamp = datetime.fromisoformat(json.loads((path / 'manifest.json').read_text())['created_at']).timestamp()
        return path.name == protected_name, timestamp, path.name
    backups = sorted((path for path in root.iterdir() if managed_backup(path, project_id)), key=creation_key, reverse=True)
    removed = []
    for path in backups[keep:]:
        # Flat-file deletion intentionally avoids recursive traversal. Unknown
        # directories, links, partial runs, and other projects are never removed.
        if not managed_backup(path, project_id):
            continue
        for name in BACKUP_FILES:
            (path / name).unlink()
        path.rmdir()
        removed.append(path.name)
    sync_directory(root)
    return removed


def private_backup_root(path):
    path = Path(path).absolute()
    if path.is_symlink() or any(ord(char) < 32 or ord(char) == 127 for char in str(path)):
        raise BackupError('Backup directory must be a real path without control characters.')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path.resolve()


def create_backup(runtime, backup_dir, *, verify_restore=False, keep=7):
    if keep < 1:
        raise BackupError('Retention must preserve at least one completed backup.')
    root = private_backup_root(backup_dir)
    name = 'eolwatch-runtime-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:12]
    staging = Path(tempfile.mkdtemp(prefix='.partial-eolwatch-runtime-', dir=root))
    try:
        with runtime.snapshot() as (snapshot_id, metadata):
            runtime.dump(staging / 'database.dump', snapshot_id)
        runtime.copy_uploads(staging / 'uploads.zip', metadata['uploads'])
        verify_upload_archive(staging / 'uploads.zip', metadata['uploads'])
        files = {filename: {'bytes': (staging / filename).stat().st_size, 'sha256': sha256_file(staging / filename)}
                 for filename in ('database.dump', 'uploads.zip')}
        if verify_restore:
            runtime.verify_restore(staging, metadata)
        # Check the files once more after restore verification before publishing.
        if any(sha256_file(staging / filename) != item['sha256'] for filename, item in files.items()):
            raise BackupError('Backup artifacts changed during verification.')
        manifest = {'format': FORMAT, 'backup_name': name, 'project_id': runtime.project_id,
                    'created_at': datetime.now(timezone.utc).isoformat(), 'files': files,
                    'database': metadata, 'restore_verified': verify_restore}
        write_private(staging / 'manifest.json', json_bytes(manifest))
        write_private(staging / 'COMPLETE', json_bytes({'format': FORMAT, 'manifest_sha256': sha256_file(staging / 'manifest.json')}))
        for path in staging.iterdir():
            path.chmod(0o600)
        sync_directory(staging)
        destination = root / name
        if destination.exists():
            raise BackupError('Backup destination already exists.')
        staging.rename(destination)
        sync_directory(root)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    # Retention is reached only after the completed backup was published.
    try:
        retain_backups(root, runtime.project_id, keep, protected_name=name)
    except OSError:
        print('Backup completed; old backup retention could not finish.', file=sys.stderr)
    return destination


def cron_text(existing, runtime, backup_dir, *, keep, verify_restore, script_path=None, python_path=None):
    script = Path(script_path or __file__).resolve()
    python = str(Path(python_path or sys.executable).resolve())
    marker = 'EOLWatch runtime backup ' + runtime.project_id[:16]
    start, end = '# BEGIN ' + marker, '# END ' + marker
    kept, owned = [], False
    for line in existing.splitlines(keepends=True):
        if line.rstrip('\r\n') == start:
            if owned:
                raise BackupError('Existing managed cron block is malformed.')
            owned = True
        elif line.rstrip('\r\n') == end:
            if not owned:
                raise BackupError('Existing managed cron block is malformed.')
            owned = False
        elif not owned:
            kept.append(line)
    if owned:
        raise BackupError('Existing managed cron block is incomplete.')
    argv = [python, str(script), '--compose-dir', str(runtime.compose_dir), '--compose-file', str(runtime.compose_file),
            '--backup-dir', str(backup_dir), '--docker-command', runtime.docker_command, '--keep', str(keep)]
    if verify_restore:
        argv.append('--verify-restore')
    if any(any(ord(char) < 32 or ord(char) == 127 for char in value) for value in argv):
        raise BackupError('Cron arguments must not contain control characters.')
    # Cron interprets percent signs even inside shell quotes. Escape those after
    # quoting all arguments, without interpolating any input into executable code.
    command = shlex.join(argv).replace('%', r'\%')
    log = shlex.quote(str(backup_dir / 'cron.log')).replace('%', r'\%')
    block = start + '\n20 3 * * * ' + command + ' >> ' + log + ' 2>&1\n' + end + '\n'
    prefix = ''.join(kept)
    return prefix + ('\n' if prefix and not prefix.endswith('\n') else '') + block


def install_schedule(runtime, backup_dir, *, keep=7, verify_restore=False):
    root = private_backup_root(backup_dir)
    try:
        current = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        if current.returncode and not (current.returncode == 1 and b'no crontab for' in current.stderr.lower()):
            raise BackupError('Existing crontab could not be read; nothing was changed.')
        existing = current.stdout.decode('utf-8') if current.returncode == 0 else ''
        content = cron_text(existing, runtime, root, keep=keep, verify_restore=verify_restore)
        result = subprocess.run(['crontab', '-'], input=content.encode('utf-8'), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode:
            raise BackupError('Managed backup schedule installation failed.')
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise BackupError('Crontab could not be accessed.') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-dir', type=Path, default=Path.cwd())
    parser.add_argument('--compose-file', default='docker-compose.prod.yml')
    parser.add_argument('--docker-command', default=shutil.which('docker') or 'docker', help='Docker executable path (one executable, not a shell command).')
    parser.add_argument('--backup-dir', type=Path, help='Default: COMPOSE_DIR/backups; permission 0700.')
    parser.add_argument('--keep', type=int, default=7, help='Number of completed managed backups to retain (default: 7).')
    parser.add_argument('--verify-restore', action='store_true', help='Restore this new dump into a unique temporary database, compare all table hashes, then drop it.')
    parser.add_argument('--install-schedule', action='store_true', help='Explicitly install/update only this project\'s 03:20 daily cron entry, without running a backup now.')
    arguments = parser.parse_args(argv)
    try:
        if arguments.keep < 1:
            raise BackupError('--keep must be at least 1.')
        runtime = ComposeRuntime(arguments.compose_dir, arguments.compose_file, arguments.docker_command)
        backup_dir = arguments.backup_dir or runtime.compose_dir / 'backups'
        if arguments.install_schedule:
            install_schedule(runtime, backup_dir, keep=arguments.keep, verify_restore=arguments.verify_restore)
            print('Managed daily backup schedule installed for 03:20 in the controller\'s local timezone.')
        else:
            destination = create_backup(runtime, backup_dir, keep=arguments.keep, verify_restore=arguments.verify_restore)
            print('Backup completed: ' + str(destination))
            print('Temporary database restore verification: ' + ('passed' if arguments.verify_restore else 'not requested'))
        return 0
    except BackupError as error:
        print('Backup operation failed: ' + str(error), file=sys.stderr)
    except (OSError, ValueError):
        print('Backup operation failed: a local file or configuration could not be processed.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
