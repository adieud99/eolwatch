"""Password-based SSH targets: encrypted storage, no leakage, host-key pinning, connect arguments."""
from __future__ import annotations

import os
from types import SimpleNamespace

import paramiko
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/eolwatch-test.db")

from app import models  # noqa: E402
from app.db import Base, engine, SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services import ssh_auth  # noqa: E402
from app.services import analysis_executor as executor  # noqa: E402


@pytest.fixture
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as test_client:
        token = test_client.post("/api/auth/login", json={"username": "admin", "password": "Eolwatch!2026"}).json()["access_token"]
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client
    Base.metadata.drop_all(bind=engine)


def test_password_roundtrip_and_tamper_resistance():
    token = ssh_auth.encrypt_password("s3cret!한글")
    assert token != "s3cret!한글" and ssh_auth.decrypt_password(token) == "s3cret!한글"
    assert ssh_auth.decrypt_password(token[:-4] + "AAAA") is None and ssh_auth.decrypt_password(None) is None


def test_api_stores_password_encrypted_and_never_returns_it(client):
    created = client.post("/api/assets", json={"asset_tag": "PW-1", "name": "비번 서버", "asset_type": "server", "ip_address": "10.0.0.9",
                                               "ssh_username": "ubuntu", "ssh_auth": "password", "ssh_password": "hunter2", "monitored": True})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["ssh_auth"] == "password" and body["has_password"] is True and body["ssh_host_key_fingerprint"] is None
    assert "hunter2" not in created.text and "ssh_password" not in body and "ssh_password_encrypted" not in body
    with SessionLocal() as db:
        asset = db.get(models.Asset, body["id"])
        assert asset.ssh_password_encrypted and "hunter2" not in asset.ssh_password_encrypted
        assert ssh_auth.decrypt_password(asset.ssh_password_encrypted) == "hunter2"
    missing = client.post("/api/assets", json={"asset_tag": "PW-2", "name": "x", "asset_type": "server", "ssh_auth": "password"})
    assert missing.status_code == 422 and "비밀번호" in missing.text
    listed = client.get("/api/assets").text
    assert "hunter2" not in listed and "ssh_password_encrypted" not in listed
    # switching back to key auth drops the stored password
    switched = client.patch(f"/api/assets/{body['id']}", json={"ssh_auth": "key"})
    assert switched.status_code == 200 and switched.json()["has_password"] is False


def test_host_key_pinning_learns_once_then_rejects_changes(client):
    created = client.post("/api/assets", json={"asset_tag": "PW-3", "name": "핀", "asset_type": "server", "ip_address": "10.0.0.10",
                                               "ssh_username": "u", "ssh_auth": "password", "ssh_password": "p"}).json()
    key_a = paramiko.RSAKey.generate(1024)
    key_b = paramiko.RSAKey.generate(1024)
    learned = []
    policy = ssh_auth.PinnedHostKeyPolicy(None, learned.append)
    policy.missing_host_key(None, "10.0.0.10", key_a)
    assert learned == [ssh_auth.host_key_line(key_a)] and policy.learned == learned[0]
    pinned = ssh_auth.PinnedHostKeyPolicy(learned[0])
    pinned.missing_host_key(None, "10.0.0.10", key_a)  # same key: fine
    with pytest.raises(paramiko.BadHostKeyException):
        pinned.missing_host_key(None, "10.0.0.10", key_b)
    with SessionLocal() as db:
        asset = db.get(models.Asset, created["id"]); asset.ssh_host_key = learned[0]; db.commit()
    shown = client.get(f"/api/assets/{created['id']}").json()
    assert shown["ssh_host_key_fingerprint"].startswith("SHA256:") and "AAAA" not in shown["ssh_host_key_fingerprint"]
    reset = client.patch(f"/api/assets/{created['id']}", json={"reset_host_key": True})
    assert reset.status_code == 200 and reset.json()["ssh_host_key_fingerprint"] is None


def test_connect_kwargs_and_executor_use_password_without_management_key(tmp_path, monkeypatch):
    snapshot = {"id": 1, "ip_address": "10.0.0.11", "ssh_port": 2222, "ssh_username": "ops", "ssh_auth": "password",
                "ssh_password_encrypted": ssh_auth.encrypt_password("pw!"), "ssh_host_key": None}
    kwargs = ssh_auth.connect_kwargs(snapshot, 7)
    assert kwargs["password"] == "pw!" and kwargs["port"] == 2222 and "key_filename" not in kwargs and kwargs["look_for_keys"] is False
    captured = {}
    class FakeClient:
        def set_missing_host_key_policy(self, policy): captured["policy"] = policy
        def load_host_keys(self, path): captured["known_hosts"] = path
        def connect(self, **kw): captured["connect"] = kw; captured["policy"].missing_host_key(self, kw["hostname"], paramiko.RSAKey.generate(1024))
        def get_transport(self): return SimpleNamespace(set_keepalive=lambda *_: None)
        def close(self): pass
    monkeypatch.setattr(executor.paramiko, "SSHClient", FakeClient)
    settings = SimpleNamespace(ssh_private_key_path="", ssh_known_hosts_path="", ssh_strict_host_key=True, ssh_connect_timeout_seconds=5)
    client = executor._connect(snapshot, settings)
    assert captured["connect"]["password"] == "pw!" and "known_hosts" not in captured
    assert client.eolwatch_learned_host_key.startswith("ssh-rsa ")
    # key mode still insists on the management key and known_hosts
    with pytest.raises(executor.AnalysisExecutionError) as failure:
        executor._connect({"ip_address": "10.0.0.11", "ssh_username": "ops", "ssh_auth": "key"}, settings)
    assert failure.value.code == "SSH_KEY_MISSING"
