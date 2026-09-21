"""SSH credentials for targets: key-based (management key + known_hosts) or password-based.

Passwords are stored encrypted (Fernet) with a key derived from CREDENTIAL_KEY, falling back to
JWT_SECRET so a fresh install works. For password mode the target's host key is pinned on the
first successful connection ("trust on first use") and every later connection must match it.
"""
from __future__ import annotations

import base64
import hashlib
import io
from typing import Any, Callable, Optional

from cryptography.fernet import Fernet, InvalidToken
import paramiko

from ..config import get_settings

AUTH_KEY = "key"
AUTH_PASSWORD = "password"
AUTH_PRIVATE_KEY = "private_key"
TARGET_AUTH_MODES = (AUTH_PASSWORD, AUTH_PRIVATE_KEY)


def _fernet() -> Fernet:
    settings = get_settings()
    secret = getattr(settings, "credential_key", "") or settings.jwt_secret
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest()))


def encrypt_password(password: str) -> str:
    return _fernet().encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_password(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def host_key_line(key: paramiko.PKey) -> str:
    return f"{key.get_name()} {key.get_base64()}"


def host_key_fingerprint(line: Optional[str]) -> Optional[str]:
    if not line:
        return None
    try:
        _, blob = line.split(" ", 1)
        digest = hashlib.sha256(base64.b64decode(blob)).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except (ValueError, TypeError):
        return None


class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept the host key once, then require the same key forever (until an admin resets it)."""

    def __init__(self, pinned: Optional[str], on_learn: Optional[Callable[[str], None]] = None):
        self.pinned = pinned
        self.on_learn = on_learn
        self.learned: Optional[str] = None

    def missing_host_key(self, client, hostname, key):
        line = host_key_line(key)
        if self.pinned:
            if line != self.pinned:
                raise paramiko.BadHostKeyException(hostname, key, key)
            return
        self.learned = line
        if self.on_learn:
            self.on_learn(line)


def auth_mode(target: Any) -> str:
    value = target.get("ssh_auth") if isinstance(target, dict) else getattr(target, "ssh_auth", None)
    return value if value in TARGET_AUTH_MODES else AUTH_KEY


def load_private_key(pem: str, passphrase: Optional[str] = None) -> paramiko.PKey:
    """Parse a pasted OpenSSH/PEM private key (Ed25519, ECDSA or RSA). Raises ValueError with a Korean message."""
    text = (pem or "").strip().replace("\r\n", "\n") + "\n"
    if "PRIVATE KEY" not in text:
        raise ValueError("개인키는 '-----BEGIN ... PRIVATE KEY-----'로 시작하는 파일 내용 전체여야 합니다")
    last_error: Optional[Exception] = None
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_class.from_private_key(io.StringIO(text), password=passphrase or None)
        except paramiko.PasswordRequiredException as error:
            raise ValueError("이 개인키는 암호(passphrase)로 보호되어 있습니다. 키 암호를 함께 입력하세요") from error
        except (paramiko.SSHException, ValueError) as error:
            last_error = error
    raise ValueError("개인키를 읽지 못했습니다. OpenSSH 또는 PEM 형식의 Ed25519·ECDSA·RSA 키인지, 키 암호가 맞는지 확인하세요") from last_error


def connect_kwargs(target: Any, timeout: int) -> dict[str, Any]:
    """paramiko.SSHClient.connect keyword arguments for a target model or job snapshot."""
    get = target.get if isinstance(target, dict) else lambda name, default=None: getattr(target, name, default)
    kwargs = dict(hostname=get("ip_address"), port=get("ssh_port") or 22, username=get("ssh_username"),
                  timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, look_for_keys=False, allow_agent=False)
    mode = auth_mode(target)
    if mode == AUTH_PASSWORD:
        kwargs.update(password=decrypt_password(get("ssh_password_encrypted")))
    elif mode == AUTH_PRIVATE_KEY:
        pem = decrypt_password(get("ssh_private_key_encrypted"))
        if not pem:
            raise ValueError("이 서버의 SSH 개인키가 저장되어 있지 않습니다")
        kwargs.update(pkey=load_private_key(pem, decrypt_password(get("ssh_password_encrypted"))))
    else:
        kwargs.update(key_filename=get_settings().ssh_private_key_path or None)
    return kwargs
