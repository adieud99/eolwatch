from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings


PBKDF2_ITERATIONS = 310_000


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _b64decode(salt), int(iterations)
        )
        return hmac.compare_digest(_b64encode(digest), expected)
    except (TypeError, ValueError):
        return False


def create_access_token(user: models.User) -> tuple[str, int]:
    settings = get_settings()
    expires_in = settings.access_token_minutes * 60
    now = datetime.now(timezone.utc)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    signing_input = ".".join(
        _b64encode(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        for value in (header, payload)
    )
    signature = hmac.new(settings.jwt_secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64encode(signature)}", expires_in


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        header_value, payload_value, signature_value = token.split(".", 2)
        signing_input = f"{header_value}.{payload_value}"
        expected = hmac.new(
            settings.jwt_secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, _b64decode(signature_value)):
            raise ValueError("서명이 올바르지 않습니다")
        header = json.loads(_b64decode(header_value))
        payload = json.loads(_b64decode(payload_value))
        if header.get("alg") != "HS256" or int(payload["exp"]) <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("토큰이 만료됐습니다")
        return payload
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("유효하지 않은 인증 토큰입니다") from exc


def ensure_admin(db: Session) -> Optional[models.User]:
    settings = get_settings()
    user = db.scalar(select(models.User).where(models.User.username == settings.admin_username))
    if user:
        return user
    if not settings.admin_password:
        # Never create an account with an empty or built-in password; the operator sets ADMIN_PASSWORD first.
        logging.getLogger(__name__).warning("ADMIN_PASSWORD is not set; no administrator account was created")
        return None
    user = models.User(
        username=settings.admin_username,
        password_hash=hash_password(settings.admin_password),
        role="ADMIN",
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
