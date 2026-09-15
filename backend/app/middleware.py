from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from . import models
from .db import SessionLocal
from .services.auth import decode_access_token


PUBLIC_PATHS = {"/health", "/api/auth/login", "/docs", "/openapi.json", "/redoc"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


async def authenticate_and_audit(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS or not request.url.path.startswith("/api/"):
        return await call_next(request)

    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "로그인이 필요합니다"})
    try:
        payload = decode_access_token(authorization[7:].strip())
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        return JSONResponse(status_code=401, content={"detail": "인증 토큰이 올바르지 않거나 만료됐습니다"})

    with SessionLocal() as db:
        user = db.scalar(select(models.User).where(models.User.id == user_id, models.User.active.is_(True)))
        if not user:
            return JSONResponse(status_code=401, content={"detail": "사용할 수 없는 계정입니다"})
        request.state.user = user
        request.state.audit_user = {"id": user.id, "username": user.username, "role": user.role}

    if request.method not in SAFE_METHODS and request.state.audit_user["role"] != "ADMIN":
        return JSONResponse(status_code=403, content={"detail": "관리자 권한이 필요합니다"})

    response = await call_next(request)
    if request.method not in SAFE_METHODS and response.status_code < 400:
        with SessionLocal() as db:
            db.add(
                models.AuditLog(
                    user_id=request.state.audit_user["id"],
                    username=request.state.audit_user["username"],
                    action="CHANGE",
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    ip_address=request.client.host if request.client else None,
                )
            )
            db.commit()
    return response
