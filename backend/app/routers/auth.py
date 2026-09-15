from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..services.auth import create_access_token, hash_password, verify_password


router = APIRouter(prefix="/auth", tags=["authentication"])


def current_user(request: Request) -> models.User:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다")
    return user


def admin_user(user: models.User = Depends(current_user)) -> models.User:
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다")
    return user


@router.post("/login", response_model=schemas.TokenResponse)
def login(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(models.User).where(models.User.username == payload.username))
    if not user or not user.active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="아이디 또는 비밀번호가 올바르지 않습니다")
    user.last_login_at = datetime.now(timezone.utc)
    db.add(
        models.AuditLog(
            user_id=user.id,
            username=user.username,
            action="LOGIN",
            method="POST",
            path="/api/auth/login",
            status_code=200,
            ip_address=request.client.host if request.client else None,
        )
    )
    db.commit()
    db.refresh(user)
    token, expires_in = create_access_token(user)
    return schemas.TokenResponse(access_token=token, expires_in=expires_in, user=user)


@router.get("/me", response_model=schemas.UserRead)
def me(user: models.User = Depends(current_user)):
    return user


@router.get("/users", response_model=list[schemas.UserRead], dependencies=[Depends(admin_user)])
def list_users(db: Session = Depends(get_db)):
    return db.scalars(select(models.User).order_by(models.User.username)).all()


@router.post("/users", response_model=schemas.UserRead, status_code=201, dependencies=[Depends(admin_user)])
def create_user(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    item = models.User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(item)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="이미 사용 중인 아이디입니다")
    db.refresh(item)
    return item


@router.patch("/users/{user_id}", response_model=schemas.UserRead, dependencies=[Depends(admin_user)])
def update_user(user_id: int, payload: schemas.UserUpdate, current: models.User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(models.User, user_id)
    if not item:
        raise HTTPException(status_code=404, detail="사용자가 없습니다")
    if item.id == current.id and payload.active is False:
        raise HTTPException(status_code=422, detail="현재 로그인한 계정은 비활성화할 수 없습니다")
    if payload.role is not None:
        item.role = payload.role
    if payload.active is not None:
        item.active = payload.active
    if payload.password:
        item.password_hash = hash_password(payload.password)
    db.commit()
    db.refresh(item)
    return item


@router.get("/audit-logs", response_model=list[schemas.AuditLogRead], dependencies=[Depends(admin_user)])
def audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    safe_limit = max(1, min(limit, 500))
    return db.scalars(select(models.AuditLog).order_by(models.AuditLog.created_at.desc()).limit(safe_limit)).all()
