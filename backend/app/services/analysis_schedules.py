"""Durable, compare-and-swap scheduled enqueueing; missed intervals are coalesced."""
from __future__ import annotations

from datetime import timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .. import models, schemas
from ..db import SessionLocal
from .analysis_jobs import analysis_snapshot, enqueue_analysis


def create_schedule(db, payload: schemas.AnalysisScheduleCreate):
    spec = {'scan_scope': payload.scan_scope, 'target_path': payload.target_path}
    snapshot = analysis_snapshot(db, payload.asset_id, **spec)
    spec['target_path'] = snapshot.get('target_path')
    schedule = models.AnalysisSchedule(asset_id=payload.asset_id, input_spec=spec,
        scan_scope=snapshot['scan_scope'], interval_minutes=payload.interval_minutes, enabled=payload.enabled,
        next_run_at=models.utcnow() + timedelta(minutes=payload.interval_minutes))
    db.add(schedule)
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail='같은 자산·분석 범위의 예약이 이미 있습니다.') from error
    db.refresh(schedule)
    return schedule


def update_schedule(db, schedule_id: int, payload: schemas.AnalysisScheduleUpdate):
    schedule = db.get(models.AnalysisSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail='분석 예약이 없습니다.')
    changes = payload.model_dump(exclude_unset=True)
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail='예약 설정에 null을 사용할 수 없습니다.')
    if changes.get('enabled'):
        analysis_snapshot(db, schedule.asset_id, **schedule.input_spec)
    if 'interval_minutes' in changes:
        schedule.interval_minutes = changes['interval_minutes']
    if 'enabled' in changes:
        schedule.enabled = changes['enabled']
    if schedule.enabled and (changes.get('enabled') or 'interval_minutes' in changes):
        schedule.next_run_at = models.utcnow() + timedelta(minutes=schedule.interval_minutes)
    schedule.last_error = None
    db.commit()
    db.refresh(schedule)
    return schedule


def enqueue_due_schedules() -> int:
    now = models.utcnow()
    with SessionLocal() as db:
        ids = db.scalars(select(models.AnalysisSchedule.id).where(
            models.AnalysisSchedule.enabled.is_(True), models.AnalysisSchedule.next_run_at <= now,
        # Persisted attempt order provides bounded progress: an early busy
        # target moves behind due targets not attempted in this sweep yet.
        ).order_by(models.AnalysisSchedule.last_requested_at.asc().nullsfirst(),
                   models.AnalysisSchedule.next_run_at, models.AnalysisSchedule.id).limit(50)).all()
    enqueued = 0
    for schedule_id in ids:
        with SessionLocal() as db:
            schedule = db.get(models.AnalysisSchedule, schedule_id)
            if not schedule or not schedule.enabled:
                continue
            previous_due = schedule.next_run_at
            due = previous_due if previous_due.tzinfo else previous_due.replace(tzinfo=timezone.utc)
            if due > now:
                continue
            interval = timedelta(minutes=schedule.interval_minutes)
            next_due = due + interval * (int((now - due) // interval) + 1)
            # The schedule claim and new queue row commit together. A process crash
            # before commit leaves both undone, and competing workers cannot claim twice.
            claim = db.execute(update(models.AnalysisSchedule).where(
                models.AnalysisSchedule.id == schedule.id,
                models.AnalysisSchedule.enabled.is_(True),
                models.AnalysisSchedule.next_run_at == previous_due,
            ).values(next_run_at=next_due, last_requested_at=now))
            if claim.rowcount != 1:
                db.rollback()
                continue
            try:
                job = enqueue_analysis(db, schedule.asset_id, **schedule.input_spec, commit=False)
                schedule.last_job_id = job.id
                schedule.last_error = None
                db.commit()
                enqueued += 1
            except HTTPException as error:
                if error.status_code == 409:
                    # Another target is active on this asset. Keep this occurrence
                    # due so it is picked up after the active analysis finishes.
                    schedule.next_run_at = previous_due
                schedule.last_error = str(error.detail)[:2000]
                db.commit()
            except IntegrityError:
                db.rollback()
                # A conflicting queue insert must not keep occupying the first
                # page forever. Preserve another worker's successful advancement.
                db.execute(update(models.AnalysisSchedule).where(
                    models.AnalysisSchedule.id == schedule_id,
                    models.AnalysisSchedule.enabled.is_(True),
                    models.AnalysisSchedule.next_run_at == previous_due,
                ).values(last_requested_at=now,
                         last_error='분석 요청이 충돌했습니다. 다음 주기에 다시 확인합니다.'))
                db.commit()
    return enqueued
