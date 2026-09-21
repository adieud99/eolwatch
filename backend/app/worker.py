from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal
from .models import Asset
from .services.collector import run_collection
from .services.analysis_jobs import process_next_analysis_job
from .services.analysis_schedules import enqueue_due_schedules


def collect_all_monitored_assets() -> None:
    with SessionLocal() as db:
        asset_ids = db.scalars(select(Asset.id).where(Asset.monitored.is_(True))).all()
    for asset_id in asset_ids:
        with SessionLocal() as db:
            run_collection(db, asset_id, trigger_type="SCHEDULED")


def main() -> None:
    settings = get_settings()
    scheduler = BlockingScheduler(timezone=settings.scheduler_timezone)
    scheduler.add_job(enqueue_due_schedules, 'interval', seconds=max(1, settings.analysis_poll_seconds),
                      id='scheduled-vulnerability-analysis', max_instances=1, coalesce=True)
    scheduler.add_job(
        process_next_analysis_job,
        'interval',
        seconds=max(1, settings.analysis_poll_seconds),
        id='web-analysis-queue',
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        collect_all_monitored_assets,
        "cron",
        hour=settings.collection_hour,
        minute=settings.collection_minute,
        id="daily-infrastructure-check",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()


if __name__ == "__main__":
    main()
