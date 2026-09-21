from datetime import datetime, timezone

from sqlalchemy import select

from . import models
from .config import get_settings
from .db import Base, SessionLocal, engine
from .services.collector import packages_to_spdx
from .services.sbom import import_spdx


def get_or_create(db, model, defaults=None, **lookup):
    item = db.scalar(select(model).filter_by(**lookup))
    if item:
        return item
    item = model(**lookup, **(defaults or {}))
    db.add(item)
    db.flush()
    return item


def seed() -> None:
    Base.metadata.create_all(bind=engine)
    target_ips = get_settings().demo_target_ip_list or ["10.77.0.21", "10.77.0.22"]
    with SessionLocal() as db:
        assets = [
            get_or_create(
                db,
                models.Asset,
                asset_tag=f"LAB-VM-{index:02d}",
                defaults={
                    "name": f"시연 대상 VM {index}",
                    "asset_type": "vm",
                    "ip_address": address,
                    "ssh_username": "eolwatch",
                    "monitored": True,
                },
            )
            for index, address in enumerate(target_ips, 1)
        ]
        db.commit()

        if not db.scalar(select(models.SbomDocument).where(models.SbomDocument.asset_id == assets[0].id)):
            document = packages_to_spdx(
                assets[0],
                [
                    {"name": "openssl", "version": "3.0.2"},
                    {"name": "postgresql", "version": "16.4"},
                    {"name": "systemd", "version": "249.11"},
                ],
                datetime.now(timezone.utc),
            )
            import_spdx(db, document, asset_id=assets[0].id)
    print(f"시연 데이터 생성 완료: 등록 서버 {len(assets)}, SBOM 1")


if __name__ == "__main__":
    seed()
