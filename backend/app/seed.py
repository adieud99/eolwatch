from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select

from . import models
from .db import Base, SessionLocal, engine
from .services.collector import packages_to_cyclonedx
from .services.sbom import import_cyclonedx


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
    today = date.today()
    with SessionLocal() as db:
        customer = get_or_create(db, models.Customer, customer_code="DEMO", defaults={"name": "시연 고객사"})
        site = get_or_create(db, models.Site, customer_id=customer.id, site_code="SEOUL-DC", defaults={"name": "서울 전산실"})

        models_and_assets = [
            ("DemoRack R700", today - timedelta(days=30), "DEMO-SRV-001", "운영 DB 서버", "10.0.1.11"),
            ("DemoRack R800", today + timedelta(days=90), "DEMO-SRV-002", "운영 웹 서버", "10.0.1.12"),
            ("DemoRack R900", today + timedelta(days=500), "DEMO-SRV-003", "백업 서버", "10.0.1.13"),
        ]
        assets = []
        for model_name, end_date, asset_tag, asset_name, ip_address in models_and_assets:
            release = get_or_create(
                db,
                models.ProductRelease,
                product_type="HARDWARE_MODEL",
                vendor="Demo Vendor",
                name=model_name,
                version="1",
                defaults={
                    "support_end_date": end_date,
                    "lifecycle_source_url": "https://example.com/demo-lifecycle",
                    "verified_at": datetime.now(timezone.utc),
                },
            )
            asset = get_or_create(
                db,
                models.Asset,
                asset_tag=asset_tag,
                defaults={
                    "site_id": site.id,
                    "model_release_id": release.id,
                    "name": asset_name,
                    "asset_type": "server",
                    "manufacturer": "Demo Vendor",
                    "model": model_name,
                    "ip_address": ip_address,
                    "ssh_username": "eolwatch",
                    "monitored": True,
                },
            )
            assets.append(asset)

        os_release = get_or_create(
            db,
            models.ProductRelease,
            product_type="OS",
            vendor="Demo Linux Foundation",
            name="DemoLinux LTS",
            version="22.04",
            defaults={
                "support_end_date": today + timedelta(days=150),
                "lifecycle_source_url": "https://example.com/demo-os-lifecycle",
                "verified_at": datetime.now(timezone.utc),
            },
        )
        for asset in assets:
            get_or_create(db, models.Deployment, asset_id=asset.id, software_product_id=os_release.id)
        db.commit()

        if not db.scalar(select(models.SbomDocument).where(models.SbomDocument.asset_id == assets[0].id)):
            document = packages_to_cyclonedx(
                assets[0],
                [
                    {"name": "openssl", "version": "3.0.2"},
                    {"name": "postgresql", "version": "16.4"},
                    {"name": "systemd", "version": "249.11"},
                ],
                datetime.now(timezone.utc),
            )
            import_cyclonedx(db, document, asset_id=assets[0].id)
    print("시연 데이터 생성 완료: 고객사 1, 사이트 1, 자산 3, SBOM 1")


if __name__ == "__main__":
    seed()
