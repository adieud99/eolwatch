from datetime import date, datetime, timezone

from sqlalchemy import select

from . import models
from .config import get_settings
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
    target_ips = get_settings().demo_target_ip_list or ["10.0.1.11", "10.0.1.12", "10.0.1.13"]
    with SessionLocal() as db:
        customer = get_or_create(db, models.Customer, customer_code="DEMO", defaults={"name": "시스원 인프라 시연 고객사"})
        site = get_or_create(db, models.Site, customer_id=customer.id, site_code="AWS-SEOUL", defaults={"name": "AWS 서울 리전"})

        models_and_assets = [
            ("AWS", "EC2 t4g.micro", None, None, "AWS-TARGET-001", "점검 대상 서버 1", target_ips[0] if len(target_ips) > 0 else None, "cloud", True),
            ("AWS", "EC2 t4g.micro", None, None, "AWS-TARGET-002", "점검 대상 서버 2", target_ips[1] if len(target_ips) > 1 else None, "cloud", True),
            ("AWS", "EC2 t4g.micro", None, None, "AWS-TARGET-003", "점검 대상 서버 3", target_ips[2] if len(target_ips) > 2 else None, "cloud", True),
            ("Cisco", "Catalyst 2960X-24TS-L", date(2027, 10, 31), "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/eos-eol-notice-c51-744432.html", "DEMO-NET-001", "시연 코어 스위치", None, "network", False),
        ]
        assets = []
        for vendor, model_name, end_date, source_url, asset_tag, asset_name, ip_address, asset_type, monitored in models_and_assets:
            release = None
            if end_date:
                release = get_or_create(
                    db,
                    models.ProductRelease,
                    product_type="HARDWARE_MODEL",
                    vendor=vendor,
                    name=model_name,
                    version="1",
                    defaults={
                        "support_end_date": end_date,
                        "lifecycle_source_url": source_url,
                        "verified_at": datetime.now(timezone.utc),
                    },
                )
            asset = get_or_create(
                db,
                models.Asset,
                asset_tag=asset_tag,
                defaults={
                    "site_id": site.id,
                    "model_release_id": release.id if release else None,
                    "name": asset_name,
                    "asset_type": asset_type,
                    "manufacturer": vendor,
                    "model": model_name,
                    "ip_address": ip_address,
                    "ssh_username": "eolwatch",
                    "monitored": monitored,
                },
            )
            assets.append(asset)

        os_release = get_or_create(
            db,
            models.ProductRelease,
            product_type="OS",
            vendor="Amazon Web Services",
            name="Amazon Linux",
            version="2023",
            defaults={
                "support_end_date": date(2029, 6, 30),
                "lifecycle_source_url": "https://docs.aws.amazon.com/linux/al2023/release-notes/support-information.html",
                "verified_at": datetime.now(timezone.utc),
            },
        )
        postgres_release = db.scalar(
            select(models.ProductRelease).where(models.ProductRelease.purl == "pkg:generic/postgresql@16.4")
        )
        if not postgres_release:
            postgres_release = models.ProductRelease(
                product_type="APPLICATION",
                vendor="PostgreSQL Global Development Group",
                name="PostgreSQL",
                version="16.4",
                purl="pkg:generic/postgresql@16.4",
            )
            db.add(postgres_release)
        postgres_release.support_end_date = date(2028, 11, 9)
        postgres_release.lifecycle_source_url = "https://www.postgresql.org/support/versioning/"
        postgres_release.verified_at = datetime.now(timezone.utc)
        for asset in assets[:3]:
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
    print("시연 데이터 생성 완료: 고객사 1, 사이트 1, 자산 4, SBOM 1")


if __name__ == "__main__":
    seed()
