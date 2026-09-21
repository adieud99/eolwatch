from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_code: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sites: Mapped[list[Site]] = relationship(back_populates="customer", cascade="all, delete-orphan")
    contracts: Mapped[list[Contract]] = relationship(back_populates="customer", cascade="all, delete-orphan")


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    site_code: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(160))
    address: Mapped[Optional[str]] = mapped_column(Text)
    timezone: Mapped[str] = mapped_column(String(50), default="Asia/Seoul")

    customer: Mapped[Customer] = relationship(back_populates="sites")
    assets: Mapped[list[Asset]] = relationship(back_populates="site_record")

    __table_args__ = (UniqueConstraint("customer_id", "site_code", name="uq_customer_site_code"),)


class ProductRelease(Base):
    __tablename__ = "product_releases"

    id: Mapped[int] = mapped_column(primary_key=True)
    product_type: Mapped[str] = mapped_column(String(40), default="OS", index=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(160))
    name: Mapped[str] = mapped_column(String(200), index=True)
    version: Mapped[str] = mapped_column(String(100), default="N/A")
    purl: Mapped[Optional[str]] = mapped_column(String(500), unique=True, index=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(500), unique=True, index=True)
    eol_date: Mapped[Optional[date]] = mapped_column(Date, index=True)
    support_end_date: Mapped[Optional[date]] = mapped_column(Date, index=True)
    security_end_date: Mapped[Optional[date]] = mapped_column(Date, index=True)
    lifecycle_source_url: Mapped[Optional[str]] = mapped_column(Text)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    assets: Mapped[list[Asset]] = relationship(back_populates="model_release")
    deployments: Mapped[list[Deployment]] = relationship(back_populates="software_product", cascade="all, delete-orphan")
    sboms: Mapped[list[SbomDocument]] = relationship(back_populates="software_product")
    component_occurrences: Mapped[list[Component]] = relationship(back_populates="product_release")

    __table_args__ = (UniqueConstraint("product_type", "vendor", "name", "version", name="uq_product_release_identity"),)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[Optional[int]] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"), index=True)
    model_release_id: Mapped[Optional[int]] = mapped_column(ForeignKey("product_releases.id", ondelete="SET NULL"), index=True)
    asset_tag: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    asset_type: Mapped[str] = mapped_column(String(40), index=True)
    manufacturer: Mapped[Optional[str]] = mapped_column(String(120))
    model: Mapped[Optional[str]] = mapped_column(String(160))
    serial_number: Mapped[Optional[str]] = mapped_column(String(160))
    site: Mapped[Optional[str]] = mapped_column(String(160))
    building: Mapped[Optional[str]] = mapped_column(String(120))
    floor: Mapped[Optional[str]] = mapped_column(String(40))
    room: Mapped[Optional[str]] = mapped_column(String(120))
    rack: Mapped[Optional[str]] = mapped_column(String(80))
    rack_position: Mapped[Optional[str]] = mapped_column(String(40))
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_username: Mapped[Optional[str]] = mapped_column(String(80))
    introduced_on: Mapped[Optional[date]] = mapped_column(Date)
    purchase_date: Mapped[Optional[date]] = mapped_column(Date)
    purchase_price: Mapped[Optional[float]] = mapped_column(Numeric(14, 2))
    power_watts: Mapped[Optional[float]] = mapped_column(Float)
    power_source: Mapped[Optional[str]] = mapped_column(String(40))
    warranty_end_date: Mapped[Optional[date]] = mapped_column(Date)
    owner_name: Mapped[Optional[str]] = mapped_column(String(120))
    owner_department: Mapped[Optional[str]] = mapped_column(String(120))
    operational_status: Mapped[str] = mapped_column(String(30), default="ACTIVE", server_default="ACTIVE", index=True)
    service_criticality: Mapped[str] = mapped_column(String(20), default="STANDARD", server_default="STANDARD", index=True)
    support_end_date: Mapped[Optional[date]] = mapped_column(Date, index=True)
    lifecycle_source_url: Mapped[Optional[str]] = mapped_column(Text)
    monitored: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    site_record: Mapped[Optional[Site]] = relationship(back_populates="assets", foreign_keys=[site_id])
    model_release: Mapped[Optional[ProductRelease]] = relationship(back_populates="assets", foreign_keys=[model_release_id])
    deployments: Mapped[list[Deployment]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    sboms: Mapped[list[SbomDocument]] = relationship(back_populates="asset")
    collection_jobs: Mapped[list[CollectionJob]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class AssetRiskSnapshot(Base):
    __tablename__ = "asset_risk_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    score: Mapped[int] = mapped_column(Integer)
    priority_level: Mapped[str] = mapped_column(String(20), index=True)
    factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    asset: Mapped[Asset] = relationship()


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    software_product_id: Mapped[int] = mapped_column(ForeignKey("product_releases.id", ondelete="CASCADE"), index=True)
    environment: Mapped[str] = mapped_column(String(40), default="production")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="deployments")
    software_product: Mapped[ProductRelease] = relationship(back_populates="deployments")

    __table_args__ = (UniqueConstraint("asset_id", "software_product_id", name="uq_deployment"),)


class SbomDocument(Base):
    __tablename__ = "sbom_documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    serial_number: Mapped[str] = mapped_column(String(200), index=True)
    bom_format: Mapped[str] = mapped_column(String(40), default="CycloneDX")
    spec_version: Mapped[str] = mapped_column(String(20))
    document_version: Mapped[int] = mapped_column(Integer, default=1)
    generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    asset_id: Mapped[Optional[int]] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    software_product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("product_releases.id", ondelete="SET NULL"), index=True)
    collection_job_id: Mapped[Optional[int]] = mapped_column(ForeignKey("collection_jobs.id", ondelete="SET NULL"), index=True)
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    dependency_count: Mapped[int] = mapped_column(Integer, default=0)
    quality_score: Mapped[float] = mapped_column(Float, default=0)
    quality_details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_document: Mapped[dict[str, Any]] = mapped_column(JSON)

    asset: Mapped[Optional[Asset]] = relationship(back_populates="sboms")
    software_product: Mapped[Optional[ProductRelease]] = relationship(back_populates="sboms")
    components: Mapped[list[Component]] = relationship(back_populates="sbom", cascade="all, delete-orphan")
    dependencies: Mapped[list[DependencyEdge]] = relationship(back_populates="sbom", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("serial_number", "document_version", name="uq_sbom_version"),)


class Component(Base):
    __tablename__ = "components"

    id: Mapped[int] = mapped_column(primary_key=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True)
    product_release_id: Mapped[Optional[int]] = mapped_column(ForeignKey("product_releases.id", ondelete="SET NULL"), index=True)
    bom_ref: Mapped[str] = mapped_column(String(600))
    component_type: Mapped[str] = mapped_column(String(40), default="library")
    group_name: Mapped[Optional[str]] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(300), index=True)
    version: Mapped[Optional[str]] = mapped_column(String(160), index=True)
    supplier: Mapped[Optional[str]] = mapped_column(String(200))
    purl: Mapped[Optional[str]] = mapped_column(String(700), index=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(700))
    licenses: Mapped[list[Any]] = mapped_column(JSON, default=list)
    hashes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    support_end_date: Mapped[Optional[date]] = mapped_column(Date, index=True)
    lifecycle_source_url: Mapped[Optional[str]] = mapped_column(Text)

    sbom: Mapped[SbomDocument] = relationship(back_populates="components")
    product_release: Mapped[Optional[ProductRelease]] = relationship(back_populates="component_occurrences")

    __table_args__ = (UniqueConstraint("sbom_id", "bom_ref", name="uq_component_bom_ref"),)


class DependencyEdge(Base):
    __tablename__ = "dependency_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True)
    source_ref: Mapped[str] = mapped_column(String(600))
    target_ref: Mapped[str] = mapped_column(String(600))

    sbom: Mapped[SbomDocument] = relationship(back_populates="dependencies")

    __table_args__ = (UniqueConstraint("sbom_id", "source_ref", "target_ref", name="uq_dependency_edge"),)


class Contract(Base):
    __tablename__ = "contracts"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    contract_no: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(160))
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date, index=True)
    annual_cost: Mapped[Optional[float]] = mapped_column(Numeric(14, 2))
    service_level: Mapped[Optional[str]] = mapped_column(String(100))

    customer: Mapped[Customer] = relationship(back_populates="contracts")
    assets: Mapped[list[ContractAsset]] = relationship(back_populates="contract", cascade="all, delete-orphan")


class ContractAsset(Base):
    __tablename__ = "contract_assets"

    contract_id: Mapped[int] = mapped_column(ForeignKey("contracts.id", ondelete="CASCADE"), primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True)

    contract: Mapped[Contract] = relationship(back_populates="assets")
    asset: Mapped[Asset] = relationship()


class CollectionJob(Base):
    __tablename__ = "collection_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    trigger_type: Mapped[str] = mapped_column(String(20), default="MANUAL")
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True)
    failure_stage: Mapped[Optional[str]] = mapped_column(String(20))
    failure_code: Mapped[Optional[str]] = mapped_column(String(80))
    failure_message: Mapped[Optional[str]] = mapped_column(Text)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    retry_count: Mapped[int] = mapped_column(Integer, default=0)

    asset: Mapped[Asset] = relationship(back_populates="collection_jobs")
    result: Mapped[Optional[CheckResult]] = relationship(back_populates="job", cascade="all, delete-orphan", uselist=False)


class CheckResult(Base):
    __tablename__ = "check_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    collection_job_id: Mapped[int] = mapped_column(ForeignKey("collection_jobs.id", ondelete="CASCADE"), unique=True, index=True)
    cpu_percent: Mapped[Optional[float]] = mapped_column(Float)
    memory_percent: Mapped[Optional[float]] = mapped_column(Float)
    max_disk_percent: Mapped[Optional[float]] = mapped_column(Float)
    uptime_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    health_level: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    disk_details: Mapped[list[Any]] = mapped_column(JSON, default=list)
    process_details: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    job: Mapped[CollectionJob] = relationship(back_populates="result")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(20), default="VIEWER", index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    username: Mapped[str] = mapped_column(String(80), index=True)
    action: Mapped[str] = mapped_column(String(40), index=True)
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    status_code: Mapped[int] = mapped_column(Integer)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    osv_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    details: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN", index=True)
    aliases: Mapped[list[Any]] = mapped_column(JSON, default=list)
    references: Mapped[list[Any]] = mapped_column(JSON, default=list)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    component_links: Mapped[list[ComponentVulnerability]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class ComponentVulnerability(Base):
    __tablename__ = "component_vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id", ondelete="CASCADE"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    vex_status: Mapped[str] = mapped_column(String(30), default="AFFECTED", index=True)
    justification: Mapped[Optional[str]] = mapped_column(String(80))
    response: Mapped[Optional[str]] = mapped_column(String(80))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    review_revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    assignee_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL", name="fk_component_vulnerabilities_assignee_id_users"), index=True)
    due_date: Mapped[Optional[date]] = mapped_column(Date, index=True)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(160))
    analysis_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("analysis_runs.id", ondelete="SET NULL"), index=True)
    finding_source: Mapped[Optional[str]] = mapped_column(String(40))
    finding_severity: Mapped[Optional[str]] = mapped_column(String(20))
    fixed_versions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    component: Mapped[Component] = relationship()
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="component_links")
    assignee: Mapped[Optional[User]] = relationship(foreign_keys=[assignee_id])
    actions: Mapped[list[VulnerabilityAction]] = relationship(back_populates="link", passive_deletes="all")

    __table_args__ = (UniqueConstraint("component_id", "vulnerability_id", name="uq_component_vulnerability"),)


class VulnerabilityAction(Base):
    """Append-only application history; snapshots remain if users/evidence are removed."""
    __tablename__ = "vulnerability_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    link_id: Mapped[int] = mapped_column(ForeignKey("component_vulnerabilities.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor_username: Mapped[str] = mapped_column(String(80))
    from_status: Mapped[str] = mapped_column(String(30))
    to_status: Mapped[str] = mapped_column(String(30))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    before_state: Mapped[dict[str, Any]] = mapped_column(JSON)
    after_state: Mapped[dict[str, Any]] = mapped_column(JSON)
    evidence_analysis_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("analysis_runs.id", ondelete="SET NULL"), index=True)
    evidence_snapshot: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    link: Mapped[ComponentVulnerability] = relationship(back_populates="actions")

    __table_args__ = (Index("ix_vulnerability_actions_link_id_id", "link_id", "id"),)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[int] = mapped_column(primary_key=True)
    channel: Mapped[str] = mapped_column(String(30), default="TEAMS")
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    response_code: Mapped[Optional[int]] = mapped_column(Integer)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    recipient_label: Mapped[Optional[str]] = mapped_column(String(160))
    payload_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


# 기존 API 이름을 유지하면서 목표 ERD의 PRODUCT_RELEASE를 사용한다.
SoftwareProduct = ProductRelease


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sbom_documents.id", ondelete="CASCADE"), index=True)
    report_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    sbom_sha256: Mapped[str] = mapped_column(String(64))
    scanner: Mapped[str] = mapped_column(String(40))
    scanner_version: Mapped[str] = mapped_column(String(80))
    generator: Mapped[str] = mapped_column(String(160))
    scan_scope: Mapped[str] = mapped_column(String(300))
    match_count: Mapped[int] = mapped_column(Integer)
    cve_count: Mapped[int] = mapped_column(Integer)
    link_count: Mapped[int] = mapped_column(Integer)
    ignored_non_cve: Mapped[int] = mapped_column(Integer)
    database_info: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_report: Mapped[dict[str, Any]] = mapped_column(JSON)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sbom: Mapped[SbomDocument] = relationship()


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    # Non-null only while queued/running: the unique constraint also prevents racing API requests.
    active_asset_id: Mapped[Optional[int]] = mapped_column(Integer, unique=True)
    asset_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="QUEUED", index=True)
    worker_token: Mapped[Optional[str]] = mapped_column(String(36))
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[Optional[str]] = mapped_column(String(80))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    analysis_run_id: Mapped[Optional[int]] = mapped_column(ForeignKey("analysis_runs.id", ondelete="SET NULL"), index=True)
    retry_of_id: Mapped[Optional[int]] = mapped_column(ForeignKey("analysis_jobs.id", ondelete="SET NULL"))

    asset: Mapped[Asset] = relationship()
    analysis_run: Mapped[Optional[AnalysisRun]] = relationship()


class AnalysisUpload(Base):
    __tablename__ = "analysis_uploads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    project_name: Mapped[str] = mapped_column(String(80))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisSchedule(Base):
    __tablename__ = "analysis_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    input_spec: Mapped[dict[str, Any]] = mapped_column(JSON)
    scan_scope: Mapped[str] = mapped_column(String(300))
    interval_minutes: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_job_id: Mapped[Optional[int]] = mapped_column(ForeignKey("analysis_jobs.id", ondelete="SET NULL"))
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    asset: Mapped[Asset] = relationship()
    __table_args__ = (UniqueConstraint("asset_id", "scan_scope", name="uq_analysis_schedule_target"),)


class LifecycleCatalogCache(Base):
    __tablename__ = "lifecycle_catalog_cache"

    id: Mapped[int] = mapped_column(primary_key=True)
    cache_key: Mapped[str] = mapped_column(String(160), unique=True)
    source_url: Mapped[str] = mapped_column(Text)
    raw_document: Mapped[Optional[str]] = mapped_column(Text)
    content_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    fetched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    provider_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    provider_last_modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[Optional[str]] = mapped_column(String(500))
    etag: Mapped[Optional[str]] = mapped_column(Text)


class LifecycleCatalogApplication(Base):
    __tablename__ = "lifecycle_catalog_applications"

    id: Mapped[int] = mapped_column(primary_key=True)
    product_release_id: Mapped[int] = mapped_column(ForeignKey("product_releases.id", ondelete="CASCADE"), index=True)
    applied_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    product_slug: Mapped[str] = mapped_column(String(120))
    release_cycle: Mapped[str] = mapped_column(String(100))
    source_url: Mapped[str] = mapped_column(Text)
    policy_url: Mapped[Optional[str]] = mapped_column(Text)
    source_sha256: Mapped[str] = mapped_column(String(64))
    source_document: Mapped[str] = mapped_column(Text)
    provider_generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    provider_last_modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    previous_values: Mapped[dict[str, Any]] = mapped_column(JSON)
    applied_values: Mapped[dict[str, Any]] = mapped_column(JSON)
