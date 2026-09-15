from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


AssetType = Literal["server", "storage", "network", "security", "vm", "cloud", "other"]
ProductType = Literal["HARDWARE_MODEL", "OS", "FIRMWARE", "HYPERVISOR", "MIDDLEWARE", "DBMS", "AGENT", "LIBRARY", "APPLICATION"]


class CustomerCreate(BaseModel):
    customer_code: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=160)


class CustomerRead(CustomerCreate):
    id: int
    status: str
    site_count: int = 0
    asset_count: int = 0
    created_at: datetime


class SiteCreate(BaseModel):
    customer_id: int
    site_code: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=160)
    address: Optional[str] = None
    timezone: str = "Asia/Seoul"


class SiteRead(SiteCreate):
    id: int
    customer_name: str
    asset_count: int = 0


class AssetBase(BaseModel):
    site_id: Optional[int] = None
    model_release_id: Optional[int] = None
    asset_tag: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    asset_type: AssetType
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    site: Optional[str] = None
    ip_address: Optional[str] = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: Optional[str] = None
    introduced_on: Optional[date] = None
    support_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None
    monitored: bool = False

    @model_validator(mode="after")
    def lifecycle_has_source(self):
        if self.support_end_date and not self.lifecycle_source_url:
            raise ValueError("지원종료일에는 근거 URL이 필요합니다")
        return self


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    site_id: Optional[int] = None
    model_release_id: Optional[int] = None
    name: Optional[str] = None
    asset_type: Optional[AssetType] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    site: Optional[str] = None
    ip_address: Optional[str] = None
    ssh_port: Optional[int] = Field(default=None, ge=1, le=65535)
    ssh_username: Optional[str] = None
    introduced_on: Optional[date] = None
    support_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None
    monitored: Optional[bool] = None


class AssetRead(AssetBase):
    id: int
    risk_level: str
    days_left: Optional[int]
    software_count: int = 0
    sbom_count: int = 0
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SoftwareCreate(BaseModel):
    product_type: ProductType = "OS"
    name: str = Field(min_length=1, max_length=200)
    vendor: Optional[str] = None
    version: str = Field(min_length=1, max_length=100)
    purl: Optional[str] = None
    cpe: Optional[str] = None
    support_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None
    asset_id: Optional[int] = None
    environment: str = "production"


class SoftwareRead(BaseModel):
    id: int
    product_type: str
    name: str
    vendor: Optional[str]
    version: str
    purl: Optional[str]
    cpe: Optional[str]
    support_end_date: Optional[date]
    lifecycle_source_url: Optional[str]
    risk_level: str
    days_left: Optional[int]
    asset_ids: list[int]


class ProductReleaseUpdate(BaseModel):
    product_type: Optional[ProductType] = None
    vendor: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    eol_date: Optional[date] = None
    support_end_date: Optional[date] = None
    security_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None


class ProductReleaseRead(BaseModel):
    id: int
    product_type: str
    vendor: Optional[str]
    name: str
    version: str
    purl: Optional[str]
    cpe: Optional[str]
    eol_date: Optional[date]
    support_end_date: Optional[date]
    security_end_date: Optional[date]
    lifecycle_source_url: Optional[str]
    verified_at: Optional[datetime]
    risk_level: str
    days_left: Optional[int]
    deployment_count: int
    component_occurrence_count: int


class SbomImportEnvelope(BaseModel):
    document: dict[str, Any]
    asset_id: Optional[int] = None
    software_product_id: Optional[int] = None


class SbomRead(BaseModel):
    id: int
    serial_number: str
    bom_format: str
    spec_version: str
    document_version: int
    generated_at: Optional[datetime]
    imported_at: datetime
    asset_id: Optional[int]
    software_product_id: Optional[int]
    component_count: int
    dependency_count: int
    quality_score: float
    quality_details: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class ComponentRead(BaseModel):
    id: int
    bom_ref: str
    component_type: str
    group_name: Optional[str]
    name: str
    version: Optional[str]
    supplier: Optional[str]
    purl: Optional[str]
    cpe: Optional[str]
    licenses: list[Any]
    support_end_date: Optional[date]
    risk_level: str
    days_left: Optional[int]


class ComponentLifecycleUpdate(BaseModel):
    support_end_date: date
    lifecycle_source_url: HttpUrl


class DashboardSummary(BaseModel):
    assets: int
    software_products: int
    sbom_documents: int
    components: int
    dependencies: int
    lifecycle_risk: dict[str, int]
    sbom_quality: dict[str, Union[int, float]]
    urgent_items: list[dict[str, Any]]


class CollectionJobRead(BaseModel):
    id: int
    asset_id: int
    asset_tag: str
    asset_name: str
    trigger_type: str
    status: str
    failure_stage: Optional[str]
    failure_code: Optional[str]
    failure_message: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    retry_count: int
    health_level: Optional[str] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    max_disk_percent: Optional[float] = None
    uptime_seconds: Optional[int] = None


class CheckResultRead(BaseModel):
    id: int
    collection_job_id: int
    cpu_percent: Optional[float]
    memory_percent: Optional[float]
    max_disk_percent: Optional[float]
    uptime_seconds: Optional[int]
    health_level: str
    disk_details: list[Any]
    process_details: list[Any]
    raw_metrics: dict[str, Any]


class ContractCreate(BaseModel):
    customer_id: int
    contract_no: str = Field(min_length=1, max_length=80)
    provider: str = Field(min_length=1, max_length=160)
    start_date: date
    end_date: date
    annual_cost: Optional[float] = Field(default=None, ge=0)
    service_level: Optional[str] = None
    asset_ids: list[int] = Field(default_factory=list)


class ContractRead(ContractCreate):
    id: int
    customer_name: str
    risk_level: str
    days_left: int


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=8, max_length=200)


class UserRead(BaseModel):
    id: int
    username: str
    role: str
    active: bool
    created_at: datetime
    last_login_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=200)
    role: Literal["ADMIN", "VIEWER"] = "VIEWER"


class UserUpdate(BaseModel):
    role: Optional[Literal["ADMIN", "VIEWER"]] = None
    active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=200)


class CsvRowError(BaseModel):
    row: int
    asset_tag: Optional[str] = None
    message: str


class AssetCsvImportResult(BaseModel):
    total_rows: int
    created: int
    failed: int
    errors: list[CsvRowError]


class SbomDiffItem(BaseModel):
    identity: str
    name: str
    before_version: Optional[str] = None
    after_version: Optional[str] = None
    purl: Optional[str] = None


class SbomDiffRead(BaseModel):
    base_sbom_id: int
    target_sbom_id: int
    added: list[SbomDiffItem]
    removed: list[SbomDiffItem]
    changed: list[SbomDiffItem]
    unchanged_count: int


class VulnerabilityRead(BaseModel):
    link_id: int
    component_id: int
    component_name: str
    component_version: Optional[str]
    sbom_id: int
    osv_id: str
    summary: Optional[str]
    severity: str
    aliases: list[Any]
    vex_status: str
    justification: Optional[str]
    response: Optional[str]
    detail: Optional[str]
    modified_at: Optional[datetime]


class VulnerabilityScanResult(BaseModel):
    sbom_id: int
    queried_components: int
    vulnerability_links: int
    unique_vulnerabilities: int


class VexUpdate(BaseModel):
    status: Literal["AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION"]
    justification: Optional[str] = Field(default=None, max_length=80)
    response: Optional[str] = Field(default=None, max_length=80)
    detail: Optional[str] = Field(default=None, max_length=2000)


class NotificationRead(BaseModel):
    id: int
    channel: str
    event_type: str
    status: str
    response_code: Optional[int]
    error_message: Optional[str]
    recipient_label: Optional[str]
    payload_summary: dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogRead(BaseModel):
    id: int
    user_id: Optional[int]
    username: str
    action: str
    method: str
    path: str
    status_code: int
    ip_address: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
