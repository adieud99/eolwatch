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
    model_config = ConfigDict(str_strip_whitespace=True)
    site_id: Optional[int] = Field(default=None, ge=1)
    model_release_id: Optional[int] = Field(default=None, ge=1)
    asset_tag: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    asset_type: AssetType
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    site: Optional[str] = None
    building: Optional[str] = None
    floor: Optional[str] = None
    room: Optional[str] = None
    rack: Optional[str] = None
    rack_position: Optional[str] = None
    ip_address: Optional[str] = None
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: Optional[str] = None
    introduced_on: Optional[date] = None
    purchase_date: Optional[date] = None
    purchase_price: Optional[float] = Field(default=None, ge=0, le=1000000000000)
    power_watts: Optional[float] = Field(default=None, ge=0, le=1000000)
    power_source: Optional[str] = Field(default=None, max_length=40)
    warranty_end_date: Optional[date] = None
    owner_name: Optional[str] = None
    owner_department: Optional[str] = None
    operational_status: str = Field(default="ACTIVE", max_length=30)
    service_criticality: str = Field(default="STANDARD", max_length=20)
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
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    site_id: Optional[int] = Field(default=None, ge=1)
    model_release_id: Optional[int] = Field(default=None, ge=1)
    asset_tag: Optional[str] = Field(default=None, min_length=1, max_length=80)
    name: Optional[str] = Field(default=None, min_length=1, max_length=160)
    asset_type: Optional[AssetType] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    site: Optional[str] = None
    building: Optional[str] = None
    floor: Optional[str] = None
    room: Optional[str] = None
    rack: Optional[str] = None
    rack_position: Optional[str] = None
    ip_address: Optional[str] = None
    ssh_port: Optional[int] = Field(default=None, ge=1, le=65535)
    ssh_username: Optional[str] = None
    introduced_on: Optional[date] = None
    purchase_date: Optional[date] = None
    purchase_price: Optional[float] = Field(default=None, ge=0, le=1000000000000)
    power_watts: Optional[float] = Field(default=None, ge=0, le=1000000)
    power_source: Optional[str] = Field(default=None, max_length=40)
    warranty_end_date: Optional[date] = None
    owner_name: Optional[str] = None
    owner_department: Optional[str] = None
    operational_status: Optional[str] = Field(default=None, max_length=30)
    service_criticality: Optional[str] = Field(default=None, max_length=20)
    support_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None
    monitored: Optional[bool] = None

    @model_validator(mode="after")
    def required_values_not_null(self):
        for name in ("asset_tag", "name", "asset_type", "ssh_port", "monitored"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} 값은 비울 수 없습니다")
        return self


class AssetRead(AssetBase):
    id: int
    risk_level: str
    days_left: Optional[int]
    software_count: int = 0
    sbom_count: int = 0
    vulnerability_counts: dict[str, int] = Field(default_factory=dict)
    vulnerability_count: int = 0
    risk_score: int = 0
    priority_level: str = "LOW"
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
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    product_type: Optional[ProductType] = None
    vendor: Optional[str] = Field(default=None, max_length=160)
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    version: Optional[str] = Field(default=None, min_length=1, max_length=100)
    purl: Optional[str] = Field(default=None, max_length=500)
    cpe: Optional[str] = Field(default=None, max_length=500)
    eol_date: Optional[date] = None
    support_end_date: Optional[date] = None
    security_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None

    @model_validator(mode="after")
    def required_values_not_null(self):
        for name in ("product_type", "name", "version"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} 값은 비울 수 없습니다")
        return self


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
    product_release_id: Optional[int] = None
    lifecycle_source_url: Optional[str] = None
    hashes: list[Any] = Field(default_factory=list)
    lifecycle_origin: str = "unknown"
    override_support_end_date: Optional[date] = None


class ComponentLifecycleUpdate(BaseModel):
    support_end_date: Optional[date] = None
    lifecycle_source_url: Optional[HttpUrl] = None

    @model_validator(mode="after")
    def lifecycle_source_required(self):
        if self.support_end_date and not self.lifecycle_source_url:
            raise ValueError("지원종료일에는 공식 근거 URL이 필요합니다")
        return self

    model_config = ConfigDict(extra="forbid")


class DashboardLatestAnalysis(BaseModel):
    asset_id: int
    asset_tag: str
    asset_name: str
    scan_scope: str
    analysis_run_id: Optional[int] = None
    sbom_id: Optional[int] = None
    cve_count: Optional[int] = None
    last_success_at: Optional[datetime] = None
    latest_attempt_id: Optional[int] = None
    latest_attempt_status: Optional[str] = None
    latest_attempt_requested_at: Optional[datetime] = None
    latest_attempt_finished_at: Optional[datetime] = None
    latest_attempt_is_newer: bool = False


class DashboardSummary(BaseModel):
    assets: int
    software_products: int
    sbom_documents: int
    components: int
    dependencies: int
    open_cves: int
    affected_assets: int
    failed_checks_24h: int
    lifecycle_risk: dict[str, int]
    sbom_quality: dict[str, Union[int, float]]
    urgent_items: list[dict[str, Any]]
    latest_analyses: list[DashboardLatestAnalysis] = Field(default_factory=list)
    current_inventory: dict[str, int] = Field(default_factory=dict)
    aggregation_basis: dict[str, str] = Field(default_factory=dict)


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
    model_config = ConfigDict(str_strip_whitespace=True)
    customer_id: int = Field(ge=1)
    contract_no: str = Field(min_length=1, max_length=80)
    provider: str = Field(min_length=1, max_length=160)
    start_date: date
    end_date: date
    annual_cost: Optional[float] = Field(default=None, ge=0, lt=1000000000000, allow_inf_nan=False)
    service_level: Optional[str] = Field(default=None, max_length=100)
    asset_ids: list[int] = Field(default_factory=list)


class ContractUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    customer_id: Optional[int] = Field(default=None, ge=1)
    contract_no: Optional[str] = Field(default=None, min_length=1, max_length=80)
    provider: Optional[str] = Field(default=None, min_length=1, max_length=160)
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    annual_cost: Optional[float] = Field(default=None, ge=0, lt=1000000000000, allow_inf_nan=False)
    service_level: Optional[str] = Field(default=None, max_length=100)
    asset_ids: Optional[list[int]] = None

    @model_validator(mode="after")
    def required_values_not_null(self):
        for name in ("customer_id", "contract_no", "provider", "start_date", "end_date", "asset_ids"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} 값은 비울 수 없습니다")
        return self


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
    asset_tag: Optional[str]
    asset_name: Optional[str]
    cve_id: str
    summary: Optional[str]
    severity: str
    aliases: list[Any]
    fixed_version: Optional[str]
    fixed_versions: list[str] = Field(default_factory=list)
    finding_source: Optional[str] = None
    analysis_run_id: Optional[int] = None
    vex_status: str
    justification: Optional[str]
    response: Optional[str]
    detail: Optional[str]
    review_revision: int = 0
    assignee_id: Optional[int] = None
    assignee_username: Optional[str] = None
    due_date: Optional[date] = None
    modified_at: Optional[datetime]


class VulnerabilityScanResult(BaseModel):
    sbom_id: int
    queried_components: int
    vulnerability_links: int
    unique_vulnerabilities: int
    ignored_non_cve: int
    skipped_components: int = 0
    ignored_withdrawn: int = 0
    ignored_unaffected: int = 0


class VexUpdate(BaseModel):
    status: Literal["AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION"]
    justification: Optional[str] = Field(default=None, max_length=80)
    response: Optional[str] = Field(default=None, max_length=80)
    detail: Optional[str] = Field(default=None, max_length=2000)
    expected_revision: Optional[int] = Field(default=None, ge=0)

    model_config = ConfigDict(extra="forbid")


class VulnerabilityActionCreate(BaseModel):
    expected_revision: int = Field(ge=0)
    status: Literal["AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION"]
    detail: str = Field(min_length=1, max_length=2000)
    assignee_id: Optional[int] = Field(default=None, ge=1)
    due_date: Optional[date] = None
    justification: Optional[str] = Field(default=None, max_length=80)
    response: Optional[str] = Field(default=None, max_length=80)
    evidence_analysis_run_id: Optional[int] = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def require_action_note(self):
        self.detail = self.detail.strip()
        if not self.detail:
            raise ValueError("조치 내용을 입력하세요.")
        return self


class VulnerabilityActionRead(BaseModel):
    id: int
    link_id: int
    actor_user_id: Optional[int]
    actor_username: str
    from_status: str
    to_status: str
    detail: Optional[str]
    before_state: dict[str, Any]
    after_state: dict[str, Any]
    evidence_analysis_run_id: Optional[int]
    evidence_snapshot: Optional[dict[str, Any]]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityActionPage(BaseModel):
    items: list[VulnerabilityActionRead]
    has_more: bool
    next_before_id: Optional[int]


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


class AnalysisImport(BaseModel):
    asset_id: int = Field(gt=0)
    sbom: dict[str, Any]
    report: dict[str, Any]
    scan_scope: str = Field(default="uploaded SPDX SBOM", min_length=1, max_length=300)


class AnalysisRead(BaseModel):
    id: int
    sbom_id: int
    asset_id: Optional[int]
    asset_tag: Optional[str]
    asset_name: Optional[str]
    scanner: str
    scanner_version: str
    generator: str
    scan_scope: str
    component_count: int
    match_count: int
    cve_count: int
    link_count: int
    ignored_non_cve: int
    database_info: dict[str, Any]
    imported_at: datetime


class AnalysisJobRequest(BaseModel):
    scan_scope: Literal["ubuntu-dpkg-installed", "demo-python-venv", "ssh-python-environment", "ssh-project-directory"] = "ubuntu-dpkg-installed"
    target_path: Optional[str] = Field(default=None, max_length=250)
    model_config = ConfigDict(extra="forbid")


class AnalysisJobRead(BaseModel):
    id: int
    asset_id: int
    asset_tag: str
    asset_name: str
    scan_scope: str = "ubuntu-dpkg-installed"
    status: Literal["QUEUED", "COLLECTING", "SCANNING", "IMPORTING", "CANCEL_REQUESTED", "CANCELLED", "SUCCESS", "FAILED"]
    requested_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error_code: Optional[str]
    error_message: Optional[str]
    analysis_run_id: Optional[int]
    sbom_id: Optional[int]
    retry_of_id: Optional[int]
    profile: str = "ubuntu-dpkg-installed"
    input_type: Literal["ssh", "zip"] = "ssh"
    target_path: Optional[str] = None
    upload_id: Optional[str] = None
    upload_sha256: Optional[str] = None
    upload_filename: Optional[str] = None
    project_name: Optional[str] = None


class AnalysisScheduleCreate(AnalysisJobRequest):
    asset_id: int = Field(gt=0)
    interval_minutes: int = Field(ge=5, le=525600)
    enabled: bool = True


class AnalysisScheduleUpdate(BaseModel):
    interval_minutes: Optional[int] = Field(default=None, ge=5, le=525600)
    enabled: Optional[bool] = None
    model_config = ConfigDict(extra="forbid")


class AnalysisScheduleRead(BaseModel):
    id: int
    asset_id: int
    asset_tag: str
    asset_name: str
    profile: str
    scan_scope: str
    target_path: Optional[str]
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_requested_at: Optional[datetime]
    last_job_id: Optional[int]
    last_error: Optional[str]
