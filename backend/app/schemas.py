from __future__ import annotations

import ipaddress
import re

from datetime import date, datetime
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


AssetType = Literal["server", "storage", "network", "security", "vm", "cloud", "other"]


HOSTNAME_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


def validate_address(value: Optional[str]) -> Optional[str]:
    """IPv4, IPv6 or a DNS host name. Empty stays empty."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass
    if HOSTNAME_PATTERN.match(text):
        return text
    raise ValueError("서버 주소는 IP 주소나 도메인 이름이어야 합니다 (예: 10.0.1.11, db01.example.com)")


class AssetBase(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    asset_tag: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    asset_type: AssetType
    ip_address: Optional[str] = Field(default=None, max_length=253)

    @field_validator("ip_address")
    @classmethod
    def _address(cls, value):
        return validate_address(value)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: Optional[str] = Field(default=None, max_length=80)
    monitored: bool = False


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    asset_tag: Optional[str] = Field(default=None, min_length=1, max_length=80)
    name: Optional[str] = Field(default=None, min_length=1, max_length=160)
    asset_type: Optional[AssetType] = None
    ip_address: Optional[str] = Field(default=None, max_length=253)

    @field_validator("ip_address")
    @classmethod
    def _address(cls, value):
        return validate_address(value)
    ssh_port: Optional[int] = Field(default=None, ge=1, le=65535)
    ssh_username: Optional[str] = Field(default=None, max_length=80)
    monitored: Optional[bool] = None

    @model_validator(mode="after")
    def required_values_not_null(self):
        for name in ("asset_tag", "name", "asset_type", "ssh_port", "monitored"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} 값은 비울 수 없습니다")
        return self


class AssetRead(AssetBase):
    id: int
    sbom_count: int = 0
    vulnerability_counts: dict[str, int] = Field(default_factory=dict)
    vulnerability_count: int = 0
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SbomImportEnvelope(BaseModel):
    document: dict[str, Any]
    asset_id: Optional[int] = None


class SbomRead(BaseModel):
    id: int
    serial_number: str
    bom_format: str
    spec_version: str
    document_version: int
    generated_at: Optional[datetime]
    imported_at: datetime
    asset_id: Optional[int]
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
    product_release_id: Optional[int] = None
    hashes: list[Any] = Field(default_factory=list)


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
    sbom_documents: int
    components: int
    dependencies: int
    open_cves: int
    affected_assets: int
    failed_checks_24h: int
    sbom_quality: dict[str, Union[int, float]]
    latest_analyses: list[DashboardLatestAnalysis] = Field(default_factory=list)
    # 자산·검사 범위별 최신 성공 SBOM(및 자산별 최신 수동 import SBOM) 기준의 미조치 CVE 수
    current_open_cves: int = 0
    current_affected_assets: int = 0


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
    server_info: Optional[dict[str, Any]] = None


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


class AnalysisGitRequest(BaseModel):
    repository_url: str = Field(min_length=12, max_length=500)
    ref: Optional[str] = Field(default=None, max_length=200)
    project_name: str = Field(min_length=1, max_length=80)
    access_token: Optional[str] = Field(default=None, min_length=1, max_length=400)
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


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
    input_type: Literal["ssh", "zip", "git"] = "ssh"
    target_path: Optional[str] = None
    upload_id: Optional[str] = None
    upload_sha256: Optional[str] = None
    upload_filename: Optional[str] = None
    project_name: Optional[str] = None
    git_url: Optional[str] = None
    git_ref: Optional[str] = None
    git_commit: Optional[str] = None


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


class AiStatus(BaseModel):
    enabled: bool
    provider: str
    model: str


class AiSummaryRead(BaseModel):
    id: int
    kind: Literal["analysis", "check"]
    target_id: int
    provider: str = "anthropic"
    model: str
    summary: str
    prompt_chars: Optional[int] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    generated_at: datetime
    generated_by: Optional[str] = None
