from functools import lru_cache
import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

SECRET_FIELDS = ("jwt_secret", "credential_key", "admin_password", "openai_api_key", "anthropic_api_key", "database_url")


class Settings(BaseSettings):
    app_name: str = "EOLWatch API"
    database_url: str = "sqlite:///./eolwatch.db"
    cors_origins: str = "http://localhost:5173,http://localhost:8080"
    ssh_private_key_path: str = ""
    ssh_known_hosts_path: str = ""
    ssh_strict_host_key: bool = True
    ssh_connect_timeout_seconds: int = 10
    credential_key: str = ""
    collection_hour: int = 8
    collection_minute: int = 30
    scheduler_timezone: str = "Asia/Seoul"
    auto_create_schema: bool = True
    jwt_secret: str = "local-development-secret-change-before-deployment"
    access_token_minutes: int = 480
    admin_username: str = "admin"
    admin_password: str = ""       # no built-in login: set ADMIN_PASSWORD (or ADMIN_PASSWORD_FILE); tests set it in conftest
    public_base_url: str = "http://localhost:8080"
    demo_target_ips: str = ""
    analysis_syft_path: str = "/opt/analysis-tools/syft"
    analysis_grype_path: str = "/opt/analysis-tools/grype"
    analysis_artifacts_dir: str = "/var/lib/eolwatch/analysis"
    analysis_cache_dir: str = "/var/cache/eolwatch"
    analysis_collect_timeout_seconds: int = 300
    analysis_scan_timeout_seconds: int = 900
    analysis_job_lease_seconds: int = 180
    analysis_poll_seconds: int = 3
    analysis_uploads_dir: str = "/var/lib/eolwatch/uploads"
    ai_provider: str = "openai"
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-5"
    openai_api_key: str = ""
    openai_model: str = "gpt-5-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    # Hidden "thinking" tokens are billed like output. "none" turns them off on Gemini/GPT-5.1; a provider that
    # rejects the value gets the request again without it. Set to low/medium/high if you want reasoning.
    openai_reasoning_effort: str = "none"
    # In-pipeline AI: library reference for sources without a lockfile, and the SSH collection agent.
    ai_pipeline: bool = True
    analysis_git_path: str = "git"
    analysis_git_timeout_seconds: int = 300
    analysis_git_max_bytes: int = 1024 * 1024 * 1024
    analysis_upload_max_bytes: int = 500 * 1024 * 1024      # real student repos with assets run past 50 MiB
    analysis_zip_max_unpacked_bytes: int = 2 * 1024 * 1024 * 1024
    analysis_zip_max_file_bytes: int = 256 * 1024 * 1024
    analysis_zip_max_entries: int = 200000
    analysis_zip_max_ratio: int = 100

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def demo_target_ip_list(self) -> list[str]:
        return [address.strip() for address in self.demo_target_ips.split(",") if address.strip()]


def _file_overrides() -> dict[str, str]:
    """<NAME>_FILE=/run/secrets/<name> wins over <NAME>: the file never appears in `docker inspect`, process lists or crash dumps."""
    values = {}
    for field in SECRET_FIELDS:
        path = os.environ.get(field.upper() + "_FILE")
        if path:
            try:
                values[field] = Path(path).read_text(encoding="utf-8").strip()
            except OSError as error:
                raise RuntimeError(f"{field.upper()}_FILE을 읽을 수 없습니다: {path}") from error
    return values


@lru_cache
def get_settings() -> Settings:
    return Settings(**_file_overrides())
