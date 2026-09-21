from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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
    admin_password: str = "Eolwatch!2026"
    osv_api_url: str = "https://api.osv.dev/v1/querybatch"
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
    ai_provider: str = "ollama"
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-5"
    ollama_base_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "qwen2.5:7b"
    analysis_git_path: str = "git"
    analysis_git_timeout_seconds: int = 300
    analysis_git_max_bytes: int = 250 * 1024 * 1024
    analysis_upload_max_bytes: int = 50 * 1024 * 1024
    analysis_zip_max_unpacked_bytes: int = 250 * 1024 * 1024
    analysis_zip_max_file_bytes: int = 32 * 1024 * 1024
    analysis_zip_max_entries: int = 20000
    analysis_zip_max_ratio: int = 100

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def demo_target_ip_list(self) -> list[str]:
        return [address.strip() for address in self.demo_target_ips.split(",") if address.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
