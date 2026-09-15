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
    collection_hour: int = 8
    collection_minute: int = 30
    scheduler_timezone: str = "Asia/Seoul"
    auto_create_schema: bool = True
    jwt_secret: str = "local-development-secret-change-before-deployment"
    access_token_minutes: int = 480
    admin_username: str = "admin"
    admin_password: str = "Eolwatch!2026"
    teams_webhook_url: str = ""
    teams_recipient_label: str = "EOLWatch 운영 채널"
    osv_api_url: str = "https://api.osv.dev/v1/querybatch"
    public_base_url: str = "http://localhost:8080"
    demo_target_ips: str = ""

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
