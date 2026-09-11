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

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
