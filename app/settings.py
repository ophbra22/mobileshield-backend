from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = 'mobileshield-ai'
    database_url: str = 'postgresql+psycopg2://mobileshield:mobileshield@db:5432/mobileshield'
    admin_token: str | None = None
    enable_admin: bool = False
    rate_limit_per_minute: int = 60
    cors_origins: str = 'http://localhost:3000,http://127.0.0.1:3000'
    admin_allow_ips: str | None = None
    env: str = 'dev'  # dev or prod
    log_level: str = 'info'
    jwt_secret: str = 'change-me'
    jwt_expires_minutes: int = 120
    server_key: str = 'change-me-server-key'
    allowlist_enabled: bool = True
    allowlist_min_score: int = 50
    allowlist_refresh_hours: int = 24
    allowlist_sources: str = 'local_popular,remote_popular'
    allowlist_cache_path: str = '/tmp/mobileshield_allowlist.txt'


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
