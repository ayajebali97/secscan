"""Application configuration loaded from environment variables."""
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    APP_NAME: str = "SecScan"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # Security
    SECRET_KEY: str = Field(..., min_length=32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
    BCRYPT_ROUNDS: int = 12

    # CORS
    CORS_ORIGINS: str = "http://localhost:3000"

    # Host header allowlist (public IP/domain behind Caddy, comma-separated)
    TRUSTED_HOSTS: str = ""

    # Database
    POSTGRES_USER: str = "secscan"
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str = "secscan"
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    AUTH_RATE_LIMIT_PER_MINUTE: int = 5

    # Scanning
    MAX_SCAN_DURATION_SECONDS: int = 600
    SCAN_USER_AGENT: str = "SecScan/0.1 (+https://secscan.local)"
    SCAN_HTTP_TIMEOUT: float = 10.0
    SCAN_ALLOW_PRIVATE: bool = False

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        weak = {"changeme", "secret", "password", "default"}
        if v.lower() in weak:
            raise ValueError("SECRET_KEY must not be a weak default value")
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def trusted_hosts_list(self) -> List[str]:
        hosts: set[str] = {"localhost", "127.0.0.1", "backend"}
        for origin in self.cors_origins_list:
            hosts.add(origin.replace("https://", "").replace("http://", "").rstrip("/"))
        for host in self.TRUSTED_HOSTS.split(","):
            h = host.strip()
            if h:
                hosts.add(h.replace("https://", "").replace("http://", "").rstrip("/"))
        return sorted(hosts)

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def sync_database_url(self) -> str:
        """Sync URL for Celery workers and Alembic."""
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
