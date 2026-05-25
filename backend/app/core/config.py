"""
PhishGuard application settings.

Pydantic BaseSettings reads values from environment variables and the
optional .env file.  Every field name here is the authoritative source —
do not rename without updating .env.example and docker-compose.yml.
"""
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Database ────────────────────────────────────────────────────────────
    DATABASE_URL: str
    """PostgreSQL async DSN — must use +asyncpg driver scheme."""

    # ── Cache / Broker ──────────────────────────────────────────────────────
    REDIS_URL: str
    """Redis DSN used for SSE Pub/Sub, JWT blacklist, rate-limit counters."""

    CELERY_BROKER_URL: str
    """Celery broker DSN (typically same Redis instance as REDIS_URL)."""

    CELERY_RESULT_BACKEND: str = ""
    """Celery result backend DSN (separate Redis DB index from the broker)."""

    # ── Security ────────────────────────────────────────────────────────────
    JWT_SECRET: str = Field(min_length=32)
    """HS256 signing secret — minimum 32 characters (NFR-2).
    Generate with: openssl rand -hex 32"""

    JWT_EXPIRE_HOURS: int = 8
    """Access token lifetime in hours (NFR-2 mandate)."""

    DIGEST_HMAC_SECRET: str
    """HMAC-SHA256 key for quarantine digest one-time action tokens.
    Generate with: openssl rand -hex 32"""

    FERNET_KEY: str
    """Fernet symmetric key for encrypting IMAP passwords at rest.
    Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"""

    # ── External APIs ───────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str
    """Anthropic Claude API key — FR-04 explanation engine + AI assistant."""

    RESEND_API_KEY: str
    """Resend transactional email API key — FR-06 digest delivery."""

    # ── Application ─────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8000"
    """Comma-separated list of allowed CORS origins (used by CORSMiddleware)."""

    MODEL_VERSION: str = "rf_v1.0.0"
    """ML model version tag — must match the artefact in ml/model.pkl."""

    FORWARDING_DOMAIN: str = "phishguard.app"
    """Domain used to build forwarding inbox slugs (scan+<slug>@<domain>)."""

    DEMO_SAMPLE_EML: str = ""
    """Raw .eml content for the 'Load Demo Sample' button (UI Figure 8).
    Paste as a single escaped string (newlines as \\n)."""

    EXPORT_VOLUME_PATH: str = "/mnt/exports"
    """Absolute path to the Docker volume where generated CSV exports live."""


settings = Settings()
