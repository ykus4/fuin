"""Server-only configuration.

Kept separate from :mod:`fuin.config` so the packer — which has no notion of a
database, an API key or an upload limit — does not depend on deployment
settings. Like the packer's settings, these are read from the environment on
every call rather than captured at import time.
"""

import os
from dataclasses import dataclass

from fuin.config import env_int


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """Everything only the FastAPI service needs."""

    # Auth
    admin_api_key: str

    # Storage
    packed_apk_dir: str
    database_url: str

    # Upload limits
    max_upload_bytes: int
    max_mapping_bytes: int

    # Auto-cleanup
    cleanup_older_than_days: int

    # Webhook
    webhook_url: str


def get_server_settings() -> ServerSettings:
    """Build a :class:`ServerSettings` from the current environment."""
    return ServerSettings(
        admin_api_key=os.environ.get("FUIN_API_KEY", ""),
        packed_apk_dir=os.environ.get("FUIN_PACKED_DIR", "./data/packed_apks"),
        database_url=os.environ.get("FUIN_DATABASE_URL", "sqlite:///./data/fuin.db"),
        max_upload_bytes=env_int("FUIN_MAX_UPLOAD_MB", 500) * 1024 * 1024,
        max_mapping_bytes=env_int("FUIN_MAX_MAPPING_MB", 50) * 1024 * 1024,
        cleanup_older_than_days=env_int("FUIN_CLEANUP_DAYS", 30),
        webhook_url=os.environ.get("FUIN_WEBHOOK_URL", ""),
    )


def validate_server_config(settings: ServerSettings | None = None) -> None:
    """Fail fast at startup if the deployment is missing required config."""
    settings = settings if settings is not None else get_server_settings()
    if not settings.admin_api_key:
        raise RuntimeError("FUIN_API_KEY is not set. Copy .env.example to .env and configure it.")
