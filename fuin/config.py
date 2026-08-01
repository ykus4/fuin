"""Shared configuration — loaded from environment variables or a .env file.

Copy .env.example → .env and fill in your values before running.

Settings are read from the environment on every :func:`get_settings` call
rather than captured at import time, so anything that mutates ``os.environ``
(notably ``monkeypatch.setenv`` in tests) takes effect without reloading this
module.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from fuin._utils import parse_env_bool

load_dotenv()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    """Snapshot of fuin's entire configuration surface."""

    # Server auth
    admin_api_key: str

    # Signing keystore (shared by packer CLI and server pipeline).
    # If unset, a temporary debug keystore is generated automatically.
    keystore_path: str | None
    keystore_alias: str
    keystore_store_pass: str | None
    keystore_key_pass: str | None

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

    # Hardening / validation
    strict_manifest_patch: bool
    verify_signature: bool

    # Packing defaults. These seed ``PackOptions``; an explicit value passed by
    # a caller always wins over the environment.
    root_detection: bool
    emulator_detection: bool
    encrypt_strings: bool
    stub_dex_path: str | None


def get_settings() -> Settings:
    """Build a :class:`Settings` from the current environment.

    Intentionally uncached — every call re-reads ``os.environ``.
    """
    return Settings(
        admin_api_key=os.environ.get("FUIN_API_KEY", ""),
        keystore_path=os.environ.get("FUIN_KEYSTORE_PATH"),
        keystore_alias=os.environ.get("FUIN_KEYSTORE_ALIAS", "fuin"),
        keystore_store_pass=os.environ.get("FUIN_KEYSTORE_STORE_PASS"),
        keystore_key_pass=os.environ.get("FUIN_KEYSTORE_KEY_PASS"),
        packed_apk_dir=os.environ.get("FUIN_PACKED_DIR", "./data/packed_apks"),
        database_url=os.environ.get("FUIN_DATABASE_URL", "sqlite:///./data/fuin.db"),
        max_upload_bytes=_env_int("FUIN_MAX_UPLOAD_MB", 500) * 1024 * 1024,
        max_mapping_bytes=_env_int("FUIN_MAX_MAPPING_MB", 50) * 1024 * 1024,
        cleanup_older_than_days=_env_int("FUIN_CLEANUP_DAYS", 30),
        webhook_url=os.environ.get("FUIN_WEBHOOK_URL", ""),
        strict_manifest_patch=parse_env_bool(
            os.environ.get("FUIN_STRICT_MANIFEST_PATCH"), default=True
        ),
        verify_signature=parse_env_bool(os.environ.get("FUIN_VERIFY_SIGNATURE")),
        root_detection=parse_env_bool(os.environ.get("FUIN_ROOT_DETECTION")),
        emulator_detection=parse_env_bool(os.environ.get("FUIN_EMULATOR_DETECTION")),
        encrypt_strings=parse_env_bool(os.environ.get("FUIN_ENCRYPT_STRINGS")),
        stub_dex_path=os.environ.get("FUIN_STUB_DEX") or None,
    )


def validate_server_config(settings: Settings | None = None) -> None:
    """Validate that the server has the minimum config needed to start.

    Called from the FastAPI lifespan hook so misconfigured deployments fail
    fast at startup instead of at the first request.
    """
    settings = settings if settings is not None else get_settings()
    if not settings.admin_api_key:
        raise RuntimeError("FUIN_API_KEY is not set. Copy .env.example to .env and configure it.")
