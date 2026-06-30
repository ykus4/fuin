"""Shared configuration — loaded from environment variables or a .env file.

Copy .env.example → .env and fill in your values before running.
"""

import os
from typing import Final

from dotenv import load_dotenv

from fuin._utils import parse_env_bool

load_dotenv()

# ---------------------------------------------------------------------------
# Server auth
# ---------------------------------------------------------------------------
ADMIN_API_KEY: Final[str] = os.environ.get("FUIN_API_KEY", "")

# ---------------------------------------------------------------------------
# Signing keystore (shared by packer CLI and server pipeline)
# If unset, a temporary debug keystore is generated automatically.
# ---------------------------------------------------------------------------
KEYSTORE_PATH: Final[str | None] = os.environ.get("FUIN_KEYSTORE_PATH")
KEYSTORE_ALIAS: Final[str] = os.environ.get("FUIN_KEYSTORE_ALIAS", "fuin")
KEYSTORE_STORE_PASS: Final[str | None] = os.environ.get("FUIN_KEYSTORE_STORE_PASS")
KEYSTORE_KEY_PASS: Final[str | None] = os.environ.get("FUIN_KEYSTORE_KEY_PASS")

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
PACKED_APK_DIR: Final[str] = os.environ.get("FUIN_PACKED_DIR", "./data/packed_apks")
DATABASE_URL: Final[str] = os.environ.get("FUIN_DATABASE_URL", "sqlite:///./data/fuin.db")

# ---------------------------------------------------------------------------
# Upload limits
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES: Final[int] = int(os.environ.get("FUIN_MAX_UPLOAD_MB", "500")) * 1024 * 1024

# ---------------------------------------------------------------------------
# Auto-cleanup
# ---------------------------------------------------------------------------
CLEANUP_OLDER_THAN_DAYS: Final[int] = int(os.environ.get("FUIN_CLEANUP_DAYS", "30"))

# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
WEBHOOK_URL: Final[str] = os.environ.get("FUIN_WEBHOOK_URL", "")

# ---------------------------------------------------------------------------
# Hardening / validation
# ---------------------------------------------------------------------------
STRICT_MANIFEST_PATCH: Final[bool] = parse_env_bool(
    os.environ.get("FUIN_STRICT_MANIFEST_PATCH"), default=True
)
VERIFY_SIGNATURE: Final[bool] = parse_env_bool(os.environ.get("FUIN_VERIFY_SIGNATURE"))


def validate_server_config() -> None:
    """Validate that the server has the minimum config needed to start.

    Called from the FastAPI lifespan hook so misconfigured deployments fail
    fast at startup instead of at the first request.
    """
    if not ADMIN_API_KEY:
        raise RuntimeError("FUIN_API_KEY is not set. Copy .env.example to .env and configure it.")
