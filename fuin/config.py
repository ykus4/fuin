"""
Shared configuration — loaded from environment variables or a .env file.

Copy .env.example → .env and fill in your values before running.
"""

import os

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Server auth
# Required when running fuin-server. Optional for fuin-pack (only needed
# if --server-url is used to auto-register after packing).
# ---------------------------------------------------------------------------
ADMIN_API_KEY: str = os.environ.get("FUIN_API_KEY", "")

# ---------------------------------------------------------------------------
# Signing keystore (shared by packer CLI and server pipeline)
# If unset, a temporary debug keystore is generated automatically.
# Set all four variables for production / release builds.
# ---------------------------------------------------------------------------
KEYSTORE_PATH: str | None = os.environ.get("FUIN_KEYSTORE_PATH")
KEYSTORE_ALIAS: str = os.environ.get("FUIN_KEYSTORE_ALIAS", "fuin")
KEYSTORE_STORE_PASS: str | None = os.environ.get("FUIN_KEYSTORE_STORE_PASS")
KEYSTORE_KEY_PASS: str | None = os.environ.get("FUIN_KEYSTORE_KEY_PASS")

# ---------------------------------------------------------------------------
# Storage (server-side defaults)
# ---------------------------------------------------------------------------
PACKED_APK_DIR: str = os.environ.get("FUIN_PACKED_DIR", "./data/packed_apks")
DATABASE_URL: str = os.environ.get("FUIN_DATABASE_URL", "sqlite:///./data/fuin.db")

# ---------------------------------------------------------------------------
# Upload limits
# ---------------------------------------------------------------------------
# Maximum APK upload size in bytes (default: 500 MB)
MAX_UPLOAD_BYTES: int = int(os.environ.get("FUIN_MAX_UPLOAD_MB", "500")) * 1024 * 1024

# ---------------------------------------------------------------------------
# Auto-cleanup
# ---------------------------------------------------------------------------
# Delete packed APKs and DB records older than this many days (0 = disabled)
CLEANUP_OLDER_THAN_DAYS: int = int(os.environ.get("FUIN_CLEANUP_DAYS", "30"))

# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
# Optional URL to POST when a pack job completes
WEBHOOK_URL: str = os.environ.get("FUIN_WEBHOOK_URL", "")
