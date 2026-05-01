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
PACKED_APK_DIR: str = os.environ.get("FUIN_PACKED_DIR", "./packed_apks")
DATABASE_URL: str = os.environ.get("FUIN_DATABASE_URL", "sqlite:///./fuin.db")

# ---------------------------------------------------------------------------
# Key server URL (used by packer CLI when registering after pack)
# ---------------------------------------------------------------------------
SERVER_URL: str | None = os.environ.get("FUIN_SERVER_URL")
