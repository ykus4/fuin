"""Packer configuration — loaded from environment variables or a .env file.

Copy .env.example → .env and fill in your values before running.

Settings are read from the environment on every :func:`get_settings` call
rather than captured at import time, so anything that mutates ``os.environ``
(notably ``monkeypatch.setenv`` in tests) takes effect without reloading this
module.

Server-only settings live in :mod:`fuin.server.config` so that installing the
packer alone does not drag in deployment concerns.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from fuin._utils import parse_env_bool

load_dotenv()


def env_int(name: str, default: int) -> int:
    """Read an integer environment variable, naming it in any parse error."""
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    """Everything the packer itself needs."""

    # Signing keystore. If unset, a temporary debug keystore is generated.
    keystore_path: str | None
    keystore_alias: str
    keystore_store_pass: str | None
    keystore_key_pass: str | None

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
        keystore_path=os.environ.get("FUIN_KEYSTORE_PATH"),
        keystore_alias=os.environ.get("FUIN_KEYSTORE_ALIAS", "fuin"),
        keystore_store_pass=os.environ.get("FUIN_KEYSTORE_STORE_PASS"),
        keystore_key_pass=os.environ.get("FUIN_KEYSTORE_KEY_PASS"),
        strict_manifest_patch=parse_env_bool(
            os.environ.get("FUIN_STRICT_MANIFEST_PATCH"), default=True
        ),
        verify_signature=parse_env_bool(os.environ.get("FUIN_VERIFY_SIGNATURE")),
        root_detection=parse_env_bool(os.environ.get("FUIN_ROOT_DETECTION")),
        emulator_detection=parse_env_bool(os.environ.get("FUIN_EMULATOR_DETECTION")),
        encrypt_strings=parse_env_bool(os.environ.get("FUIN_ENCRYPT_STRINGS")),
        stub_dex_path=os.environ.get("FUIN_STUB_DEX") or None,
    )
