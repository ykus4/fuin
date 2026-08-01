"""Shared low-level helpers: byte readers, size formatting, package name fallback."""

import struct


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def fallback_package_name(axml: bytes) -> str:
    """Best-effort package name extraction from raw AXML bytes."""
    idx = axml.find(b"package")
    if idx == -1:
        return "unknown"
    chunk = axml[idx : idx + 256]
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = chunk.decode(encoding, errors="ignore")
            for p in text.split():
                if "." in p and p.replace(".", "").replace("_", "").isalnum():
                    return p
        except Exception:
            pass
    return "unknown"


def parse_env_bool(value: str | None, default: bool = False) -> bool:
    """Parse an environment-variable string into a bool. Accepts 1/true/yes (case-insensitive)."""
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes")
