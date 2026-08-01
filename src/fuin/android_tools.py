"""Locate Android build-tools binaries (apksigner, zipalign, d8)."""

import os
import shutil
from pathlib import Path


def find_build_tool(name: str) -> str | None:
    """Locate an Android build-tool binary.

    Order: PATH → $ANDROID_HOME/build-tools/<latest>. Returns the absolute
    path if found, else None.
    """
    found = shutil.which(name)
    if found:
        return found

    sdk_root = os.environ.get("ANDROID_HOME")
    if sdk_root:
        bt_root = Path(sdk_root) / "build-tools"
        if bt_root.is_dir():
            for version_dir in sorted(bt_root.iterdir(), reverse=True):
                candidate = version_dir / name
                if candidate.is_file():
                    return str(candidate)
    return None


def require_build_tool(name: str) -> str:
    """Locate an Android build-tool binary or raise FileNotFoundError."""
    path = find_build_tool(name)
    if not path:
        raise FileNotFoundError(
            f"{name} not found. Set ANDROID_HOME or add Android build-tools to PATH."
        )
    return path
