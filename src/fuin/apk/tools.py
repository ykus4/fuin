"""Locate and run Android build-tools binaries (apksigner, zipalign, d8)."""

import os
import shutil
import subprocess
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


# Generous enough for d8 on a large app, short enough that a wedged tool does
# not pin a server worker for the lifetime of the process.
DEFAULT_TOOL_TIMEOUT = 600.0


def run_tool(
    argv: list[str],
    *,
    cwd: str | Path | None = None,
    what: str | None = None,
    check: bool = True,
    timeout: float | None = DEFAULT_TOOL_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run an external tool, capturing its output.

    With ``check`` (the default) a non-zero exit raises ``RuntimeError``
    carrying the tool's stderr. Pass ``check=False`` when the caller needs to
    inspect the failure itself — e.g. to fall back to a pure-Python path.

    A timeout is always applied: these are third-party binaries handling
    attacker-supplied archives, and without one a hang is unrecoverable.
    """
    name = what or Path(argv[0]).name
    try:
        result = subprocess.run(
            argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{name} timed out after {timeout:.0f}s") from exc

    if check and result.returncode != 0:
        raise RuntimeError(f"{name} failed:\n{result.stderr}")
    return result
