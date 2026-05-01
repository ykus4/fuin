"""
Build or locate the pre-compiled stub DEX.

Strategy (in order):
1. If FUIN_STUB_DEX env var points to an existing .dex file, use it.
2. If a pre-built stub.dex exists next to this file (fuin/stub.dex), use it.
3. Build from source: run `./gradlew assembleRelease` in stub/, then extract
   classes.jar from the AAR and convert with d8.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

log = logging.getLogger(__name__)

FUIN_DIR = Path(__file__).parent
STUB_DIR = FUIN_DIR.parent / "stub"
PREBUILT_DEX = FUIN_DIR / "stub.dex"


def get_stub_dex() -> bytes:
    """Return the bytes of the compiled stub DEX, building if necessary."""
    env_path = os.environ.get("FUIN_STUB_DEX")
    if env_path and Path(env_path).is_file():
        log.debug("using stub DEX from FUIN_STUB_DEX: %s", env_path)
        return Path(env_path).read_bytes()

    if PREBUILT_DEX.is_file():
        log.debug("using pre-built stub DEX: %s", PREBUILT_DEX)
        return PREBUILT_DEX.read_bytes()

    return _build_stub_dex()


def _build_stub_dex() -> bytes:
    """Run Gradle to build the stub AAR, then d8 to produce stub.dex."""
    gradlew = STUB_DIR / "gradlew"
    if not gradlew.is_file():
        raise FileNotFoundError(
            f"Cannot find {gradlew}. Either pre-build the stub and place stub.dex "
            f"at fuin/stub.dex, or set FUIN_STUB_DEX to its path."
        )

    log.info("building stub AAR with Gradle")
    result = subprocess.run(
        ["./gradlew", ":app:assembleRelease", "--quiet"],
        cwd=STUB_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Gradle build failed:\n{result.stderr}")

    aar_path = STUB_DIR / "app" / "build" / "outputs" / "aar" / "app-release.aar"
    if not aar_path.is_file():
        raise FileNotFoundError(f"Expected AAR at {aar_path} — check Gradle output")

    dex_bytes = _aar_to_dex(str(aar_path))
    PREBUILT_DEX.write_bytes(dex_bytes)
    log.info("stub.dex cached at %s", PREBUILT_DEX)
    return dex_bytes


def _aar_to_dex(aar_path: str) -> bytes:
    """Extract classes.jar from an AAR and convert to DEX using d8."""
    d8 = _find_d8()
    log.debug("using d8: %s", d8)

    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(aar_path, "r") as z:
            if "classes.jar" not in z.namelist():
                raise FileNotFoundError("classes.jar not found inside AAR")
            z.extract("classes.jar", tmpdir)
            jar_path = os.path.join(tmpdir, "classes.jar")

        out_dir = os.path.join(tmpdir, "dex_out")
        os.makedirs(out_dir)
        result = subprocess.run(
            [d8, "--output", out_dir, "--min-api", "24", jar_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"d8 failed:\n{result.stderr}")

        dex_file = os.path.join(out_dir, "classes.dex")
        if not os.path.exists(dex_file):
            raise FileNotFoundError(f"d8 did not produce classes.dex in {out_dir}")

        return Path(dex_file).read_bytes()


def _find_d8() -> str:
    """Locate the d8 binary from ANDROID_HOME or PATH."""
    if "ANDROID_HOME" in os.environ:
        bt_root = Path(os.environ["ANDROID_HOME"]) / "build-tools"
        if bt_root.is_dir():
            for v in sorted(bt_root.iterdir(), reverse=True):
                candidate = v / "d8"
                if candidate.is_file():
                    return str(candidate)

    found = shutil.which("d8")
    if found:
        return found

    raise FileNotFoundError("d8 not found. Set ANDROID_HOME or add build-tools to PATH.")
