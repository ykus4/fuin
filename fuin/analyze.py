"""
APK encryption target analysis.

Scans an APK and reports all files that can be encrypted by fuin,
categorized by type (DEX, native libs, assets).
"""

import re
import zipfile
from pathlib import Path

_DEX_PATTERN = re.compile(r"^classes\d*\.dex$")

# Assets that fuin injects — never encrypt these
_FUIN_INTERNAL = {
    "assets/encrypted.dex",
    "assets/encrypted_extra.dex",
    "assets/key.bin",
    "assets/original_app_class.txt",
    "assets/cert_fingerprint.bin",
    "assets/security_policy.json",
    "assets/native_lib_manifest.json",
    "assets/res_map.json",
    "assets/string_key.bin",
}


def analyze_targets(apk_path: str) -> dict:
    """Analyze an APK and return all encryptable targets.

    Returns a dict with:
      - dex: DEX files info
      - native_libs: .so files info
      - assets: user asset files info
      - summary: totals and coverage
    """
    apk_size = Path(apk_path).stat().st_size

    dex_files = []
    native_files = []
    asset_files = []

    with zipfile.ZipFile(apk_path, "r") as z:
        for info in z.infolist():
            name = info.filename

            if _DEX_PATTERN.match(name):
                dex_files.append({"name": name, "size": info.file_size})
            elif name.startswith("lib/") and name.endswith(".so"):
                native_files.append({"name": name, "size": info.file_size})
            elif name.startswith("assets/") and name not in _FUIN_INTERNAL:
                if not name.startswith("assets/encrypted_libs/"):
                    if not name.startswith("assets/encrypted_res/"):
                        if not name.endswith("/"):  # skip directories
                            asset_files.append({"name": name, "size": info.file_size})

    dex_total = sum(f["size"] for f in dex_files)
    native_total = sum(f["size"] for f in native_files)
    assets_total = sum(f["size"] for f in asset_files)
    total_size = dex_total + native_total + assets_total
    total_files = len(dex_files) + len(native_files) + len(asset_files)

    coverage = (total_size / apk_size * 100) if apk_size else 0

    return {
        "dex": {
            "files": dex_files,
            "total_size": dex_total,
        },
        "native_libs": {
            "files": native_files,
            "total_size": native_total,
        },
        "assets": {
            "files": asset_files,
            "total_size": assets_total,
        },
        "summary": {
            "total_files": total_files,
            "total_size": total_size,
            "apk_size": apk_size,
            "coverage_percent": round(coverage, 1),
        },
    }
