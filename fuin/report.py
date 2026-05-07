"""
Pack result diff report.

Compares an original APK with its packed counterpart and generates
a structured report showing size changes, encryption targets, and metadata.
"""

import zipfile
from pathlib import Path


def generate_report(original_path: str, packed_path: str) -> dict:
    """Generate a diff report comparing original and packed APKs.

    Returns a dict with:
      - size_before / size_after / size_delta
      - file_counts
      - encrypted_targets (DEX files encrypted)
      - entry_changes (added/removed entries)
      - signature_info
    """
    orig_size = Path(original_path).stat().st_size
    packed_size = Path(packed_path).stat().st_size

    orig_entries: dict[str, int] = {}
    packed_entries: dict[str, int] = {}

    with zipfile.ZipFile(original_path, "r") as z:
        for info in z.infolist():
            orig_entries[info.filename] = info.file_size

    with zipfile.ZipFile(packed_path, "r") as z:
        for info in z.infolist():
            packed_entries[info.filename] = info.file_size

    orig_names = set(orig_entries.keys())
    packed_names = set(packed_entries.keys())

    added = sorted(packed_names - orig_names)
    removed = sorted(orig_names - packed_names)

    # Identify encrypted targets (DEX files that were removed)
    encrypted_dex = [f for f in removed if f.endswith(".dex")]

    # Identify fuin-injected assets
    fuin_assets = [f for f in added if f.startswith("assets/")]

    # Signature info
    orig_signatures = [f for f in orig_names if f.startswith("META-INF/")]
    packed_signatures = [f for f in packed_names if f.startswith("META-INF/")]

    return {
        "size": {
            "before": orig_size,
            "after": packed_size,
            "delta": packed_size - orig_size,
            "delta_percent": round((packed_size - orig_size) / orig_size * 100, 2)
            if orig_size
            else 0,
        },
        "file_counts": {
            "before": len(orig_entries),
            "after": len(packed_entries),
            "added": len(added),
            "removed": len(removed),
        },
        "encrypted_targets": {
            "dex_files": encrypted_dex,
            "count": len(encrypted_dex),
        },
        "injected_assets": fuin_assets,
        "entry_changes": {
            "added": added,
            "removed": removed,
        },
        "signature": {
            "original": sorted(orig_signatures),
            "packed": sorted(packed_signatures),
        },
    }


def format_report(report: dict) -> str:
    """Format a report dict into a human-readable string."""
    lines = []
    lines.append("=== Fuin Pack Report ===")
    lines.append("")

    s = report["size"]
    lines.append(
        f"APK Size: {_fmt_size(s['before'])} -> {_fmt_size(s['after'])} ({s['delta_percent']:+.1f}%)"
    )
    lines.append("")

    fc = report["file_counts"]
    lines.append(f"ZIP Entries: {fc['before']} -> {fc['after']} (+{fc['added']}/-{fc['removed']})")
    lines.append("")

    et = report["encrypted_targets"]
    lines.append(f"Encrypted DEX files: {et['count']}")
    for f in et["dex_files"]:
        lines.append(f"  - {f}")
    lines.append("")

    lines.append("Injected assets:")
    for f in report["injected_assets"]:
        lines.append(f"  + {f}")
    lines.append("")

    lines.append("Signature files:")
    for f in report["signature"]["packed"]:
        lines.append(f"  {f}")

    return "\n".join(lines)


def _fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"
