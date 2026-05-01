"""
Parse and patch AndroidManifest.xml (binary XML format inside APK).
Uses the `axml` approach: read the raw bytes and patch the Application
android:name attribute in-place using string replacement on the decoded text.

For production use, integrate a proper AXML library (e.g. androguard).
This implementation handles the common case where the manifest contains
a plain UTF-8 / UTF-16 encoded application class name in the string pool.
"""

import io
import logging
import re
import zipfile

log = logging.getLogger(__name__)

# Stub Application class that will replace the original
STUB_CLASS = "com.fuin.stub.StubApplication"


def _axml_strings(data: bytes) -> list[tuple[int, int, str]]:
    """
    Extract UTF-16LE strings from the AXML string pool.
    Returns list of (offset, length_bytes, string).
    This is a best-effort parser for finding application class names.
    """
    results = []
    # Look for UTF-16LE encoded strings that look like Java class names
    # Pattern: sequences of (char, 0x00) bytes forming dotted class names
    i = 0
    while i < len(data) - 4:
        # Try to decode a null-terminated UTF-16LE string
        if data[i + 1] == 0x00 and chr(data[i]).isalpha():
            end = i
            while end + 1 < len(data) and (data[end + 1] == 0x00):
                if data[end] == 0x00:
                    break
                end += 2
            raw = data[i:end]
            try:
                s = raw.decode("utf-16-le")
                if re.match(r"^[a-zA-Z][a-zA-Z0-9_./$]+$", s) and "." in s:
                    results.append((i, len(raw), s))
            except (UnicodeDecodeError, ValueError) as e:
                log.debug("skipping non-decodable string at offset %d: %s", i, e)
        i += 1
    return results


def patch_manifest(apk_path: str, output_path: str, original_app_class: str | None) -> str:
    """
    Patch AndroidManifest.xml inside the APK:
    - Replace the Application android:name with StubApplication
    - Store original class name as meta-data value (string patch)

    Returns the original application class name (or empty string if none).
    """
    with zipfile.ZipFile(apk_path, "r") as zin:
        manifest_data = zin.read("AndroidManifest.xml")

    patched, found_class = _patch_axml(manifest_data, original_app_class)

    # Rewrite APK with patched manifest
    buf = io.BytesIO()
    with (
        zipfile.ZipFile(apk_path, "r") as zin,
        zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for item in zin.infolist():
            if item.filename == "AndroidManifest.xml":
                zout.writestr(item, patched)
            else:
                zout.writestr(item, zin.read(item.filename))

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    return found_class


def _patch_axml(data: bytes, original_app_class: str | None) -> tuple[bytes, str]:
    """
    Patch the AXML binary by replacing the application class string.
    Returns (patched_bytes, original_class_name).
    """
    stub_utf16 = STUB_CLASS.encode("utf-16-le")

    if original_app_class:
        target_utf16 = original_app_class.encode("utf-16-le")
        if target_utf16 in data:
            patched = data.replace(target_utf16, stub_utf16, 1)
            return patched, original_app_class

    # Auto-detect: find any Application subclass name in the manifest
    candidates = _axml_strings(data)
    for offset, length, name in candidates:
        if "Application" in name or "App" in name:
            target_utf16 = name.encode("utf-16-le")
            if target_utf16 in data:
                patched = data.replace(target_utf16, stub_utf16, 1)
                return patched, name

    # No existing Application class — just return data unchanged
    # The stub will be set as android:name via apktool in a full implementation
    return data, ""
