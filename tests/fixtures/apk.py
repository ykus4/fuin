"""Minimal APK (ZIP) builder for tests."""

import io
import zipfile

from tests.fixtures.axml import make_axml


def make_minimal_apk(
    app_class: str = "com.example.MyApp",
    dex_content: bytes = b"dex\n035\x00" + b"\x00" * 100,
    extra_dex: dict[str, bytes] | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> bytes:
    """Build a minimal valid APK (ZIP) with AndroidManifest.xml + classes.dex."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", make_axml(app_class))
        z.writestr("classes.dex", dex_content)
        if extra_dex:
            for name, data in extra_dex.items():
                z.writestr(name, data)
        if extra_files:
            for name, data in extra_files.items():
                z.writestr(name, data)
        z.writestr("res/layout/main.xml", b"<root/>")
    return buf.getvalue()
