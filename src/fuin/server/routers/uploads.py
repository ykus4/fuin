"""Upload validation shared by the /analyze and /pack routes."""

from fastapi import HTTPException, UploadFile

from fuin._constants import ZIP_LOCAL_HEADER_MAGIC


def ensure_valid_apk(apk_bytes: bytes, *, filename: str | None) -> None:
    """Reject anything that is not plausibly an APK before we spend work on it."""
    if not filename or not filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")
    if len(apk_bytes) < 4 or not apk_bytes.startswith(ZIP_LOCAL_HEADER_MAGIC):
        raise HTTPException(
            status_code=400, detail="File does not appear to be a valid APK (invalid ZIP header)"
        )


async def read_apk_upload(file: UploadFile) -> bytes:
    """Read an uploaded APK and validate its shape."""
    apk_bytes = await file.read()
    ensure_valid_apk(apk_bytes, filename=file.filename)
    return apk_bytes
