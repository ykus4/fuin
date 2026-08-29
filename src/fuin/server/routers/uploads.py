"""Upload validation shared by the /analyze and /pack routes."""

import logging

from fastapi import HTTPException, UploadFile

from fuin.apk.constants import ZIP_LOCAL_HEADER_MAGIC
from fuin.server.config import get_server_settings

log = logging.getLogger(__name__)

# Read uploads a megabyte at a time so an oversized body is rejected while it
# is still arriving, rather than after it is all resident.
_CHUNK_SIZE = 1 << 20


def ensure_valid_apk(apk_bytes: bytes, *, filename: str | None) -> None:
    """Reject anything that is not plausibly an APK before we spend work on it."""
    if not filename or not filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")
    if len(apk_bytes) < 4 or not apk_bytes.startswith(ZIP_LOCAL_HEADER_MAGIC):
        raise HTTPException(
            status_code=400, detail="File does not appear to be a valid APK (invalid ZIP header)"
        )


def _too_large(limit: int) -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"APK too large (limit: {limit // (1024 * 1024)} MB)",
    )


async def read_apk_upload(file: UploadFile, *, max_bytes: int | None = None) -> bytes:
    """Read an uploaded APK, enforcing the size limit as it is read.

    ``/analyze`` used to skip the limit entirely and ``/pack`` only applied it
    after ``await file.read()`` had already materialised the whole body, so
    neither actually bounded memory.
    """
    limit = get_server_settings().max_upload_bytes if max_bytes is None else max_bytes

    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_CHUNK_SIZE):
        total += len(chunk)
        if total > limit:
            raise _too_large(limit)
        chunks.append(chunk)

    apk_bytes = b"".join(chunks)
    ensure_valid_apk(apk_bytes, filename=file.filename)
    return apk_bytes
