"""Upload limits must bound reads, including for files without a known size."""

from io import BytesIO

import pytest
from fastapi import HTTPException, UploadFile

from fuin.server.routers.uploads import read_upload


@pytest.mark.parametrize("size", [0, 7, 8])
async def test_upload_at_or_below_limit_is_preserved(size):
    content = b"x" * size
    with BytesIO(content) as stream:
        file = UploadFile(stream)
        assert await read_upload(file, max_bytes=8, label="Test") == content


async def test_oversized_upload_stops_reading_at_limit_plus_one():
    with BytesIO(b"x" * 100) as stream:
        file = UploadFile(stream)
        with pytest.raises(HTTPException) as exc:
            await read_upload(file, max_bytes=8, label="Test")
        assert exc.value.status_code == 413
        assert stream.tell() == 9
