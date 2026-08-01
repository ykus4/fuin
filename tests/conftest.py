"""Shared fixtures for fuin tests.

Test data builders live in :mod:`tests.fixtures`.
"""

import pytest

from tests.fixtures import make_minimal_apk


@pytest.fixture
def minimal_apk_bytes() -> bytes:
    return make_minimal_apk()


@pytest.fixture
def minimal_apk(tmp_path, minimal_apk_bytes) -> str:
    """Path to a minimal APK on disk — the setup 13 tests were repeating inline."""
    path = tmp_path / "test.apk"
    path.write_bytes(minimal_apk_bytes)
    return str(path)
