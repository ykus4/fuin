"""ZIP entry alignment for APKs.

Uses the Android SDK `zipalign` binary when available; falls back to a
pure-Python implementation so fuin works without the Android SDK installed.
"""

import struct
import subprocess
from pathlib import Path

from fuin._constants import ZIP_LFH_SIG
from fuin.android_tools import find_build_tool


def zipalign(apk_path: str, output_path: str) -> None:
    """Align stored (uncompressed) ZIP entries to 4-byte boundaries."""
    bin_path = find_build_tool("zipalign")
    if bin_path and Path(bin_path).is_file():
        result = subprocess.run(
            [bin_path, "-f", "-v", "4", apk_path, output_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"zipalign failed:\n{result.stderr}")
        return
    _zipalign_py(apk_path, output_path)


def _zipalign_py(apk_path: str, output_path: str, alignment: int = 4) -> None:
    """Pure-Python zipalign: align STORED entries to `alignment` bytes."""
    data = Path(apk_path).read_bytes()
    out = bytearray()
    src = 0

    while src < len(data) - 4:
        sig = struct.unpack_from("<I", data, src)[0]
        if sig != ZIP_LFH_SIG:
            break

        (
            version,
            flags,
            method,
            mtime,
            mdate,
            crc,
            comp_size,
            uncomp_size,
            fname_len,
            extra_len,
        ) = struct.unpack_from("<HHHHHIIIIHH", data, src + 4)

        header_size = 30 + fname_len + extra_len
        fname = data[src + 30 : src + 30 + fname_len]
        file_data = data[src + header_size : src + header_size + comp_size]

        if method == 0:
            future_data_start = len(out) + 30 + fname_len
            pad = (alignment - (future_data_start % alignment)) % alignment
            new_extra = (
                data[src + 30 + fname_len : src + 30 + fname_len + extra_len] + b"\x00" * pad
            )
            new_extra_len = len(new_extra)
        else:
            new_extra = data[src + 30 + fname_len : src + 30 + fname_len + extra_len]
            new_extra_len = extra_len

        out += struct.pack("<I", ZIP_LFH_SIG)
        out += struct.pack(
            "<HHHHHIIIIHH",
            version,
            flags,
            method,
            mtime,
            mdate,
            crc,
            comp_size,
            uncomp_size,
            fname_len,
            new_extra_len,
        )
        out += fname
        out += new_extra
        out += file_data

        src += header_size + comp_size

    out += data[src:]
    Path(output_path).write_bytes(bytes(out))
