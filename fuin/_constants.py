"""Centralized constants for asset paths, AXML chunk types, and signing block IDs."""

# ---------------------------------------------------------------------------
# Injected asset paths
# ---------------------------------------------------------------------------
ENCRYPTED_DEX_ASSET = "assets/encrypted.dex"
ENCRYPTED_EXTRA_DEX_ASSET = "assets/encrypted_extra.dex"
KEY_ASSET = "assets/key.bin"
ORIGINAL_APP_META_ASSET = "assets/original_app_class.txt"
CERT_FINGERPRINT_ASSET = "assets/cert_fingerprint.bin"
SECURITY_POLICY_ASSET = "assets/security_policy.json"
NATIVE_LIB_MANIFEST_ASSET = "assets/native_lib_manifest.json"
RES_MAP_ASSET = "assets/res_map.json"
STRING_KEY_ASSET = "assets/string_key.bin"

ENCRYPTED_LIBS_PREFIX = "assets/encrypted_libs/"
ENCRYPTED_RES_PREFIX = "assets/encrypted_res/"

# Assets injected by fuin itself — never re-encrypt these.
FUIN_INTERNAL_ASSETS: frozenset[str] = frozenset(
    {
        ENCRYPTED_DEX_ASSET,
        ENCRYPTED_EXTRA_DEX_ASSET,
        KEY_ASSET,
        ORIGINAL_APP_META_ASSET,
        CERT_FINGERPRINT_ASSET,
        SECURITY_POLICY_ASSET,
        NATIVE_LIB_MANIFEST_ASSET,
        RES_MAP_ASSET,
        STRING_KEY_ASSET,
    }
)

# ---------------------------------------------------------------------------
# AXML chunk types (from Android frameworks/base ResourceTypes.h)
# ---------------------------------------------------------------------------
AXML_FILE_MAGIC = 0x00080003
CHUNK_STRING_POOL = 0x001C0001
CHUNK_RESOURCE_MAP = 0x00180002
CHUNK_XML_START_NS = 0x00100100
CHUNK_XML_END_NS = 0x00100101
CHUNK_XML_START_ELEMENT = 0x00100102
CHUNK_XML_END_ELEMENT = 0x00100103
CHUNK_XML_CDATA = 0x00100104

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Android resource IDs for common attributes
RES_VERSION_CODE = 0x0101021B
RES_VERSION_NAME = 0x0101021C
RES_MIN_SDK = 0x0101020C
RES_TARGET_SDK = 0x01010270
RES_NAME = 0x01010003

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
ZIP_LOCAL_HEADER_MAGIC = b"PK\x03\x04"
ZIP_EOCD_MAGIC = b"PK\x05\x06"
ZIP_LFH_SIG = 0x04034B50

APK_V2_BLOCK_ID = 0x7109871A
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
