"""The interface between the Python packer and the Kotlin stub.

These names are the real cross-language contract: the packer writes them into
the APK, and `jvm/stub` reads them back at runtime. Changing anything here
means changing the stub too.
"""

import re

# ---------------------------------------------------------------------------
# DEX entry names
# ---------------------------------------------------------------------------
PRIMARY_DEX = "classes.dex"
# Any DEX: classes.dex, classes2.dex, ...
DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")
# Multidex only, i.e. everything but the primary classes.dex.
EXTRA_DEX_RE = re.compile(r"^classes(\d+)\.dex$")

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

# The class the manifest's android:name is rewritten to point at.
STUB_CLASS = "com.fuin.stub.StubApplication"
