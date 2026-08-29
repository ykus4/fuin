"""AXML chunk types and resource IDs, from Android's ResourceTypes.h."""

AXML_FILE_MAGIC = 0x00080003

# Each value is the chunk's u16 type ORed with its u16 header size, so
# RES_XML_RESOURCE_MAP_TYPE (0x0180) with an 8-byte header reads 0x00080180.
CHUNK_STRING_POOL = 0x001C0001
CHUNK_RESOURCE_MAP = 0x00080180
CHUNK_XML_START_NS = 0x00100100
CHUNK_XML_END_NS = 0x00100101
CHUNK_XML_START_ELEMENT = 0x00100102
CHUNK_XML_END_ELEMENT = 0x00100103
CHUNK_XML_CDATA = 0x00100104

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Resource IDs for the attributes fuin reads.
RES_VERSION_CODE = 0x0101021B
RES_VERSION_NAME = 0x0101021C
RES_MIN_SDK = 0x0101020C
RES_TARGET_SDK = 0x01010270
RES_NAME = 0x01010003

MANIFEST_NAME = "AndroidManifest.xml"

# ResValue type byte for a string reference into the pool.
TYPE_STRING = 0x03
