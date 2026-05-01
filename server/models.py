from pydantic import BaseModel


class RegisterAppRequest(BaseModel):
    package_name: str
    key: str  # hex-encoded AES key
    apk_signature: str  # SHA-256 hex of the signed APK


class RegisterAppResponse(BaseModel):
    app_id: str


class KeyRequest(BaseModel):
    app_id: str
    device_id: str
    apk_signature: str  # SHA-256 hex computed on-device


class KeyResponse(BaseModel):
    key: str  # hex-encoded AES key


class AppInfo(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    revoked: bool


class PackResult(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict


class AnalysisResult(BaseModel):
    package_name: str
    has_classes_dex: bool
    file_size_bytes: int
    entry_count: int
