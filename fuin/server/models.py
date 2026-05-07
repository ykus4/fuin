from pydantic import BaseModel


class PackResult(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict
    report: dict | None = None


class RegisterAppResponse(BaseModel):
    app_id: str


class AppInfo(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict | None = None
    has_mapping: bool = False
    created_at: str | None = None
