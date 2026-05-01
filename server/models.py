from pydantic import BaseModel


class PackResult(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict


class RegisterAppResponse(BaseModel):
    app_id: str


class AppInfo(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
