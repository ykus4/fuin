"""Pydantic response/request schemas exposed by the FastAPI server."""

from pydantic import BaseModel, Field


class PackResult(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict = Field(default_factory=dict)
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
