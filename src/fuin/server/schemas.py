"""Pydantic response/request schemas exposed by the FastAPI server."""

from pydantic import BaseModel, Field


class PackedApp(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict = Field(default_factory=dict)
    report: dict | None = None


class AppInfo(BaseModel):
    app_id: str
    package_name: str
    apk_signature: str
    analysis: dict | None = None
    has_mapping: bool = False
    created_at: str | None = None


class JobStatus(BaseModel):
    """Job progress, whether it came from the in-memory store or the DB."""

    job_id: str
    status: str
    step: str = ""
    pct: int = 0
    result: dict | None = None
    error: str | None = None


class JobAccepted(BaseModel):
    job_id: str


class StatusResponse(BaseModel):
    status: str


class MappingUploaded(StatusResponse):
    app_id: str
    size_bytes: int
