"""Scan-related Pydantic schemas."""
import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.models.scan import ScanModule, ScanStatus
from app.schemas.vulnerability import VulnerabilityPublic


class ScanCreate(BaseModel):
    target_url: HttpUrl
    modules: List[ScanModule] = Field(
        default_factory=lambda: [
            ScanModule.HEADERS,
            ScanModule.SSL,
            ScanModule.FINGERPRINT,
        ]
    )
    depth: str = Field(default="standard", pattern="^(quick|standard|deep)$")

    @field_validator("modules")
    @classmethod
    def must_have_module(cls, v: List[ScanModule]) -> List[ScanModule]:
        if not v:
            raise ValueError("At least one scan module must be selected.")
        return list(dict.fromkeys(v))


class ScanPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_url: str
    target_host: str
    status: ScanStatus
    modules: List[str]
    depth: str
    progress: int
    current_module: Optional[str] = None
    risk_score: Optional[float] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime


class ScanList(BaseModel):
    items: List[ScanPublic]
    total: int
    page: int
    page_size: int


class ScanDetail(ScanPublic):
    vulnerabilities: List[VulnerabilityPublic] = Field(default_factory=list)
