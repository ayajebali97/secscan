"""Scan model representing a single scanning job."""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanModule(str, enum.Enum):
    HEADERS = "headers"
    SSL = "ssl"
    PORTS = "ports"
    WEB_VULN = "web_vuln"
    SUBDOMAIN = "subdomain"
    FINGERPRINT = "fingerprint"
    DNS_RECON = "dns_recon"
    CVE_LOOKUP = "cve_lookup"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    modules: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    depth: Mapped[str] = mapped_column(String(16), default="standard", nullable=False)

    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    owner: Mapped["User"] = relationship("User", back_populates="scans")  # type: ignore[name-defined]  # noqa: F821
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
