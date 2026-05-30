"""Base scanner module interface and shared types."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.vulnerability import OwaspCategory, Severity


@dataclass
class Finding:
    """A single vulnerability finding produced by a scanner module."""

    module: str
    title: str
    description: str
    severity: Severity
    owasp_category: OwaspCategory = OwaspCategory.NONE
    evidence: Optional[dict[str, Any]] = None
    remediation: Optional[str] = None
    reference_url: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference_url": self.reference_url,
            "cvss_score": self.cvss_score,
        }


@dataclass
class ScanContext:
    target_url: str
    target_host: str
    depth: str = "standard"
    timeout: float = 10.0
    user_agent: str = "SecScan/0.1"
    extra: dict[str, Any] = field(default_factory=dict)


class BaseScanner(ABC):
    """Abstract scanner module."""

    name: str = "base"

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        ...
