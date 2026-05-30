from app.models.user import User, UserRole
from app.models.scan import Scan, ScanStatus, ScanModule
from app.models.vulnerability import Vulnerability, Severity, OwaspCategory

__all__ = [
    "User",
    "UserRole",
    "Scan",
    "ScanStatus",
    "ScanModule",
    "Vulnerability",
    "Severity",
    "OwaspCategory",
]
