"""Map findings to OWASP Top 10 (2021) categories."""
import re

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import Finding


_KEYWORD_RULES: list[tuple[re.Pattern[str], OwaspCategory]] = [
    (re.compile(r"\bSQL.?Injection|SQLi\b", re.I), OwaspCategory.A03_INJECTION),
    (re.compile(r"\bXSS|cross.site.scripting\b", re.I), OwaspCategory.A03_INJECTION),
    (re.compile(r"\bcommand.?injection\b", re.I), OwaspCategory.A03_INJECTION),
    (re.compile(r"\bopen.?redirect|broken.?access\b", re.I), OwaspCategory.A01_BROKEN_ACCESS),
    (re.compile(r"\bsensitive.?path|directory.?listing|exposed\b", re.I), OwaspCategory.A05_MISCONFIGURATION),
    (re.compile(r"\bTLS|SSL|certificate|HSTS|cipher\b", re.I), OwaspCategory.A02_CRYPTO_FAILURES),
    (re.compile(r"\bauth|jwt|session|brute.?force|weak.?password\b", re.I), OwaspCategory.A07_AUTH_FAILURES),
    (re.compile(r"\bSSRF\b", re.I), OwaspCategory.A10_SSRF),
    (re.compile(r"\boutdated|vulnerable.?component|CVE|known.?vuln", re.I), OwaspCategory.A06_VULN_COMPONENTS),
    (re.compile(r"\bCORS|CSP|header\b", re.I), OwaspCategory.A05_MISCONFIGURATION),
    (re.compile(r"\blog|monitoring|audit\b", re.I), OwaspCategory.A09_LOGGING_FAILURES),
]


def refine_owasp_category(finding: Finding) -> OwaspCategory:
    """Return a more specific OWASP category for a finding, falling back to existing one."""
    if finding.owasp_category not in (OwaspCategory.NONE,):
        return finding.owasp_category

    if finding.severity == Severity.INFO:
        return OwaspCategory.NONE

    haystack = f"{finding.title}\n{finding.description}"
    for pattern, category in _KEYWORD_RULES:
        if pattern.search(haystack):
            return category
    return OwaspCategory.A05_MISCONFIGURATION
