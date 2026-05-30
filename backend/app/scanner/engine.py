"""Engine that orchestrates scanner modules with shared context."""
import asyncio
import logging
from typing import Callable

from app.core.config import settings
from app.models.scan import ScanModule
from app.scanner.base import BaseScanner, Finding, ScanContext
from app.scanner.cve_lookup import CVELookupScanner
from app.scanner.dns_recon import DNSReconScanner
from app.scanner.fingerprint import FingerprintScanner
from app.scanner.headers import HeadersScanner
from app.scanner.owasp_mapper import refine_owasp_category
from app.scanner.port_scanner import PortScanner
from app.scanner.ssl_analyzer import SSLAnalyzer
from app.scanner.subdomain import SubdomainScanner
from app.scanner.web_vuln import WebVulnScanner

logger = logging.getLogger(__name__)


MODULE_REGISTRY: dict[ScanModule, type[BaseScanner]] = {
    ScanModule.DNS_RECON: DNSReconScanner,
    ScanModule.HEADERS: HeadersScanner,
    ScanModule.SSL: SSLAnalyzer,
    ScanModule.PORTS: PortScanner,
    ScanModule.WEB_VULN: WebVulnScanner,
    ScanModule.SUBDOMAIN: SubdomainScanner,
    ScanModule.FINGERPRINT: FingerprintScanner,
    ScanModule.CVE_LOOKUP: CVELookupScanner,
}

# CVE_LOOKUP must always run after FINGERPRINT so it can read detected_tech
EXECUTION_ORDER: list[ScanModule] = [
    ScanModule.DNS_RECON,
    ScanModule.HEADERS,
    ScanModule.SSL,
    ScanModule.PORTS,
    ScanModule.WEB_VULN,
    ScanModule.SUBDOMAIN,
    ScanModule.FINGERPRINT,
    ScanModule.CVE_LOOKUP,
]


async def run_modules_sync(
    target_url: str,
    target_host: str,
    modules: list[ScanModule],
    depth: str = "standard",
    progress_cb: Callable[[str, int], None] | None = None,
) -> list[dict]:
    """Run scanner modules sequentially (ordered) and return finding dicts.

    The ScanContext is shared across all modules so that downstream modules
    (like CVE Lookup) can access data produced by upstream modules (like Fingerprint).
    """
    ctx = ScanContext(
        target_url=target_url,
        target_host=target_host,
        depth=depth,
        timeout=settings.SCAN_HTTP_TIMEOUT,
        user_agent=settings.SCAN_USER_AGENT,
    )

    # If cve_lookup requested but fingerprint not, add fingerprint automatically
    module_set = set(modules)
    if ScanModule.CVE_LOOKUP in module_set and ScanModule.FINGERPRINT not in module_set:
        module_set.add(ScanModule.FINGERPRINT)

    ordered = [m for m in EXECUTION_ORDER if m in module_set]
    for m in modules:
        if m not in ordered:
            ordered.append(m)

    all_findings: list[Finding] = []
    total = max(len(ordered), 1)
    for idx, module_id in enumerate(ordered):
        scanner_cls = MODULE_REGISTRY.get(module_id)
        if not scanner_cls:
            continue
        scanner = scanner_cls()
        if progress_cb:
            progress_cb(scanner.name, int(idx * 100 / total))
        try:
            findings = await asyncio.wait_for(
                scanner.run(ctx), timeout=settings.MAX_SCAN_DURATION_SECONDS
            )
        except asyncio.TimeoutError:
            logger.warning("Module %s timed out", scanner.name)
            findings = []
        except Exception as exc:
            logger.exception("Module %s crashed", scanner.name)
            from app.models.vulnerability import Severity

            findings = [
                Finding(
                    module=scanner.name,
                    title=f"Module {scanner.name} crashed",
                    description=str(exc)[:500],
                    severity=Severity.INFO,
                )
            ]
        for f in findings:
            f.owasp_category = refine_owasp_category(f)
            all_findings.append(f)

    if progress_cb:
        progress_cb("done", 100)
    return [f.to_dict() for f in all_findings]
