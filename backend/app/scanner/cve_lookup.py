"""CVE Lookup module: queries NVD API 2.0 for real CVEs matching detected tech."""
import asyncio
import logging
from typing import Any

import httpx

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 6.5  # seconds between requests (NVD public rate limit: 5 req/30s)

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

QUERYABLE_PRODUCTS = {
    "nginx", "apache httpd", "iis", "php", "node.js", "tomcat",
    "wordpress", "drupal", "joomla", "laravel", "django",
    "spring boot", "express.js", "next.js", "asp.net",
    "openssl", "mysql", "postgresql", "redis", "mongodb",
    "elasticsearch", "varnish", "jquery", "bootstrap", "angular",
    "react", "vue.js", "lodash", "moment.js",
}

MAX_CVES_PER_PRODUCT = 2


async def _query_nvd(product: str, version: str, client: httpx.AsyncClient) -> list[dict]:
    """Query NVD API 2.0 and return the top CVEs sorted by CVSS score."""
    search = f"{product} {version}"
    try:
        resp = await client.get(
            NVD_API,
            params={"keywordSearch": search, "resultsPerPage": 10},
            timeout=15.0,
        )
        if resp.status_code != 200:
            logger.warning("NVD API returned %d for %r", resp.status_code, search)
            return []
        data = resp.json()
    except Exception as exc:
        logger.warning("NVD API error for %r: %s", search, exc)
        return []

    results: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id.startswith("CVE-"):
            continue

        descriptions = cve_data.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        cvss_score: float | None = None
        cvss_severity: str | None = None
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "").upper()
                break

        if cvss_score is None:
            continue

        refs = cve_data.get("references", [])
        ref_url = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        results.append({
            "cve": cve_id,
            "title": desc_en[:200] if desc_en else cve_id,
            "cvss": cvss_score,
            "severity": (cvss_severity or "MEDIUM").lower(),
            "ref": ref_url,
            "product": product,
            "detected_version": version,
        })

    # Sort by CVSS descending and keep only the top results
    results.sort(key=lambda c: c.get("cvss", 0), reverse=True)
    return results[:MAX_CVES_PER_PRODUCT]


class CVELookupScanner(BaseScanner):
    name = "cve_lookup"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        detected_tech: list[dict[str, Any]] = ctx.extra.get("detected_tech", [])
        if not detected_tech:
            return [
                Finding(
                    module=self.name,
                    title="No technologies with versions detected",
                    description=(
                        "The fingerprint module did not detect any versioned software. "
                        "CVE lookup requires version information to query the NVD."
                    ),
                    severity=Severity.INFO,
                )
            ]

        candidates = [
            t for t in detected_tech
            if t.get("version") and t.get("tech", "").lower() in QUERYABLE_PRODUCTS
        ]
        if not candidates:
            return [
                Finding(
                    module=self.name,
                    title="No queryable technologies found",
                    description=(
                        f"Detected {len(detected_tech)} technologies but none had "
                        "a recognized product name with a version for NVD lookup."
                    ),
                    severity=Severity.INFO,
                )
            ]

        findings: list[Finding] = []
        seen_cves: set[str] = set()

        async with httpx.AsyncClient(
            headers={"User-Agent": ctx.user_agent},
            verify=True,
        ) as client:
            for i, tech in enumerate(candidates[:6]):
                product = tech["tech"]
                version = tech["version"]
                try:
                    hits = await _query_nvd(product, version, client)
                    for hit in hits:
                        if hit["cve"] in seen_cves:
                            continue
                        seen_cves.add(hit["cve"])

                        sev_str = hit.get("severity", "medium").lower()
                        severity = SEVERITY_MAP.get(sev_str.upper(), Severity.MEDIUM)
                        cve_id = hit["cve"]
                        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                        findings.append(
                            Finding(
                                module=self.name,
                                title=f"{cve_id} — {product} {version}",
                                description=hit.get("title", cve_id),
                                severity=severity,
                                owasp_category=OwaspCategory.A06_VULN_COMPONENTS,
                                cvss_score=hit.get("cvss"),
                                evidence={
                                    "cve_id": cve_id,
                                    "product": product,
                                    "detected_version": version,
                                    "cvss_score": hit.get("cvss"),
                                    "cvss_severity": sev_str,
                                    "source": "nvd_api",
                                },
                                remediation=f"Check {nvd_url} for patched versions of {product}.",
                                reference_url=hit.get("ref", nvd_url),
                            )
                        )
                except Exception as exc:
                    logger.warning("NVD lookup failed for %s %s: %s", product, version, exc)

                if i < len(candidates) - 1:
                    await asyncio.sleep(NVD_DELAY)

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    title="No known CVEs found for detected versions",
                    description=(
                        f"Queried the NVD for {len(candidates)} detected technologies. "
                        "No matching vulnerabilities were returned."
                    ),
                    severity=Severity.INFO,
                    evidence={
                        "checked": [
                            {"tech": t.get("tech"), "version": t.get("version")}
                            for t in candidates
                        ],
                    },
                )
            )

        return findings
