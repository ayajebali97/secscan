"""HTTP Security Headers analyzer."""
from typing import Any

import httpx

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext


HEADER_RULES: dict[str, dict[str, Any]] = {
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "remediation": (
            "Configure a strict Content-Security-Policy header. At minimum: "
            "`default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`."
        ),
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
    },
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "remediation": (
            "Enable HSTS: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` "
            "(HTTPS-only sites)."
        ),
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "https_only": True,
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "remediation": "Set `X-Content-Type-Options: nosniff` to prevent MIME-sniffing attacks.",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "remediation": "Set `X-Frame-Options: DENY` (or use CSP frame-ancestors) to prevent clickjacking.",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "remediation": "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "remediation": (
            "Set a restrictive Permissions-Policy disabling unused features, e.g.: "
            "`geolocation=(), microphone=(), camera=(), payment=()`."
        ),
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
    },
}


def _validate_csp(value: str) -> tuple[Severity, list[str]]:
    issues = []
    lower = value.lower()
    if "unsafe-inline" in lower:
        issues.append("CSP allows 'unsafe-inline' (XSS risk).")
    if "unsafe-eval" in lower:
        issues.append("CSP allows 'unsafe-eval'.")
    if "default-src" not in lower:
        issues.append("CSP missing 'default-src' directive.")
    if "*" in lower.split():
        issues.append("CSP uses wildcard '*' source.")
    if issues:
        return Severity.MEDIUM, issues
    return Severity.INFO, []


def _validate_hsts(value: str) -> tuple[Severity, list[str]]:
    issues = []
    lower = value.lower()
    if "max-age" not in lower:
        return Severity.MEDIUM, ["HSTS missing max-age."]
    try:
        max_age = int([p.split("=")[1] for p in lower.split(";") if "max-age" in p][0])
        if max_age < 15768000:  # < 6 months
            issues.append(f"HSTS max-age={max_age} is below recommended 15768000 (6 months).")
    except (ValueError, IndexError):
        issues.append("HSTS max-age value could not be parsed.")
    if "includesubdomains" not in lower:
        issues.append("HSTS missing 'includeSubDomains'.")
    if issues:
        return Severity.LOW, issues
    return Severity.INFO, []


class HeadersScanner(BaseScanner):
    name = "headers"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=ctx.timeout,
                follow_redirects=True,
                headers={"User-Agent": ctx.user_agent},
                verify=True,
            ) as client:
                resp = await client.get(ctx.target_url)
        except httpx.HTTPError as exc:
            findings.append(
                Finding(
                    module=self.name,
                    title="Failed to fetch target",
                    description=f"Could not retrieve URL for header analysis: {exc}",
                    severity=Severity.INFO,
                )
            )
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        is_https = ctx.target_url.lower().startswith("https://")

        for header, rule in HEADER_RULES.items():
            if rule.get("https_only") and not is_https:
                continue
            value = headers_lower.get(header.lower())
            if value is None:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Missing security header: {header}",
                        description=f"The response is missing the {header} header.",
                        severity=rule["severity"],
                        owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                        evidence={"missing_header": header, "url": ctx.target_url},
                        remediation=rule["remediation"],
                        reference_url=rule["ref"],
                    )
                )
                continue

            if header == "Content-Security-Policy":
                sev, issues = _validate_csp(value)
                if issues:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Weak Content-Security-Policy",
                            description="; ".join(issues),
                            severity=sev,
                            owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                            evidence={"header": header, "value": value, "issues": issues},
                            remediation=rule["remediation"],
                            reference_url=rule["ref"],
                        )
                    )
            elif header == "Strict-Transport-Security":
                sev, issues = _validate_hsts(value)
                if issues:
                    findings.append(
                        Finding(
                            module=self.name,
                            title="Weak HSTS configuration",
                            description="; ".join(issues),
                            severity=sev,
                            owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                            evidence={"header": header, "value": value, "issues": issues},
                            remediation=rule["remediation"],
                            reference_url=rule["ref"],
                        )
                    )

        if "server" in headers_lower:
            findings.append(
                Finding(
                    module=self.name,
                    title="Server header discloses version",
                    description=f"Server: {headers_lower['server']}",
                    severity=Severity.INFO,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"Server": headers_lower["server"]},
                    remediation="Remove or obfuscate the Server response header.",
                )
            )
        if "x-powered-by" in headers_lower:
            findings.append(
                Finding(
                    module=self.name,
                    title="X-Powered-By header discloses technology",
                    description=f"X-Powered-By: {headers_lower['x-powered-by']}",
                    severity=Severity.LOW,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"X-Powered-By": headers_lower["x-powered-by"]},
                    remediation="Disable the X-Powered-By header.",
                )
            )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    title="Security headers properly configured",
                    description="No missing or weak security headers detected.",
                    severity=Severity.INFO,
                )
            )
        return findings
