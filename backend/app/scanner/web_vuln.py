"""Web vulnerability scanner: XSS, SQLi, open redirect, directory traversal, CORS."""
import asyncio
import re
import time
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext


XSS_PAYLOADS = [
    "<svg/onload=secscan_xss(1)>",
    '"><script>secscan_xss(1)</script>',
    "javascript:secscan_xss(1)",
]

SQLI_ERROR_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"sql syntax",
        r"mysql_fetch",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query\(",
        r"sqlite3\.OperationalError",
        r"ORA-\d{5}",
        r"syntax error at or near",
        r"odbc.*driver",
        r"warning: mysql_",
    ]
]

SQLI_TIME_PAYLOADS_SECONDS = 5
SQLI_TIME_PAYLOADS = [
    f"' AND SLEEP({SQLI_TIME_PAYLOADS_SECONDS})-- -",
    f"\" AND SLEEP({SQLI_TIME_PAYLOADS_SECONDS})-- -",
    f"';SELECT pg_sleep({SQLI_TIME_PAYLOADS_SECONDS})-- -",
]
SQLI_ERROR_PAYLOADS = ["'", "\"", "')", "';--", "' OR '1'='1"]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.example.com/secscan",
    "//evil.example.com/secscan",
    "/\\evil.example.com",
]

SENSITIVE_PATHS = [
    ".env", ".env.bak", ".env.local", ".env.production",
    ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".svn/wc.db",
    ".htaccess", ".htpasswd",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "wp-admin/install.php", "wp-login.php",
    "config.php", "config.php.bak", "configuration.php.bak",
    "web.config", "web.config.bak",
    "phpinfo.php", "info.php", "test.php",
    "server-status", "server-info",
    "actuator/env", "actuator/health", "actuator/configprops",
    ".DS_Store", "Thumbs.db",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "database.sql", "data.sql",
    "admin/", "administrator/", "panel/", "cpanel/",
    "phpmyadmin/", "pma/", "adminer.php",
    "api/", "api/v1/", "swagger.json", "openapi.json",
    "graphql", ".well-known/security.txt",
    "composer.json", "package.json", "Gemfile",
    "debug/", "trace.axd", "elmah.axd",
    "console/", "jmx-console/",
    "solr/", "jenkins/", "manager/html",
    ".aws/credentials", ".docker/config.json",
    "id_rsa", "id_dsa", ".ssh/authorized_keys",
    "wp-content/debug.log", "error_log", "error.log",
    "access.log", "logs/error.log",
]

REDIRECT_PARAM_NAMES = {
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "url",
    "return",
    "return_to",
    "returnurl",
    "continue",
    "dest",
    "destination",
}


def _replace_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new_params = [(k, value if k == key else v) for k, v in params]
    new_query = urlencode(new_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class WebVulnScanner(BaseScanner):
    name = "web_vuln"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        async with httpx.AsyncClient(
            timeout=ctx.timeout,
            headers={"User-Agent": ctx.user_agent},
            follow_redirects=False,
            verify=True,
        ) as client:
            try:
                resp = await client.get(ctx.target_url, follow_redirects=True)
            except httpx.HTTPError as exc:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Could not fetch target for web vulnerability scan",
                        description=str(exc),
                        severity=Severity.INFO,
                    )
                )
                return findings

            target_after_redirect = str(resp.url)
            findings.extend(await self._check_sensitive_paths(client, ctx))
            findings.extend(await self._check_cors(client, target_after_redirect, ctx))

            params = parse_qsl(urlparse(target_after_redirect).query, keep_blank_values=True)
            param_keys = [k for k, _ in params]

            if param_keys:
                findings.extend(
                    await self._check_xss(client, target_after_redirect, param_keys, ctx)
                )
                findings.extend(
                    await self._check_sqli(client, target_after_redirect, param_keys, ctx)
                )
                findings.extend(
                    await self._check_open_redirect(client, target_after_redirect, param_keys, ctx)
                )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    title="No web vulnerabilities detected (low-confidence)",
                    description=(
                        "No obvious XSS/SQLi/Open Redirect/CORS misconfig found with active probes. "
                        "Manual review still recommended."
                    ),
                    severity=Severity.INFO,
                )
            )
        return findings

    async def _check_sensitive_paths(
        self, client: httpx.AsyncClient, ctx: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(ctx.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        sem = asyncio.Semaphore(8)

        async def probe(path: str) -> Optional[Finding]:
            url = f"{base}/{path.lstrip('/')}"
            async with sem:
                try:
                    r = await client.get(url, follow_redirects=False)
                except httpx.HTTPError:
                    return None
            if r.status_code != 200 or len(r.content) < 4:
                return None
            text_preview = r.text[:200] if r.text else ""
            high_risk = path in {".env", ".git/config", ".git/HEAD", "wp-config.php.bak", "config.php.bak"}
            return Finding(
                module=self.name,
                title=f"Sensitive path exposed: /{path}",
                description=f"Path /{path} returned HTTP 200 with {len(r.content)} bytes.",
                severity=Severity.CRITICAL if high_risk else Severity.MEDIUM,
                owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                evidence={
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "preview": text_preview,
                },
                remediation=(
                    f"Remove or block access to /{path}. Add it to your web server deny list."
                ),
            )

        results = await asyncio.gather(*(probe(p) for p in SENSITIVE_PATHS))
        findings.extend([r for r in results if r is not None])
        return findings

    async def _check_cors(
        self, client: httpx.AsyncClient, url: str, ctx: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        evil_origin = "https://evil.example.com"
        try:
            r = await client.get(url, headers={"Origin": evil_origin})
        except httpx.HTTPError:
            return findings

        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            findings.append(
                Finding(
                    module=self.name,
                    title="CORS misconfiguration: wildcard origin with credentials",
                    description=(
                        "Server returns Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true (forbidden combination)."
                    ),
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"ACAO": acao, "ACAC": acac},
                    remediation="Never combine ACAO=* with credentials. Use an explicit origin whitelist.",
                )
            )
        elif acao == evil_origin:
            findings.append(
                Finding(
                    module=self.name,
                    title="CORS misconfiguration: arbitrary origin reflected",
                    description=(
                        f"Server reflected attacker-controlled origin {evil_origin} in "
                        "Access-Control-Allow-Origin without validation."
                    ),
                    severity=Severity.HIGH if acac == "true" else Severity.MEDIUM,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"ACAO": acao, "ACAC": acac, "sent_origin": evil_origin},
                    remediation="Validate the Origin against a strict whitelist before reflecting it.",
                )
            )
        return findings

    async def _check_xss(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: list[str],
        ctx: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        sem = asyncio.Semaphore(6)

        async def probe(param: str, payload: str) -> Optional[Finding]:
            test_url = _replace_query_param(url, param, payload)
            async with sem:
                try:
                    r = await client.get(test_url, follow_redirects=True)
                except httpx.HTTPError:
                    return None
            content_type = r.headers.get("content-type", "")
            if "html" not in content_type.lower():
                return None
            if payload in r.text:
                return Finding(
                    module=self.name,
                    title=f"Reflected XSS in parameter {param!r}",
                    description=(
                        f"Payload {payload!r} was reflected verbatim in the HTML response."
                    ),
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A03_INJECTION,
                    evidence={"param": param, "payload": payload, "url": test_url},
                    remediation=(
                        "Context-encode all user input before rendering. "
                        "Use a templating engine that escapes by default and add a strict CSP."
                    ),
                    reference_url="https://owasp.org/www-community/attacks/xss/",
                )
            return None

        tasks = [
            probe(p, payload)
            for p in params
            for payload in (XSS_PAYLOADS if ctx.depth != "quick" else XSS_PAYLOADS[:1])
        ]
        results = await asyncio.gather(*tasks)
        # Dedupe by param
        seen: set[str] = set()
        for f in results:
            if f and f.evidence and f.evidence["param"] not in seen:
                seen.add(f.evidence["param"])
                findings.append(f)
        return findings

    async def _check_sqli(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: list[str],
        ctx: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Error-based first
        for param in params:
            for payload in SQLI_ERROR_PAYLOADS:
                test_url = _replace_query_param(url, param, payload)
                try:
                    r = await client.get(test_url, follow_redirects=True)
                except httpx.HTTPError:
                    continue
                for pattern in SQLI_ERROR_PATTERNS:
                    m = pattern.search(r.text or "")
                    if m:
                        findings.append(
                            Finding(
                                module=self.name,
                                title=f"Possible SQL Injection in parameter {param!r}",
                                description=(
                                    f"Payload {payload!r} triggered a database error pattern in the response."
                                ),
                                severity=Severity.CRITICAL,
                                owasp_category=OwaspCategory.A03_INJECTION,
                                evidence={
                                    "param": param,
                                    "payload": payload,
                                    "match": m.group(0),
                                    "url": test_url,
                                },
                                remediation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL."
                                ),
                                reference_url="https://owasp.org/www-community/attacks/SQL_Injection",
                            )
                        )
                        break
                else:
                    continue
                break  # One finding per param is enough

        # Time-based only in deep depth (single probe per param)
        if ctx.depth == "deep" and not findings:
            for param in params[:3]:  # limit cost
                payload = SQLI_TIME_PAYLOADS[0]
                test_url = _replace_query_param(url, param, payload)
                start = time.monotonic()
                try:
                    await client.get(
                        test_url,
                        follow_redirects=True,
                        timeout=httpx.Timeout(SQLI_TIME_PAYLOADS_SECONDS + 5),
                    )
                except httpx.HTTPError:
                    continue
                elapsed = time.monotonic() - start
                if elapsed >= SQLI_TIME_PAYLOADS_SECONDS - 0.5:
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"Possible time-based SQL injection in {param!r}",
                            description=(
                                f"Response was delayed by {elapsed:.1f}s after injecting a SLEEP() payload."
                            ),
                            severity=Severity.CRITICAL,
                            owasp_category=OwaspCategory.A03_INJECTION,
                            evidence={
                                "param": param,
                                "payload": payload,
                                "elapsed_seconds": round(elapsed, 2),
                            },
                            remediation="Use parameterized queries; review backend DB access layer.",
                        )
                    )
        return findings

    async def _check_open_redirect(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: list[str],
        ctx: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        candidates = [p for p in params if p.lower() in REDIRECT_PARAM_NAMES]
        if not candidates:
            return findings

        for param in candidates:
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_url = _replace_query_param(url, param, payload)
                try:
                    r = await client.get(test_url, follow_redirects=False)
                except httpx.HTTPError:
                    continue
                location = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and (
                    "evil.example.com" in location.lower()
                ):
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"Open redirect in parameter {param!r}",
                            description=(
                                f"Server issues redirect to attacker-controlled host via {param}={payload}."
                            ),
                            severity=Severity.MEDIUM,
                            owasp_category=OwaspCategory.A01_BROKEN_ACCESS,
                            evidence={
                                "param": param,
                                "payload": payload,
                                "location": location,
                                "url": test_url,
                            },
                            remediation=(
                                "Validate redirect destinations against an internal allowlist of paths. "
                                "Never trust user-supplied absolute URLs."
                            ),
                        )
                    )
                    break
        return findings
