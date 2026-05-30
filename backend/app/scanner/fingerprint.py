"""Technology fingerprinting with version extraction."""
import re
from typing import Any

import httpx
from bs4 import BeautifulSoup

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext

HEADER_RULES: list[dict[str, Any]] = [
    {"tech": "nginx", "where": "header:server", "re": r"nginx(?:/([\d.]+))?"},
    {"tech": "Apache httpd", "where": "header:server", "re": r"Apache(?:/([\d.]+))?"},
    {"tech": "IIS", "where": "header:server", "re": r"(?:Microsoft-)?IIS/([\d.]+)"},
    {"tech": "LiteSpeed", "where": "header:server", "re": r"LiteSpeed(?:/([\d.]+))?"},
    {"tech": "Cloudflare", "where": "header:server", "re": r"cloudflare"},
    {"tech": "Varnish", "where": "header:via", "re": r"varnish(?:/([\d.]+))?"},
    {"tech": "OpenResty", "where": "header:server", "re": r"openresty(?:/([\d.]+))?"},
    {"tech": "Tomcat", "where": "header:server", "re": r"(?:Apache-Coyote|Tomcat)(?:/([\d.]+))?"},

    {"tech": "PHP", "where": "header:x-powered-by", "re": r"PHP/([\d.]+)"},
    {"tech": "ASP.NET", "where": "header:x-powered-by", "re": r"ASP\.NET"},
    {"tech": "ASP.NET", "where": "header:x-aspnet-version", "re": r"([\d.]+)"},
    {"tech": "Express.js", "where": "header:x-powered-by", "re": r"Express(?:/([\d.]+))?"},
    {"tech": "Next.js", "where": "header:x-powered-by", "re": r"Next\.js(?:/([\d.]+))?"},
    {"tech": "Kestrel", "where": "header:server", "re": r"Kestrel"},

    {"tech": "Laravel", "where": "header:set-cookie", "re": r"laravel_session"},
    {"tech": "Django", "where": "header:set-cookie", "re": r"csrftoken"},
    {"tech": "Spring Boot", "where": "header:set-cookie", "re": r"JSESSIONID"},
    {"tech": "Rails", "where": "header:x-powered-by", "re": r"Phusion Passenger"},
    {"tech": "Rails", "where": "header:set-cookie", "re": r"_rails_session|_session_id"},
]

BODY_RULES: list[dict[str, Any]] = [
    {"tech": "WordPress", "re": r"/wp-(content|includes|admin)/", "version_re": r'content="WordPress\s+([\d.]+)"'},
    {"tech": "Drupal", "re": r'(?:Drupal\.settings|drupal\.org|/sites/default/files/)'},
    {"tech": "Joomla", "re": r'(?:/media/jui/|/administrator/|Joomla!)', "version_re": r'<meta\s+name="generator"\s+content="Joomla!\s+([\d.]+)"'},
    {"tech": "Magento", "re": r'(?:Mage\.Cookies|/skin/frontend/|magento)'},
    {"tech": "Shopify", "re": r'cdn\.shopify\.com'},

    {"tech": "React", "re": r'(?:data-reactroot|_react|react(?:\.production|\.development)\.min\.js)', "version_re": r'react(?:\.production|\.development)?\.min\.js\?v=([\d.]+)'},
    {"tech": "Vue.js", "re": r'(?:vue(?:\.runtime)?(?:\.min)?\.js|__vue__|vue@)', "version_re": r'vue(?:\.runtime)?(?:\.min)?\.js[^"]*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Angular", "re": r'(?:ng-version|angular(?:\.min)?\.js)', "version_re": r'ng-version="([\d.]+)"'},

    {"tech": "jQuery", "re": r'jquery[./-]', "version_re": r'jquery[./-]([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Bootstrap", "re": r'bootstrap', "version_re": r'bootstrap(?:\.min)?\.(?:css|js)[^"]*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Lodash", "re": r'lodash', "version_re": r'lodash(?:\.min)?\.js[^"]*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Moment.js", "re": r'moment(?:\.min)?\.js', "version_re": r'moment(?:\.min)?\.js[^"]*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Axios", "re": r'axios(?:\.min)?\.js'},
    {"tech": "Tailwind CSS", "re": r'tailwindcss|tailwind\.min\.css'},
    {"tech": "Font Awesome", "re": r'font-awesome|fontawesome'},

    {"tech": "Google Analytics", "re": r'(?:google-analytics\.com|gtag|ga\.js|analytics\.js)'},
    {"tech": "Google Tag Manager", "re": r'googletagmanager\.com'},
    {"tech": "reCAPTCHA", "re": r'google\.com/recaptcha'},
]

SCRIPT_VERSION_PATTERNS: list[dict[str, str]] = [
    {"tech": "jQuery", "re": r'jquery[./-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:\.min)?\.js'},
    {"tech": "Bootstrap", "re": r'bootstrap[./-]([\d]+\.[\d]+(?:\.[\d]+)?)(?:/|\.min)?'},
    {"tech": "Angular", "re": r'angular(?:\.min)?\.js\??([\d]+\.[\d]+\.[\d]+)?'},
    {"tech": "Vue.js", "re": r'vue(?:\.global|\.runtime)?(?:\.prod)?(?:\.min)?\.js.*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Lodash", "re": r'lodash(?:\.min)?\.js.*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "Moment.js", "re": r'moment(?:\.min)?\.js.*?([\d]+\.[\d]+\.[\d]+)'},
    {"tech": "React", "re": r'react(?:\.production)?(?:\.min)?\.js.*?([\d]+\.[\d]+\.[\d]+)'},
]


class FingerprintScanner(BaseScanner):
    name = "fingerprint"

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
            return [
                Finding(
                    module=self.name,
                    title="Could not fetch target for fingerprinting",
                    description=str(exc),
                    severity=Severity.INFO,
                )
            ]

        body = resp.text or ""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        detected: list[dict[str, Any]] = []
        seen_tech: set[str] = set()

        def _add(tech: str, version: str | None, source: str):
            key = f"{tech.lower()}:{version or ''}"
            if key in seen_tech:
                return
            seen_tech.add(key)
            detected.append({"tech": tech, "version": version, "source": source})

        # Header-based detection
        for rule in HEADER_RULES:
            header_key = rule["where"].split(":", 1)[1] if ":" in rule["where"] else ""
            target_text = headers_lower.get(header_key, "")
            if not target_text:
                continue
            m = re.search(rule["re"], target_text, re.I)
            if m:
                version = m.group(1) if m.groups() and m.group(1) else None
                _add(rule["tech"], version, f"header:{header_key}")

        # Body-based detection
        body_search = body[:300_000]
        for rule in BODY_RULES:
            m = re.search(rule["re"], body_search, re.I)
            if m:
                version = None
                if "version_re" in rule:
                    vm = re.search(rule["version_re"], body_search, re.I)
                    if vm and vm.group(1):
                        version = vm.group(1)
                _add(rule["tech"], version, "body")

        # Script tag version extraction
        try:
            soup = BeautifulSoup(body, "lxml") if body else None
        except Exception:
            soup = None

        if soup:
            script_tags = soup.find_all("script", src=True)
            for tag in script_tags:
                src = tag.get("src", "")
                for pattern in SCRIPT_VERSION_PATTERNS:
                    m = re.search(pattern["re"], src, re.I)
                    if m:
                        version = m.group(1) if m.groups() and m.group(1) else None
                        _add(pattern["tech"], version, f"script:{src[:100]}")

            link_tags = soup.find_all("link", href=True)
            for tag in link_tags:
                href = tag.get("href", "")
                for pattern in SCRIPT_VERSION_PATTERNS:
                    m = re.search(pattern["re"], href, re.I)
                    if m:
                        version = m.group(1) if m.groups() and m.group(1) else None
                        _add(pattern["tech"], version, f"link:{href[:100]}")

            gen_meta = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
            if gen_meta:
                content = gen_meta.get("content", "")
                if content:
                    gm = re.search(r"([\w.\-]+)\s+([\d]+\.[\d]+(?:\.[\d]+)?)", content)
                    if gm:
                        _add(gm.group(1), gm.group(2), "meta:generator")
                    else:
                        _add(content.split()[0] if content.split() else content, None, "meta:generator")

        # Store in ctx.extra for the CVE lookup module
        ctx.extra["detected_tech"] = detected

        # Generate findings
        versioned = [d for d in detected if d.get("version")]
        unversioned = [d for d in detected if not d.get("version")]

        if any(d["tech"] in {"WordPress", "Drupal", "Joomla", "Magento"} for d in detected):
            cms_list = [d for d in detected if d["tech"] in {"WordPress", "Drupal", "Joomla", "Magento"}]
            findings.append(
                Finding(
                    module=self.name,
                    title=f"CMS detected: {', '.join(d['tech'] for d in cms_list)}",
                    description=(
                        "Content management systems are high-value targets. "
                        "Ensure core, plugins, and themes are up to date."
                    ),
                    severity=Severity.LOW,
                    owasp_category=OwaspCategory.A06_VULN_COMPONENTS,
                    evidence={"cms": cms_list},
                    remediation="Enable auto-updates. Remove unused plugins/themes. Keep CMS core patched.",
                )
            )

        findings.append(
            Finding(
                module=self.name,
                title=f"Detected {len(detected)} technologies ({len(versioned)} with version info)",
                description=(
                    "Technologies: " +
                    ", ".join(
                        f"{d['tech']} {d['version']}" if d.get("version") else d["tech"]
                        for d in detected
                    )
                    if detected else "No technology fingerprints matched."
                ),
                severity=Severity.INFO,
                evidence={
                    "detected": detected,
                    "versioned_count": len(versioned),
                    "unversioned_count": len(unversioned),
                    "status_code": resp.status_code,
                    "final_url": str(resp.url),
                },
                remediation=(
                    "Detected versions will be checked against the CVE database. "
                    "Remove version-disclosing headers (Server, X-Powered-By) in production."
                ),
            )
        )
        return findings
