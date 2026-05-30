"""Subdomain enumeration via crt.sh + DNS resolution."""
import asyncio
from typing import Set

import dns.asyncresolver
import httpx

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "api",
    "dev", "staging", "test", "qa", "preprod", "uat",
    "blog", "shop", "store", "portal", "intranet", "internal",
    "vpn", "remote", "ssh", "git", "gitlab", "jenkins", "ci",
    "db", "sql", "redis", "mongo", "elastic",
    "cdn", "static", "assets", "media", "images", "img",
    "monitoring", "grafana", "kibana", "metrics", "logs",
    "support", "help", "docs", "wiki",
    "auth", "sso", "login", "oauth",
    "old", "beta", "alpha", "demo",
]


async def _resolve(host: str) -> bool:
    try:
        await dns.asyncresolver.resolve(host, "A", lifetime=3.0)
        return True
    except Exception:
        try:
            await dns.asyncresolver.resolve(host, "AAAA", lifetime=3.0)
            return True
        except Exception:
            return False


def _get_base_domain(host: str) -> str:
    """Strip leading www. and try to get registrable domain (naive)."""
    parts = host.split(".")
    if parts[0] == "www" and len(parts) > 2:
        parts = parts[1:]
    return ".".join(parts)


class SubdomainScanner(BaseScanner):
    name = "subdomain"

    async def _fetch_crtsh(self, domain: str, timeout: float) -> Set[str]:
        results: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                r = await client.get(url)
        except httpx.HTTPError:
            return results
        if r.status_code != 200:
            return results
        try:
            data = r.json()
        except Exception:
            return results
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    results.add(sub)
        return results

    async def run(self, ctx: ScanContext) -> list[Finding]:
        domain = _get_base_domain(ctx.target_host)

        crtsh_subs = await self._fetch_crtsh(domain, min(ctx.timeout * 2, 15.0))

        wordlist_subs = {f"{w}.{domain}" for w in COMMON_SUBDOMAINS}

        all_candidates = crtsh_subs | wordlist_subs

        sem = asyncio.Semaphore(20)

        async def check(sub: str) -> str | None:
            async with sem:
                ok = await _resolve(sub)
            return sub if ok else None

        results = await asyncio.gather(*(check(s) for s in all_candidates))
        live = sorted({s for s in results if s})

        findings: list[Finding] = []

        risky_keywords = ("admin", "dev", "staging", "test", "internal", "intranet", "jenkins", "git", "old", "beta")
        risky = [s for s in live if any(k in s for k in risky_keywords)]
        if risky:
            findings.append(
                Finding(
                    module=self.name,
                    title=f"Internal/staging subdomains exposed publicly ({len(risky)})",
                    description=(
                        "Subdomains that look like internal/staging services were resolvable from the internet. "
                        "Review whether they should be public."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"risky_subdomains": risky[:50]},
                    remediation="Restrict non-production subdomains via VPN, IP allowlist, or take them offline.",
                )
            )

        findings.append(
            Finding(
                module=self.name,
                title=f"Subdomain enumeration found {len(live)} live hosts",
                description=(
                    f"Discovered {len(live)} live subdomains (sources: crt.sh + wordlist)."
                ),
                severity=Severity.INFO,
                evidence={
                    "domain": domain,
                    "live_subdomains": live[:100],
                    "sources": {
                        "crtsh": len(crtsh_subs),
                        "wordlist": len(wordlist_subs),
                    },
                },
            )
        )
        return findings
