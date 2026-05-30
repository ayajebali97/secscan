"""DNS reconnaissance module: A/AAAA/MX/NS/TXT/SOA records + reverse DNS."""
import asyncio
import socket

import dns.asyncresolver
import dns.name
import dns.resolver

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def _get_base_domain(host: str) -> str:
    parts = host.split(".")
    if parts[0] == "www" and len(parts) > 2:
        parts = parts[1:]
    return ".".join(parts)


async def _resolve_records(domain: str, rtype: str) -> list[str]:
    try:
        answers = await dns.asyncresolver.resolve(domain, rtype, lifetime=8.0)
        return [str(r) for r in answers]
    except Exception:
        return []


async def _reverse_dns(ip: str) -> str | None:
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyaddr(ip)
        )
        return result[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


class DNSReconScanner(BaseScanner):
    name = "dns_recon"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        host = ctx.target_host
        domain = _get_base_domain(host)
        findings: list[Finding] = []

        dns_data: dict[str, list[str]] = {}
        tasks = {rtype: _resolve_records(domain, rtype) for rtype in RECORD_TYPES}
        if host != domain:
            tasks["HOST_A"] = _resolve_records(host, "A")
            tasks["HOST_AAAA"] = _resolve_records(host, "AAAA")

        results = {}
        for key, coro in tasks.items():
            results[key] = await coro

        for rtype in RECORD_TYPES:
            if results.get(rtype):
                dns_data[rtype] = results[rtype]

        a_records = results.get("HOST_A", []) or results.get("A", [])
        aaaa_records = results.get("HOST_AAAA", []) or results.get("AAAA", [])
        all_ips = a_records + aaaa_records

        reverse_map: dict[str, str | None] = {}
        for ip in all_ips[:8]:
            reverse_map[ip] = await _reverse_dns(ip)

        txt_records = dns_data.get("TXT", [])
        spf_found = any("v=spf1" in t for t in txt_records)
        dmarc_records = await _resolve_records(f"_dmarc.{domain}", "TXT")
        dkim_hint = any("domainkey" in t.lower() for t in txt_records)

        findings.append(
            Finding(
                module=self.name,
                title=f"DNS records for {domain}",
                description=(
                    f"Resolved {len(dns_data)} record types. "
                    f"A: {', '.join(a_records) or 'none'} | "
                    f"AAAA: {', '.join(aaaa_records) or 'none'} | "
                    f"NS: {', '.join(dns_data.get('NS', [])) or 'none'} | "
                    f"MX: {', '.join(dns_data.get('MX', [])) or 'none'}"
                ),
                severity=Severity.INFO,
                evidence={
                    "domain": domain,
                    "hostname": host,
                    "dns_records": dns_data,
                    "resolved_ips": all_ips,
                    "reverse_dns": reverse_map,
                },
            )
        )

        if not spf_found:
            findings.append(
                Finding(
                    module=self.name,
                    title="Missing SPF record",
                    description=(
                        f"No SPF (v=spf1) TXT record found for {domain}. "
                        "Attackers can spoof emails from this domain."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"domain": domain, "txt_records": txt_records},
                    remediation="Add a TXT record: v=spf1 include:... -all",
                    reference_url="https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
                )
            )

        if not dmarc_records:
            findings.append(
                Finding(
                    module=self.name,
                    title="Missing DMARC record",
                    description=(
                        f"No DMARC record found at _dmarc.{domain}. "
                        "Email spoofing and phishing attacks are easier without DMARC."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"domain": domain},
                    remediation="Add a TXT record at _dmarc.domain: v=DMARC1; p=reject; rua=mailto:...",
                    reference_url="https://dmarc.org/overview/",
                )
            )
        else:
            dmarc_val = " ".join(dmarc_records).lower()
            if "p=none" in dmarc_val:
                findings.append(
                    Finding(
                        module=self.name,
                        title="DMARC policy set to 'none' (monitoring only)",
                        description="DMARC policy=none does not reject spoofed emails.",
                        severity=Severity.LOW,
                        owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                        evidence={"dmarc": dmarc_records},
                        remediation="Upgrade DMARC policy to p=quarantine or p=reject.",
                    )
                )

        ns_records = dns_data.get("NS", [])
        if ns_records:
            providers = set()
            for ns in ns_records:
                ns_lower = ns.lower().rstrip(".")
                for prov in ["cloudflare", "awsdns", "google", "azure", "ns1.", "dnsimple", "route53"]:
                    if prov in ns_lower:
                        providers.add(prov)
            if providers:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"DNS provider identified: {', '.join(providers)}",
                        description=f"Nameservers: {', '.join(ns_records)}",
                        severity=Severity.INFO,
                        evidence={"nameservers": ns_records, "providers": list(providers)},
                    )
                )

        if len(set(ns.split(".")[-2] if "." in ns else ns for ns in ns_records)) <= 1 and len(ns_records) > 0:
            pass
        elif len(ns_records) < 2:
            findings.append(
                Finding(
                    module=self.name,
                    title="Single nameserver detected",
                    description="Having only one nameserver is a single point of failure.",
                    severity=Severity.LOW,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"nameservers": ns_records},
                    remediation="Use at least 2 nameservers from different networks for redundancy.",
                )
            )

        return findings
