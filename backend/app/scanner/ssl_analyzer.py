"""SSL/TLS analyzer."""
import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext


WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def _fetch_cert(host: str, port: int, timeout: float) -> tuple[bytes, str | None]:
    """Synchronous cert fetch run in a thread."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            version = ssock.version()
            return der, version


def _probe_protocol(host: str, port: int, protocol: int, timeout: float) -> bool:
    """Try to handshake with a specific TLS/SSL protocol."""
    try:
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, ValueError):
        return False


class SSLAnalyzer(BaseScanner):
    name = "ssl"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        parsed = urlparse(ctx.target_url)
        if parsed.scheme != "https":
            return [
                Finding(
                    module=self.name,
                    title="Target is not served over HTTPS",
                    description=(
                        f"Target {ctx.target_url} is HTTP only. "
                        "All traffic is transmitted in cleartext."
                    ),
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    remediation="Serve the application over HTTPS with a valid TLS certificate. "
                    "Redirect HTTP -> HTTPS and enable HSTS.",
                    reference_url="https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
                )
            ]

        host = ctx.target_host
        port = parsed.port or 443
        findings: list[Finding] = []

        try:
            der, version = await asyncio.to_thread(_fetch_cert, host, port, ctx.timeout)
        except Exception as exc:
            return [
                Finding(
                    module=self.name,
                    title="Could not establish TLS connection",
                    description=str(exc),
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence={"host": host, "port": port},
                )
            ]

        cert = x509.load_der_x509_certificate(der)

        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        evidence: dict[str, Any] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_left": days_left,
            "negotiated_protocol": version,
        }

        if now > not_after:
            findings.append(
                Finding(
                    module=self.name,
                    title="TLS certificate is expired",
                    description=f"Certificate expired on {not_after.isoformat()} ({-days_left} days ago).",
                    severity=Severity.CRITICAL,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence=evidence,
                    remediation="Renew the TLS certificate immediately.",
                )
            )
        elif days_left < 14:
            findings.append(
                Finding(
                    module=self.name,
                    title="TLS certificate expires soon",
                    description=f"Certificate expires in {days_left} days.",
                    severity=Severity.HIGH if days_left < 7 else Severity.MEDIUM,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence=evidence,
                    remediation="Renew the TLS certificate before expiry. Automate with Let's Encrypt / certbot.",
                )
            )

        if now < not_before:
            findings.append(
                Finding(
                    module=self.name,
                    title="TLS certificate not yet valid",
                    description=f"Certificate becomes valid on {not_before.isoformat()}.",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence=evidence,
                )
            )

        try:
            sig_algo = cert.signature_hash_algorithm
            if sig_algo and isinstance(sig_algo, (hashes.MD5, hashes.SHA1)):
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Weak certificate signature algorithm ({sig_algo.name})",
                        description="Certificate signed with a deprecated weak hash algorithm.",
                        severity=Severity.HIGH,
                        owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                        evidence={"signature_algorithm": sig_algo.name},
                        remediation="Reissue the certificate using SHA-256 or stronger.",
                    )
                )
        except Exception:
            pass

        san_hosts: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_hosts = san_ext.value.get_values_for_type(x509.DNSName)
            evidence["san"] = san_hosts
        except x509.ExtensionNotFound:
            findings.append(
                Finding(
                    module=self.name,
                    title="Certificate missing Subject Alternative Name (SAN)",
                    description="Modern TLS requires SAN; CN-only certs are rejected by most browsers.",
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence=evidence,
                )
            )

        if san_hosts and not any(
            host == s or (s.startswith("*.") and host.endswith(s[1:])) for s in san_hosts
        ):
            findings.append(
                Finding(
                    module=self.name,
                    title="Hostname does not match certificate SAN",
                    description=f"Host {host!r} is not present in the certificate SAN entries.",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence=evidence,
                )
            )

        if version in WEAK_TLS_VERSIONS:
            findings.append(
                Finding(
                    module=self.name,
                    title=f"Server negotiates weak TLS version: {version}",
                    description=f"Server negotiated {version} which is deprecated/insecure.",
                    severity=Severity.HIGH,
                    owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                    evidence=evidence,
                    remediation="Disable TLS < 1.2 on the server. Prefer TLS 1.3 only.",
                )
            )

        if ctx.depth in ("standard", "deep"):
            legacy_protocols = []
            for name, proto_const in (
                ("TLSv1", getattr(ssl, "PROTOCOL_TLSv1", None)),
                ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
            ):
                if proto_const is None:
                    continue
                try:
                    supported = await asyncio.to_thread(
                        _probe_protocol, host, port, proto_const, min(ctx.timeout, 5.0)
                    )
                    if supported:
                        legacy_protocols.append(name)
                except Exception:
                    continue

            if legacy_protocols:
                findings.append(
                    Finding(
                        module=self.name,
                        title="Server supports legacy TLS protocols",
                        description=f"Server still accepts: {', '.join(legacy_protocols)}",
                        severity=Severity.HIGH,
                        owasp_category=OwaspCategory.A02_CRYPTO_FAILURES,
                        evidence={"legacy_protocols": legacy_protocols},
                        remediation="Disable TLS 1.0 and 1.1 in your server config.",
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    module=self.name,
                    title="TLS configuration looks healthy",
                    description=(
                        f"Certificate valid until {not_after.isoformat()} "
                        f"({days_left} days), protocol: {version}."
                    ),
                    severity=Severity.INFO,
                    evidence=evidence,
                )
            )
        return findings
