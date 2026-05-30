"""Validate scan targets to prevent SSRF and abuse."""
import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

import dns.asyncresolver
import dns.resolver

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata.aws.amazon.com"}
BLOCKED_TLDS = {"local", "internal", "lan", "corp", "home", "intranet"}


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def _resolve_host(host: str) -> list[str]:
    """Resolve a hostname to its A/AAAA records."""
    addrs: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = await dns.asyncresolver.resolve(host, record_type, lifetime=5.0)
            addrs.extend(str(a) for a in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue

    if not addrs:
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = list({i[4][0] for i in infos})
        except socket.gaierror:
            pass
    return addrs


async def validate_target_url(url: str, *, allow_private: bool = False) -> tuple[str, str]:
    """Validate a scan target URL.

    Returns (hostname, normalized_url).
    Raises ValueError on invalid / disallowed targets.
    """
    parsed = urlparse(url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme must be http or https, got: {parsed.scheme!r}")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("URL must include a hostname")

    if host in BLOCKED_HOSTNAMES:
        raise ValueError(f"Hostname {host!r} is not allowed")

    tld = host.rsplit(".", 1)[-1] if "." in host else host
    if tld in BLOCKED_TLDS:
        raise ValueError(f"Top-level domain {tld!r} is not scannable")

    try:
        ipaddress.ip_address(host)
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    if not allow_private:
        if is_literal_ip and _is_private_ip(host):
            raise ValueError(f"Private / loopback IPs are not allowed: {host}")

        if not is_literal_ip:
            resolved = await _resolve_host(host)
            if not resolved:
                raise ValueError(f"Could not resolve hostname: {host}")
            for ip in resolved:
                if _is_private_ip(ip):
                    raise ValueError(
                        f"Host {host} resolves to a private/internal IP ({ip}); blocked"
                    )

    if parsed.port is not None and (parsed.port < 1 or parsed.port > 65535):
        raise ValueError("Invalid port number")

    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )
    return host, normalized
