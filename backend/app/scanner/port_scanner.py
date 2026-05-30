"""Async TCP port scanner with DNS resolution and banner grabbing."""
import asyncio
import socket
from typing import Any

from app.models.vulnerability import OwaspCategory, Severity
from app.scanner.base import BaseScanner, Finding, ScanContext

COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1434: "MSSQL-UDP",
    1521: "Oracle", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 6443: "K8s-API", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Shard",
}

EXTENDED_PORTS: list[int] = [
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 139,
    143, 161, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 990,
    993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083,
    2181, 2222, 3000, 3306, 3389, 4443, 5000, 5060, 5432, 5672, 5900,
    5984, 5985, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9090, 9200, 9300, 9418, 9443, 10000, 11211, 27017, 27018, 50000,
]

RISKY_OPEN_PORTS: dict[int, tuple[Severity, str, str]] = {
    21: (Severity.MEDIUM, "FTP transmits credentials in cleartext.", "Disable FTP. Use SFTP/SCP (port 22) instead."),
    23: (Severity.HIGH, "Telnet exposes all traffic (including passwords) in cleartext.", "Disable Telnet. Use SSH."),
    25: (Severity.LOW, "SMTP port open may allow relay if misconfigured.", "Ensure SMTP relay is properly restricted."),
    111: (Severity.MEDIUM, "RPCBind can leak service info and is often targeted.", "Block port 111 externally or disable rpcbind."),
    135: (Severity.MEDIUM, "MS-RPC exposed can lead to remote code execution.", "Block port 135 from the internet with a firewall."),
    139: (Severity.HIGH, "NetBIOS exposed can leak host info and enable attacks.", "Block NetBIOS (139) from the internet."),
    445: (Severity.HIGH, "SMB exposed is a prime ransomware/worm vector.", "Block port 445 from the internet. Use VPN for file sharing."),
    1433: (Severity.HIGH, "MSSQL should not be directly internet-facing.", "Restrict MSSQL to trusted IPs or use a VPN/bastion."),
    3306: (Severity.HIGH, "MySQL should not be directly internet-facing.", "Restrict MySQL to localhost or trusted IPs behind VPN."),
    3389: (Severity.HIGH, "RDP is the #1 brute-forced service on the internet.", "Use VPN or Zero Trust. Enable NLA. Restrict by IP."),
    5432: (Severity.HIGH, "PostgreSQL should not be directly internet-facing.", "Restrict PostgreSQL to trusted IPs behind VPN."),
    5900: (Severity.HIGH, "VNC is often unencrypted and password-only.", "Tunnel VNC through SSH. Never expose to the internet."),
    5985: (Severity.MEDIUM, "WinRM can allow remote management if credentials are weak.", "Restrict WinRM to internal networks."),
    6379: (Severity.CRITICAL, "Redis is often unauthenticated. Public Redis = full compromise.", "Bind Redis to 127.0.0.1 and require a password. Never expose."),
    9200: (Severity.HIGH, "Elasticsearch often has no auth. Data exfiltration risk.", "Bind to localhost, enable security features, or use a reverse proxy."),
    11211: (Severity.HIGH, "Memcached can be abused for DDoS amplification.", "Bind Memcached to 127.0.0.1, disable UDP."),
    27017: (Severity.HIGH, "MongoDB often has no auth by default. Data leak risk.", "Enable auth, bind to 127.0.0.1, use TLS."),
}


async def _resolve_to_ips(host: str) -> list[str]:
    """Resolve hostname to IP addresses."""
    try:
        infos = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        )
        return list(dict.fromkeys(info[4][0] for info in infos))
    except socket.gaierror:
        return []


async def _check_port(
    ip: str, port: int, timeout: float
) -> tuple[int, bool, str | None]:
    """Return (port, is_open, banner_or_none)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return port, False, None

    banner: str | None = None
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=1.5)
        if data:
            banner = data.decode("utf-8", errors="replace").strip()[:256]
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return port, True, banner


class PortScanner(BaseScanner):
    name = "ports"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        host = ctx.target_host
        resolved_ips = await _resolve_to_ips(host)
        if not resolved_ips:
            return [
                Finding(
                    module=self.name,
                    title="DNS resolution failed",
                    description=f"Could not resolve {host} to any IP address.",
                    severity=Severity.MEDIUM,
                    owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                    evidence={"host": host},
                )
            ]

        scan_ip = resolved_ips[0]

        if ctx.depth == "quick":
            ports = sorted({21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017})
        elif ctx.depth == "deep":
            ports = sorted(set(EXTENDED_PORTS))
        else:
            ports = sorted(set(COMMON_PORTS.keys()))

        sem = asyncio.Semaphore(100)
        timeout = min(ctx.timeout, 3.0)

        async def bounded(p: int):
            async with sem:
                return await _check_port(scan_ip, p, timeout)

        results = await asyncio.gather(*(bounded(p) for p in ports))

        open_ports: list[dict[str, Any]] = []
        closed_count = 0
        for port, is_open, banner in results:
            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open",
                    "banner": banner,
                })
            else:
                closed_count += 1

        findings: list[Finding] = []

        findings.append(
            Finding(
                module=self.name,
                title=f"Host resolved: {host} -> {scan_ip}",
                description=(
                    f"Target hostname resolved to {', '.join(resolved_ips)}. "
                    f"Port scan conducted against {scan_ip}."
                ),
                severity=Severity.INFO,
                evidence={
                    "hostname": host,
                    "resolved_ips": resolved_ips,
                    "scan_ip": scan_ip,
                },
            )
        )

        for op in open_ports:
            port = op["port"]
            if port in RISKY_OPEN_PORTS:
                sev, desc, remediation = RISKY_OPEN_PORTS[port]
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Risky service exposed: {op['service']} (port {port})",
                        description=desc,
                        severity=sev,
                        owasp_category=OwaspCategory.A05_MISCONFIGURATION,
                        evidence={
                            "port": port,
                            "service": op["service"],
                            "banner": op["banner"],
                            "ip": scan_ip,
                        },
                        remediation=remediation,
                    )
                )

        findings.append(
            Finding(
                module=self.name,
                title=f"Port scan results: {len(open_ports)} open / {closed_count} closed",
                description=(
                    f"Scanned {len(ports)} TCP ports on {scan_ip}. "
                    f"Found {len(open_ports)} open, {closed_count} closed/filtered."
                ),
                severity=Severity.INFO if not any(
                    p["port"] in RISKY_OPEN_PORTS for p in open_ports
                ) else Severity.LOW,
                evidence={
                    "ip": scan_ip,
                    "hostname": host,
                    "total_scanned": len(ports),
                    "open_ports": open_ports,
                    "open_count": len(open_ports),
                    "closed_count": closed_count,
                },
            )
        )

        return findings
