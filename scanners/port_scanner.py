"""
scanners/port_scanner.py — Port scanner (v2 async rewrite).
Uses native Nmap via python-nmap with async executor, falling back
to async TCP socket sweep if Nmap is not installed or errors.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

from loguru import logger

from core.context import ScanContext
from core.findings import Finding
from scanners.base_scanner import BaseScanner

# Fallback service registry if Nmap is not used
COMMON_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    4443: "HTTPS-Alt", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 6443: "K8s-API",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    9000: "SonarQube", 9090: "Prometheus", 9200: "Elasticsearch",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 50000: "SAP/Jenkins",
}

try:
    import nmap
    _NMAP_AVAILABLE = True
except ImportError:
    _NMAP_AVAILABLE = False


class PortScanner(BaseScanner):
    """Hybrid port scanner utilizing Nmap with an async socket fallback."""

    async def scan(self) -> List[Finding]:
        host = self.ctx.host
        ports = self.ctx.ports or list(COMMON_SERVICES.keys())
        findings: List[Finding] = []

        self.log.info(f"Initiating port scan for {host} (Nmap={_NMAP_AVAILABLE})")

        open_ports = []
        nmap_success = False

        if _NMAP_AVAILABLE:
            try:
                open_ports = await self._scan_with_nmap(host, ports)
                nmap_success = True
            except Exception as exc:
                self.log.warning(f"Nmap scan failed ({exc}); falling back to socket scan")

        if not nmap_success:
            open_ports = await self._scan_with_sockets(host, ports)

        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])

        for p in open_ports:
            port = p["port"]
            service = p["service"]
            version = p.get("version", "")
            banner = p.get("banner", "")
            os_match = p.get("os", "")
            self.ctx.add_open_port(port)

            # Determine severity based on port type and protocol security
            if port in (21, 23):  # Plaintext admin protocols
                severity = "HIGH"
                desc = f"Port {port} ({service}) is open and transmits data in plaintext."
            elif port in (22, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017):
                severity = "MEDIUM"
                desc = f"Port {port} ({service}) is open, exposing a potential administrative or database service."
            elif port in (80, 443):
                severity = "INFO"
                desc = f"Port {port} ({service}) is open for standard web traffic."
            else:
                severity = "LOW"
                desc = f"Port {port} ({service}) is open."

            evidence = {
                "port": port,
                "service": service,
                "host": host,
            }
            if version:
                evidence["version"] = version
                desc += f" Detected version: {version}."
            if banner:
                evidence["banner"] = banner
            if os_match:
                evidence["os_detection"] = os_match

            remediation = (
                f"Ensure port {port} ({service}) is firewalled and not publicly exposed unless required. "
                "Keep the service updated and enforce strong authentication."
            )

            findings.append(self.finding(
                title=f"Open Port: {port}/{service}",
                severity=severity,
                description=desc,
                evidence=evidence,
                remediation=remediation,
                target=f"{host}:{port}",
                tags=["port-scan", service.lower()],
            ))

        self.log.info(f"Port scan completed. Discovered {len(open_ports)} open ports.")
        return findings

    async def _scan_with_nmap(self, host: str, ports: List[int]) -> List[dict]:
        """Run Nmap in a background thread executor."""
        ports_str = ",".join(str(p) for p in ports)
        loop = asyncio.get_running_loop()

        def _run():
            nm = nmap.PortScanner()
            # Try running with OS detection first
            try:
                return nm.scan(host, ports_str, arguments="-sT -sV -O")
            except Exception as e:
                self.log.debug(f"Nmap scan with OS detection failed: {e}")
                self.add_error("Nmap Scan OS Detection", e)
                # Fallback to no OS detection (e.g. if running without root/admin privileges)
                return nm.scan(host, ports_str, arguments="-sT -sV")

        scan_result = await loop.run_in_executor(None, _run)
        open_ports = []

        if host in scan_result.get("scan", {}):
            host_data = scan_result["scan"][host]
            
            # Extract OS details if available
            os_match = ""
            if "osmatch" in host_data and host_data["osmatch"]:
                os_match = host_data["osmatch"][0].get("name", "")

            if "tcp" in host_data:
                for port, port_info in host_data["tcp"].items():
                    if port_info.get("state") == "open":
                        service_name = port_info.get("name", COMMON_SERVICES.get(port, "Unknown"))
                        product = port_info.get("product", "")
                        version = port_info.get("version", "")
                        
                        full_version = f"{product} {version}".strip()
                        open_ports.append({
                            "port": port,
                            "service": service_name,
                            "version": full_version,
                            "os": os_match,
                            "banner": port_info.get("extrainfo", ""),
                        })

        return open_ports

    async def _scan_with_sockets(self, host: str, ports: List[int]) -> List[dict]:
        """Fall back to async socket sweeps if Nmap is missing or errors."""
        semaphore = asyncio.Semaphore(50)
        tasks = [self._scan_port_socket(host, port, semaphore) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for res in results:
            if isinstance(res, dict) and res.get("open"):
                open_ports.append(res)
        return open_ports

    async def _scan_port_socket(self, host: str, port: int, semaphore: asyncio.Semaphore) -> dict:
        """Attempt socket TCP handshake for fallback scanning."""
        service = COMMON_SERVICES.get(port, "Unknown")
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.ctx.timeout,
                )
                banner = await self._grab_banner(reader, writer, host)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    self.log.debug(f"Socket close wait failed: {e}")
                    pass
                return {"port": port, "service": service, "open": True, "banner": banner}
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return {"port": port, "service": service, "open": False}
            except Exception as e:
                self.log.debug(f"Socket connection on port {port} failed: {e}")
                self.add_error(f"Port Socket Check Generic Exception {port}", e)
                return {"port": port, "service": service, "open": False}

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str) -> str:
        """Helper to read initial banners or request server headers on TCP ports."""
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if banner:
                return banner.decode("utf-8", errors="ignore").strip()
            
            # Probe HTTP header fallback
            writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            text = resp.decode("utf-8", errors="ignore")
            for line in text.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.strip()
            return ""
        except Exception as e:
            self.log.debug(f"Banner grab failed: {e}")
            return ""
