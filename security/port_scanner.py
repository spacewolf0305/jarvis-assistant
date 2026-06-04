"""
J.A.R.V.I.S — Port Scanner
Scan ports on a target and assess risks.
"""

import asyncio
import socket
import config


# Well-known port service names
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1434: "MSSQL Browser", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    8080: "HTTP Proxy", 8443: "HTTPS Alt", 8888: "HTTP Alt", 9090: "Web Admin"
}


class PortScanner:
    """Scan ports on a target host and assess security risks."""

    async def scan(self, target, ports=None):
        """Scan common ports on a target."""
        if ports is None:
            ports = config.COMMON_PORTS

        # Resolve hostname if needed
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return f"I couldn't resolve the hostname '{target}', sir."

        # Scan ports concurrently
        open_ports = []
        tasks = [self._check_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks)

        for port, is_open in results:
            if is_open:
                service = PORT_SERVICES.get(port, "Unknown")
                risk = config.RISKY_PORTS.get(port, None)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "risky": risk is not None,
                    "risk_detail": risk
                })

        return self._format_results(target, ip, open_ports)

    async def _check_port(self, ip, port, timeout=1.5):
        """Check if a single port is open."""
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return (port, True)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (port, False)

    def _format_results(self, target, ip, open_ports):
        """Format scan results for voice output."""
        if not open_ports:
            return f"Port scan complete on {target}. No open ports found among the top {len(config.COMMON_PORTS)} common ports. That's a good sign, sir."

        risky = [p for p in open_ports if p["risky"]]
        safe = [p for p in open_ports if not p["risky"]]

        msg = f"Port scan complete on {target}. Found {len(open_ports)} open ports."

        if risky:
            msg += f" Warning: {len(risky)} potentially dangerous ports detected."
            for p in risky:
                msg += f" Port {p['port']} {p['service']} is open. {p['risk_detail']}."

        if safe:
            safe_list = ", ".join(f"{p['port']} {p['service']}" for p in safe[:5])
            msg += f" Other open ports: {safe_list}."

        return msg

    def get_scan_data(self, target, open_ports):
        """Get port scan data for HUD dashboard."""
        return {
            "target": target,
            "open_ports": open_ports,
            "risky_count": sum(1 for p in open_ports if p.get("risky")),
        }
