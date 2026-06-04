"""
J.A.R.V.I.S — Connection Monitor
Monitor active network connections and flag suspicious activity.
"""

import psutil
import socket
from datetime import datetime

import config


# Suspicious ports that may indicate malicious activity
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999,  # Common RAT/backdoor ports
    1337, 31337,  # Hacker culture ports
    4443, 8443,   # Alt HTTPS often used for C2
    12345, 54321, # Common trojan ports
}

# Known benign processes
BENIGN_PROCESSES = {
    "svchost.exe", "system", "chrome.exe", "firefox.exe", "msedge.exe",
    "code.exe", "explorer.exe", "searchhost.exe", "runtimebroker.exe",
    "sihost.exe", "ctfmon.exe", "taskhostw.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "applicationframehost.exe",
    "textinputhost.exe", "widgetservice.exe", "securityhealthservice.exe",
    "windowsterminal.exe", "powershell.exe",
}


class ConnectionMonitor:
    """Monitor active network connections and detect suspicious activity."""

    def __init__(self):
        self._monitoring = False
        self._alerts = []

    def list_connections(self):
        """List all active network connections with risk assessment."""
        try:
            connections = psutil.net_connections(kind="inet")
            established = [c for c in connections if c.status == "ESTABLISHED"]
            listening = [c for c in connections if c.status == "LISTEN"]

            suspicious = []
            for conn in established:
                risk = self._assess_connection(conn)
                if risk:
                    suspicious.append(risk)

            msg = (
                f"Sir, you have {len(established)} active connections and "
                f"{len(listening)} listening ports."
            )

            if suspicious:
                msg += f" Warning: {len(suspicious)} suspicious connections detected."
                for s in suspicious[:3]:
                    msg += f" {s}"
            else:
                msg += " No suspicious connections detected."

            return msg

        except psutil.AccessDenied:
            return "I need administrator privileges to view all connections, sir. Try running JARVIS as administrator."
        except Exception as e:
            return f"Error checking connections: {str(e)}"

    def _assess_connection(self, conn):
        """Assess if a connection is suspicious."""
        reasons = []

        # Get process name
        try:
            process = psutil.Process(conn.pid)
            proc_name = process.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_name = "unknown"
            reasons.append("unknown process")

        # Check for suspicious remote port
        if conn.raddr:
            remote_port = conn.raddr.port
            remote_ip = conn.raddr.ip

            if remote_port in SUSPICIOUS_PORTS:
                reasons.append(f"suspicious port {remote_port}")

            # Check for non-standard ports from system processes
            if proc_name == "svchost.exe" and remote_port not in (80, 443, 53, 123, 8080):
                reasons.append(f"svchost on unusual port {remote_port}")

        if reasons:
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
            return f"Process '{proc_name}' connected to {remote} — {', '.join(reasons)}."

        return None

    def start_monitoring(self):
        """Start continuous connection monitoring."""
        self._monitoring = True
        result = self.list_connections()
        return result + " I'll continue monitoring in the background and alert you of any changes."

    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self._monitoring = False
        return "Connection monitoring stopped, sir."

    def get_security_status(self):
        """Get overall security status summary."""
        try:
            connections = psutil.net_connections(kind="inet")
            established = [c for c in connections if c.status == "ESTABLISHED"]
            listening = [c for c in connections if c.status == "LISTEN"]

            # Count suspicious
            suspicious_count = 0
            for conn in established:
                if self._assess_connection(conn):
                    suspicious_count += 1

            # Check for risky listening ports
            risky_listening = []
            for conn in listening:
                if conn.laddr and conn.laddr.port in config.RISKY_PORTS:
                    risky_listening.append(conn.laddr.port)

            # Determine threat level
            if suspicious_count > 3 or len(risky_listening) > 2:
                threat_level = "HIGH"
            elif suspicious_count > 0 or len(risky_listening) > 0:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            # CPU and memory check
            cpu = psutil.cpu_percent(interval=0.5)
            ram = psutil.virtual_memory().percent

            msg = f"Security status: Threat level {threat_level}. "
            msg += f"{len(established)} active connections, {suspicious_count} suspicious. "
            msg += f"{len(listening)} listening ports"

            if risky_listening:
                port_names = [f"{p} ({config.RISKY_PORTS.get(p, 'Unknown')})" for p in risky_listening]
                msg += f", including risky: {', '.join(port_names)}"

            msg += f". CPU: {cpu}%, RAM: {ram}%."

            if cpu > 90:
                msg += " Warning: Very high CPU usage — possible cryptominer or runaway process."

            return msg

        except Exception as e:
            return f"Error getting security status: {str(e)}"

    def get_dashboard_data(self):
        """Get data for the security dashboard on the HUD."""
        try:
            connections = psutil.net_connections(kind="inet")
            established = [c for c in connections if c.status == "ESTABLISHED"]
            listening = [c for c in connections if c.status == "LISTEN"]

            suspicious_count = sum(
                1 for c in established if self._assess_connection(c)
            )

            risky_ports = [
                c.laddr.port for c in listening
                if c.laddr and c.laddr.port in config.RISKY_PORTS
            ]

            if suspicious_count > 3 or len(risky_ports) > 2:
                threat_level = "HIGH"
            elif suspicious_count > 0 or len(risky_ports) > 0:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            return {
                "threat_level": threat_level,
                "established": len(established),
                "listening": len(listening),
                "suspicious": suspicious_count,
                "risky_ports": risky_ports,
                "cpu": psutil.cpu_percent(),
                "ram": psutil.virtual_memory().percent,
                "timestamp": datetime.now().isoformat()
            }
        except Exception:
            return {"threat_level": "UNKNOWN", "error": True}
