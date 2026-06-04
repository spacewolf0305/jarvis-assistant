"""
J.A.R.V.I.S — Security Dashboard
Aggregates all security data for the HUD.
"""

from datetime import datetime
from security.connection_monitor import ConnectionMonitor


class SecurityDashboard:
    """Aggregated security status for the HUD dashboard."""

    def __init__(self):
        self.connection_monitor = ConnectionMonitor()
        self.last_network_scan = None
        self.last_port_scan = None
        self.network_devices = {}
        self.recent_events = []

    def get_status(self):
        """Get full security dashboard data."""
        dashboard = self.connection_monitor.get_dashboard_data()
        dashboard["last_network_scan"] = self.last_network_scan
        dashboard["last_port_scan"] = self.last_port_scan
        dashboard["network_devices_count"] = len(self.network_devices)
        dashboard["recent_events"] = self.recent_events[-20:]
        return dashboard

    def add_event(self, event_type, message):
        """Add a security event to the log."""
        self.recent_events.append({
            "type": event_type,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
        # Keep only last 100 events
        if len(self.recent_events) > 100:
            self.recent_events = self.recent_events[-100:]

    def update_network_scan(self, devices):
        """Update with latest network scan results."""
        self.last_network_scan = datetime.now().isoformat()
        self.network_devices = devices
        self.add_event("network_scan", f"Network scan completed. {len(devices)} devices found.")

    def update_port_scan(self, target, results):
        """Update with latest port scan results."""
        self.last_port_scan = datetime.now().isoformat()
        self.add_event("port_scan", f"Port scan on {target} completed.")
