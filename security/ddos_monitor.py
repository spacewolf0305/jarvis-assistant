"""
J.A.R.V.I.S — DDoS Monitor
Detects DDoS-like connection floods by analysing connection rates,
SYN states, and per-IP connection counts using psutil.
"""

import time
import threading
from collections import Counter, defaultdict
from datetime import datetime

import psutil


# Thresholds
CONN_PER_IP_THRESHOLD = 15       # Flag IPs with more connections than this
SPIKE_THRESHOLD = 50             # New connections in a sampling window
SAMPLE_INTERVAL = 2              # Seconds between monitor samples
SYN_RATIO_WARNING = 0.40         # Warn if >40 % connections are SYN_SENT/SYN_RECV


class DDoSMonitor:
    """Monitor for DDoS-like traffic patterns on this machine."""

    def __init__(self):
        self._monitoring = False
        self._monitor_thread = None
        self._last_conn_count = 0
        self._alerts = []

    # ── One-shot check ────────────────────────────────────

    def check_ddos(self):
        """Quick snapshot: check current connections for DDoS indicators."""
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return (
                "I need administrator privileges to inspect all connections, sir. "
                "Try running JARVIS as administrator."
            )

        total = len(connections)
        if total == 0:
            return "No active network connections detected, sir. No signs of a DDoS."

        # Count by remote IP
        ip_counter = Counter()
        state_counter = Counter()
        for c in connections:
            state_counter[c.status] += 1
            if c.raddr:
                ip_counter[c.raddr.ip] += 1

        # Flag IPs over threshold
        offenders = [
            (ip, count) for ip, count in ip_counter.most_common()
            if count >= CONN_PER_IP_THRESHOLD
        ]

        # SYN flood detection
        syn_states = state_counter.get("SYN_SENT", 0) + state_counter.get("SYN_RECV", 0)
        syn_ratio = syn_states / max(total, 1)

        # Build response
        msg = f"Sir, I analysed {total} connections."

        if offenders:
            msg += (
                f" WARNING: {len(offenders)} IP(s) exceed the flood threshold "
                f"of {CONN_PER_IP_THRESHOLD} connections."
            )
            for ip, count in offenders[:5]:
                msg += f" {ip} has {count} connections."
        else:
            msg += " No single IP is flooding your machine."

        if syn_ratio >= SYN_RATIO_WARNING:
            msg += (
                f" ALERT: {syn_states} connections ({syn_ratio:.0%}) are in SYN state — "
                f"possible SYN flood attack."
            )
        else:
            msg += f" SYN state ratio is normal ({syn_ratio:.0%})."

        time_wait = state_counter.get("TIME_WAIT", 0)
        if time_wait > 100:
            msg += (
                f" Note: {time_wait} connections in TIME_WAIT — high churn, "
                f"which may indicate a recent burst."
            )

        return msg

    # ── Detailed flood report ─────────────────────────────

    def get_flood_report(self):
        """Detailed breakdown: state ratios, top IPs, per-port heatmap."""
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return "Administrator privileges required for a full flood report, sir."

        total = len(connections)
        if total == 0:
            return "No connections to report, sir."

        state_counter = Counter()
        ip_counter = Counter()
        port_counter = Counter()

        for c in connections:
            state_counter[c.status] += 1
            if c.raddr:
                ip_counter[c.raddr.ip] += 1
            if c.laddr:
                port_counter[c.laddr.port] += 1

        # State breakdown
        msg = f"Flood report — {total} total connections. States: "
        msg += ", ".join(f"{state} {count}" for state, count in state_counter.most_common(5))
        msg += "."

        # Top source IPs
        top_ips = ip_counter.most_common(5)
        if top_ips:
            msg += " Top remote IPs: "
            msg += ", ".join(f"{ip} ({count})" for ip, count in top_ips)
            msg += "."

        # Hottest local ports
        top_ports = port_counter.most_common(5)
        if top_ports:
            msg += " Busiest local ports: "
            msg += ", ".join(f"{port} ({count})" for port, count in top_ports)
            msg += "."

        return msg

    # ── Continuous monitor ────────────────────────────────

    def start_monitor(self):
        """Start background DDoS monitoring."""
        if self._monitoring:
            return "DDoS monitoring is already running, sir."

        self._monitoring = True
        self._alerts = []

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

        initial = self.check_ddos()
        return (
            f"{initial} Background DDoS monitoring is now active. "
            f"I'll alert you if I detect a connection spike."
        )

    def stop_monitor(self):
        """Stop background monitoring."""
        self._monitoring = False
        return "DDoS monitoring stopped, sir."

    def _monitor_loop(self):
        """Background thread that watches for connection spikes."""
        prev_count = self._count_connections()

        while self._monitoring:
            time.sleep(SAMPLE_INTERVAL)
            current = self._count_connections()
            delta = current - prev_count

            if delta >= SPIKE_THRESHOLD:
                alert = (
                    f"[{datetime.now().strftime('%H:%M:%S')}] SPIKE: "
                    f"+{delta} connections in {SAMPLE_INTERVAL}s "
                    f"(total {current})"
                )
                self._alerts.append(alert)

            prev_count = current

    def _count_connections(self):
        try:
            return len(psutil.net_connections(kind="inet"))
        except Exception:
            return 0

    # ── Firewall helper ───────────────────────────────────

    def block_ip(self, ip):
        """Generate a Windows Firewall rule to block an IP (manual execution)."""
        rule_name = f"JARVIS_Block_{ip.replace('.', '_')}"
        cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=block remoteip={ip}'
        )
        return (
            f"Sir, to block {ip}, run this command in an admin terminal: {cmd}. "
            f"I've generated the rule but won't execute it automatically for safety."
        )
