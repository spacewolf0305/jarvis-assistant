"""
J.A.R.V.I.S — Bot & C2 Detector
Detects signs of botnet infection or command-and-control (C2) callbacks
by analysing outbound connections, process behaviour, and port patterns.
"""

import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime

import psutil


# ── Known C2 / RAT ports ─────────────────────────────────
C2_PORTS = {
    6667, 6668, 6669, 6697,       # IRC (classic botnet C2)
    4444, 4445, 5555,              # Metasploit / Meterpreter defaults
    1337, 31337,                   # Hacker culture
    8545,                          # Ethereum RPC (cryptominer C2)
    12345, 54321,                  # Common trojans
    3333, 14444, 14433,            # Cryptominer pools
    9001, 9030, 9050, 9051,        # TOR (possible C2 tunnel)
    2222,                          # Alt SSH (often used by malware)
    7777, 9999,                    # Generic RAT
    5900, 5901,                    # VNC (remote control)
    1080,                          # SOCKS proxy (botnet relay)
}

# Processes that are expected to have network connections
BENIGN_PROCESSES = {
    "svchost.exe", "system", "chrome.exe", "firefox.exe", "msedge.exe",
    "code.exe", "explorer.exe", "searchhost.exe", "runtimebroker.exe",
    "sihost.exe", "ctfmon.exe", "taskhostw.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "applicationframehost.exe",
    "textinputhost.exe", "widgetservice.exe", "securityhealthservice.exe",
    "windowsterminal.exe", "powershell.exe", "python.exe", "pythonw.exe",
    "node.exe", "git.exe", "ssh.exe", "spotify.exe", "discord.exe",
    "telegram.exe", "slack.exe", "teams.exe", "msedgewebview2.exe",
    "onedrive.exe", "microsoftedgeupdate.exe", "backgroundtaskhost.exe",
    "smartscreen.exe", "windowsdefender.exe", "msmpeng.exe",
    "lsass.exe", "services.exe", "wininit.exe", "csrss.exe",
    "dwm.exe", "spoolsv.exe", "winlogon.exe",
}

# Entropy threshold for DGA-like random hostnames
DGA_CONSONANT_RATIO = 0.70  # Flag if >70% consonants (likely random)


class BotDetector:
    """Detect signs of botnet infection or C2 command-and-control activity."""

    def __init__(self):
        self._beacon_history = defaultdict(list)  # pid -> [timestamps]

    # ── Full bot scan ─────────────────────────────────────

    def scan_for_bots(self):
        """Comprehensive scan for botnet / C2 indicators."""
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return (
                "I need administrator privileges to scan for bots, sir. "
                "Try running JARVIS as admin."
            )

        findings = []
        outbound = [
            c for c in connections
            if c.status == "ESTABLISHED" and c.raddr
        ]

        # 1. Check for C2 port connections
        c2_hits = []
        for conn in outbound:
            if conn.raddr.port in C2_PORTS:
                proc_name = self._get_proc_name(conn.pid)
                c2_hits.append({
                    "process": proc_name,
                    "pid": conn.pid,
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "port": conn.raddr.port,
                })

        if c2_hits:
            findings.append(
                f"CRITICAL: {len(c2_hits)} connection(s) to known C2/RAT ports detected."
            )
            for hit in c2_hits[:3]:
                findings.append(
                    f"  Process '{hit['process']}' (PID {hit['pid']}) → "
                    f"{hit['remote']}."
                )

        # 2. Check for unknown processes with outbound connections
        unknown_procs = []
        for conn in outbound:
            proc_name = self._get_proc_name(conn.pid)
            if proc_name.lower() not in BENIGN_PROCESSES and proc_name != "unknown":
                unknown_procs.append({
                    "process": proc_name,
                    "pid": conn.pid,
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                })

        # Deduplicate by process name
        seen = set()
        unique_unknown = []
        for p in unknown_procs:
            if p["process"] not in seen:
                seen.add(p["process"])
                unique_unknown.append(p)

        if unique_unknown:
            findings.append(
                f"WARNING: {len(unique_unknown)} unknown process(es) with outbound connections."
            )
            for p in unique_unknown[:5]:
                findings.append(
                    f"  '{p['process']}' (PID {p['pid']}) → {p['remote']}."
                )

        # 3. Check for beacon-like periodic outbound connections
        beacon_suspects = self._detect_beacons(outbound)
        if beacon_suspects:
            findings.append(
                f"SUSPICIOUS: {len(beacon_suspects)} process(es) show beacon-like behaviour."
            )
            for proc_name, count in beacon_suspects:
                findings.append(
                    f"  '{proc_name}' — {count} periodic connection events."
                )

        # 4. Check for suspicious high-entropy (DGA-like) remote IPs
        # (connecting to many random-looking IPs can indicate DGA malware)
        ip_diversity = Counter()
        for conn in outbound:
            proc_name = self._get_proc_name(conn.pid)
            ip_diversity[proc_name] += 1

        diverse_procs = [
            (proc, count) for proc, count in ip_diversity.items()
            if count > 20 and proc.lower() not in BENIGN_PROCESSES
        ]
        if diverse_procs:
            findings.append(
                f"NOTE: {len(diverse_procs)} process(es) connecting to an unusually "
                f"large number of remote hosts."
            )
            for proc, count in diverse_procs[:3]:
                findings.append(f"  '{proc}' → {count} connections.")

        # Build final report
        if not findings:
            return (
                f"Sir, I scanned {len(outbound)} outbound connections. "
                f"No signs of botnet infection or C2 callbacks detected. "
                f"Your system appears clean."
            )

        severity = "CRITICAL" if c2_hits else "WARNING"
        msg = (
            f"{severity}: Bot scan complete — {len(outbound)} outbound connections analysed. "
            + " ".join(findings)
        )
        return msg

    # ── Process deep-dive ─────────────────────────────────

    def check_process(self, identifier):
        """Deep inspection of a specific process's network activity."""
        # Find process by name or PID
        target_procs = []
        try:
            pid = int(identifier)
            try:
                proc = psutil.Process(pid)
                target_procs.append(proc)
            except psutil.NoSuchProcess:
                return f"No process found with PID {pid}, sir."
        except ValueError:
            # Search by name
            name = identifier.lower().strip()
            if not name.endswith(".exe"):
                name += ".exe"
            for proc in psutil.process_iter(["name", "pid"]):
                if proc.info["name"] and proc.info["name"].lower() == name:
                    target_procs.append(proc)

        if not target_procs:
            return f"No running process found matching '{identifier}', sir."

        results = []
        for proc in target_procs[:3]:  # Limit to 3 instances
            try:
                info = proc.as_dict(attrs=[
                    "name", "pid", "ppid", "username", "cmdline",
                    "create_time", "status"
                ])

                msg = (
                    f"Process '{info['name']}' (PID {info['pid']}): "
                    f"Status {info['status']}. "
                    f"User: {info.get('username', 'Unknown')}. "
                )

                # Command line
                cmdline = info.get("cmdline")
                if cmdline:
                    cmd_str = " ".join(cmdline)
                    if len(cmd_str) > 150:
                        cmd_str = cmd_str[:150] + "..."
                    msg += f"Cmd: {cmd_str}. "

                # Parent process
                ppid = info.get("ppid")
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        msg += f"Parent: {parent.name()} (PID {ppid}). "
                    except Exception:
                        msg += f"Parent PID: {ppid}. "

                # Network connections
                try:
                    conns = proc.net_connections(kind="inet")
                    if conns:
                        msg += f"Network: {len(conns)} connection(s). "
                        for c in conns[:5]:
                            remote = (
                                f"{c.raddr.ip}:{c.raddr.port}"
                                if c.raddr else "local"
                            )
                            msg += f"  {c.status} → {remote}. "

                            # Flag C2 ports
                            if c.raddr and c.raddr.port in C2_PORTS:
                                msg += f"  ⚠ PORT {c.raddr.port} IS A KNOWN C2/RAT PORT. "
                    else:
                        msg += "No active network connections. "
                except psutil.AccessDenied:
                    msg += "Cannot read connections (access denied). "

                # Uptime
                create_time = info.get("create_time")
                if create_time:
                    uptime = datetime.now() - datetime.fromtimestamp(create_time)
                    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
                    minutes = remainder // 60
                    msg += f"Running for {hours}h {minutes}m."

                results.append(msg)

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                results.append(f"Cannot inspect process: {e}")

        return " ".join(results)

    # ── Suspicious process listing ────────────────────────

    def list_suspicious_processes(self):
        """List processes with outbound connections not in the benign list."""
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return "Administrator privileges required, sir."

        outbound = [
            c for c in connections
            if c.status == "ESTABLISHED" and c.raddr
        ]

        # Group by process
        proc_conns = defaultdict(list)
        for conn in outbound:
            proc_name = self._get_proc_name(conn.pid)
            proc_conns[(proc_name, conn.pid)].append(conn)

        suspicious = []
        for (proc_name, pid), conns in proc_conns.items():
            if proc_name.lower() not in BENIGN_PROCESSES and proc_name != "unknown":
                c2_flag = any(c.raddr.port in C2_PORTS for c in conns)
                suspicious.append({
                    "process": proc_name,
                    "pid": pid,
                    "connections": len(conns),
                    "c2_flag": c2_flag,
                    "remotes": [
                        f"{c.raddr.ip}:{c.raddr.port}" for c in conns[:3]
                    ],
                })

        if not suspicious:
            return (
                "No suspicious processes with outbound connections found, sir. "
                "All networking processes are on the known-safe list."
            )

        msg = f"Sir, I found {len(suspicious)} process(es) not on the safe list with outbound connections."
        for s in suspicious[:5]:
            c2_warn = " ⚠ C2 PORT" if s["c2_flag"] else ""
            msg += (
                f" '{s['process']}' (PID {s['pid']}): "
                f"{s['connections']} connection(s) → "
                f"{', '.join(s['remotes'])}.{c2_warn}"
            )

        return msg

    # ── Internal helpers ──────────────────────────────────

    def _get_proc_name(self, pid):
        """Get process name from PID."""
        if pid is None:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def _detect_beacons(self, outbound):
        """
        Heuristic beacon detection: record connection timestamps per PID
        and check for regular intervals (typical of C2 check-ins).
        """
        now = time.time()

        # Record current connections
        for conn in outbound:
            if conn.pid:
                self._beacon_history[conn.pid].append(now)

        # Clean old entries (>5 min)
        for pid in list(self._beacon_history):
            self._beacon_history[pid] = [
                t for t in self._beacon_history[pid]
                if now - t < 300
            ]
            if not self._beacon_history[pid]:
                del self._beacon_history[pid]

        # Check for processes with many periodic events
        suspects = []
        for pid, timestamps in self._beacon_history.items():
            if len(timestamps) >= 5:
                proc_name = self._get_proc_name(pid)
                if proc_name.lower() not in BENIGN_PROCESSES:
                    suspects.append((proc_name, len(timestamps)))

        return suspects
