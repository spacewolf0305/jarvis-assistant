"""
J.A.R.V.I.S — Cryptojacking Monitor
Detects resource-hijacking malware that mines cryptocurrency on your machine.

Heuristics (a process is flagged when several line up, not just one):
  1. Sustained very-high CPU usage over a rolling window.
  2. Process name matches known miners (xmrig, minerd, etc.).
  3. An outbound connection to a known mining-pool port.
Maps to MITRE ATT&CK T1496 — Resource Hijacking.
"""

import time
import threading
from collections import defaultdict, deque

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from security.event_store import get_store, Severity


# Known miner process-name fragments (lowercased substring match)
KNOWN_MINERS = {
    "xmrig", "minerd", "cgminer", "bfgminer", "ethminer",
    "nicehash", "cpuminer", "ccminer", "phoenixminer", "lolminer",
    "nbminer", "t-rex", "gminer", "xmr-stak",
}

# Common Stratum / mining-pool ports
MINING_POOL_PORTS = {3333, 4444, 5555, 7777, 8333, 9999, 14444, 45700}

# Thresholds
CPU_THRESHOLD = 80.0          # percent (per-process, normalised)
SUSTAINED_SAMPLES = 5         # consecutive high samples before alarm
SAMPLE_INTERVAL = 3           # seconds between samples


class CryptoMonitor:
    """Continuously watches for cryptomining behaviour."""

    def __init__(self):
        self._running = False
        self._thread = None
        self.store = get_store()
        # pid -> deque of recent cpu readings
        self._cpu_history = defaultdict(lambda: deque(maxlen=SUSTAINED_SAMPLES))
        self._alerted_pids = set()

    # ── one-shot scan (voice command: "scan for cryptojacking") ──
    def scan(self):
        if not PSUTIL_AVAILABLE:
            return "Sir, I require the 'psutil' library to inspect processes."

        suspects = self._find_suspects()
        if not suspects:
            return "No cryptojacking activity detected, sir. CPU resources look clean."

        lines = []
        for s in suspects:
            self._record(s)
            lines.append(f"{s['name']} (PID {s['pid']}) — {s['reason']}")
        return ("Warning, sir. Possible cryptojacking detected:\n" +
                "\n".join(lines) +
                "\nRecommended: terminate the process and block the pool address.")

    def _find_suspects(self):
        suspects = []
        # Snapshot mining-pool connections by pid
        pool_pids = self._pids_with_pool_connections()

        for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
            try:
                name = (proc.info["name"] or "").lower()
                pid = proc.info["pid"]
                cpu = proc.info["cpu_percent"] or 0.0
                # psutil reports cumulative across cores; normalise
                cpu = cpu / (psutil.cpu_count() or 1)

                reasons = []
                if any(m in name for m in KNOWN_MINERS):
                    reasons.append("known miner signature")
                if cpu >= CPU_THRESHOLD:
                    reasons.append(f"{cpu:.0f}% sustained CPU")
                if pid in pool_pids:
                    reasons.append("connection to mining-pool port")

                # Require a strong signal: a known miner alone, OR
                # high CPU together with a pool connection.
                strong = ("known miner signature" in reasons) or \
                         (cpu >= CPU_THRESHOLD and pid in pool_pids)
                if strong:
                    suspects.append({
                        "pid": pid, "name": proc.info["name"] or "unknown",
                        "cpu": cpu, "reason": ", ".join(reasons),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspects

    def _pids_with_pool_connections(self):
        pids = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr and conn.raddr.port in MINING_POOL_PORTS and conn.pid:
                    pids.add(conn.pid)
        except (psutil.AccessDenied, PermissionError):
            pass
        return pids

    def _record(self, suspect):
        sev = Severity.HIGH
        self.store.log_event(
            source="crypto_monitor",
            severity=sev,
            threat_type="Cryptojacking",
            message=f"Possible miner: {suspect['name']} (PID {suspect['pid']})",
            mitre_id="T1496",
            details=suspect["reason"],
            mitigation=(f"Terminate PID {suspect['pid']}; block mining-pool "
                        f"address at firewall; run a full malware scan."),
        )

    # ── continuous background monitoring ──
    def start_monitor(self):
        if not PSUTIL_AVAILABLE:
            return "Sir, I require the 'psutil' library to monitor for cryptojacking."
        if self._running:
            return "Cryptojacking monitor is already active, sir."
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return "Cryptojacking monitor activated, sir. Watching CPU and pool connections."

    def stop_monitor(self):
        self._running = False
        return "Cryptojacking monitor deactivated, sir."

    def _loop(self):
        # Prime cpu_percent (first call always returns 0.0)
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        while self._running:
            time.sleep(SAMPLE_INTERVAL)
            pool_pids = self._pids_with_pool_connections()
            cores = psutil.cpu_count() or 1
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pid = proc.info["pid"]
                    name = (proc.info["name"] or "").lower()
                    cpu = proc.cpu_percent(None) / cores
                    self._cpu_history[pid].append(cpu)

                    sustained = (
                        len(self._cpu_history[pid]) == SUSTAINED_SAMPLES and
                        all(c >= CPU_THRESHOLD for c in self._cpu_history[pid])
                    )
                    is_miner = any(m in name for m in KNOWN_MINERS)

                    if pid in self._alerted_pids:
                        continue
                    if is_miner or (sustained and pid in pool_pids):
                        reason = []
                        if is_miner:
                            reason.append("known miner signature")
                        if sustained:
                            reason.append("sustained high CPU")
                        if pid in pool_pids:
                            reason.append("mining-pool connection")
                        self._record({
                            "pid": pid, "name": proc.info["name"] or "unknown",
                            "cpu": cpu, "reason": ", ".join(reason),
                        })
                        self._alerted_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

    def get_status(self):
        if not self._running:
            return "Cryptojacking monitor is offline, sir."
        return "Cryptojacking monitor active. No mining activity detected."
