"""
J.A.R.V.I.S — Active Response / Auto-Mitigation
Turns advisory mitigations into real actions — safely.

Capabilities:
  - block_ip / unblock_ip   via Windows Firewall (netsh advfirewall)
  - kill_process            via psutil
  - quarantine_file         move a suspicious file into a quarantine folder

SAFETY (this can affect a live machine, so guards come first):
  - DRY-RUN by default: actions are logged and described but NOT executed
    until you explicitly enable execution (config.AUTO_MITIGATE_EXECUTE).
  - IP guard: refuses to block private/loopback/gateway-like and localhost
    addresses, so you can't lock yourself out of your own network.
  - Process guard: refuses to kill critical system PIDs / its own process.
  - Every action is reversible where possible and logged to the event store.

MITRE (defensive): aligns with response to T1110, T1496, T1486, T1071, etc.
"""

import ipaddress
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from security.event_store import get_store, Severity

try:
    import psutil
    PSUTIL_OK = True
except Exception:
    PSUTIL_OK = False

import config

QUARANTINE_DIR = Path(getattr(config, "BASE_DIR", Path("."))) / "quarantine"

# Never kill these (case-insensitive name match) — would destabilize Windows
_PROTECTED_NAMES = {
    "system", "system idle process", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "smss.exe",
    "svchost.exe", "explorer.exe", "python.exe", "pythonw.exe",
}


def _execute_enabled():
    """Master switch. When False, everything is dry-run (simulated)."""
    return bool(getattr(config, "AUTO_MITIGATE_EXECUTE", False))


class Responder:
    """Performs (or simulates) defensive mitigations."""

    def __init__(self):
        self.store = get_store()
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # ── IP guard ──
    @staticmethod
    def _is_blockable_ip(ip):
        """Return (ok, reason). Refuse anything that could self-lock."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, "not a valid IP address"
        if addr.is_loopback:
            return False, "loopback address"
        if addr.is_private:
            # Private LAN addresses are usually your own network/gateway.
            return False, "private/LAN address (could lock you out)"
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return False, "reserved/multicast address"
        return True, "ok"

    def block_ip(self, ip, reason="JARVIS auto-block"):
        ok, why = self._is_blockable_ip(ip)
        if not ok:
            return f"Refusing to block {ip} — {why}, sir."

        rule = f"JARVIS_block_{ip.replace('.', '_').replace(':', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=in", "action=block", f"remoteip={ip}",
        ]
        return self._run_action(
            description=f"Block inbound traffic from {ip} at the firewall",
            cmd=cmd,
            log=dict(threat_type="Active Response", mitre_id="M1037",
                     message=f"Firewall block applied to {ip}",
                     mitigation=f"Reason: {reason}. Reverse with unblock_ip."),
        )

    def unblock_ip(self, ip):
        rule = f"JARVIS_block_{ip.replace('.', '_').replace(':', '_')}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
               f"name={rule}"]
        return self._run_action(
            description=f"Remove firewall block for {ip}",
            cmd=cmd,
            log=dict(threat_type="Active Response", mitre_id="M1037",
                     message=f"Firewall block removed for {ip}",
                     mitigation="Manual unblock."),
        )

    def kill_process(self, pid, name_hint=""):
        if not PSUTIL_OK:
            return "Sir, I require 'psutil' to terminate processes."
        try:
            proc = psutil.Process(int(pid))
            pname = (proc.name() or "").lower()
        except Exception as e:
            return f"Cannot access PID {pid}: {e}"

        if pname in _PROTECTED_NAMES:
            return f"Refusing to terminate protected system process '{pname}', sir."
        if int(pid) == os.getpid():
            return "Refusing to terminate my own process, sir."

        if not _execute_enabled():
            self._log_sim(f"Terminate process {pname} (PID {pid})")
            return (f"[SIMULATED] Would terminate {pname} (PID {pid}). "
                    f"Enable AUTO_MITIGATE_EXECUTE to act for real, sir.")
        try:
            proc.terminate()
            proc.wait(timeout=5)
            self.store.log_event(
                source="responder", severity=Severity.HIGH,
                threat_type="Active Response", mitre_id="M1040",
                message=f"Terminated process {pname} (PID {pid})",
                mitigation="Process killed by JARVIS active response.")
            return f"Process {pname} (PID {pid}) terminated, sir."
        except Exception as e:
            return f"Failed to terminate PID {pid}: {e}"

    def quarantine_file(self, filepath):
        src = Path(filepath)
        if not src.exists():
            return f"File not found: {filepath}"
        dest = QUARANTINE_DIR / f"{datetime.now():%Y%m%d_%H%M%S}_{src.name}.quarantine"
        if not _execute_enabled():
            self._log_sim(f"Quarantine {src} -> {dest}")
            return f"[SIMULATED] Would quarantine {src.name}, sir."
        try:
            shutil.move(str(src), str(dest))
            self.store.log_event(
                source="responder", severity=Severity.HIGH,
                threat_type="Active Response", mitre_id="M1040",
                message=f"Quarantined {src.name}",
                mitigation=f"Moved to {dest}. Restore manually if false positive.")
            return f"Quarantined {src.name}, sir."
        except Exception as e:
            return f"Failed to quarantine: {e}"

    # ── Internals ──
    def _run_action(self, description, cmd, log):
        if not _execute_enabled():
            self._log_sim(description, cmd)
            return (f"[SIMULATED] Would: {description}. "
                    f"Enable AUTO_MITIGATE_EXECUTE in config to act for real, sir.")
        if sys.platform != "win32":
            return f"[{description}] requires Windows (netsh). Skipped, sir."
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                self.store.log_event(
                    source="responder", severity=Severity.HIGH, **log)
                return f"Done, sir: {description}."
            return f"Action failed: {result.stderr.strip() or 'unknown error'}"
        except Exception as e:
            return f"Action error: {e}"

    def _log_sim(self, description, cmd=None):
        self.store.log_event(
            source="responder", severity=Severity.INFO,
            threat_type="Active Response (Simulated)", mitre_id=None,
            message=f"[DRY-RUN] {description}",
            mitigation="No action taken — execution disabled.")

    def _log(self, **kw):
        self.store.log_event(source="responder", **kw)


if __name__ == "__main__":
    # Self-test: guards and dry-run behavior (no real actions taken)
    r = Responder()
    print("Public IP blockable check :", r._is_blockable_ip("185.220.101.45"))
    print("Loopback refused          :", r._is_blockable_ip("127.0.0.1"))
    print("Private LAN refused       :", r._is_blockable_ip("192.168.1.1"))
    print("Garbage refused           :", r._is_blockable_ip("not-an-ip"))
    print()
    print("block_ip (public, dry-run):", r.block_ip("185.220.101.45"))
    print("block_ip (private)        :", r.block_ip("192.168.1.10"))
