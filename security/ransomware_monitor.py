"""
J.A.R.V.I.S — Ransomware / File Integrity Monitor
Uses watchdog to monitor a specific directory for rapid file modifications 
or suspicious file extension changes typical of ransomware encryption.
"""

import os
import time
import threading
from collections import deque
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from security.event_store import get_store, Severity


# Thresholds
MODIFICATIONS_PER_SECOND = 5
TIME_WINDOW_SEC = 2
SUSPICIOUS_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".crypted", ".crypto",
    ".ransom", ".wannacry", ".wncry", ".locky", ".zepto"
}


class RansomwareHandler(FileSystemEventHandler):
    """Handles file system events and detects rapid modifications."""
    def __init__(self, monitor):
        self.monitor = monitor

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.record_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.record_event("created", event.src_path)
            self.monitor.check_extension(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor.record_event("renamed", event.dest_path)
            self.monitor.check_extension(event.dest_path)


class RansomwareMonitor:
    """Monitors a directory for ransomware-like behavior."""

    def __init__(self):
        self.observer = None
        self.event_queue = deque()
        self.lock = threading.Lock()
        self._monitoring = False
        self.target_dir = None
        self.alerts = []
        self.store = get_store()

    def start_monitor(self, path=None):
        """Start monitoring a directory (defaults to User's Documents)."""
        if not WATCHDOG_AVAILABLE:
            return "Sir, I need the 'watchdog' Python library to monitor files. Please install it."

        if self._monitoring:
            return f"Ransomware protection is already active on {self.target_dir}, sir."

        if path is None:
            path = str(Path.home() / "Documents")
            
        if not os.path.exists(path):
            return f"Directory {path} does not exist, sir."

        self.target_dir = path
        self._monitoring = True
        self.alerts.clear()

        event_handler = RansomwareHandler(self)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.target_dir, recursive=True)
        self.observer.start()

        # Start background analyzer
        threading.Thread(target=self._analyze_loop, daemon=True).start()

        return f"Ransomware shield activated, sir. Monitoring {self.target_dir} for unauthorized encryption."

    def stop_monitor(self):
        """Stop monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self._monitoring = False
        return "Ransomware protection deactivated, sir."

    def record_event(self, event_type, path):
        """Record a file event timestamp."""
        with self.lock:
            self.event_queue.append(time.time())

    def check_extension(self, path):
        """Check if a new or renamed file has a ransomware extension."""
        ext = os.path.splitext(path)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            alert = f"CRITICAL: Suspicious file extension '{ext}' detected on {os.path.basename(path)}."
            self.alerts.append(alert)
            self.store.log_event(
                source="ransomware_monitor", severity=Severity.CRITICAL,
                threat_type="Ransomware", mitre_id="T1486",
                message=f"Suspicious encrypted-file extension '{ext}' on {os.path.basename(path)}",
                details=f"Full path: {path}",
                mitigation=("Immediately disconnect this machine from the network, "
                            "do not pay any ransom, and restore affected files from backup."),
            )

    def _analyze_loop(self):
        """Continuously check for high-frequency modifications."""
        while self._monitoring:
            time.sleep(1)
            now = time.time()

            with self.lock:
                # Remove events older than the time window
                while self.event_queue and now - self.event_queue[0] > TIME_WINDOW_SEC:
                    self.event_queue.popleft()

                count = len(self.event_queue)

            if count >= (MODIFICATIONS_PER_SECOND * TIME_WINDOW_SEC):
                alert = f"CRITICAL: Ransomware behavior detected! {count} files modified in {TIME_WINDOW_SEC} seconds."
                if alert not in self.alerts:
                    self.alerts.append(alert)
                    self.store.log_event(
                        source="ransomware_monitor", severity=Severity.CRITICAL,
                        threat_type="Ransomware", mitre_id="T1486",
                        message=f"High-frequency file modification: {count} files in {TIME_WINDOW_SEC}s",
                        details=f"Monitored directory: {self.target_dir}",
                        mitigation=("Disconnect from the network immediately, isolate the host, "
                                    "and restore from a known-good backup. Do not pay the ransom."),
                    )
                # Pause recording briefly to avoid spam
                with self.lock:
                    self.event_queue.clear()

    def get_status(self):
        """Get current status and any alerts."""
        if not self._monitoring:
            return "Ransomware shield is currently offline, sir."

        if self.alerts:
            msg = f"WARNING! {len(self.alerts)} ransomware alerts triggered:\n"
            msg += "\n".join(self.alerts[-3:])
            return msg
            
        return f"Ransomware shield is active on {self.target_dir}. No malicious activity detected."
