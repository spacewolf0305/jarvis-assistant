"""
J.A.R.V.I.S — Alert Manager
Real-time dispatch of high-severity detections.

Detectors already write to the SQLite event store. This manager polls the
store for NEW events at or above an alert threshold and, for each one:

  1. Speaks it aloud through JARVIS ("Warning, sir. ...")
  2. Raises a native desktop notification (plyer / win10toast if available)
  3. Hands it back to the caller so the server can push it over WebSocket

Polling (rather than hooking every detector) keeps this decoupled: any
current or future detector that logs to the store gets alerting for free.
All optional imports are guarded so the module always loads.
"""

import threading

from security.event_store import get_store, Severity, mitre_label

# ── Guarded desktop-notification backends ────────────────────
_NOTIFY_BACKEND = None
try:
    from plyer import notification as _plyer_notification
    _NOTIFY_BACKEND = "plyer"
except Exception:
    try:
        from win10toast import ToastNotifier
        _toaster = ToastNotifier()
        _NOTIFY_BACKEND = "win10toast"
    except Exception:
        _NOTIFY_BACKEND = None


# Spoken urgency prefix per severity
_SPOKEN_PREFIX = {
    Severity.CRITICAL: "Critical alert, sir.",
    Severity.HIGH: "Warning, sir.",
    Severity.MEDIUM: "Heads up, sir.",
    Severity.LOW: "A minor note, sir.",
    Severity.INFO: "For your information, sir.",
}


class AlertManager:
    """Dispatches new high-severity events to voice, desktop, and HUD."""

    def __init__(self, speaker=None, min_severity=Severity.HIGH, speak=True):
        self.store = get_store()
        self.speaker = speaker
        self.min_severity = min_severity
        self.speak_enabled = speak
        self._last_id = self._current_max_id()
        self._lock = threading.Lock()

    def _current_max_id(self):
        events = self.store.get_events(limit=1)
        return events[0]["id"] if events else 0

    def check_new_alerts(self):
        """Find events newer than the last check; dispatch and return them.

        Returns a list of dispatched event dicts (so the server can broadcast
        them to the HUD). Safe to call on a timer from the server loop.
        """
        with self._lock:
            events = self.store.get_events(
                min_severity=self.min_severity, limit=50
            )
            # Only those newer than what we've already alerted on
            new_events = [e for e in events if e["id"] > self._last_id]
            if new_events:
                self._last_id = max(e["id"] for e in new_events)

        # Oldest first so alerts fire in the order they occurred
        new_events.reverse()
        for ev in new_events:
            self._dispatch(ev)
        return new_events

    def _dispatch(self, ev):
        sev = Severity(ev["severity"])
        title = f"JARVIS — {ev['threat_type']} [{sev.label}]"
        body = ev["message"]

        # 1. Speak
        if self.speak_enabled and self.speaker:
            prefix = _SPOKEN_PREFIX.get(sev, "")
            try:
                self.speaker.speak(f"{prefix} {ev['message']}")
            except Exception:
                pass

        # 2. Desktop notification
        self._desktop_notify(title, body)

    @staticmethod
    def _desktop_notify(title, body):
        try:
            if _NOTIFY_BACKEND == "plyer":
                _plyer_notification.notify(
                    title=title, message=body, app_name="JARVIS", timeout=8
                )
            elif _NOTIFY_BACKEND == "win10toast":
                _toaster.show_toast(title, body, duration=8, threaded=True)
        except Exception:
            pass

    @property
    def notify_backend(self):
        return _NOTIFY_BACKEND or "none (install plyer for desktop alerts)"


# Module-level singleton
_manager = None


def get_alert_manager(speaker=None):
    global _manager
    if _manager is None:
        _manager = AlertManager(speaker=speaker)
    elif speaker is not None:
        _manager.speaker = speaker
    return _manager
