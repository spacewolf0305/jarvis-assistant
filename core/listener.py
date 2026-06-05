"""
J.A.R.V.I.S — Voice Listener (always-on, hands-free)

Two-stage pipeline so you can talk to JARVIS directly — no spacebar:

  Stage 1  Wake word    A lightweight always-on engine listens ONLY for
                        "Jarvis". Engine is auto-selected by accuracy:
                          1. Porcupine    (best; needs a free access key)
                          2. openWakeWord (open-source; no key)
                          3. Vosk keyword (fallback; reuses bundled model)
  Stage 2  Command STT   Once woken, the bundled Vosk model transcribes the
                        spoken command until you stop talking, then emits it.

Runs on a background thread, so it keeps listening while JARVIS does other
work and while the window is unfocused. All heavy/audio imports are guarded
so this module always loads; if a backend is missing JARVIS reports it
clearly instead of crashing.
"""

import json
import threading
import time
import queue
from pathlib import Path

import config

# ── Guarded optional imports ─────────────────────────────────
try:
    import pyaudio
    PYAUDIO_OK = True
except Exception:
    PYAUDIO_OK = False

try:
    from vosk import Model as VoskModel, KaldiRecognizer
    VOSK_OK = True
except Exception:
    VOSK_OK = False

try:
    import pvporcupine
    PORCUPINE_OK = True
except Exception:
    PORCUPINE_OK = False

try:
    import numpy as np
    import openwakeword
    from openwakeword.model import Model as OWWModel
    OWW_OK = True
except Exception:
    OWW_OK = False


# Audio capture constants (16 kHz mono is what Vosk + wake engines expect)
SAMPLE_RATE = 16000
FRAME_LENGTH = 512          # samples per read
CMD_SILENCE_TIMEOUT = 0.7   # seconds of silence that ends a command (lower = snappier)
CMD_MAX_SECONDS = 8         # hard cap on a single command utterance


# ─────────────────────────────────────────────────────────────
#  Wake-word engines (each exposes .process(pcm_bytes) -> bool)
# ─────────────────────────────────────────────────────────────
class _PorcupineWake:
    name = "porcupine"

    def __init__(self, wake_word, access_key):
        # Porcupine ships several built-in keywords incl. "jarvis"
        keyword = wake_word if wake_word in pvporcupine.KEYWORDS else "jarvis"
        self._pp = pvporcupine.create(access_key=access_key, keywords=[keyword])
        self.frame_length = self._pp.frame_length
        self.sample_rate = self._pp.sample_rate

    def process(self, pcm_bytes):
        pcm = np.frombuffer(pcm_bytes, dtype=np.int16)
        return self._pp.process(pcm) >= 0

    def close(self):
        try:
            self._pp.delete()
        except Exception:
            pass


class _OpenWakeWordWake:
    name = "openwakeword"
    frame_length = FRAME_LENGTH
    sample_rate = SAMPLE_RATE

    def __init__(self, wake_word):
        # Uses pre-trained models; "hey jarvis" is a bundled model name
        try:
            self._model = OWWModel(wakeword_models=["hey_jarvis"])
        except Exception:
            self._model = OWWModel()  # load all defaults
        self._threshold = 0.5

    def process(self, pcm_bytes):
        pcm = np.frombuffer(pcm_bytes, dtype=np.int16)
        preds = self._model.predict(pcm)
        return any(score >= self._threshold for score in preds.values())

    def close(self):
        pass


class _VoskKeywordWake:
    """Fallback: run Vosk continuously and look for the wake word in partials."""
    name = "vosk-keyword"
    frame_length = FRAME_LENGTH
    sample_rate = SAMPLE_RATE

    def __init__(self, wake_word, model):
        self._rec = KaldiRecognizer(model, SAMPLE_RATE)
        self._wake = wake_word.lower()

    def process(self, pcm_bytes):
        if self._rec.AcceptWaveform(pcm_bytes):
            text = json.loads(self._rec.Result()).get("text", "")
        else:
            text = json.loads(self._rec.PartialResult()).get("partial", "")
        if self._wake in text.lower():
            self._rec.Reset()
            return True
        return False

    def close(self):
        pass


# ─────────────────────────────────────────────────────────────
#  Listener
# ─────────────────────────────────────────────────────────────
class Listener:
    """Always-on, hands-free voice listener with wake-word activation."""

    def __init__(self, wake_word=None, on_command=None, on_state_change=None):
        self.wake_word = (wake_word or config.WAKE_WORD).lower()
        self.on_command = on_command
        self.on_state_change = on_state_change

        self._running = False
        self._thread = None
        self._push_to_talk_flag = False
        self.command_queue = queue.Queue()
        # Tunable end-of-command silence (config overrides the default)
        self._silence_timeout = getattr(config, "CMD_SILENCE_TIMEOUT", CMD_SILENCE_TIMEOUT)

        self._pa = None
        self._stream = None
        self._wake_engine = None
        self._vosk_model = None
        self._cmd_rec = None

        self._init_backends()

    # ── State helper ──
    def _notify(self, state, data=""):
        if self.on_state_change:
            try:
                self.on_state_change(state, data)
            except Exception:
                pass

    # ── Backend selection ──
    def _init_backends(self):
        """Load the Vosk model (for commands) and pick the best wake engine."""
        if not PYAUDIO_OK:
            self._notify("error", "PyAudio not installed — microphone capture unavailable.")
            return
        if not VOSK_OK:
            self._notify("error", "Vosk not installed — command recognition unavailable.")
            return

        # Vosk model for command transcription (and fallback wake word)
        model_path = getattr(config, "VOSK_MODEL_PATH", str(config.BASE_DIR / "model"))
        if not Path(model_path).exists():
            self._notify("error", f"Vosk model not found at {model_path}.")
            return
        self._vosk_model = VoskModel(model_path)
        self._cmd_rec = KaldiRecognizer(self._vosk_model, SAMPLE_RATE)

        # Pick wake engine
        choice = getattr(config, "WAKE_ENGINE", "auto").lower()
        key = getattr(config, "PORCUPINE_ACCESS_KEY", "")

        def try_porcupine():
            if PORCUPINE_OK and key:
                return _PorcupineWake(self.wake_word, key)
            return None

        def try_oww():
            return _OpenWakeWordWake(self.wake_word) if OWW_OK else None

        def try_vosk():
            return _VoskKeywordWake(self.wake_word, self._vosk_model)

        order = {
            "auto": [try_porcupine, try_oww, try_vosk],
            "porcupine": [try_porcupine],
            "openwakeword": [try_oww],
            "vosk": [try_vosk],
        }.get(choice, [try_porcupine, try_oww, try_vosk])

        for factory in order:
            try:
                engine = factory()
                if engine:
                    self._wake_engine = engine
                    break
            except Exception:
                continue

        if self._wake_engine:
            self._notify("ready", f"Wake engine: {self._wake_engine.name}")
        else:
            self._notify("error", "No wake-word engine available.")

    @property
    def ready(self):
        return bool(self._wake_engine and self._cmd_rec and PYAUDIO_OK)

    # ── Audio stream ──
    def _open_stream(self, frames_per_buffer):
        self._pa = pyaudio.PyAudio()
        self._stream = self._pa.open(
            rate=SAMPLE_RATE, channels=1, format=pyaudio.paInt16,
            input=True, frames_per_buffer=frames_per_buffer,
        )

    def _close_stream(self):
        try:
            if self._stream:
                self._stream.stop_stream()
                self._stream.close()
            if self._pa:
                self._pa.terminate()
        except Exception:
            pass
        self._stream = None
        self._pa = None

    # ── Main loop ──
    def _loop(self):
        frame_len = getattr(self._wake_engine, "frame_length", FRAME_LENGTH)
        try:
            self._open_stream(frame_len)
        except Exception as e:
            self._notify("error", f"Could not open microphone: {e}")
            return

        self._notify("listening", f"Listening for '{self.wake_word}'...")
        while self._running:
            try:
                pcm = self._stream.read(frame_len, exception_on_overflow=False)

                woke = self._push_to_talk_flag or self._wake_engine.process(pcm)
                if woke:
                    self._push_to_talk_flag = False
                    self._notify("wake", "Wake word detected")
                    command = self._capture_command()
                    if command:
                        self._notify("command_received", command)
                        self.command_queue.put(command)
                        if self.on_command:
                            self.on_command(command)
                    self._notify("listening", f"Listening for '{self.wake_word}'...")
            except Exception as e:
                self._notify("error", str(e))
                time.sleep(0.5)

        self._close_stream()

    def _capture_command(self):
        """After wake, transcribe one spoken command via Vosk."""
        self._notify("processing", "Listening for your command...")
        self._cmd_rec.Reset()
        start = time.time()
        last_voice = time.time()
        collected = ""

        while self._running and (time.time() - start) < CMD_MAX_SECONDS:
            pcm = self._stream.read(FRAME_LENGTH, exception_on_overflow=False)
            if self._cmd_rec.AcceptWaveform(pcm):
                text = json.loads(self._cmd_rec.Result()).get("text", "").strip()
                if text:
                    collected = (collected + " " + text).strip()
                    last_voice = time.time()
            else:
                partial = json.loads(self._cmd_rec.PartialResult()).get("partial", "").strip()
                if partial:
                    last_voice = time.time()
            # End of utterance: enough silence after we heard something
            if collected and (time.time() - last_voice) >= self._silence_timeout:
                break

        # Strip an accidental leading wake word ("jarvis open chrome" -> "open chrome")
        if collected.lower().startswith(self.wake_word):
            collected = collected[len(self.wake_word):].lstrip(", ").strip()
        return collected

    # ── Public control ──
    def start(self):
        if self._running:
            return
        if not self.ready:
            self._notify("error", "Listener not ready — check microphone/model/engine.")
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._notify("listening", "JARVIS is listening")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        if self._wake_engine:
            self._wake_engine.close()
        self._notify("offline", "Listener stopped")

    def push_to_talk(self):
        """Optional manual override — skip the wake word for one command."""
        self._push_to_talk_flag = True
        self._notify("listening", "Listening (manual)...")

    def get_command(self, timeout=None):
        try:
            return self.command_queue.get(timeout=timeout)
        except queue.Empty:
            return None
