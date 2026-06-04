"""
J.A.R.V.I.S — Voice Speaker
Text-to-speech engine using pyttsx3 (fully offline).
"""

import threading
import queue


class Speaker:
    """Text-to-speech engine with queue management."""

    def __init__(self, rate=175, volume=1.0, preferred_gender="male", on_state_change=None):
        self.on_state_change = on_state_change
        self._speech_queue = queue.Queue()
        self._running = True
        self._engine = None
        self._rate = rate
        self._volume = volume
        self._preferred_gender = preferred_gender
        self._tts_available = True

        # Run TTS engine in its own thread (pyttsx3 requirement)
        self._thread = threading.Thread(target=self._engine_loop, daemon=True)
        self._thread.start()

    def _init_engine(self):
        """Initialize the pyttsx3 engine (must be done in the engine thread)."""
        # COM must be initialized in this thread for SAPI5
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            # pythoncom not available, try ctypes fallback
            try:
                import ctypes
                ctypes.windll.ole32.CoInitialize(None)
            except Exception:
                pass

        import pyttsx3
        engine = pyttsx3.init()
        engine.setProperty("rate", self._rate)
        engine.setProperty("volume", self._volume)

        # Try to select preferred voice
        voices = engine.getProperty("voices")
        selected = None

        for voice in voices:
            name_lower = voice.name.lower()
            if self._preferred_gender == "male" and ("david" in name_lower or "male" in name_lower):
                selected = voice
                break
            elif self._preferred_gender == "female" and ("zira" in name_lower or "female" in name_lower):
                selected = voice
                break

        if selected:
            engine.setProperty("voice", selected.id)
        elif voices:
            engine.setProperty("voice", voices[0].id)

        return engine

    def _notify_state(self, state, data=""):
        """Send state updates to the HUD."""
        if self.on_state_change:
            self.on_state_change(state, data)

    def _engine_loop(self):
        """TTS engine loop — processes speech queue."""
        try:
            self._engine = self._init_engine()
        except Exception as e:
            print(f"  [WARNING] TTS engine failed to initialize: {e}")
            print(f"  [WARNING] JARVIS will work without voice output.")
            self._tts_available = False
            # Still drain the queue so callers don't block
            while self._running:
                try:
                    text = self._speech_queue.get(timeout=0.5)
                    if text is None:
                        break
                except queue.Empty:
                    continue
            return

        while self._running:
            try:
                text = self._speech_queue.get(timeout=0.5)
                if text is None:
                    break

                self._notify_state("speaking", text)
                self._engine.say(text)
                self._engine.runAndWait()
                self._notify_state("idle", "")

            except queue.Empty:
                continue
            except Exception as e:
                self._notify_state("error", f"TTS Error: {e}")

    def speak(self, text):
        """Add text to speech queue."""
        if text and self._running:
            self._speech_queue.put(text)

    def stop(self):
        """Stop the speaker."""
        self._running = False
        self._speech_queue.put(None)  # Signal to exit
        if self._thread:
            self._thread.join(timeout=3)

    @property
    def is_speaking(self):
        """Check if there are items in the speech queue."""
        return not self._speech_queue.empty()

