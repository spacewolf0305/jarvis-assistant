"""
J.A.R.V.I.S — Voice Listener
Continuous microphone listener with wake word detection.
Uses SpeechRecognition library with Google free STT.
"""

import speech_recognition as sr
import threading
import time
import queue


class Listener:
    """Continuous voice listener with wake word detection."""

    def __init__(self, wake_word="jarvis", on_command=None, on_state_change=None):
        self.recognizer = sr.Recognizer()
        self.microphone = sr.Microphone()
        self.wake_word = wake_word.lower()
        self.on_command = on_command  # Callback: (command_text) -> None
        self.on_state_change = on_state_change  # Callback: (state, data) -> None
        self._running = False
        self._thread = None
        self._push_to_talk = False
        self.command_queue = queue.Queue()

        # Adjust for ambient noise on init
        with self.microphone as source:
            self._notify_state("calibrating", "Adjusting for ambient noise...")
            self.recognizer.adjust_for_ambient_noise(source, duration=1)
            self._notify_state("ready", "Microphone calibrated")

    def _notify_state(self, state, data=""):
        """Send state updates to the HUD via callback."""
        if self.on_state_change:
            self.on_state_change(state, data)

    def _process_audio(self, audio):
        """Convert audio to text and check for wake word."""
        try:
            self._notify_state("processing", "Recognizing speech...")
            # Use completely offline PocketSphinx engine
            text = self.recognizer.recognize_sphinx(audio).lower().strip()
            
            if not text:
                return
                
            self._notify_state("transcript", text)

            # Check for wake word or push-to-talk mode
            if self._push_to_talk:
                self._push_to_talk = False
                command = text
            elif text.startswith(self.wake_word):
                # Strip wake word: "jarvis open chrome" → "open chrome"
                command = text[len(self.wake_word):].strip()
                # Handle comma/space after wake word
                if command.startswith(","):
                    command = command[1:].strip()
            else:
                # No wake word detected, ignore
                return

            if command:
                self._notify_state("command_received", command)
                self.command_queue.put(command)
                if self.on_command:
                    self.on_command(command)

        except sr.UnknownValueError:
            self._notify_state("idle", "")
        except sr.RequestError as e:
            self._notify_state("error", f"Speech service error: {e}")

    def _listen_loop(self):
        """Main listening loop — runs in background thread."""
        while self._running:
            try:
                with self.microphone as source:
                    self._notify_state("listening", "Listening...")
                    audio = self.recognizer.listen(
                        source,
                        timeout=None,
                        phrase_time_limit=10
                    )
                self._process_audio(audio)
            except sr.WaitTimeoutError:
                continue
            except Exception as e:
                self._notify_state("error", str(e))
                time.sleep(1)

    def start(self):
        """Start listening in background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        self._notify_state("listening", "JARVIS is listening")

    def stop(self):
        """Stop listening."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._notify_state("offline", "Listener stopped")

    def push_to_talk(self):
        """Enable one-shot listen without wake word."""
        self._push_to_talk = True
        self._notify_state("listening", "Listening (push-to-talk)...")

    def get_command(self, timeout=None):
        """Get next command from queue (blocking)."""
        try:
            return self.command_queue.get(timeout=timeout)
        except queue.Empty:
            return None
