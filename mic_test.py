"""
JARVIS — Microphone & Wake-Word Diagnostic
Isolates the voice path (no browser, no HUD, no spacebar) so we can see
exactly what the listener is doing.

Run:  python mic_test.py
Then speak your wake word ("Jarvis") followed by a short phrase.
Press Ctrl+C to stop.
"""
import time
import config
from core.listener import (
    Listener, PYAUDIO_OK, VOSK_OK, PORCUPINE_OK, OWW_OK,
)

print("\n=== JARVIS Mic Diagnostic ===")
print(f"Configured wake word : {config.WAKE_WORD}")
print(f"Configured engine    : {getattr(config, 'WAKE_ENGINE', 'auto')}")
print("Backends installed   :",
      f"pyaudio={PYAUDIO_OK}", f"vosk={VOSK_OK}",
      f"porcupine={PORCUPINE_OK}", f"openwakeword={OWW_OK}")
print("-" * 40)


def on_state(state, data):
    # Print EVERY state change so we can see the full pipeline
    print(f"  [{state}] {data}")


listener = Listener(wake_word=config.WAKE_WORD, on_state_change=on_state)

print(f"Listener ready? {listener.ready}")
if listener._wake_engine:
    print(f"ACTIVE WAKE ENGINE -> {listener._wake_engine.name}")
else:
    print("NO WAKE ENGINE LOADED — see messages above.")
print("-" * 40)

if not listener.ready:
    print("Listener is NOT ready. The messages above explain why.")
    raise SystemExit(1)

print("Listening now. Say your wake word, then a phrase. Ctrl+C to stop.\n")
listener.start()

try:
    while True:
        cmd = listener.get_command(timeout=1)
        if cmd:
            print(f"\n  >>> RECOGNIZED COMMAND: '{cmd}'\n")
except KeyboardInterrupt:
    print("\nStopping...")
    listener.stop()
