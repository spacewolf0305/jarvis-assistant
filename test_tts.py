import sys
import traceback

def test_tts():
    try:
        import pythoncom
        pythoncom.CoInitialize()
        print("CoInitialize success")
    except Exception as e:
        print(f"pythoncom fail: {e}")
        
    try:
        import pyttsx3
        print("Initializing pyttsx3...")
        engine = pyttsx3.init()
        print("pyttsx3 initialized!")
        
        voices = engine.getProperty("voices")
        print(f"Found {len(voices)} voices")
        
        for v in voices:
            print(f"- {v.name}")
            
        print("Trying to say test...")
        engine.say("Testing voice")
        engine.runAndWait()
        print("Done!")
    except Exception as e:
        print(f"TTS Error: {type(e).__name__} - {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_tts()
