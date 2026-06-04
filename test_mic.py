import speech_recognition as sr
import traceback

def test_mic():
    try:
        print("Finding microphone...")
        mic = sr.Microphone()
        print("Microphone found!")
        rec = sr.Recognizer()
        with mic as source:
            print("Adjusting ambient noise...")
            rec.adjust_for_ambient_noise(source, duration=1)
        print("Listening for 3 seconds...")
        with mic as source:
            audio = rec.listen(source, timeout=3, phrase_time_limit=3)
        print("Got audio. Processing with PocketSphinx...")
        text = rec.recognize_sphinx(audio)
        print(f"PocketSphinx says: {text}")
    except Exception as e:
        print(f"MIC ERROR: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_mic()
