import os
from google import genai
import config

client = genai.Client(api_key=config.GEMINI_API_KEY)

def transcribe_audio_bytes(wav_bytes):
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=[
                {"mime_type": "audio/wav", "data": wav_bytes},
                "Transcribe this audio exactly. Do not add any extra text or markdown."
            ]
        )
        return response.text
    except Exception as e:
        print(f"Gemini Error: {e}")
        return None

if __name__ == "__main__":
    print("Testing gemini client for STT...")
    # create 1 sec silent wav bytes to test
    import speech_recognition as sr
    audio = sr.AudioData(b'\x00' * 16000, 16000, 2)
    wav_bytes = audio.get_wav_data()
    print("Sending to Gemini...")
    res = transcribe_audio_bytes(wav_bytes)
    print(f"Result: {res}")
