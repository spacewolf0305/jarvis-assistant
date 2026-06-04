import urllib.request
import zipfile
import os

url = "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip"
file_name = "vosk-model.zip"

print(f"Downloading Vosk model from {url}...")
urllib.request.urlretrieve(url, file_name)
print("Download complete. Extracting...")

with zipfile.ZipFile(file_name, 'r') as zip_ref:
    zip_ref.extractall(".")

# The extracted folder is named "vosk-model-small-en-us-0.15"
# Rename it to "model" for speech_recognition to find it easily, or pass the path.
extracted_folder = "vosk-model-small-en-us-0.15"
if os.path.exists("model"):
    import shutil
    shutil.rmtree("model")
os.rename(extracted_folder, "model")
os.remove(file_name)

print("Vosk model successfully setup in 'model' directory!")
