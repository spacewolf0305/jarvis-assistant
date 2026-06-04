# J.A.R.V.I.S. Cybersecurity Assistant 🛡️🤖

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green.svg)

J.A.R.V.I.S. is an advanced, AI-powered cybersecurity voice assistant and Endpoint Detection and Response (EDR) tool designed for Windows environments. Inspired by Iron Man's AI, JARVIS combines natural language processing with powerful local security monitoring tools to act as a personal Security Operations Center (SOC).

## ✨ Key Features

- **🧠 AI Threat Analyst (Gemini Integration)**: Gathers local network telemetry and utilizes Google's Gemini LLM to generate professional, executive-level Cybersecurity Threat Reports.
- **🛡️ Ransomware & File Integrity Monitor**: Uses `watchdog` to actively monitor critical directories for high-frequency modifications and suspicious file extensions, alerting you immediately to ransomware-like behavior.
- **🚨 DDoS & Flood Detection**: Continuously analyzes inbound network connections, tracking SYN states and connection rates to detect and automatically generate firewall rules to block potential DoS/DDoS attacks.
- **🤖 Botnet & C2 Detector**: Scans all active outbound connections against known malicious ports (RATs, Meterpreter, IRC) and identifies unknown processes making unauthorized external connections.
- **🌐 Network & Wi-Fi Security Scanner**: Performs ARP scans to identify devices on the network and analyzes Wi-Fi encryption standards.
- **🎙️ Voice Control & STT/TTS**: Full offline voice recognition using Vosk and natural text-to-speech feedback via pyttsx3.
- **🖥️ Cyber HUD**: A beautiful, real-time web dashboard built with vanilla JS and WebSockets for monitoring system status and executing quick actions.

## 🚀 Prerequisites

- **OS**: Windows 10/11
- **Python**: Python 3.10 or higher
- **Microphone**: Required for voice commands

## 🛠️ Installation

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/spacewolf0305/jarvis-assistant.git
   cd jarvis-assistant
   ```

2. **Install the dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Configure API Keys (Optional but Recommended):**
   Open `config.py` (or set environment variables) and add your keys to enable advanced features:
   - `GEMINI_API_KEY`: Required for the AI Threat Analyst and conversational fallback.
   - `VIRUSTOTAL_API_KEY`: Required for scanning IP addresses and files against VirusTotal.

4. **Download the Offline Voice Model:**
   Download the [Vosk English Model](https://alphacephei.com/vosk/models) (e.g., `vosk-model-small-en-us-0.15`), extract it, and place it in a folder named `model` in the root directory. (Or simply run `python setup_vosk.py` if available).

## 🎮 Usage

Start JARVIS by running the main server script:

```powershell
python jarvis.py
```

Once running, JARVIS will begin listening for your voice commands. You can also open the **Cyber HUD** by navigating your web browser to:
`http://127.0.0.1:8765`

### Example Commands
- *"JARVIS, check for DDoS"* - Analyzes inbound connections for flood attacks.
- *"Scan for bots"* - Checks outbound connections for C2 callbacks.
- *"Enable ransomware shield"* - Activates real-time file integrity monitoring.
- *"Generate a security report"* - Compiles telemetry and uses Gemini to write a Threat Report to your Desktop.
- *"Scan my network"* - Discovers other devices on your local network.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/spacewolf0305/jarvis-assistant/issues).

## 📝 License
This project is licensed under the MIT License.
