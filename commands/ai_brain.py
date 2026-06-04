"""
J.A.R.V.I.S — AI Brain
Gemini LLM integration for conversational fallback.
"""

import config

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    try:
        import google.generativeai as genai_legacy
        GENAI_AVAILABLE = True
    except ImportError:
        GENAI_AVAILABLE = False


SYSTEM_PROMPT = """You are JARVIS, an advanced AI assistant inspired by the AI from Iron Man.

Personality:
- Polite, witty, and slightly formal (British butler style)
- Address the user as "sir" occasionally
- Be concise — your responses will be spoken aloud, so keep them under 3 sentences
- Be helpful and knowledgeable
- You have cybersecurity expertise — you can explain security concepts clearly
- When you don't know something, say so honestly

Context:
- You are running on the user's Windows PC
- You can control their computer (open apps, search web, manage files)
- You have cybersecurity tools (network scanner, breach checker, threat intel)
- Keep responses SHORT and natural for voice — no bullet points, no markdown
- Current time will be provided in the conversation
"""


class AIBrain:
    """Gemini LLM integration for conversational AI."""

    def __init__(self):
        self.client = None
        self.chat = None
        self.history = []

        if GENAI_AVAILABLE and config.GEMINI_API_KEY:
            try:
                self.client = genai.Client(api_key=config.GEMINI_API_KEY)
                self.chat = self.client.chats.create(
                    model=config.GEMINI_MODEL,
                    config={"system_instruction": SYSTEM_PROMPT}
                )
            except Exception:
                self.client = None

    async def ask(self, question):
        """Ask the AI a question and get a response."""
        from datetime import datetime

        # Add time context
        time_context = f"[Current time: {datetime.now().strftime('%I:%M %p, %A %B %d, %Y')}] "

        # Try Gemini API
        if self.chat:
            try:
                response = self.chat.send_message(time_context + question)
                text = response.text.strip()
                return text
            except Exception as e:
                return self._offline_response(question)

        # Offline fallback
        return self._offline_response(question)

    def _offline_response(self, question):
        """Basic offline responses when Gemini is not available."""
        q = question.lower()

        if any(word in q for word in ["hello", "hi", "hey"]):
            return "Hello, sir. How may I assist you?"
        elif "how are you" in q:
            return "I'm functioning within normal parameters, sir. Thank you for asking."
        elif "thank" in q:
            return "You're welcome, sir. Always happy to help."
        elif "who are you" in q or "what are you" in q:
            return "I am JARVIS, your cybersecurity AI voice assistant. I can control your computer, scan networks, check for breaches, and much more."
        elif any(word in q for word in ["joke", "funny"]):
            return "Why do programmers prefer dark mode? Because light attracts bugs, sir."
        elif "bye" in q or "goodbye" in q or "good night" in q:
            return "Goodbye, sir. JARVIS will be here when you need me."
        else:
            if config.GEMINI_API_KEY:
                return "I apologize, sir. I'm having trouble connecting to my AI systems. Please check your internet connection."
            else:
                return "Sir, my AI capabilities are limited in offline mode. Set up a Gemini API key in the settings for full conversational abilities."
