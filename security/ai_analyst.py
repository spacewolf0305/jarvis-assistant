"""
J.A.R.V.I.S — AI Security Analyst
Gathers data from all security modules and uses Gemini to generate
a professional Cybersecurity Threat Report.
"""

import os
from datetime import datetime
from pathlib import Path

import config
from commands.ai_brain import AIBrain
from security.connection_monitor import ConnectionMonitor
from security.bot_detector import BotDetector
from security.ddos_monitor import DDoSMonitor


class AIAnalyst:
    def __init__(self):
        self.ai_brain = AIBrain()
        self.conn_monitor = ConnectionMonitor()
        self.bot_detector = BotDetector()
        self.ddos_monitor = DDoSMonitor()

    async def generate_report(self):
        """Gather telemetry and generate a report using Gemini."""
        if not config.GEMINI_API_KEY:
            return (
                "Sir, I require a Gemini API key to perform advanced AI threat analysis. "
                "Please configure one in the settings."
            )

        if not self.ai_brain.client:
            return "AI subsystems are currently offline, sir."

        # 1. Gather Telemetry
        conn_status = self.conn_monitor.get_security_status()
        bot_status = self.bot_detector.scan_for_bots()
        ddos_status = self.ddos_monitor.check_ddos()

        raw_data = f"""
        TIMESTAMP: {datetime.now().isoformat()}
        
        [CONNECTION MONITOR]
        {conn_status}
        
        [BOT/C2 DETECTOR]
        {bot_status}
        
        [DDOS/FLOOD MONITOR]
        {ddos_status}
        """

        prompt = f"""
        You are an elite Cybersecurity SOC Analyst. 
        Analyze the following raw telemetry data from a Windows endpoint.
        
        Raw Data:
        {raw_data}
        
        Write a professional, executive-level "Cybersecurity Threat Report".
        Format it in Markdown. Include:
        1. Executive Summary (overall threat level)
        2. Network Connections Analysis
        3. Malware & Botnet Indicators
        4. DDoS & Flood Assessment
        5. Recommendations / Remediation steps
        """

        try:
            # 2. Call Gemini
            model = self.ai_brain.client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt
            )
            report_markdown = model.text

            # 3. Save to Desktop
            desktop = Path.home() / "Desktop"
            filename = f"JARVIS_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
            filepath = desktop / filename

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_markdown)

            return (
                f"Analysis complete, sir. I have generated a comprehensive Threat Report "
                f"and saved it to your Desktop as '{filename}'. Please review it at your convenience."
            )

        except Exception as e:
            return f"An error occurred during AI analysis, sir: {str(e)}"
