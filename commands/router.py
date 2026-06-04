"""
J.A.R.V.I.S — Command Router
Central dispatcher that parses natural language into intents
and routes to the correct handler.
"""

import re
from commands.app_launcher import AppLauncher
from commands.folder_opener import FolderOpener
from commands.web_commands import WebCommands
from commands.system_control import SystemControl
from commands.info_commands import InfoCommands
from commands.ai_brain import AIBrain
from security.network_scanner import NetworkScanner
from security.port_scanner import PortScanner
from security.breach_checker import BreachChecker
from security.threat_intel import ThreatIntel
from security.password_tools import PasswordTools
from security.wifi_analyzer import WiFiAnalyzer
from security.file_scanner import FileScanner
from security.connection_monitor import ConnectionMonitor
from security.ddos_monitor import DDoSMonitor
from security.bot_detector import BotDetector


class CommandRouter:
    """Routes voice commands to appropriate handlers."""

    def __init__(self, speaker=None, ws_broadcast=None):
        self.speaker = speaker
        self.ws_broadcast = ws_broadcast

        # Initialize all command handlers
        self.app_launcher = AppLauncher()
        self.folder_opener = FolderOpener()
        self.web_commands = WebCommands()
        self.system_control = SystemControl()
        self.info_commands = InfoCommands()
        self.ai_brain = AIBrain()

        # Security handlers
        self.network_scanner = NetworkScanner()
        self.port_scanner = PortScanner()
        self.breach_checker = BreachChecker()
        self.threat_intel = ThreatIntel()
        self.password_tools = PasswordTools()
        self.wifi_analyzer = WiFiAnalyzer()
        self.file_scanner = FileScanner()
        self.connection_monitor = ConnectionMonitor()
        self.ddos_monitor = DDoSMonitor()
        self.bot_detector = BotDetector()

        # Intent patterns — order matters (first match wins)
        self.intent_patterns = [
            # ─── System Control ─────────────────────
            (r"\b(volume up|increase volume|louder)\b", self._handle_volume_up),
            (r"\b(volume down|decrease volume|quieter|softer)\b", self._handle_volume_down),
            (r"\bset volume (?:to )?(\d+)\b", self._handle_set_volume),
            (r"\b(mute|unmute)\b", self._handle_mute),
            (r"\b(lock|lock the screen|lock screen|lock computer)\b", self._handle_lock),
            (r"\b(shutdown|shut down)\b", self._handle_shutdown),
            (r"\b(restart|reboot)\b", self._handle_restart),
            (r"\btake (?:a )?screenshot\b", self._handle_screenshot),

            # ─── Security Operations ────────────────
            (r"\bscan (?:my )?network\b", self._handle_network_scan),
            (r"\bscan ports? (?:on )?(.+)\b", self._handle_port_scan),
            (r"\b(?:check|has) (?:if )?(?:my )?(?:email )?(.+?) (?:been |has been )?breach", self._handle_breach_check),
            (r"\b(?:has )?(?:this )?password (?:been )?breach", self._handle_password_breach),
            (r"\b(?:check|scan|is) (?:this )?(?:ip|ip address) (.+?)(?:\s|$)", self._handle_ip_check),
            (r"\b(?:check|scan|is) (?:this )?url (.+?)(?:\s|$)", self._handle_url_scan),
            (r"\bgenerate (?:a )?(?:secure )?password\b", self._handle_generate_password),
            (r"\b(?:how )?strong (?:is )?(?:this )?password\b", self._handle_password_strength),
            (r"\b(?:check )?wi-?fi (?:security|status)\b", self._handle_wifi_check),
            (r"\bhash (?:this )?file (.+)\b", self._handle_file_hash),
            (r"\b(?:show )?active connections?\b", self._handle_connections),
            (r"\bmonitor connections?\b", self._handle_monitor_connections),
            (r"\bsecurity status\b", self._handle_security_status),

            # ─── DDoS Detection ─────────────────────
            (r"\b(?:check for |am i being )?ddos(?:ed)?(?:\b| status)", self._handle_ddos_check),
            (r"\bmonitor (?:for )?ddos\b", self._handle_ddos_monitor),
            (r"\bflood report\b", self._handle_flood_report),
            (r"\bblock ip (.+?)(?:\s|$)", self._handle_block_ip),

            # ─── Bot / C2 Detection ─────────────────
            (r"\b(?:scan|check) for bots?\b|\bbot scan\b", self._handle_bot_scan),
            (r"\b(?:check|inspect) process (.+?)(?:\s|$)", self._handle_check_process),
            (r"\bsuspicious processes\b", self._handle_suspicious_processes),

            # ─── Web Commands ───────────────────────
            (r"\bsearch (?:on )?youtube (?:for )?(.+)\b", self._handle_youtube_search),
            (r"\bsearch (?:for )?(.+) on youtube\b", self._handle_youtube_search),
            (r"\bplay (.+) on youtube\b", self._handle_youtube_search),
            (r"\bsearch (?:on )?google (?:for )?(.+)\b", self._handle_google_search),
            (r"\bsearch (?:for )?(.+) on google\b", self._handle_google_search),
            (r"\bsearch (?:on )?wikipedia (?:for )?(.+)\b", self._handle_wikipedia_search),
            (r"\bsearch (?:for )?(.+) on wikipedia\b", self._handle_wikipedia_search),
            (r"\bsearch (?:for )?(.+)\b", self._handle_google_search),
            (r"\bopen (?:my )?email\b", self._handle_open_email),
            (r"\bopen (?:website |site )?(?:www\.)?(\S+\.(?:com|org|net|io|dev|co|in))\b", self._handle_open_website),

            # ─── Folder Commands ────────────────────
            (r"\bopen (?:my )?(documents?|downloads?|desktop|pictures?|videos?|music|home)(?: folder)?\b", self._handle_open_folder),
            (r"\bopen folder (.+)\b", self._handle_open_path),

            # ─── App Commands ───────────────────────
            (r"\bclose (.+)\b", self._handle_close_app),
            (r"\b(?:open|launch|start|run) (.+)\b", self._handle_open_app),

            # ─── Info Commands ──────────────────────
            (r"\bwhat(?:'s| is) the time\b|what time is it", self._handle_time),
            (r"\bwhat(?:'s| is) (?:today(?:'s)?|the) date\b", self._handle_date),
            (r"\bbattery(?: status| level)?\b", self._handle_battery),
            (r"\bsystem status\b", self._handle_system_status),
            (r"\b(?:what(?:'s| is) )?my ip(?: address)?\b", self._handle_ip_address),
            (r"\btime\b", self._handle_time),
            (r"\bdate\b", self._handle_date),
        ]

    async def route(self, command):
        """Parse and route a voice command. Returns response text."""
        command_lower = command.lower().strip()

        # Try pattern matching first
        for pattern, handler in self.intent_patterns:
            match = re.search(pattern, command_lower)
            if match:
                try:
                    result = await handler(match, command_lower)
                    return result
                except Exception as e:
                    error_msg = f"Sorry sir, I encountered an error: {str(e)}"
                    return error_msg

        # Fallback to AI brain for unrecognized commands
        try:
            result = await self.ai_brain.ask(command)
            return result
        except Exception as e:
            return f"I apologize, sir. My AI systems are experiencing issues: {str(e)}"

    # ─── System Control Handlers ──────────────────────

    async def _handle_volume_up(self, match, command):
        return self.system_control.volume_up()

    async def _handle_volume_down(self, match, command):
        return self.system_control.volume_down()

    async def _handle_set_volume(self, match, command):
        level = int(match.group(1))
        return self.system_control.set_volume(level)

    async def _handle_mute(self, match, command):
        return self.system_control.toggle_mute()

    async def _handle_lock(self, match, command):
        return self.system_control.lock_screen()

    async def _handle_shutdown(self, match, command):
        return self.system_control.shutdown()

    async def _handle_restart(self, match, command):
        return self.system_control.restart()

    async def _handle_screenshot(self, match, command):
        return self.system_control.take_screenshot()

    # ─── Security Handlers ────────────────────────────

    async def _handle_network_scan(self, match, command):
        return await self.network_scanner.scan()

    async def _handle_port_scan(self, match, command):
        target = match.group(1).strip()
        return await self.port_scanner.scan(target)

    async def _handle_breach_check(self, match, command):
        email = match.group(1).strip()
        return await self.breach_checker.check_email(email)

    async def _handle_password_breach(self, match, command):
        return "Sir, please type the password in the HUD settings panel for security. I won't ask you to say it aloud."

    async def _handle_ip_check(self, match, command):
        ip = match.group(1).strip()
        return await self.threat_intel.check_ip(ip)

    async def _handle_url_scan(self, match, command):
        url = match.group(1).strip()
        return await self.threat_intel.scan_url(url)

    async def _handle_generate_password(self, match, command):
        return self.password_tools.generate()

    async def _handle_password_strength(self, match, command):
        return "Sir, please type the password in the HUD for analysis. For security, I don't process passwords by voice."

    async def _handle_wifi_check(self, match, command):
        return self.wifi_analyzer.check()

    async def _handle_file_hash(self, match, command):
        filepath = match.group(1).strip()
        return await self.file_scanner.scan(filepath)

    async def _handle_connections(self, match, command):
        return self.connection_monitor.list_connections()

    async def _handle_monitor_connections(self, match, command):
        return self.connection_monitor.start_monitoring()

    async def _handle_security_status(self, match, command):
        return self.connection_monitor.get_security_status()

    # ─── DDoS Handlers ────────────────────────────────

    async def _handle_ddos_check(self, match, command):
        return self.ddos_monitor.check_ddos()

    async def _handle_ddos_monitor(self, match, command):
        return self.ddos_monitor.start_monitor()

    async def _handle_flood_report(self, match, command):
        return self.ddos_monitor.get_flood_report()

    async def _handle_block_ip(self, match, command):
        ip = match.group(1).strip()
        return self.ddos_monitor.block_ip(ip)

    # ─── Bot / C2 Handlers ────────────────────────────

    async def _handle_bot_scan(self, match, command):
        return self.bot_detector.scan_for_bots()

    async def _handle_check_process(self, match, command):
        identifier = match.group(1).strip()
        return self.bot_detector.check_process(identifier)

    async def _handle_suspicious_processes(self, match, command):
        return self.bot_detector.list_suspicious_processes()

    # ─── Web Handlers ─────────────────────────────────

    async def _handle_youtube_search(self, match, command):
        query = match.group(1).strip()
        return self.web_commands.youtube_search(query)

    async def _handle_google_search(self, match, command):
        query = match.group(1).strip()
        return self.web_commands.google_search(query)

    async def _handle_wikipedia_search(self, match, command):
        query = match.group(1).strip()
        return self.web_commands.wikipedia_search(query)

    async def _handle_open_email(self, match, command):
        return self.web_commands.open_email()

    async def _handle_open_website(self, match, command):
        site = match.group(1).strip()
        return self.web_commands.open_website(site)

    # ─── Folder Handlers ──────────────────────────────

    async def _handle_open_folder(self, match, command):
        folder_name = match.group(1).strip().rstrip("s")  # "documents" → "document"
        return self.folder_opener.open_shortcut(folder_name)

    async def _handle_open_path(self, match, command):
        path = match.group(1).strip()
        return self.folder_opener.open_path(path)

    # ─── App Handlers ─────────────────────────────────

    async def _handle_open_app(self, match, command):
        app_name = match.group(1).strip()
        # Filter out web/folder commands that might match
        skip_words = ["youtube", "google", "wikipedia", "email", "folder", "my "]
        for word in skip_words:
            if app_name.startswith(word):
                return None
        return self.app_launcher.open(app_name)

    async def _handle_close_app(self, match, command):
        app_name = match.group(1).strip()
        return self.app_launcher.close(app_name)

    # ─── Info Handlers ────────────────────────────────

    async def _handle_time(self, match, command):
        return self.info_commands.get_time()

    async def _handle_date(self, match, command):
        return self.info_commands.get_date()

    async def _handle_battery(self, match, command):
        return self.info_commands.get_battery()

    async def _handle_system_status(self, match, command):
        return self.info_commands.get_system_status()

    async def _handle_ip_address(self, match, command):
        return self.info_commands.get_ip()
