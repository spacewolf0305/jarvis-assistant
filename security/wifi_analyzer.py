"""
J.A.R.V.I.S — Wi-Fi Analyzer
Check current Wi-Fi security and audit saved networks.
"""

import subprocess
import re


class WiFiAnalyzer:
    """Analyze Wi-Fi security using Windows netsh commands."""

    def check(self):
        """Check current Wi-Fi connection and saved network security."""
        current = self._get_current_wifi()
        saved = self._get_saved_networks()

        msg = current

        # Check for insecure saved networks
        insecure = [n for n in saved if n["auth"] in ("Open", "WEP", "")]
        if insecure:
            msg += f" Warning: I found {len(insecure)} saved networks with weak or no security: "
            msg += ", ".join(f"'{n['name']}' ({n['auth'] or 'Open'})" for n in insecure[:3])
            msg += ". I recommend removing these networks."

        return msg

    def _get_current_wifi(self):
        """Get current Wi-Fi connection details."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode != 0:
                return "I couldn't access the Wi-Fi interface, sir."

            output = result.stdout

            # Parse the output
            ssid = self._extract_field(output, r"SSID\s*:\s*(.+)")
            auth = self._extract_field(output, r"Authentication\s*:\s*(.+)")
            cipher = self._extract_field(output, r"Cipher\s*:\s*(.+)")
            signal = self._extract_field(output, r"Signal\s*:\s*(\d+)%")
            band = self._extract_field(output, r"Band\s*:\s*(.+)")

            if not ssid or ssid == "":
                return "You're not connected to any Wi-Fi network, sir."

            msg = f"Connected to '{ssid}'"

            if auth:
                msg += f" using {auth}"
                if "WPA3" in auth:
                    msg += " — excellent security"
                elif "WPA2" in auth:
                    msg += " — good security, though WPA3 is recommended"
                elif "WPA" in auth:
                    msg += " — WARNING: WPA is outdated, upgrade to WPA2 or WPA3"
                elif "WEP" in auth:
                    msg += " — CRITICAL: WEP is broken and insecure. Change immediately"
                elif "Open" in auth:
                    msg += " — CRITICAL: No encryption. Your traffic is visible to everyone"

            if cipher:
                msg += f". Cipher: {cipher}"

            if signal:
                msg += f". Signal strength: {signal}%"

            msg += "."
            return msg

        except Exception as e:
            return f"Error checking Wi-Fi: {str(e)}"

    def _get_saved_networks(self):
        """Get all saved Wi-Fi profiles and their security."""
        networks = []
        try:
            # Get profile names
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True, text=True, timeout=5
            )

            profile_names = re.findall(
                r"All User Profile\s*:\s*(.+)",
                result.stdout
            )

            for name in profile_names:
                name = name.strip()
                # Get each profile's security details
                detail = subprocess.run(
                    ["netsh", "wlan", "show", "profile", f"name={name}"],
                    capture_output=True, text=True, timeout=5
                )

                auth = self._extract_field(detail.stdout, r"Authentication\s*:\s*(.+)")
                networks.append({
                    "name": name,
                    "auth": auth.strip() if auth else ""
                })

        except Exception:
            pass

        return networks

    def _extract_field(self, text, pattern):
        """Extract a field value using regex."""
        match = re.search(pattern, text)
        return match.group(1).strip() if match else ""
