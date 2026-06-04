"""
J.A.R.V.I.S — Breach Checker
Check if emails/passwords have been compromised using HaveIBeenPwned.
Uses k-Anonymity for password checks (safe — only sends first 5 chars of SHA1).
"""

import hashlib
import asyncio
import requests


HIBP_API = "https://haveibeenpwned.com/api/v3"
HIBP_PASSWORD_API = "https://api.pwnedpasswords.com/range/"


class BreachChecker:
    """Check for email and password breaches via HaveIBeenPwned."""

    async def check_email(self, email):
        """Check if an email has been in any known data breaches."""
        try:
            headers = {
                "User-Agent": "JARVIS-Security-Assistant",
            }

            response = await asyncio.to_thread(
                requests.get,
                f"{HIBP_API}/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=10
            )

            if response.status_code == 200:
                breaches = response.json()
                return self._format_breach_results(email, breaches)
            elif response.status_code == 404:
                return f"Good news, sir. The email {email} has not been found in any known data breaches."
            elif response.status_code == 401:
                # API key required for email lookups — use alternative approach
                return await self._check_email_alternative(email)
            else:
                return f"I received an unexpected response from the breach database. Status: {response.status_code}"

        except Exception as e:
            return f"Error checking breaches: {str(e)}"

    async def _check_email_alternative(self, email):
        """Alternative breach check when API key is not available."""
        return (
            f"Sir, the HaveIBeenPwned email lookup requires an API key for direct queries. "
            f"You can check manually at https://haveibeenpwned.com. "
            f"However, I can still check passwords for breaches using the k-Anonymity model, which doesn't require an API key."
        )

    async def check_password(self, password):
        """Check if a password has been in any known breaches.
        Uses k-Anonymity: only the first 5 chars of the SHA1 hash are sent.
        The actual password NEVER leaves the machine.
        """
        try:
            # Hash the password
            sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]

            # Query the API with only the prefix
            response = await asyncio.to_thread(
                requests.get,
                f"{HIBP_PASSWORD_API}{prefix}",
                timeout=10
            )

            if response.status_code == 200:
                # Search for our suffix in the results
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(":")
                    if hash_suffix == suffix:
                        count = int(count)
                        if count > 1000000:
                            severity = "extremely compromised"
                        elif count > 100000:
                            severity = "heavily compromised"
                        elif count > 10000:
                            severity = "significantly compromised"
                        elif count > 1000:
                            severity = "moderately compromised"
                        else:
                            severity = "compromised"

                        return (
                            f"Warning, sir. This password has been found in {count:,} data breaches. "
                            f"It is {severity}. You should change it immediately and never reuse it."
                        )

                return "Good news, sir. This password has NOT been found in any known data breaches. However, that alone doesn't guarantee its security."
            else:
                return "I was unable to check the password breach database at this time."

        except Exception as e:
            return f"Error checking password: {str(e)}"

    def _format_breach_results(self, email, breaches):
        """Format breach results for voice output."""
        count = len(breaches)
        msg = f"Sir, the email {email} has been found in {count} data breach{'es' if count > 1 else ''}."

        # List first 5 breaches by name
        breach_names = [b.get("Name", "Unknown") for b in breaches[:5]]
        msg += f" Including: {', '.join(breach_names)}."

        if count > 5:
            msg += f" And {count - 5} more."

        # Find most recent breach
        dates = [b.get("BreachDate", "") for b in breaches if b.get("BreachDate")]
        if dates:
            latest = max(dates)
            msg += f" The most recent breach was on {latest}."

        msg += " I strongly recommend changing passwords for these services and enabling two-factor authentication."
        return msg
