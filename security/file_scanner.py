"""
J.A.R.V.I.S — File Scanner
Hash files and check against VirusTotal for malware.
"""

import hashlib
import asyncio
import os
import requests
import config


class FileScanner:
    """Hash files and check hashes against VirusTotal."""

    async def scan(self, filepath):
        """Hash a file and check it against VirusTotal."""
        # Expand path
        filepath = os.path.expandvars(filepath)
        filepath = os.path.expanduser(filepath)

        if not os.path.exists(filepath):
            return f"The file '{filepath}' doesn't exist, sir."

        if not os.path.isfile(filepath):
            return f"'{filepath}' is not a file, sir."

        # Calculate hashes
        try:
            file_size = os.path.getsize(filepath)
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                return "That file is over 100MB, sir. I can only hash files up to 100MB."

            hashes = await asyncio.to_thread(self._calculate_hashes, filepath)

            msg = (
                f"File hashes for {os.path.basename(filepath)}: "
                f"MD5: {hashes['md5']}, SHA256: {hashes['sha256']}."
            )

            # Check against VirusTotal
            if config.VIRUSTOTAL_API_KEY:
                vt_result = await self._check_virustotal(hashes["sha256"])
                msg += f" {vt_result}"
            else:
                msg += " Set up a VirusTotal API key to check this hash against malware databases."

            return msg

        except PermissionError:
            return f"I don't have permission to read that file, sir."
        except Exception as e:
            return f"Error scanning file: {str(e)}"

    def _calculate_hashes(self, filepath):
        """Calculate MD5 and SHA256 hashes of a file."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest()
        }

    async def _check_virustotal(self, sha256):
        """Check file hash against VirusTotal."""
        try:
            headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

            response = await asyncio.to_thread(
                requests.get,
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                if malicious > 0:
                    return (
                        f"DANGER! This file has been flagged as MALICIOUS by {malicious} out of {total} "
                        f"antivirus engines. Do NOT execute this file."
                    )
                elif suspicious > 0:
                    return (
                        f"CAUTION. This file was marked as suspicious by {suspicious} out of {total} engines. "
                        f"Proceed with caution."
                    )
                else:
                    return f"This file appears CLEAN. {total} security engines found no issues."

            elif response.status_code == 404:
                return "This file hash was not found in VirusTotal's database. It may be a new or uncommon file."
            else:
                return "I couldn't complete the VirusTotal check at this time."

        except Exception as e:
            return f"VirusTotal check error: {str(e)}"
