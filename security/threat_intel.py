"""
J.A.R.V.I.S — Threat Intelligence
IP reputation (AbuseIPDB) and URL/Hash scanning (VirusTotal).
"""

import asyncio
import requests
import config


class ThreatIntel:
    """Threat intelligence lookups via AbuseIPDB and VirusTotal."""

    async def check_ip(self, ip):
        """Check IP reputation using AbuseIPDB and VirusTotal."""
        results = []

        # Try AbuseIPDB
        if config.ABUSEIPDB_API_KEY:
            abuse_result = await self._check_abuseipdb(ip)
            results.append(abuse_result)

        # Try VirusTotal
        if config.VIRUSTOTAL_API_KEY:
            vt_result = await self._check_vt_ip(ip)
            results.append(vt_result)

        if not results:
            return (
                f"Sir, I don't have API keys configured for threat intelligence. "
                f"Set VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY environment variables for full threat intel capabilities. "
                f"Both offer free tiers."
            )

        return " ".join(results)

    async def scan_url(self, url):
        """Scan a URL using VirusTotal."""
        if not config.VIRUSTOTAL_API_KEY:
            return "Sir, I need a VirusTotal API key to scan URLs. It's free at virustotal.com."

        try:
            headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

            # Submit URL for scanning
            response = await asyncio.to_thread(
                requests.post,
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )

            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                # Wait briefly then get results
                await asyncio.sleep(3)

                result = await asyncio.to_thread(
                    requests.get,
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=15
                )

                if result.status_code == 200:
                    stats = result.json()["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + harmless + undetected

                    if malicious > 0:
                        return (
                            f"WARNING, sir. This URL has been flagged as MALICIOUS by {malicious} out of {total} "
                            f"security engines. {suspicious} marked it as suspicious. "
                            f"I strongly advise against visiting this URL."
                        )
                    elif suspicious > 0:
                        return (
                            f"Caution, sir. This URL has been marked as SUSPICIOUS by {suspicious} out of {total} "
                            f"security engines. Proceed with care."
                        )
                    else:
                        return (
                            f"This URL appears to be SAFE, sir. {harmless} out of {total} security engines "
                            f"found no issues."
                        )

            return "I was unable to complete the URL scan at this time, sir."

        except Exception as e:
            return f"Error scanning URL: {str(e)}"

    async def _check_abuseipdb(self, ip):
        """Check IP on AbuseIPDB."""
        try:
            headers = {
                "Key": config.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }

            response = await asyncio.to_thread(
                requests.get,
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()["data"]
                score = data["abuseConfidenceScore"]
                total_reports = data["totalReports"]
                country = data.get("countryCode", "Unknown")
                isp = data.get("isp", "Unknown ISP")
                usage = data.get("usageType", "Unknown")
                is_tor = data.get("isTor", False)

                if score >= 80:
                    severity = "HIGHLY MALICIOUS"
                elif score >= 50:
                    severity = "SUSPICIOUS"
                elif score >= 25:
                    severity = "POTENTIALLY RISKY"
                else:
                    severity = "LOW RISK"

                msg = (
                    f"AbuseIPDB report for {ip}: {severity} with a {score}% abuse confidence score. "
                    f"Reported {total_reports} times. Country: {country}. ISP: {isp}."
                )

                if is_tor:
                    msg += " This IP is identified as a TOR exit node."

                return msg

            return f"AbuseIPDB returned status {response.status_code} for IP {ip}."

        except Exception as e:
            return f"AbuseIPDB error: {str(e)}"

    async def _check_vt_ip(self, ip):
        """Check IP on VirusTotal."""
        try:
            headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

            response = await asyncio.to_thread(
                requests.get,
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                if malicious > 0 or suspicious > 0:
                    return (
                        f"VirusTotal: {malicious} security vendors flagged this IP as malicious, "
                        f"{suspicious} as suspicious, out of {total} total."
                    )
                else:
                    return f"VirusTotal: No security vendors flagged this IP. It appears clean."

            return ""

        except Exception as e:
            return f"VirusTotal error: {str(e)}"
