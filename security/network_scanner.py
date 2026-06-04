"""
J.A.R.V.I.S — Network Scanner
LAN device discovery using ARP scanning.
Detects all devices on the local network, flags new/rogue devices.
"""

import asyncio
import json
import socket
from pathlib import Path
from datetime import datetime

import config

# Store known devices
KNOWN_DEVICES_FILE = config.BASE_DIR / "data" / "known_devices.json"


class NetworkScanner:
    """Discover devices on the local network via ARP scan."""

    def __init__(self):
        self.known_devices = self._load_known_devices()

    def _load_known_devices(self):
        """Load previously seen devices."""
        try:
            if KNOWN_DEVICES_FILE.exists():
                with open(KNOWN_DEVICES_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_known_devices(self):
        """Save known devices to disk."""
        try:
            KNOWN_DEVICES_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(KNOWN_DEVICES_FILE, "w") as f:
                json.dump(self.known_devices, f, indent=2)
        except Exception:
            pass

    async def scan(self):
        """Perform ARP scan on the local network."""
        try:
            # Try scapy first
            return await self._scan_scapy()
        except ImportError:
            # Fallback to arp -a command
            return await self._scan_arp_command()

    async def _scan_scapy(self):
        """Scan using scapy ARP."""
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0

        # Get local IP to determine subnet
        local_ip = self._get_local_ip()
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"

        # Create ARP request packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Send and receive
        result = await asyncio.to_thread(srp, packet, timeout=3, verbose=False)
        answered = result[0]

        devices = []
        new_devices = []

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.upper()
            hostname = self._resolve_hostname(ip)
            vendor = self._get_vendor(mac)

            device = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "first_seen": self.known_devices.get(mac, {}).get("first_seen", datetime.now().isoformat()),
                "last_seen": datetime.now().isoformat()
            }
            devices.append(device)

            # Check if new device
            if mac not in self.known_devices:
                new_devices.append(device)
                self.known_devices[mac] = device
            else:
                self.known_devices[mac]["last_seen"] = datetime.now().isoformat()

        self._save_known_devices()
        return self._format_results(devices, new_devices)

    async def _scan_arp_command(self):
        """Fallback: scan using Windows arp -a command."""
        import subprocess

        result = await asyncio.to_thread(
            subprocess.run,
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10
        )

        devices = []
        new_devices = []

        for line in result.stdout.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 3 and parts[1].count("-") == 5:
                ip = parts[0]
                mac = parts[1].upper().replace("-", ":")
                dtype = parts[2] if len(parts) > 2 else "unknown"

                if ip.startswith("224.") or ip.startswith("255."):
                    continue  # Skip multicast/broadcast

                hostname = self._resolve_hostname(ip)
                vendor = self._get_vendor(mac)

                device = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "type": dtype,
                    "first_seen": self.known_devices.get(mac, {}).get("first_seen", datetime.now().isoformat()),
                    "last_seen": datetime.now().isoformat()
                }
                devices.append(device)

                if mac not in self.known_devices:
                    new_devices.append(device)
                    self.known_devices[mac] = device
                else:
                    self.known_devices[mac]["last_seen"] = datetime.now().isoformat()

        self._save_known_devices()
        return self._format_results(devices, new_devices)

    def _get_local_ip(self):
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "192.168.1.1"

    def _resolve_hostname(self, ip):
        """Try to resolve hostname from IP."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return "Unknown"

    def _get_vendor(self, mac):
        """Get device vendor from MAC prefix (first 3 octets)."""
        # Common vendor OUI prefixes
        vendors = {
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "08:00:27": "VirtualBox",
            "00:1A:79": "Google",
            "F4:F5:D8": "Google",
            "3C:22:FB": "Apple",
            "A4:83:E7": "Apple",
            "AC:DE:48": "Apple",
            "88:66:A5": "Apple",
            "FC:18:3C": "Samsung",
            "8C:F5:A3": "Samsung",
            "30:07:4D": "Samsung",
            "00:17:88": "Philips Hue",
            "EC:FA:BC": "Xiaomi",
            "64:CE:D1": "Xiaomi",
            "78:02:F8": "Xiaomi",
            "44:07:0B": "Google Nest",
            "F8:0F:F9": "Google",
            "18:B4:30": "Nest Labs",
        }
        prefix = mac[:8].upper()
        return vendors.get(prefix, "Unknown Vendor")

    def _format_results(self, devices, new_devices):
        """Format scan results for voice output."""
        if not devices:
            return "I didn't find any devices on the network, sir. This might indicate a scanning permission issue."

        msg = f"Sir, I found {len(devices)} devices on your network."

        if new_devices:
            msg += f" Warning: {len(new_devices)} new device{'s' if len(new_devices) > 1 else ''} detected since the last scan."
            for d in new_devices[:3]:  # Only speak first 3 for brevity
                msg += f" New device at {d['ip']}, vendor: {d['vendor']}."

        return msg

    def get_devices_data(self):
        """Get device data for HUD dashboard."""
        return self.known_devices
