"""
J.A.R.V.I.S — Info Commands
Time, date, battery, system status, IP address.
"""

import socket
import psutil
from datetime import datetime


class InfoCommands:
    """Handle information queries."""

    def get_time(self):
        """Get current time."""
        now = datetime.now()
        hour = now.strftime("%I").lstrip("0")
        minute = now.strftime("%M")
        period = now.strftime("%p")

        if minute == "00":
            return f"It's {hour} {period}, sir."
        return f"It's {hour}:{minute} {period}, sir."

    def get_date(self):
        """Get current date."""
        now = datetime.now()
        return f"Today is {now.strftime('%A, %B %d, %Y')}, sir."

    def get_battery(self):
        """Get battery status."""
        try:
            battery = psutil.sensors_battery()
            if battery is None:
                return "I can't detect a battery, sir. You may be on a desktop."

            percent = battery.percent
            plugged = "plugged in" if battery.power_plugged else "on battery"
            time_left = ""

            if battery.secsleft > 0 and not battery.power_plugged:
                hours = battery.secsleft // 3600
                minutes = (battery.secsleft % 3600) // 60
                time_left = f" Approximately {hours} hours and {minutes} minutes remaining."

            return f"Battery is at {percent}%, {plugged}.{time_left}"
        except Exception:
            return "I'm unable to check the battery status, sir."

    def get_system_status(self):
        """Get CPU, RAM, and uptime."""
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            # Uptime
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            hours = int(uptime.total_seconds() // 3600)
            minutes = int((uptime.total_seconds() % 3600) // 60)

            return (
                f"System status: CPU at {cpu}%, "
                f"RAM at {ram.percent}% ({ram.used // (1024**3):.1f} GB used of {ram.total // (1024**3):.1f} GB), "
                f"Disk at {disk.percent}% used. "
                f"System uptime: {hours} hours and {minutes} minutes."
            )
        except Exception as e:
            return f"Error getting system status: {str(e)}"

    def get_ip(self):
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return f"Your local IP address is {ip}, sir."
        except Exception:
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                return f"Your IP address is {ip}, sir."
            except Exception:
                return "I'm unable to determine your IP address, sir."
