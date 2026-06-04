"""
J.A.R.V.I.S — System Control
Volume control, screenshots, lock screen, shutdown/restart.
"""

import subprocess
import os
import ctypes
from datetime import datetime
from pathlib import Path

import pyautogui
import config


class SystemControl:
    """Control system functions — volume, screen, power."""

    def __init__(self):
        self._volume_interface = None
        self._init_volume()

    def _init_volume(self):
        """Initialize the Windows audio volume interface."""
        try:
            from ctypes import cast, POINTER
            from comtypes import CLSCTX_ALL
            from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume

            devices = AudioUtilities.GetSpeakers()
            interface = devices.Activate(
                IAudioEndpointVolume._iid_, CLSCTX_ALL, None
            )
            self._volume_interface = cast(interface, POINTER(IAudioEndpointVolume))
        except Exception:
            self._volume_interface = None

    def volume_up(self, step=10):
        """Increase volume by step percent."""
        if self._volume_interface:
            current = self._volume_interface.GetMasterVolumeLevelScalar()
            new_vol = min(1.0, current + step / 100)
            self._volume_interface.SetMasterVolumeLevelScalar(new_vol, None)
            return f"Volume increased to {int(new_vol * 100)}%, sir."
        return self._fallback_volume("up")

    def volume_down(self, step=10):
        """Decrease volume by step percent."""
        if self._volume_interface:
            current = self._volume_interface.GetMasterVolumeLevelScalar()
            new_vol = max(0.0, current - step / 100)
            self._volume_interface.SetMasterVolumeLevelScalar(new_vol, None)
            return f"Volume decreased to {int(new_vol * 100)}%, sir."
        return self._fallback_volume("down")

    def set_volume(self, level):
        """Set volume to a specific percentage."""
        if self._volume_interface:
            new_vol = max(0.0, min(1.0, level / 100))
            self._volume_interface.SetMasterVolumeLevelScalar(new_vol, None)
            return f"Volume set to {level}%, sir."
        return "I'm unable to control the volume at the moment, sir."

    def toggle_mute(self):
        """Toggle mute/unmute."""
        if self._volume_interface:
            current_mute = self._volume_interface.GetMute()
            self._volume_interface.SetMute(not current_mute, None)
            state = "unmuted" if current_mute else "muted"
            return f"Audio {state}, sir."
        return "I'm unable to control the mute setting, sir."

    def _fallback_volume(self, direction):
        """Fallback volume control using nircmd or keyboard."""
        try:
            if direction == "up":
                pyautogui.press("volumeup", presses=5)
            else:
                pyautogui.press("volumedown", presses=5)
            return f"Volume {direction}, sir."
        except Exception:
            return f"I'm unable to adjust the volume, sir."

    def lock_screen(self):
        """Lock the Windows screen."""
        try:
            ctypes.windll.user32.LockWorkStation()
            return "Locking the screen now, sir."
        except Exception as e:
            return f"Error locking screen: {str(e)}"

    def take_screenshot(self):
        """Take a screenshot and save to Desktop."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"jarvis_screenshot_{timestamp}.png"
            filepath = config.SCREENSHOT_DIR / filename

            screenshot = pyautogui.screenshot()
            screenshot.save(str(filepath))
            return f"Screenshot saved to your Desktop as {filename}, sir."
        except Exception as e:
            return f"Error taking screenshot: {str(e)}"

    def shutdown(self):
        """Shutdown the computer (with 60 second delay for safety)."""
        try:
            os.system("shutdown /s /t 60")
            return "Initiating shutdown in 60 seconds, sir. Say 'cancel shutdown' to abort."
        except Exception as e:
            return f"Error initiating shutdown: {str(e)}"

    def restart(self):
        """Restart the computer (with 60 second delay for safety)."""
        try:
            os.system("shutdown /r /t 60")
            return "Restarting in 60 seconds, sir. Say 'cancel shutdown' to abort."
        except Exception as e:
            return f"Error initiating restart: {str(e)}"
