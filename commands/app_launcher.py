"""
J.A.R.V.I.S — App Launcher
Opens and closes Windows applications.
"""

import subprocess
import os
import config


class AppLauncher:
    """Launch and close Windows applications by name."""

    def open(self, app_name):
        """Open an application by name."""
        app_key = app_name.lower().strip()

        # Check registry first
        if app_key in config.APP_REGISTRY:
            exe = config.APP_REGISTRY[app_key]
            try:
                # Handle special URI-based apps (like ms-settings:)
                if ":" in exe and not exe.endswith(".exe"):
                    os.startfile(exe)
                else:
                    subprocess.Popen(
                        exe,
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                return f"Yes sir, opening {app_name}."
            except FileNotFoundError:
                return f"I couldn't find {app_name} on your system, sir."
            except Exception as e:
                return f"Error launching {app_name}: {str(e)}"

        # Try direct execution as fallback
        try:
            subprocess.Popen(
                app_key,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return f"Yes sir, opening {app_name}."
        except Exception:
            pass

        # Try os.startfile as last resort
        try:
            os.startfile(app_key)
            return f"Yes sir, opening {app_name}."
        except Exception:
            return f"I'm sorry sir, I couldn't find an application called '{app_name}'."

    def close(self, app_name):
        """Close an application by name."""
        app_key = app_name.lower().strip()

        # Get the executable name
        exe = config.APP_REGISTRY.get(app_key, app_key)

        # Ensure it ends with .exe for taskkill
        if not exe.endswith(".exe"):
            exe += ".exe"

        try:
            result = subprocess.run(
                ["taskkill", "/IM", exe, "/F"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return f"Yes sir, closing {app_name}."
            else:
                return f"I couldn't find {app_name} running, sir."
        except Exception as e:
            return f"Error closing {app_name}: {str(e)}"
