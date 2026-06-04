"""
J.A.R.V.I.S — Folder Opener
Opens folders in Windows File Explorer.
"""

import os
import subprocess
from pathlib import Path
import config


class FolderOpener:
    """Open folders in File Explorer."""

    def open_shortcut(self, folder_name):
        """Open a folder using a shortcut name."""
        # Normalize: "document" or "documents" → match
        key = folder_name.lower().strip()

        # Try direct match
        if key in config.FOLDER_SHORTCUTS:
            return self._open(config.FOLDER_SHORTCUTS[key], key)

        # Try with 's' appended
        if key + "s" in config.FOLDER_SHORTCUTS:
            return self._open(config.FOLDER_SHORTCUTS[key + "s"], key)

        return f"I don't recognize the folder '{folder_name}', sir."

    def open_path(self, path_str):
        """Open a specific folder path."""
        # Expand environment variables and user home
        path_str = os.path.expandvars(path_str)
        path_str = os.path.expanduser(path_str)
        path = Path(path_str)

        if path.exists():
            return self._open(path, path_str)
        else:
            return f"The folder '{path_str}' doesn't exist, sir."

    def _open(self, path, display_name):
        """Open a folder path in Explorer."""
        try:
            path = Path(path)
            if path.exists():
                subprocess.Popen(["explorer", str(path)])
                return f"Opening {display_name} folder, sir."
            else:
                return f"The folder '{display_name}' doesn't exist, sir."
        except Exception as e:
            return f"Error opening folder: {str(e)}"
