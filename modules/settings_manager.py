# modules/settings_manager.py
# Handles saving and loading user settings on their local machine
# Settings are stored in a JSON file in the user's home directory
# This means each user has their own API key — not shared with anyone

import json
import os
from config import SETTINGS_PATH

def load_settings():
    """
    Loads settings from the local JSON file.
    Returns a dict with all saved settings.
    Returns empty dict if file doesn't exist yet (first launch).
    """
    if not os.path.exists(SETTINGS_PATH):
        return {}

    try:
        with open(SETTINGS_PATH, "r") as f:
            return json.load(f)
    except:
        return {}

def save_settings(settings):
    """
    Saves settings dict to the local JSON file.
    Creates the file if it doesn't exist.
    """
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump(settings, f, indent=2)
        return True
    except:
        return False

def get_vt_api_key():
    """
    Returns the user's saved VirusTotal API key.
    Returns None if not set yet.
    """
    settings = load_settings()
    return settings.get("vt_api_key", None)

def save_vt_api_key(api_key):
    """Saves the user's VirusTotal API key to their local settings."""
    settings = load_settings()
    settings["vt_api_key"] = api_key.strip()
    return save_settings(settings)

def clear_vt_api_key():
    """Removes the saved API key — used if user wants to reset."""
    settings = load_settings()
    settings.pop("vt_api_key", None)
    return save_settings(settings)