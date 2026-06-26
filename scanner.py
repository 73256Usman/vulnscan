# scanner.py
# Entry point for running VulnScan from the command line
# The GUI (gui.py) is the main way users interact with the tool
# This file just ties all the modules together

from modules.database import initialize_db

# Initialize the database every time the app starts
# If tables already exist this does nothing — safe to always run
initialize_db()

# Launch the GUI
from gui import launch_gui
launch_gui()