# MIT License
#
# Copyright (c) 2024 rpimaster
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import json
import datetime
import logging
from pydexcom import Dexcom
from notifypy import Notify
from cryptography.fernet import Fernet
import os
import stat
import requests
import hashlib
import numpy as np
from sklearn.linear_model import LinearRegression
import time
import random
import base64
import tempfile
import threading
import webbrowser
import packaging.version  # For version comparison
import subprocess
import sys
import shutil
import platform
import ctypes
from PIL import Image
from sklearn.utils import resample

# Get platform-specific application support directory
def get_app_support_dir():
    """Determine the application support directory with fallbacks for restricted environments."""
    # 0. Check for snap environment first (special handling)
    if 'SNAP' in os.environ:
        # Use SNAP_USER_DATA for per-user persistent storage in snap environment
        snap_user_data = os.environ.get('SNAP_USER_DATA', '')
        if snap_user_data:
            snap_path = os.path.join(snap_user_data, "DexMateData")
            try:
                os.makedirs(snap_path, exist_ok=True)
                # Test write permission
                test_file = os.path.join(snap_path, 'write_test.tmp')
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                return snap_path
            except Exception as e:
                logging.warning(f"Snap data directory not writable: {e}. Using fallback.")
    
    # 1. Check custom environment variable first
    custom_path = os.environ.get('DEXMATE_DATA_PATH')
    if custom_path:
        custom_path = os.path.abspath(os.path.expanduser(custom_path))
        try:
            os.makedirs(custom_path, exist_ok=True)
            # Test write permission
            test_file = os.path.join(custom_path, 'write_test.tmp')
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            return custom_path
        except Exception:
            pass  # We'll try other locations
    
    # 2. Create dedicated DexMate directory in user's home folder
    home_path = os.path.expanduser("~")
    dexmate_home_path = os.path.join(home_path, "DexMateData")
    
    try:
        os.makedirs(dexmate_home_path, exist_ok=True)
        # Test write permission
        test_file = os.path.join(dexmate_home_path, 'write_test.tmp')
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        return dexmate_home_path
    except Exception as e:
        logging.warning(f"Home directory not writable: {e}")
    
    # 3. Platform-specific standard locations (as fallback only)
    system = platform.system()
    standard_path = None
    
    if system == "Darwin":
        standard_path = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "DexMate")
    elif system == "Windows":
        base_path = os.environ.get("LOCALAPPDATA", os.path.join(os.environ["USERPROFILE"], "AppData", "Local"))
        standard_path = os.path.join(base_path, "DexMate")
    else:  # Linux and other
        data_home = os.environ.get("XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share"))
        standard_path = os.path.join(data_home, "DexMate")
    
    # 4. Try to use standard location
    if standard_path:
        try:
            os.makedirs(standard_path, exist_ok=True)
            # Test write permission
            test_file = os.path.join(standard_path, 'write_test.tmp')
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            return standard_path
        except Exception as e:
            logging.warning(f"Standard directory not writable: {e}")
    
    # 5. Fallback to portable directory in executable location
    try:
        if getattr(sys, 'frozen', False):  # Running as executable
            base_path = os.path.dirname(sys.executable)
        else:  # Running as script
            base_path = os.path.dirname(os.path.abspath(__file__))
        
        portable_path = os.path.join(base_path, "DexMateData")
        os.makedirs(portable_path, exist_ok=True)
        return portable_path
    except Exception as e:
        logging.warning(f"Portable directory creation failed: {e}")
    
    # 6. Final fallback to temporary directory
    temp_path = tempfile.mkdtemp(prefix="DexMate_")
    logging.warning(f"Using temporary directory: {temp_path}")
    return temp_path

# Initialize application support directory before any usage
app_support_dir = get_app_support_dir()

# Log that we've successfully initialized logging
logging.info("Logging system initialized successfully")
logging.info(f"Application support directory: {app_support_dir}")

# Current app version - update this with each release
VERSION = "2.0.0"
# GitHub API URL for checking latest release
UPDATE_CHECK_URL = "https://api.github.com/repos/rpimaster/DexMate/releases/latest"

class GlucoseWidget:
    # Define helper methods first
    @staticmethod
    def get_file_path(filename):
        """Get full path for a file in application support directory"""
        return os.path.join(app_support_dir, filename)

    def get_icon_path(self):
        """Get path to application icon, copy if needed."""
        # Use the global app_support_dir that's now defined
        icon_path = os.path.join(app_support_dir, "logo_png.png")
        
        # Only attempt to copy if the icon doesn't exist
        if not os.path.exists(icon_path):
            try:
                # Determine base path for resources
                if getattr(sys, 'frozen', False):  # Running as a PyInstaller bundle
                    base_path = sys._MEIPASS
                else:  # Running as a script
                    base_path = os.path.dirname(os.path.abspath(__file__))
                
                source_icon = os.path.join(base_path, "logo_png.png")
                
                if os.path.exists(source_icon):
                    shutil.copy(source_icon, icon_path)
                    logging.info(f"Copied application icon to {icon_path}")
                else:
                    logging.warning(f"Source icon not found at {source_icon}")
            except Exception as e:
                logging.error(f"Error copying icon: {e}")
        
        return icon_path

    def __init__(self, root):
        """Initialize the application."""
        self.root = root
        
        # Initialize attributes
        self.opacity = 0.8  # Default opacity value
        # ... other attributes ...

        # Initialize the rest of the class
        # ... existing code ...

        # Initialize attributes early
        self.data_source = "Dexcom"  # Default data source
        self.unit = "mmol"  # Default unit (initialize early to avoid AttributeError)
        self.prediction_enabled = True  # Default value for prediction_enabled
        self.prediction_history = []  # Initialize prediction history
        self.max_history = 6  # Use last 6 readings for prediction

        # Initialize file paths using helper methods
        self.key_file_path = self.get_file_path('secret.key')
        self.credentials_file_path = self.get_file_path('credentials.json')
        self.settings_file_path = self.get_file_path('settings.json')
        self.history_file = self.get_file_path('history.json')

        # Set DexMate logo path
        self.dexmate_icon_path = self.get_icon_path()

        # Set DexMate logo as window icon
        if self.dexmate_icon_path and os.path.exists(self.dexmate_icon_path):
            try:
                # Windows needs special handling for .ico files
                if platform.system() == "Windows":
                    # Convert PNG to ICO in temp directory
                    ico_path = self.convert_png_to_ico(self.dexmate_icon_path)
                    if ico_path:
                        self.root.iconbitmap(ico_path)
                        logging.info("Windows icon set using ICO")
                    else:
                        # Fallback to PNG if conversion fails
                        self.icon_img = tk.PhotoImage(file=self.dexmate_icon_path)
                        self.root.iconphoto(True, self.icon_img)
                        logging.info("Windows icon set using PNG fallback")
                else:
                    # Non-Windows platforms can use PNG directly
                    self.icon_img = tk.PhotoImage(file=self.dexmate_icon_path)
                    self.root.iconphoto(True, self.icon_img)
                    logging.info("Main window icon set successfully")
            except Exception as e:
                logging.error(f"Error setting window icon: {e}")
        else:
            logging.warning("DexMate icon not available")

        self.login_window = None  # Initialize login_window as None
        self.login_window_created = False  # Track whether the login window has been created

        self.root.title("DexMate")
        self.root.geometry("300x270")  # Increased height for prediction label

        # Add prediction history before any updates
        logging.info(f"Max history initialized: {self.max_history}")

        self.label = tk.Label(root, text="Glucose Level:")
        self.label.pack(pady=5)

        self.glucose_value = tk.StringVar()
        self.glucose_label = tk.Label(root, textvariable=self.glucose_value, font=("Helvetica", 22))
        self.glucose_label.pack()

        self.trend_label = tk.Label(root, text="", font=("Helvetica", 22))
        self.trend_label.pack(pady=5)

        self.time_label = tk.Label(root, text="", font=("Helvetica", 12))
        self.time_label.pack(pady=5)

        self.delta_label = tk.Label(root, text="", font=("Helvetica", 12))
        self.delta_label.pack(pady=5)

        # Add prediction label with delta and trend
        self.prediction_label = tk.Label(root, text="Prediction: --", font=("Helvetica", 12))
        self.prediction_label.pack(pady=5)

        # Default target range in mmol
        self.target_range = (3.9, 12.0)
        self.last_reading_time = None  # Initialize last reading time to NONE
        self.dexcom = None  # Initialize dexcom object to None
        self.previous_glucose = None
        self.notifications_snoozed_until = None  # To track the snooze status
        self.connection_retries = 0  # Track connection retries
        self.max_retries = 5  # Max connection retries before giving up
        self.last_successful_update = None  # Track last successful update time

        self.locations = [self.set_top_left, self.set_bottom_left, self.set_bottom_right, self.set_top_right]
        self.current_location = 0

        # Create a frame for the buttons
        self.button_frame = tk.Frame(root)
        self.button_frame.pack(pady=5)  # Add padding around the frame

        # Create a button for changing widget location
        self.location_button = tk.Button(self.button_frame, text="Change Location", command=self.change_location)
        self.location_button.pack(side="left", padx=10)  # Pack left with some padding

        # Create a settings button
        self.settings_button = tk.Button(self.button_frame, text="Settings", command=self.open_settings)
        self.settings_button.pack(side="left", padx=10)  # Pack left with some padding

        # Load saved settings
        self.load_settings()

        # Load the last saved position with fallbacks
        self.load_last_position()

        # Always load prediction history
        self.prediction_history = self.load_history() or []
        logging.info(f"Loaded prediction history: {len(self.prediction_history)} entries")
        
        # Only show prediction UI if enabled
        if self.prediction_enabled:
            self.prediction_label.pack(pady=5)
        else:
            self.prediction_label.pack_forget()

        # Check if credentials are already saved, if not, show the login window
        self.check_saved_credentials()

        # Variable to track the pin state
        self.is_pinned = False

        # Bind the window close event to save the position
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Initial update of labels
        self.update_labels()
        self.schedule_update()  # Schedule periodic updates
        
        # Check for updates in the background
        self.check_for_updates()

        # Obfuscate sensitive strings in memory
        self.OBFUSCATOR = os.urandom(16)
    
        # Register cleanup for secure memory wipe
        import atexit
        atexit.register(self.secure_cleanup)

        # Verify directory permissions at startup
        if not self.verify_directory_permissions():
            messagebox.showwarning(
                "Permission Issue",
                f"Couldn't write to data directory:\n{app_support_dir}\n"
                "Some features may not work properly."
            )

    def convert_target_range(self, min_val, max_val, from_unit, to_unit):
        """Convert target range between units"""
        if from_unit == to_unit:
            return min_val, max_val
            
        if from_unit == "mmol" and to_unit == "mgdl":
            return min_val * 18.0, max_val * 18.0
        elif from_unit == "mgdl" and to_unit == "mmol":
            return min_val / 18.0, max_val / 18.0
        return min_val, max_val

    def convert_png_to_ico(self, png_path):
        """Convert PNG to ICO format for Windows icons."""
        try:
            # Save the .ico file in the application support directory
            ico_path = os.path.join(app_support_dir, "dexmate.ico")

            # Open PNG and convert to ICO
            img = Image.open(png_path)
            img.save(ico_path, format='ICO')

            logging.info(f"Converted PNG to ICO: {ico_path}")
            return ico_path
        except ImportError:
            logging.warning("Pillow not installed, cannot convert PNG to ICO")
        except Exception as e:
            logging.error(f"Error converting PNG to ICO: {e}")
        return None

    def convert_png_to_temp_bmp(self, png_path):
        """Convert PNG to temporary BMP for Windows notifications."""
        try:
            if not png_path or not os.path.exists(png_path):
                return None
                
            # Create temp BMP file in application support directory
            bmp_path = os.path.join(app_support_dir, "temp_notify_icon.bmp")
            
            # Open PNG and convert to BMP
            img = Image.open(png_path)
            img.save(bmp_path, format='BMP')
            
            logging.info(f"Converted PNG to BMP: {bmp_path}")
            return bmp_path
        except Exception as e:
            logging.error(f"PNG to BMP conversion failed: {e}")
            return None

    def toggle_pin_on_top(self):
        self.is_pinned = not self.is_pinned
        self.root.wm_attributes("-topmost", self.is_pinned)
        self.pin_on_top_button.config(text="Unpin" if self.is_pinned else "Pin on Top")

    def check_saved_credentials(self):
        """Check saved credentials and authenticate if available."""
        config = self.load_config()
        if config:
            self.data_source = config.get("data_source", "")
            self.region = config.get("region", "us")
            self.unit = config.get("unit", "mmol")
            # ... (rest of existing code) ...
        else:
            self.data_source = ""  # Ensure it's empty if no config
    
        # Show login window if no data source is set
        if not self.data_source:
            self.show_login_window()
            return
        
        # Get credentials from ENCRYPTED storage
        all_credentials = self.get_saved_credentials()
        
        if self.data_source == "Dexcom":
            credentials = all_credentials.get("Dexcom", {})
            if credentials.get("username") and credentials.get("password"):
                self.authenticate_dexcom(credentials["username"], credentials["password"])
            else:
                self.show_login_window()
        elif self.data_source == "Nightscout":
            credentials = all_credentials.get("Nightscout", {})
            if credentials.get("url"):
                self.nightscout_url = credentials["url"]
                self.nightscout_api_secret = credentials.get("api_secret")
            else:
                self.show_login_window()

    def generate_key(self):
        """Generate a new encryption key with secure permissions."""
        key = Fernet.generate_key()
        with open(self.key_file_path, 'wb') as key_file:
            key_file.write(key)
        # Set restrictive file permissions
        self.set_file_permissions(self.key_file_path)
        return key

    def load_key(self):
        """Load encryption key with validation."""
        try:
            # Verify file exists and has content
            if not os.path.exists(self.key_file_path) or os.path.getsize(self.key_file_path) == 0:
                return self.generate_key()
            
            with open(self.key_file_path, 'rb') as key_file:
                key = key_file.read()
                
            # Validate key format
            if len(key) != 44:  # Fernet keys are 44 bytes in base64
                logging.warning("Invalid key format detected, generating new key")
                return self.generate_key()
                
            return key
        except Exception as e:
            logging.error(f"Key loading error: {e}")
            return self.generate_key()

    def encrypt_credentials(self, credentials):
        """Encrypt credentials with additional validation."""
        key = self.load_key()
        fernet = Fernet(key)
        
        # Add timestamp to detect stale credentials
        credentials['timestamp'] = datetime.datetime.now().isoformat()
        credential_data = json.dumps(credentials).encode()
        
        # Add random padding to obscure data length
        padding = os.urandom(random.randint(5, 15))
        padded_data = padding + credential_data
        
        return fernet.encrypt(padded_data)

    def decrypt_credentials(self, encrypted_credentials):
        """Decrypt credentials with validation checks."""
        key = self.load_key()
        fernet = Fernet(key)
        
        decrypted = fernet.decrypt(encrypted_credentials)
        
        # Remove random padding
        try:
            # Find first valid JSON character
            start_index = next(i for i, byte in enumerate(decrypted) 
                             if chr(byte) in '{["')
            credential_data = decrypted[start_index:]
        except (StopIteration, ValueError):
            raise ValueError("Invalid credential format")
        
        credentials = json.loads(credential_data.decode())
        
        # Validate timestamp
        cred_time = datetime.datetime.fromisoformat(credentials['timestamp'])
        if (datetime.datetime.now() - cred_time) > datetime.timedelta(days=365):
            logging.warning("Stale credentials detected (>1 year old)")
            
        return credentials

    def get_saved_credentials(self):
        """Retrieve saved credentials for all data sources."""
        try:
            # Decrypt the credentials file
            encrypted_credentials = self.load_encrypted_credentials()
            if not encrypted_credentials:
                return {}
            
            decrypted = self.decrypt_credentials(encrypted_credentials)
            
            # Return credentials for both data sources
            return {
                "Dexcom": decrypted.get("Dexcom"),
                "Nightscout": decrypted.get("Nightscout")
            }
        except Exception as e:
            logging.error(f"Failed to retrieve saved credentials: {e}")
            return {}

    def save_credentials(self, data_source, credentials):
        """Save credentials for a specific data source."""
        # Retrieve existing credentials
        all_credentials = self.get_saved_credentials() or {}
    
        # Update credentials for the specified data source
        all_credentials[data_source] = credentials
    
        # Encrypt and save all credentials
        encrypted = self.encrypt_credentials(all_credentials)
    
        # Use atomic write to prevent corruption
        temp_path = self.credentials_file_path + '.tmp'
        with open(temp_path, 'wb') as file:
            file.write(encrypted)
    
        # Atomic replace
        os.replace(temp_path, self.credentials_file_path)
        self.set_file_permissions(self.credentials_file_path)
    
        logging.info(f"Saved credentials for {data_source}")

    def load_settings(self):
        try:
            with open(self.settings_file_path, 'r') as settings_file:
                settings = json.load(settings_file)
                min_value = settings.get("min_value")
                max_value = settings.get("max_value")
                opacity = settings.get("opacity", 0.8)
                self.prediction_enabled = settings.get("prediction_enabled", True)
                self.unit = settings.get("unit", "mmol")
                
                # Convert target range to current unit if needed
                if min_value is not None and max_value is not None:
                    if self.unit == "mgdl":
                        # Convert from stored mmol to mg/dL
                        self.target_range = (min_value * 18.0, max_value * 18.0)
                    else:
                        self.target_range = (min_value, max_value)
                if opacity is not None:
                    self.opacity = opacity
                    self.root.attributes('-alpha', self.opacity)
                return settings
        except FileNotFoundError:
            # If settings file doesn't exist, keep default values
            return None

    def load_history(self):
        """Load prediction history from file."""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
                    return [(datetime.datetime.fromisoformat(t), g) for t, g in history]
        except Exception as e:
            logging.error(f"History load error: {e}")
        return None

    def save_history(self):
        """Save prediction history with robust error handling."""
        try:
            history_data = [(t.isoformat(), g) for t, g in self.prediction_history]
            
            # Use safe write method with Windows-specific fixes
            success = self.safe_write_json(self.history_file, history_data)
            
            if success:
                logging.info(f"Saved {len(history_data)} history entries")
            else:
                logging.error("History save failed after retries")
        except Exception as e:
            logging.error(f"History save error: {e}")
            # Emergency fallback to memory-only operation
            self.prediction_history = self.prediction_history[-self.max_history:]

    def authenticate_dexcom(self, username, password):
        """Authenticate with Dexcom and initialize session."""
        try:
            self.dexcom = Dexcom(username=username, password=password, region=self.region)
            self.connection_retries = 0  # Reset retry counter on success
            self.update_labels()
            self.schedule_update()
            
            # Schedule first update immediately
            self.root.after(100, self.update_labels)
            
        except Exception as e:
            logging.error(f"Dexcom authentication failed: {e}")
            messagebox.showerror("Authentication Error", "Failed to authenticate with Dexcom. Please check your credentials.")

    def login(self):
        if isinstance(self.username_entry, tk.Entry) and isinstance(self.password_entry, tk.Entry):
            username = self.username_entry.get()
            password = self.password_entry.get()

        if username and password:
            self.authenticate_dexcom(username, password)
            self.save_credentials(username, password)
            # Clear the Entry widgets after successful login
            self.username_entry.delete(0, 'end')
            self.password_entry.delete(0, 'end')
            self.login_window.destroy()
        else:
            messagebox.showerror("Input Error", "Both username and password are required.")

    def open_settings(self):
        """Open the settings window."""
        # Check for file locks before opening settings
        self.check_file_locks()
        
        self.settings_window = tk.Toplevel(self.root)
        self.settings_window.title("Settings")
        self.settings_window.geometry("300x450")  # Increased height for unit selection
        
        # Set window icon
        self.set_window_icon(self.settings_window)

        # Target Range Settings
        target_frame = ttk.LabelFrame(self.settings_window, text="Target Range")
        target_frame.pack(padx=10, pady=5, fill="x")

        ttk.Label(target_frame, text="Min:").grid(row=0, column=0, padx=5, pady=5)
        self.new_min_entry = ttk.Entry(target_frame)
        self.new_min_entry.grid(row=0, column=1, padx=5, pady=5)
        self.new_min_entry.insert(0, str(self.target_range[0]))

        ttk.Label(target_frame, text="Max:").grid(row=1, column=0, padx=5, pady=5)
        self.new_max_entry = ttk.Entry(target_frame)
        self.new_max_entry.grid(row=1, column=1, padx=5, pady=5)
        self.new_max_entry.insert(0, str(self.target_range[1]))

        # Unit Settings
        unit_frame = ttk.LabelFrame(self.settings_window, text="Glucose Unit")
        unit_frame.pack(padx=10, pady=5, fill="x")
        
        self.unit_var = tk.StringVar(value=self.unit)
        
        # Function to handle unit changes
        def on_unit_change():
            current_unit = self.unit_var.get()
            try:
                # Get current min/max values in current display units
                current_min = float(self.new_min_entry.get())
                current_max = float(self.new_max_entry.get())
                
                # Convert to new units
                new_min, new_max = self.convert_target_range(
                    current_min, current_max,
                    self.settings_window.current_display_unit, 
                    current_unit
                )
                
                # Update entry fields with converted values
                self.new_min_entry.delete(0, tk.END)
                self.new_min_entry.insert(0, f"{new_min:.1f}")
                self.new_max_entry.delete(0, tk.END)
                self.new_max_entry.insert(0, f"{new_max:.1f}")
                
                # Update current display unit
                self.settings_window.current_display_unit = current_unit
            except ValueError:
                # Ignore if values aren't numbers
                pass
        
        # Create radio buttons with command
        ttk.Radiobutton(unit_frame, text="mmol/L", variable=self.unit_var, value="mmol", 
                        command=on_unit_change).pack(anchor="w", padx=5)
        ttk.Radiobutton(unit_frame, text="mg/dL", variable=self.unit_var, value="mgdl", 
                        command=on_unit_change).pack(anchor="w", padx=5)
        
        # Store current display unit for conversion
        self.settings_window.current_display_unit = self.unit

        # Opacity Settings
        opacity_frame = ttk.LabelFrame(self.settings_window, text="Opacity")
        opacity_frame.pack(padx=10, pady=5, fill="x")
        
        ttk.Label(opacity_frame, text="Opacity (0.0-1.0):").grid(row=0, column=0, padx=5, pady=5)
        self.opacity_entry = ttk.Entry(opacity_frame)
        self.opacity_entry.grid(row=0, column=1, padx=5, pady=5)
        self.opacity_entry.insert(0, str(self.opacity))

        # Prediction Settings
        prediction_frame = ttk.LabelFrame(self.settings_window, text="Predictions")
        prediction_frame.pack(padx=10, pady=5, fill="x")

        self.prediction_var = tk.BooleanVar(value=self.prediction_enabled)
        prediction_check = ttk.Checkbutton(
            prediction_frame, 
            text="Enable Glucose Predictions",
            variable=self.prediction_var
        )
        prediction_check.pack(padx=5, pady=5)

        # Buttons Frame
        button_frame = ttk.Frame(self.settings_window)
        button_frame.pack(pady=10)

        # Save Button
        save_button = ttk.Button(button_frame, text="Save Settings", command=self.save_settings)
        save_button.grid(row=0, column=0, padx=5)

        # Manual Update Button
        update_button = ttk.Button(button_frame, text="Update Now", command=self.update_labels)
        update_button.grid(row=0, column=1, padx=5)

        # Pin on Top Button
        pin_text = "Unpin" if self.is_pinned else "Pin on Top"
        self.pin_on_top_button = ttk.Button(button_frame, text=pin_text, command=self.toggle_pin_on_top)
        self.pin_on_top_button.grid(row=1, column=0, padx=5, pady=5)

        # Snooze Button
        snooze_button = ttk.Button(button_frame, text="Snooze Alerts", command=self.snooze_notifications)
        snooze_button.grid(row=1, column=1, padx=5, pady=5)

        # Logout Button
        logout_button = ttk.Button(button_frame, text="Logout", command=self.logout)
        logout_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Add "Open Data Folder" button
        open_dir_button = ttk.Button(button_frame, text="Open Data Folder", command=self.open_data_directory)
        open_dir_button.grid(row=3, column=0, columnspan=2, pady=5)

    def logout(self):
        """Log out the user and reset session variables."""
        try:
            # Delete credentials file
            if os.path.exists(self.credentials_file_path):
                try:
                    os.remove(self.credentials_file_path)
                except PermissionError as pe:
                    logging.warning(f"Could not delete credentials file: {pe}")
                    with open(self.credentials_file_path, 'w') as f:
                        f.write("")
                    logging.info("Overwrote credentials file instead")

            # Reset data source in config
            config = self.load_config() or {}
            config["data_source"] = ""  # Clear data source
            
            # Save the updated config
            self.save_config(config)

            # Reset session variables
            self.data_source = ""
            self.dexcom = None
            self.nightscout_url = None
            self.nightscout_api_secret = None
            self.previous_glucose = None

            # Reset UI immediately
            self.reset_ui_after_logout()

            # Show the login window
            self.show_login_window()

        except Exception as e:
            logging.error(f"Unexpected error during logout: {e}")
            self.show_login_window()

    def reset_ui_after_logout(self):
        """Reset UI elements to default state after logout."""
        self.glucose_value.set("--")
        self.trend_label.configure(text="")
        self.time_label.configure(text="")
        self.delta_label.configure(text="")
        self.prediction_label.configure(text="Prediction: --")
        self.glucose_label.configure(fg="black")
        self.last_reading_time = None
        self.previous_glucose = None
        self.prediction_history = []

    def secure_cleanup(self):
        """Securely wipe sensitive data from memory on exit"""
        try:
            # Wipe Dexcom session if it exists
            if hasattr(self, 'dexcom') and self.dexcom:
                try:
                    # Try to properly log out if possible
                    if hasattr(self.dexcom, 'logout'):
                        self.dexcom.logout()
                except Exception:
                    pass
                self.dexcom = None
            
            # Wipe Nightscout credentials
            if hasattr(self, 'nightscout_api_secret') and self.nightscout_api_secret:
                # Overwrite the secret with zeros
                if isinstance(self.nightscout_api_secret, str):
                    # Convert to mutable bytearray to overwrite
                    secret_bytes = bytearray(self.nightscout_api_secret.encode('utf-8'))
                    for i in range(len(secret_bytes)):
                        secret_bytes[i] = 0
                    self.nightscout_api_secret = None
                elif isinstance(self.nightscout_api_secret, bytes):
                    # Create a mutable copy and overwrite
                    secret_bytes = bytearray(self.nightscout_api_secret)
                    for i in range(len(secret_bytes)):
                        secret_bytes[i] = 0
                    self.nightscout_api_secret = None
            
            # Wipe other sensitive attributes
            sensitive_attrs = ['_credentials', 'OBFUSCATOR']
            for attr in sensitive_attrs:
                if hasattr(self, attr):
                    value = getattr(self, attr)
                    if isinstance(value, str):
                        # Create mutable version and overwrite
                        mutable = bytearray(value.encode('utf-8'))
                        for i in range(len(mutable)):
                            mutable[i] = 0
                        setattr(self, attr, None)
                    elif isinstance(value, bytes):
                        # Create mutable version and overwrite
                        mutable = bytearray(value)
                        for i in range(len(mutable)):
                            mutable[i] = 0
                        setattr(self, attr, None)
                    else:
                        setattr(self, attr, None)
            
            logging.info("Securely cleaned memory")
        except Exception as e:
            logging.error(f"Secure cleanup failed: {e}")

    def save_settings(self):
        """Save settings and handle unit changes."""
        new_min = self.new_min_entry.get()
        new_max = self.new_max_entry.get()
        new_opacity = self.opacity_entry.get()
        new_unit = self.unit_var.get()

        try:
            new_min = float(new_min)
            new_max = float(new_max)
            new_opacity = float(new_opacity)

            if new_min < new_max and 0.0 <= new_opacity <= 1.0:
                # Update current target range with new values (in current unit)
                self.target_range = (new_min, new_max)
                self.opacity = new_opacity
                self.root.attributes('-alpha', self.opacity)  # Apply the new opacity
                self.is_pinned = self.root.wm_attributes("-topmost")
                
                # Update prediction enabled state
                prediction_was_enabled = self.prediction_enabled
                self.prediction_enabled = self.prediction_var.get()
                
                # Don't clear history when disabling predictions
                # Just show/hide the UI element
                if self.prediction_enabled:
                    self.prediction_label.pack(pady=5)
                    self.prediction_label.config(text="Prediction: --")
                else:
                    self.prediction_label.pack_forget()
                
                # Handle unit change
                new_unit = self.unit_var.get()
                if new_unit != self.unit:
                    self.unit = new_unit
                    self.prediction_history = []  # Clear prediction history on unit change
                    logging.info("Unit changed - cleared prediction history")

                # Save to config
                config = self.load_config() or {}
                
                # Store target range in mmol format regardless of current unit
                if new_unit == "mgdl":
                    stored_min = new_min / 18.0
                    stored_max = new_max / 18.0
                else:
                    stored_min = new_min
                    stored_max = new_max
                    
                config["min_value"] = stored_min
                config["max_value"] = stored_max
                config["opacity"] = self.opacity
                config["is_pinned"] = self.is_pinned
                config["prediction_enabled"] = self.prediction_enabled
                config["unit"] = new_unit
                self.unit = new_unit  # Update current unit

                with open(self.settings_file_path, 'w') as settings_file:
                    json.dump(config, settings_file)
                self.set_file_permissions(self.settings_file_path)
                
                # Show or hide prediction label based on new setting
                if self.prediction_enabled:
                    self.prediction_label.pack(pady=5)
                    self.prediction_label.config(text="Prediction: --")
                else:
                    self.prediction_label.pack_forget()
                
                self.settings_window.destroy()
            else:
                messagebox.showerror("Invalid Range or Opacity", "Ensure minimum value is less than maximum value and opacity is between 0.0 and 1.0.")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numbers for the target range and opacity.")

    def update_labels(self):
        """Update labels with current glucose and prediction data."""
        try:
            # Skip updates if no data source is set
            if not self.data_source:
                return
            
            glucose_value = None
            bg = None
            color = "black"

            try:
                if self.data_source == "Dexcom" and self.dexcom:
                    # Add retry logic for connection issues
                    try:
                        bg = self.dexcom.get_current_glucose_reading()
                        self.connection_retries = 0  # Reset on success
                    except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                        self.connection_retries += 1
                        if self.connection_retries <= self.max_retries:
                            logging.warning(f"Connection error (retry {self.connection_retries}/{self.max_retries}): {e}")
                            time.sleep(2)  # Wait before retrying
                            return self.update_labels()  # Retry immediately
                        else:
                            logging.error(f"Max connection retries reached: {e}")
                            self.connection_retries = 0
                            raise
                elif self.data_source == "Nightscout" and self.nightscout_url:
                    bg = self.get_nightscout_reading()

                if bg is not None:
                    # Use correct attributes based on unit setting
                    if self.unit == "mgdl":
                        glucose_value = bg.value  # For Dexcom, this is mg_dl
                    else:
                        # For mmol units, use mmol_l for Dexcom
                        if hasattr(bg, 'mmol_l'):
                            glucose_value = bg.mmol_l
                        else:
                            # Convert mg/dL to mmol/L for Nightscout
                            glucose_value = bg.value / 18.0
                    
                    bg_datetime = bg.datetime.replace(tzinfo=None)
                    current_time = datetime.datetime.now()

                    # Only process if we have a new reading (>= 60 seconds since last)
                    if self.last_reading_time is None or (bg_datetime - self.last_reading_time).total_seconds() >= 60:
                        # Calculate delta only when we have a new reading
                        delta_value = 0.0  # Initialize with default value
                        if self.previous_glucose is not None:
                            delta_value = glucose_value - self.previous_glucose

                        # Format delta to one decimal point - safely
                        try:
                            delta_text = f"{delta_value:.1f}"
                        except (TypeError, ValueError):
                            delta_text = "N/A"
                        self.delta_label.configure(text=f"Delta: {delta_text}")
                        self.previous_glucose = glucose_value  # Update previous glucose value

                        # Format glucose value to one decimal point
                        self.glucose_value.set(f"{glucose_value:.1f}")

                        # Check against target range using native units
                        if self.target_range[0] <= glucose_value <= self.target_range[1]:
                            color = "green"
                        elif glucose_value < self.target_range[0]:
                            color = "red"
                            self.trigger_notification(glucose_value)  # Trigger low glucose notification
                        elif glucose_value > self.target_range[1]:
                            color = "orange"
                            self.trigger_notification(glucose_value)  # Trigger high glucose notification
                        self.glucose_label.configure(fg=color)

                        if hasattr(bg, 'trend_description') and bg.trend_description is not None:
                            trend_arrow = self.get_trend_arrow(bg.trend_description)
                            self.trend_label.configure(text=trend_arrow)
                        else:
                            self.trend_label.configure(text="Trend N/A")

                        # Only update prediction history if prediction is enabled
                        if self.prediction_enabled:
                            self.update_prediction_history(bg_datetime, glucose_value)

                        # Handle predictions
                        if self.prediction_enabled:
                            prediction_result = self.predict_glucose()
                            if prediction_result[0] is not None:  # Check if prediction is available
                                prediction_value, delta, trend, confidence = prediction_result
                                
                                # Format prediction with delta and trend
                                prediction_text = f"Prediction (15min): {prediction_value:.1f} ({delta:+.1f} {trend})"
                                if confidence < 90:  # Show confidence if below 90%
                                    prediction_text += f" [{confidence}%]"
                                self.prediction_label.config(text=prediction_text)
                            else:
                                self.prediction_label.config(text="Prediction: --")
                
                        # Update last reading time after processing
                        self.last_reading_time = bg_datetime
                    
                    # Always update time label
                    self.update_time_label()

            except AttributeError as e:
                logging.error(f"Dexcom object not initialized or missing attribute: {e}")
            except Exception as e:
                logging.error(f"Error updating labels: {e}")

        except Exception as e:
            logging.error(f"Error in update_labels: {e}")
        finally:
            # Schedule next update regardless of errors
            self.root.after(1000, self.update_labels)

    def update_time_label(self):
        if self.last_reading_time is not None:
            current_time = datetime.datetime.now()
            time_diff = current_time - self.last_reading_time
            minutes_diff = int(time_diff.total_seconds() // 60)
            self.time_label.configure(text=f"{minutes_diff} minutes ago")

    def get_trend_arrow(self, trend_description):
        arrows = {
            "rising quickly": "↑↑",
            "rising": "↑",
            "rising slightly": "↗",
            "steady": "→",
            "falling slightly": "↘",
            "falling": "↓",
            "falling quickly": "↓↓",
            "unable to determine trend": "?",
        }
        return arrows.get(trend_description.lower(), "→")
    
    def get_windows_notification_icon(self):
        """Get or create ICO icon for Windows notifications."""
        ico_path = os.path.join(app_support_dir, "dexmate_notify.ico")
        
        # Create ICO file if it doesn't exist
        if not os.path.exists(ico_path):
            try:
                png_path = self.get_icon_path()
                if png_path and os.path.exists(png_path):
                    # Convert PNG to ICO
                    img = Image.open(png_path)
                    
                    # Resize to standard notification icon size (64x64)
                    img = img.resize((64, 64), Image.LANCZOS)
                    
                    # Save as ICO
                    img.save(ico_path, format='ICO')
                    logging.info(f"Created notification ICO: {ico_path}")
                else:
                    logging.warning("Source PNG not available for ICO conversion")
                    return None
            except Exception as e:
                logging.error(f"ICO conversion failed: {e}")
                return None
        
        return ico_path

    def trigger_notification(self, glucose_value):
        """Send a notification about glucose levels using notifypy with PNG icon."""
        # Check if notifications are snoozed
        if self.notifications_snoozed_until and datetime.datetime.now() < self.notifications_snoozed_until:
            return
        
        title = "DexMate Glucose Alert"
        unit_label = "mg/dL" if self.unit == "mgdl" else "mmol/L"
        message = f"Glucose level is {'low' if glucose_value < self.target_range[0] else 'high'}: {glucose_value:.1f} {unit_label}"
        
        # Get appropriate icon path
        icon_path = self.get_icon_path()
        
        # Special handling for Windows PNG icons
        if platform.system() == "Windows" and icon_path:
            # Windows needs a temporary BMP file for notifypy to work with PNGs
            icon_path = self.convert_png_to_temp_bmp(icon_path)
    
        try:
            notification = Notify()
            notification.title = title
            notification.application_name = "DexMate"
            notification.message = message
            
            if icon_path and os.path.exists(icon_path):
                notification.icon = icon_path
                
            notification.send()
            logging.info("Notification sent successfully")
        except Exception as e:
            logging.error(f"Notification failed: {e}")
            # Simple fallback without icon
            try:
                notification = Notify()
                notification.title = title
                notification.message = message
                notification.send()
                logging.info("Fallback notification sent successfully")
            except Exception as fallback_error:
                logging.error(f"Fallback notification also failed: {fallback_error}")

    def win32_notification(self, title, message):
        """Fallback notification using Windows API via ctypes."""
        try:
            import ctypes
            
            # Load Windows API functions
            ctypes.windll.user32.MessageBoxW(0, message, title, 0)
            logging.info("Windows API notification sent")
        except Exception as e:
            logging.error(f"Windows API notification failed: {e}")
            # Ultimate fallback to notifypy without icon
            try:
                notification = Notify()
                notification.title = title
                notification.message = message
                notification.send()
            except Exception as fallback_error:
                logging.error(f"Final fallback notification failed: {fallback_error}")

    def set_top_left(self):
        """Position the window in the top-left corner of the work area."""
        work_x, work_y, work_width, work_height = self.get_work_area()
        self.root.geometry(f"+{work_x}+{work_y}")

    def set_bottom_left(self):
        """Position the window in the bottom-left corner of the work area."""
        self.root.update_idletasks()  # Ensure window size is calculated
        work_x, work_y, work_width, work_height = self.get_work_area()
        window_height = self.root.winfo_height()
        y = work_y + work_height - window_height
        self.root.geometry(f"+{work_x}+{y}")

    def set_bottom_right(self):
        """Position the window in the bottom-right corner of the work area."""
        self.root.update_idletasks()  # Ensure window size is calculated
        work_x, work_y, work_width, work_height = self.get_work_area()
        window_width = self.root.winfo_width()
        window_height = self.root.winfo_height()
        x = work_x + work_width - window_width
        y = work_y + work_height - window_height
        self.root.geometry(f"+{x}+{y}")

    def set_top_right(self):
        """Position the window in the top-right corner of the work area."""
        self.root.update_idletasks()  # Ensure window size is calculated
        work_x, work_y, work_width, work_height = self.get_work_area()
        window_width = self.root.winfo_width()
        x = work_x + work_width - window_width
        self.root.geometry(f"+{x}+{work_y}")

    def on_close(self):
        self.save_last_position()
        self.save_history()  # Save history on exit
        self.root.destroy()

    def change_location(self):
        """Cycle through predefined window positions."""
        self.current_location = (self.current_location + 1) % len(self.locations)
        self.locations[self.current_location]()  # Call the next position method
        logging.info(f"Window moved to position: {self.current_location}")

    def schedule_update(self):
        self.root.after(1000, self.update_labels)

    def load_config(self):
        try:
            if not os.path.exists(self.settings_file_path) or os.path.getsize(self.settings_file_path) == 0:
                return None
            with open(self.settings_file_path, 'r') as file:
                config = json.load(file)
                return config
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return None

    def save_config(self, config):
        try:
            with open(self.settings_file_path, 'w') as file:
                json.dump(config, file)
            self.set_file_permissions(self.settings_file_path)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

    def get_nightscout_reading(self):
        """Fetch the latest glucose reading from Nightscout."""
        try:
            endpoint = f"{self.nightscout_url}/api/v1/entries.json?count=2"  # Fetch the last two entries
            headers = {}

            if self.nightscout_api_secret:
                hashed_secret = hashlib.sha1(self.nightscout_api_secret.encode()).hexdigest()
                headers["api-secret"] = hashed_secret

            response = requests.get(endpoint, headers=headers, timeout=10)
            response.raise_for_status()

            entries = response.json()
            if not entries or len(entries) < 2:
                return None

            latest_entry = entries[0]
            previous_entry = entries[1]

            class NightscoutReading:
                pass

            reading = NightscoutReading()
            
            # Always get value in mg/dL from Nightscout
            reading.value = latest_entry.get("sgv", 0)
            reading.datetime = datetime.datetime.fromtimestamp(
                latest_entry["date"] / 1000
            ).replace(tzinfo=None)  # Ensure naive datetime

            # Calculate delta
            previous_glucose = previous_entry.get("sgv", 0)
            reading.delta = reading.value - previous_glucose

            direction_map = {
                "DoubleUp": "rising quickly",
                "SingleUp": "rising",
                "FortyFiveUp": "rising slightly",
                "Flat": "steady",
                "FortyFiveDown": "falling slightly",
                "SingleDown": "falling",
                "DoubleDown": "falling quickly",
                "NOT COMPUTABLE": "unable to determine trend",
                "RATE OUT OF RANGE": "unable to determine trend"
            }
            reading.trend_description = direction_map.get(latest_entry.get("direction", "NOT COMPUTABLE"), "unable to determine trend")

            return reading

        except Exception as e:
            logging.error(f"Nightscout error: {str(e)}")
            return None

    def toggle_data_source_fields(self):
        # Clear existing fields
        for widget in self.fields_container.winfo_children():
            widget.destroy()

        if self.source_var.get() == "Dexcom":
            # Dexcom fields
            tk.Label(self.fields_container, text="Dexcom Username:").pack(anchor='w')
            self.username_entry = tk.Entry(self.fields_container)
            self.username_entry.pack(fill='x', pady=5)

            tk.Label(self.fields_container, text="Dexcom Password:").pack(anchor='w')
            self.password_entry = tk.Entry(self.fields_container, show="*")
            self.password_entry.pack(fill='x', pady=5)
            
            # Region selection
            tk.Label(self.fields_container, text="Region:").pack(anchor='w')
            self.region_var = tk.StringVar(value="us")
            region_frame = tk.Frame(self.fields_container)
            region_frame.pack(fill='x', pady=5)
            ttk.Radiobutton(region_frame, text="US", variable=self.region_var, value="us").pack(side="left")
            ttk.Radiobutton(region_frame, text="OUS", variable=self.region_var, value="ous").pack(side="left")
            ttk.Radiobutton(region_frame, text="Japan", variable=self.region_var, value="jp").pack(side="left")
        else:
            # Nightscout fields
            tk.Label(self.fields_container, text="Nightscout URL:").pack(anchor='w')
            self.ns_url_entry = tk.Entry(self.fields_container)
            self.ns_url_entry.pack(fill='x', pady=5)

            tk.Label(self.fields_container, text="API Secret (if required):").pack(anchor='w')
            self.ns_secret_entry = tk.Entry(self.fields_container, show="*")
            self.ns_secret_entry.pack(fill='x', pady=5)

            tk.Label(self.fields_container, text="Note: URL should be in format: https://your-site.domain or for local server: http://ip-address:port",
                     font=("Helvetica", 8), fg="gray").pack(anchor='w')

    def save_data_source_config(self):
        """Save configuration for the selected data source."""
        config = {}
        data_source = self.source_var.get()
        config["data_source"] = data_source

        if data_source == "Dexcom":
            username = self.username_entry.get()
            password = self.password_entry.get()
            region = self.region_var.get()

            if not username or not password:
                messagebox.showerror("Input Error", "Both username and password are required for Dexcom")
                return

            # Save credentials to ENCRYPTED storage
            self.save_credentials("Dexcom", {
                "username": username,
                "password": password
            })
            config["region"] = region
            self.region = region
            self.authenticate_dexcom(username, password)
            
            # Trigger immediate update
            self.root.after(100, self.update_labels)

        elif data_source == "Nightscout":
            url = self.ns_url_entry.get().strip()
            if not url:
                messagebox.showerror("Input Error", "Nightscout URL is required")
                return

            # Validate URL format
            if not url.startswith("http"):
                url = "https://" + url

            api_secret = self.ns_secret_entry.get()
            
            # Save Nightscout credentials to ENCRYPTED storage
            self.save_credentials("Nightscout", {
                "url": url,
                "api_secret": api_secret
            })
            self.nightscout_url = url
            self.nightscout_api_secret = api_secret
            
            # Trigger immediate update
            self.root.after(100, self.update_labels)

        # Save NON-SENSITIVE config only
        self.save_config(config)
        
        # Update the current data source immediately
        self.data_source = data_source
        logging.info(f"Data source set to: {data_source}")
        
        self.login_window.destroy()
        self.login_window_created = False
        logging.info("Login window closed")
        
        # Trigger immediate update
        self.root.after(100, self.update_labels)

    def update_prediction_history(self, timestamp, glucose):
        """Maintain a history of recent glucose readings for prediction"""
        # Convert glucose to mg/dL for consistent storage
        if self.unit == "mmol":
            store_glucose = glucose * 18.0  # Convert to mg/dL
        else:
            store_glucose = glucose
        
        # Filter out old readings (keep only last 60 minutes)
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=60)
        self.prediction_history = [
            (t, g) for t, g in self.prediction_history 
            if t >= cutoff
        ]
        
        # Add new reading if not duplicate
        if not self.prediction_history or timestamp != self.prediction_history[-1][0]:
            self.prediction_history.append((timestamp, store_glucose))
            logging.info(f"Added to history: {timestamp} - {store_glucose:.1f} mg/dL")
        
        # Save history after each update
        self.save_history()

    def predict_glucose(self):
        """Predict glucose 15 minutes ahead using time-aware linear regression"""
        if len(self.prediction_history) < 3:
            logging.info("Prediction skipped: Not enough history data")
            return None, None, None, None

        try:
            # Create a segment of consecutive readings without large gaps
            segment = []
            sorted_history = sorted(self.prediction_history, key=lambda x: x[0])
            
            # Start from most recent reading and go backward
            segment.append(sorted_history[-1])
            for i in range(len(sorted_history)-2, -1, -1):
                time_gap = (segment[0][0] - sorted_history[i][0]).total_seconds() / 60
                if time_gap > 15:  # Found a gap larger than 15 minutes
                    break
                segment.insert(0, sorted_history[i])  # Add to beginning
                
            if len(segment) < 3:
                logging.info(f"Prediction skipped: Only {len(segment)} consecutive readings")
                return None, None, None, None
                
            timestamps, glucose_vals = zip(*segment)
            
            # Log segment being used
            segment_str = ", ".join(
                f"{t.strftime('%H:%M')}:{g:.1f}mg/dL" 
                for t, g in segment
            )
            logging.info(f"Using consecutive segment: {segment_str}")
            
            # Calculate time differences in minutes from most recent reading
            base_time = timestamps[-1]  # Most recent reading
            time_deltas = [(t - base_time).total_seconds() / 60 for t in timestamps]
            
            # Prepare data for regression
            X = np.array(time_deltas).reshape(-1, 1)
            y = np.array(glucose_vals)
            
            # Fit linear regression model
            model = LinearRegression()
            model.fit(X, y)
            
            # Predict 15 minutes from last reading
            prediction_mgdl = model.predict([[15]])[0]
            
            # Calculate trend and confidence
            last_glucose = glucose_vals[-1]
            delta_mgdl = prediction_mgdl - last_glucose
            slope = model.coef_[0]  # mg/dL per minute
            
            # Convert slope to mmol/min for consistent trend thresholds
            slope_mmol = slope / 18.0
            
            # Determine trend arrow
            if slope_mmol > 0.03: trend = "↑↑"
            elif slope_mmol > 0.01: trend = "↑"
            elif slope_mmol < -0.03: trend = "↓↓"
            elif slope_mmol < -0.01: trend = "↓"
            else: trend = "→"
            
            # Calculate confidence (R² + time span factor)
            r2 = max(0, model.score(X, y))
            time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 60
            confidence = int((r2 * 0.7 + min(1, time_span/30) * 0.3) * 100)
            
            # Convert to display unit
            if self.unit == "mmol":
                prediction = prediction_mgdl / 18.0
                delta = delta_mgdl / 18.0
            else:
                prediction = prediction_mgdl
                delta = delta_mgdl
            
            # Validate prediction sanity
            reasonable_min = 2.0 if self.unit == "mmol" else 36.0
            reasonable_max = 25.0 if self.unit == "mmol" else 450.0
            
            if prediction < reasonable_min or prediction > reasonable_max:
                logging.warning(
                    f"Discarding implausible prediction: {prediction:.1f} "
                    f"(min={reasonable_min}, max={reasonable_max})"
                )
                return None, None, None, None
            
            logging.info(
                f"Prediction: {last_glucose/18.0 if self.unit == 'mmol' else last_glucose:.1f} → "
                f"{prediction:.1f} ({trend}), confidence: {confidence}%"
            )
            return prediction, delta, trend, confidence

        except Exception as e:
            logging.error(f"Prediction failed: {e}", exc_info=True)
            return None, None, None, None

    def show_login_window(self):
        """Create and display the login window."""
        if not self.login_window_created:
            self.login_window = tk.Toplevel(self.root)
            self.login_window.title("Data Source Configuration")
            self.login_window.geometry("400x350")
            
            # Set window icon
            self.set_window_icon(self.login_window)

            # Source Selection
            source_frame = ttk.LabelFrame(self.login_window, text="Select Data Source")
            source_frame.pack(padx=10, pady=10, fill="x")

            self.source_var = tk.StringVar(value=self.data_source)
            ttk.Radiobutton(source_frame, text="Dexcom", variable=self.source_var,
                           value="Dexcom", command=self.toggle_data_source_fields).pack(anchor="w", padx=5, pady=5)
            ttk.Radiobutton(source_frame, text="Nightscout", variable=self.source_var,
                           value="Nightscout", command=self.toggle_data_source_fields).pack(anchor="w", padx=5, pady=5)

            # Fields Container
            self.fields_container = ttk.Frame(self.login_window)
            self.fields_container.pack(padx=10, pady=10, fill="both", expand=True)

            # Buttons
            button_frame = ttk.Frame(self.login_window)
            button_frame.pack(padx=10, pady=10, fill="x")

            save_button = ttk.Button(button_frame, text="Save Configuration", command=self.save_data_source_config)
            save_button.pack(side="right", padx=5)

            cancel_button = ttk.Button(button_frame, text="Cancel", command=self.login_window.destroy)
            cancel_button.pack(side="right", padx=5)

            # Initialize fields
            self.toggle_data_source_fields()

            self.login_window_created = True

    def check_for_updates(self):
        """Check for updates in a background thread"""
        def update_check():
            try:
                logging.info("Checking for updates...")
                response = requests.get(UPDATE_CHECK_URL, timeout=10)
                response.raise_for_status()
                release_info = response.json()
                
                # Get the latest version
                latest_version = release_info["tag_name"].lstrip('v')
                
                # Compare versions
                if packaging.version.parse(latest_version) <= packaging.version.parse(VERSION):
                    logging.info(f"Running latest version ({VERSION})")
                    return

                # Get current platform
                current_platform = self.get_current_platform()
                
                # Define platform-specific keywords
                PLATFORM_KEYWORDS = {
                    "windows": ["windows", "win", ".exe"],
                    "macos": ["mac", "osx", ".dmg"],
                    "linux": ["linux", ".deb", ".snap", ".AppImage"]
                }
                
                # Find compatible asset
                compatible_asset = None
                for asset in release_info.get("assets", []):
                    asset_name = asset["name"].lower()
                    
                    # Check for platform keywords
                    if any(kw in asset_name for kw in PLATFORM_KEYWORDS.get(current_platform, [])):
                        compatible_asset = asset
                        break
                
                if not compatible_asset:
                    logging.error(f"No compatible asset found for {current_platform}")
                    return
                    
                download_url = compatible_asset["browser_download_url"]
                self.notify_update_available(latest_version, download_url)
                        
            except Exception as e:
                logging.error(f"Update check failed: {e}")
                
        # Run in background thread
        threading.Thread(target=update_check, daemon=True).start()

    @staticmethod
    def get_current_platform():
        """Get normalized platform name"""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        else:  # Linux variants
            return "linux"

    def notify_update_available(self, new_version, download_url):
        """Notify user about available update"""
        logging.info(f"New version available: {new_version}")
        
        # Create a notification
        notification = Notify()
        notification.title = "DexMate Update Available"
        notification.application_name = "DexMate"
        notification.message = f"Version {new_version} is available. Click to download."
        if self.dexmate_icon_path and os.path.exists(self.dexmate_icon_path):
            notification.icon = self.dexmate_icon_path
        
        # Open download page when clicked
        notification.on_click = lambda: webbrowser.open(download_url)
        
        # Send notification
        notification.send()
        
        # Also show in-app notification
        self.root.after(0, lambda: self.show_update_dialog(new_version, download_url))

    def show_update_dialog(self, new_version, download_url):
        """Show in-app update notification"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Update Available")
        dialog.geometry("400x200")
        dialog.transient(self.root)  # Set as child of main window
        
        # Set icon if available
        if self.dexmate_icon_path and os.path.exists(self.dexmate_icon_path):
            try:
                dialog.icon_img = tk.PhotoImage(file=self.dexmate_icon_path)
                dialog.iconphoto(True, dialog.icon_img)
            except Exception as e:
                logging.error(f"Error setting dialog icon: {e}")
        
        # Content
        tk.Label(dialog, text=f"New DexMate version {new_version} is available!", 
                font=("Helvetica", 14)).pack(pady=20)
        
        tk.Label(dialog, text=f"You're currently using version {VERSION}.", 
                font=("Helvetica", 11)).pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Download Now", 
                 command=lambda: [webbrowser.open(download_url), dialog.destroy()],
                 width=15).pack(side="left", padx=10)
        
        tk.Button(button_frame, text="Remind Later", 
                 command=dialog.destroy,
                 width=15).pack(side="left", padx=10)

    @staticmethod
    def set_file_permissions(file_path):
        """Set secure file permissions for sensitive files."""
        try:
            if platform.system() == "Windows":
                # Remove all access except owner
                os.chmod(file_path, stat.S_IREAD | stat.S_IWRITE)
                # Mark as hidden
                ctypes.windll.kernel32.SetFileAttributesW(file_path, 2)
            else:
                # Unix: Restrict to owner only
                os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logging.error(f"Permission setting failed: {e}")

    def set_file_permissions(self, path):
        """Set secure file permissions with Windows-specific fixes."""
        try:
            if not os.path.exists(path):
                return
                
            if platform.system() == "Windows":
                try:
                    # Reset read-only attribute if set
                    ctypes.windll.kernel32.SetFileAttributesW(path, 128)  # FILE_ATTRIBUTE_NORMAL
                    
                    # Grant full control to current user
                    import win32security
                    import ntsecuritycon
                    
                    user, _, _ = win32security.LookupAccountName("", os.getlogin())
                    sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
                    
                    dacl = win32security.ACL()
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        ntsecuritycon.FILE_ALL_ACCESS,
                        user
                    )
                    
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
                except Exception:
                    # Fallback to basic permission set
                    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            else:
                # Unix: Restrict to owner only
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception as e:
            logging.error(f"Permission setting failed for {path}: {e}")

    def verify_file_creation(self, path):
        """Verify if a file was successfully created and log results."""
        try:
            if os.path.exists(path):
                size = os.path.getsize(path)
                logging.info(f"File verified: {path} (Size: {size} bytes)")
                return True
            else:
                logging.error(f"File creation FAILED: {path}")
                return False
        except Exception as e:
            logging.error(f"File verification error for {path}: {e}")
            return False

    def open_data_directory(self):
        """Open the application data directory in the file explorer."""
        try:
            if platform.system() == "Windows":
                os.startfile(app_support_dir)
            elif platform.system() == "Darwin":
                subprocess.run(["open", app_support_dir])
            else:  # Linux
                subprocess.run(["xdg-open", app_support_dir])
        except Exception as e:
            logging.error(f"Could not open data directory: {e}")
            messagebox.showerror("Error", f"Could not open directory: {e}")

    def check_file_locks(self):
        """Check if any files are locked and log results."""
        files_to_check = [
            self.credentials_file_path,
            self.settings_file_path,
            self.history_file
        ]
        
        for file_path in files_to_check:
            if not os.path.exists(file_path):
                continue
            
            try:
                # Try to open in append mode to check lock
                with open(file_path, 'a') as f:
                    f.write("\n")
                logging.info(f"File {os.path.basename(file_path)} is NOT locked")
            except IOError as e:
                logging.warning(f"File {os.path.basename(file_path)} is LOCKED: {e}")

    def safe_write_json(self, file_path, data, retries=3):
        """Safely write JSON data with Windows permission fixes."""
        for attempt in range(retries):
            try:
                # Create directory if needed
                dir_path = os.path.dirname(file_path)
                if dir_path and not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                    self.set_file_permissions(dir_path)
            
                # Write to temporary file first
                temp_path = file_path + f'.tmp{random.randint(1000,9999)}'
                with open(temp_path, 'w') as f:
                    json.dump(data, f)
                
                # Ensure permissions before move
                self.set_file_permissions(temp_path)
                
                # Atomic replace
                if os.path.exists(file_path):
                    self.set_file_permissions(file_path)  # Ensure target is writable
                os.replace(temp_path, file_path)
                
                # Final permission set
                self.set_file_permissions(file_path)
                return True
            except PermissionError as pe:
                logging.warning(f"Attempt {attempt+1} permission error: {pe}")
                time.sleep(0.5 * (attempt + 1))
            except Exception as e:
                logging.error(f"Write error: {e}")
                break
    
        # Fallback to user's temp directory
        try:
            temp_dir = tempfile.gettempdir()
            fallback_path = os.path.join(temp_dir, os.path.basename(file_path))
            
            with open(fallback_path, 'w') as f:
                json.dump(data, f)
            
            logging.warning(f"Used fallback location: {fallback_path}")
            return True
        except Exception as e:
            logging.critical(f"Fallback write failed: {e}")
            return False
    def save_last_position(self):
        """Save the last window position to the settings file."""
        try:
            # Get the current window position
            position = {
                "x": self.root.winfo_x(),
                "y": self.root.winfo_y(),
                "is_pinned": self.is_pinned
            }
            
            # Load existing settings or create a new dictionary
            settings = self.load_settings() or {}
            settings["last_position"] = position
            
            # Save settings to file
            self.safe_write_json(self.settings_file_path, settings)
            logging.info("Window position saved successfully")
        except Exception as e:
            logging.error(f"Error saving window position: {e}")

    def load_last_position(self):
        """Load the last saved window position with fallbacks."""
        try:
            # Try to load position from settings
            settings = self.load_settings()
            if settings and "last_position" in settings:
                pos = settings["last_position"]
                if isinstance(pos, dict) and "x" in pos and "y" in pos:
                    self.root.geometry(f"+{pos['x']}+{pos['y']}")
                    self.is_pinned = settings.get("is_pinned", False)
                    self.root.wm_attributes("-topmost", self.is_pinned)
                    return
            
            # Fallback to default position
            self.set_top_left()
        except Exception as e:
            logging.error(f"Error loading last position: {e}")
            self.set_top_left()

    def on_close(self):
        """Handle window close event safely."""
        try:
            # Save the last window position
            self.save_last_position()
        except Exception as e:
            logging.error(f"Error during close: {e}")
        finally:
            # Ensure the window closes regardless of errors
            self.root.destroy()

    def snooze_notifications(self):
        """Snooze notifications for a specified duration."""
        try:
            # Prompt the user for snooze duration in minutes
            duration = simpledialog.askinteger(
                "Snooze Alerts",
                "Enter snooze duration in minutes:",
                minvalue=1,
                maxvalue=120
            )
            if duration:
                self.notifications_snoozed_until = datetime.datetime.now() + datetime.timedelta(minutes=duration)
                logging.info(f"Notifications snoozed until {self.notifications_snoozed_until}")
                messagebox.showinfo("Snooze Alerts", f"Notifications snoozed for {duration} minutes.")
        except Exception as e:
            logging.error(f"Error snoozing notifications: {e}")
            messagebox.showerror("Error", "Failed to snooze notifications.")

    def set_window_icon(self, window):
        """Set the window icon for any Tk or Toplevel window."""
        if not self.dexmate_icon_path or not os.path.exists(self.dexmate_icon_path):
            return
        
        try:
            # Windows needs special handling for .ico files
            if platform.system() == "Windows":
                # Convert PNG to ICO in temp directory
                ico_path = self.convert_png_to_ico(self.dexmate_icon_path)
                if ico_path:
                    window.iconbitmap(ico_path)
                    logging.info(f"Set window icon using ICO: {ico_path}")
                else:
                    # Fallback to PNG if conversion fails
                    icon_img = tk.PhotoImage(file=self.dexmate_icon_path)
                    window.iconphoto(True, icon_img)
                    logging.info("Set window icon using PNG fallback")
            else:
                # Non-Windows platforms can use PNG directly
                icon_img = tk.PhotoImage(file=self.dexmate_icon_path)
                window.iconphoto(True, icon_img)
                logging.info("Window icon set successfully")
        except Exception as e:
            logging.error(f"Error setting window icon: {e}")

    def get_work_area(self):
        if platform.system() == "Windows":
            try:
                import ctypes
                user32 = ctypes.windll.user32
                SPI_GETWORKAREA = 48

                class RECT(ctypes.Structure):
                    _fields_ = [
                        ("left", ctypes.c_long),
                        ("top", ctypes.c_long),
                        ("right", ctypes.c_long),
                        ("bottom", ctypes.c_long)
                    ]

                rect = RECT()
                ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.pointer(rect), 0)
                return (rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
            except Exception:
                # Fallback if ctypes fails
                return (0, 0, self.root.winfo_screenwidth(), self.root.winfo_screenheight())
        else:
            # For macOS/Linux, use screen dimensions (most window managers handle this automatically)
            return (0, 0, self.root.winfo_screenwidth(), self.root.winfo_screenheight())

    def load_prediction_model(self):
        """Load previously trained model parameters."""
        model_path = self.get_file_path('prediction_model.json')
        try:
            if os.path.exists(model_path):
                with open(model_path, 'r') as f:
                    model_data = json.load(f)
                    self.model.coef_ = np.array(model_data['coef'])
                    self.model.intercept_ = model_data['intercept']
                    logging.info(f"Loaded trained model from {model_data['last_trained']}")
        except Exception as e:
            logging.error(f"Error loading model: {e}")

    def update_prediction_model(self, actual_value):
        """Update model with actual glucose value for continuous learning."""
        if self.last_prediction and self.prediction_history:
            try:
                # Get features used in last prediction
                X = self.last_prediction_features
                y = actual_value
                
                # Update model with new data point
                self.model.partial_fit(X, np.array([y]))
                
                # Save updated model
                self.save_prediction_model()
                logging.info("Model updated successfully")
            except Exception as e:
                logging.error(f"Model update failed: {e}")
        logging.info("Securely cleaned memory")

    def verify_directory_permissions(self):
        """Check and fix directory permissions."""
        try:
            test_file = os.path.join(app_support_dir, 'permission_test.tmp')
            
            # Test write permission
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            return True
        except PermissionError:
            logging.warning("Directory not writable, attempting repair")
            
            try:
                if platform.system() == "Windows":
                    # Take ownership of directory
                    subprocess.run(
                        ['takeown', '/f', app_support_dir, '/r', '/d', 'y'],
                        check=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    # Grant full control to current user
                    import win32security
                    import ntsecuritycon
                    
                    user, _, _ = win32security.LookupAccountName("", os.getlogin())
                    sd = win32security.GetFileSecurity(app_support_dir, win32security.DACL_SECURITY_INFORMATION)
                    

                    dacl = win32security.ACL()
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        ntsecuritycon.FILE_ALL_ACCESS,
                        user
                    )
                    
                    win32security.SetFileSecurity(app_support_dir, win32security.DACL_SECURITY_INFORMATION, sd)
                    
                    logging.info("Directory permissions repaired")
                    return True
            except Exception as e:
                logging.error(f"Error repairing directory permissions: {e}")
                return False
        
        return True  # Default to true if no PermissionError

    def migrate_credentials(self):
        """Move any plaintext credentials to encrypted storage."""
        config = self.load_config()
        if not config:
            return

        migrated = False
        
        # Migrate Dexcom credentials
        if "dexcom_credentials" in config:
            creds = config["dexcom_credentials"]
            if "username" in creds and "password" in creds:
                self.save_credentials("Dexcom", creds)
                del config["dexcom_credentials"]
                migrated = True
        
        # Migrate Nightscout credentials
        if "nightscout_credentials" in config:
            creds = config["nightscout_credentials"]
            if "url" in creds:
                self.save_credentials("Nightscout", creds)
                del config["nightscout_credentials"]
                migrated = True
                
        if migrated:
            self.save_config(config)
            logging.info("Migrated plaintext credentials to encrypted storage")

    def load_encrypted_credentials(self):
        """Load encrypted credentials from the credentials file."""
        try:
            if not os.path.exists(self.credentials_file_path):
                logging.warning("Credentials file does not exist")
                return None
            
            with open(self.credentials_file_path, 'rb') as file:
                encrypted_credentials = file.read()
            
            if not encrypted_credentials:
                logging.warning("Credentials file is empty")
                return None
            
            return encrypted_credentials
        except Exception as e:
            logging.error(f"Failed to load encrypted credentials: {e}")
           

           
            return None

    @staticmethod
    def get_current_platform():
        """Return the current platform as a string."""
        import platform
        return platform.system().lower()

if __name__ == "__main__":
    root = tk.Tk()
    app = GlucoseWidget(root)
    
    # Set icon for main window using our new method
    app.set_window_icon(root)
    
    root.mainloop()
