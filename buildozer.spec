[app]
title = Secure Keylogger
package.name = securekeylogger
package.domain = org.securekeylogger

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json

version = 1.0
requirements = python3,kivy==2.2.1,kivymd==1.1.1,plyer==2.1.0,android-permissions==1.1.1,cryptography==41.0.1,pillow==10.0.0,pynput==1.7.6,schedule==1.2.0

orientation = portrait
fullscreen = 0

android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 33
android.minapi = 21
android.sdk = 33
android.ndk = 25b
android.arch = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1

buildozer android clean
buildozer android debug

# Check if the APK file exists
ls -la bin/securekeylogger-1.0-debug.apk

cat .buildozer/android/platform/python-for-android/dists/securekeylogger/build.log

buildozer requirements

cp bin/securekeylogger-1.0-debug.apk "/c/Users/Devansh Patel/Downloads/securekeylogger-1.0-debug.apk"

ls -la "/c/Users/Devansh Patel/Downloads/securekeylogger-1.0-debug.apk"