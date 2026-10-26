@echo off
echo [1/7] Push mitmproxy cert...
adb push C:\Users\25293\Desktop\c8750f0d.0 /sdcard/c8750f0d.0

echo [2/7] Clean old backup...
adb shell "su -c 'rm -rf /sdcard/cacerts_backup'"
adb shell "su -c 'mkdir -p /sdcard/cacerts_backup'"

echo [3/7] Backup original system certs BEFORE tmpfs mount...
adb shell "su -c 'cp /system/etc/security/cacerts/* /sdcard/cacerts_backup/'"
                          
echo [4/7] Mount tmpfs over cacerts directory...
adb shell "su -c 'mount -t tmpfs tmpfs /system/etc/security/cacerts'"

echo [5/7] Restore original system certs into tmpfs...
adb shell "su -c 'cp /sdcard/cacerts_backup/* /system/etc/security/cacerts/'"

echo [6/7] Install mitmproxy cert...
adb shell "su -c 'cp /sdcard/c8750f0d.0 /system/etc/security/cacerts/c8750f0d.0'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/*.0'"
adb shell "su -c 'chown 0:0 /system/etc/security/cacerts/*.0'"

echo [7/7] Check cert count and mitmproxy cert...
adb shell "su -c 'ls /system/etc/security/cacerts/ | wc -l'"
adb shell "su -c 'ls -l /system/etc/security/cacerts/ | grep c8750f0d'"

pause