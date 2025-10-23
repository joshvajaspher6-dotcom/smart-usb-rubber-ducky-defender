import ctypes
import time
import subprocess
import shutil
import os
import wmi
from usbmonitor import USBMonitor
from usbmonitor.attributes import ID_VENDOR_ID, ID_MODEL_ID

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def find_devcon():
    """Find devcon.exe in current directory or PATH"""
    script_dir = os.path.dirname(__file__)
    local_path = os.path.join(script_dir, "devcon.exe")
    if os.path.isfile(local_path):
        return local_path
    return shutil.which("devcon.exe") or shutil.which("devcon")

def block_device(vid, pid, devcon_path):
    """Physically disable USB device using devcon"""
    pattern = f"USB\\VID_{vid}&PID_{pid}"
    result = subprocess.run(
        [devcon_path, "disable", pattern],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"   ✅ Device BLOCKED: {pattern}")
        return True
    else:
        print(f"   ❌ Failed to block {pattern}")
        if result.stderr:
            print(f"   Error: {result.stderr.strip()}")
        return False

def allow_device(vid, pid, devcon_path):
    """Physically enable USB device using devcon"""
    pattern = f"USB\\VID_{vid}&PID_{pid}"
    result = subprocess.run(
        [devcon_path, "enable", pattern],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"   ✅ Device ALLOWED: {pattern}")
        return True
    else:
        print(f"   ❌ Failed to allow {pattern}")
        if result.stderr:
            print(f"   Error: {result.stderr.strip()}")
        return False

def operate_on_existing(vid, pid, devcon_path, action):
    """Check if device is currently connected and apply action"""
    found = False
    c = wmi.WMI()
    for device in c.Win32_PnPEntity():
        if device.DeviceID and f"VID_{vid.upper()}" in device.DeviceID and f"PID_{pid.upper()}" in device.DeviceID:
            print(f"   Device currently connected: {device.DeviceID}")
            if action == 'block':
                block_device(vid, pid, devcon_path)
            elif action == 'allow':
                allow_device(vid, pid, devcon_path)
            found = True
    return found

def usb_manager(target_vid, target_pid, action):
    """Standalone USB device manager (for manual use)"""
    devcon_path = find_devcon()
    if not devcon_path:
        print("❌ devcon.exe not found.")
        print("   Download Windows Driver Kit (WDK) and place devcon.exe in folder")
        return
    
    print(f"Using devcon at: {devcon_path}")
    
    if not operate_on_existing(target_vid, target_pid, devcon_path, action):
        print(f"No connected device found with VID={target_vid} PID={target_pid}")
    
    monitor = USBMonitor()
    print(f"Monitoring for VID={target_vid}, PID={target_pid}...")
    
    while True:
        _, added = monitor.changes_from_last_check(update_last_check_devices=True)
        for info in added.values():
            vid = info.get(ID_VENDOR_ID)
            pid = info.get(ID_MODEL_ID)
            if vid and pid and vid.lower() == target_vid.lower() and pid.lower() == target_pid.lower():
                print(f"Device detected: VID={vid}, PID={pid}")
                if action == 'block':
                    block_device(target_vid, target_pid, devcon_path)
                elif action == 'allow':
                    allow_device(target_vid, target_pid, devcon_path)
        time.sleep(3)

if __name__ == "__main__":
    if not is_admin():
        print("❌ Please run as Administrator!")
        exit(1)
    
    vid = input("Enter USB Vendor ID (VID) in hex (e.g. 0781): ").strip()
    pid = input("Enter USB Product ID (PID) in hex (e.g. 5567): ").strip()
    action = input("Type 'block' to disable or 'allow' to enable: ").strip().lower()
    
    if action in ['block', 'allow']:
        usb_manager(vid, pid, action)
    else:
        print("Invalid action. Please type 'block' or 'allow'.")
