#!/usr/bin/env python3
"""
USB Device Allow/Block Module for Linux
Integrates with USB Rubber Ducky Detection System
"""

import os
import subprocess
from pathlib import Path

def check_usb_authorization_support():
    """
    Check if the system supports USB authorization (sysfs interface)
    Returns True if USB authorization is available, False otherwise
    """
    usb_devices_path = Path("/sys/bus/usb/devices")
    
    if not usb_devices_path.exists():
        print("⚠️  USB sysfs interface not found (/sys/bus/usb/devices)")
        return False
    
    # Check if at least one USB device has 'authorized' attribute
    for device_path in usb_devices_path.iterdir():
        authorized_file = device_path / "authorized"
        if authorized_file.exists():
            return True
    
    print("⚠️  USB authorization not supported on this system")
    return False

def find_usb_device_paths(vid, pid):
    """
    Find all sysfs paths for USB devices matching VID and PID
    Returns list of device paths
    """
    vid = vid.lower()
    pid = pid.lower()
    device_paths = []
    
    usb_devices_path = Path("/sys/bus/usb/devices")
    
    if not usb_devices_path.exists():
        return device_paths
    
    for device_path in usb_devices_path.iterdir():
        vid_file = device_path / "idVendor"
        pid_file = device_path / "idProduct"
        
        if vid_file.exists() and pid_file.exists():
            try:
                device_vid = vid_file.read_text().strip().lower()
                device_pid = pid_file.read_text().strip().lower()
                
                if device_vid == vid and device_pid == pid:
                    device_paths.append(device_path)
            except Exception:
                continue
    
    return device_paths

def create_udev_block_rule(vid, pid):
    """
    Create a udev rule to block USB device
    Returns True on success, False on failure
    """
    vid = vid.lower()
    pid = pid.lower()
    
    rule_content = f'# Block USB device VID={vid} PID={pid}\n'
    rule_content += f'# Created by USB Rubber Ducky Detection System\n'
    rule_content += f'ACTION=="add", SUBSYSTEMS=="usb", ATTRS{{idVendor}}=="{vid}", ATTRS{{idProduct}}=="{pid}", ATTR{{authorized}}="0"\n'
    
    rule_file = f"/etc/udev/rules.d/99-usb-block-{vid}-{pid}.rules"
    
    try:
        # Check if running as root
        if os.geteuid() != 0:
            print("   ⚠️  Not running as root - cannot create udev rule")
            print("   Run with: sudo python3 usb_monitor_linux.py")
            return False
        
        # Write udev rule
        with open(rule_file, 'w') as f:
            f.write(rule_content)
        
        # Reload udev rules
        subprocess.run(["udevadm", "control", "--reload-rules"], 
                      capture_output=True, check=False)
        subprocess.run(["udevadm", "trigger", "--subsystem-match=usb"], 
                      capture_output=True, check=False)
        
        return True
    except PermissionError:
        print("   ⚠️  Permission denied - run with sudo")
        return False
    except FileNotFoundError:
        print("   ⚠️  udevadm not found - install udev package")
        return False
    except Exception as e:
        print(f"   ⚠️  Error creating udev rule: {e}")
        return False

def remove_udev_block_rule(vid, pid):
    """
    Remove udev block rule for USB device
    Returns True on success, False on failure
    """
    vid = vid.lower()
    pid = pid.lower()
    
    rule_file = f"/etc/udev/rules.d/99-usb-block-{vid}-{pid}.rules"
    
    try:
        # Check if running as root
        if os.geteuid() != 0:
            print("   ⚠️  Not running as root - cannot remove udev rule")
            return False
        
        # Remove rule file if it exists
        if os.path.exists(rule_file):
            os.remove(rule_file)
        
        # Reload udev rules
        subprocess.run(["udevadm", "control", "--reload-rules"], 
                      capture_output=True, check=False)
        subprocess.run(["udevadm", "trigger", "--subsystem-match=usb"], 
                      capture_output=True, check=False)
        
        return True
    except PermissionError:
        print("   ⚠️  Permission denied - run with sudo")
        return False
    except Exception as e:
        print(f"   ⚠️  Error removing udev rule: {e}")
        return False

def authorize_device_immediate(device_path):
    """
    Immediately authorize a USB device via sysfs
    """
    try:
        authorized_file = device_path / "authorized"
        if authorized_file.exists():
            with open(authorized_file, 'w') as f:
                f.write('1')
            return True
    except Exception:
        return False
    return False

def unauthorize_device_immediate(device_path):
    """
    Immediately unauthorize/disable a USB device via sysfs
    """
    try:
        authorized_file = device_path / "authorized"
        if authorized_file.exists():
            with open(authorized_file, 'w') as f:
                f.write('0')
            return True
    except Exception:
        return False
    return False

def block_device_linux(vid, pid):
    """
    Block a USB device by VID and PID
    - Creates persistent udev rule
    - Immediately disables currently connected devices
    
    Args:
        vid: USB Vendor ID (e.g., "0781")
        pid: USB Product ID (e.g., "5567")
    
    Returns:
        True if operation successful, False otherwise
    """
    vid = vid.upper()  # Normalize to uppercase for display
    pid = pid.upper()
    
    print(f"   🔒 Blocking USB device VID={vid}, PID={pid}...")
    
    # Create persistent udev rule
    rule_created = create_udev_block_rule(vid.lower(), pid.lower())
    if rule_created:
        print(f"   ✅ Udev block rule created (persists across reboots)")
    else:
        print(f"   ⚠️  Could not create udev rule (blocking may not persist)")
    
    # Immediately disable any currently connected matching devices
    device_paths = find_usb_device_paths(vid.lower(), pid.lower())
    
    if device_paths:
        for device_path in device_paths:
            if unauthorize_device_immediate(device_path):
                print(f"   ✅ Device {device_path.name} disabled immediately")
            else:
                print(f"   ⚠️  Could not disable {device_path.name}")
        return True
    else:
        print(f"   ℹ️  No matching devices currently connected")
        print(f"   ℹ️  Block rule will apply when device is plugged in")
        return rule_created

def allow_device_linux(vid, pid):
    """
    Allow/enable a USB device by VID and PID
    - Removes persistent udev block rule
    - Immediately enables currently connected devices
    
    Args:
        vid: USB Vendor ID (e.g., "0781")
        pid: USB Product ID (e.g., "5567")
    
    Returns:
        True if operation successful, False otherwise
    """
    vid = vid.upper()  # Normalize to uppercase for display
    pid = pid.upper()
    
    print(f"   🔓 Allowing USB device VID={vid}, PID={pid}...")
    
    # Remove persistent udev rule
    rule_removed = remove_udev_block_rule(vid.lower(), pid.lower())
    if rule_removed:
        print(f"   ✅ Udev block rule removed")
    else:
        print(f"   ℹ️  No block rule found (or could not remove)")
    
    # Immediately enable any currently connected matching devices
    device_paths = find_usb_device_paths(vid.lower(), pid.lower())
    
    if device_paths:
        for device_path in device_paths:
            if authorize_device_immediate(device_path):
                print(f"   ✅ Device {device_path.name} enabled immediately")
            else:
                print(f"   ⚠️  Could not enable {device_path.name}")
        return True
    else:
        print(f"   ℹ️  No matching devices currently connected")
        print(f"   ℹ️  Device will be allowed when plugged in")
        return rule_removed

def get_device_status(vid, pid):
    """
    Get current status of USB device (connected/authorized)
    
    Returns:
        dict with status information
    """
    vid = vid.lower()
    pid = pid.lower()
    
    device_paths = find_usb_device_paths(vid, pid)
    
    if not device_paths:
        return {
            "connected": False,
            "authorized": None,
            "count": 0
        }
    
    authorized_devices = 0
    for device_path in device_paths:
        authorized_file = device_path / "authorized"
        if authorized_file.exists():
            try:
                status = authorized_file.read_text().strip()
                if status == "1":
                    authorized_devices += 1
            except Exception:
                pass
    
    return {
        "connected": True,
        "authorized": authorized_devices > 0,
        "count": len(device_paths),
        "authorized_count": authorized_devices
    }

# Test function for standalone usage
if __name__ == "__main__":
    import sys
    
    print("\n" + "="*60)
    print("USB Device Allow/Block Module - Test Mode")
    print("="*60 + "\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root")
        print("   Some operations may fail without sudo privileges\n")
    
    # Check USB authorization support
    if check_usb_authorization_support():
        print("✅ USB authorization is supported on this system\n")
    else:
        print("❌ USB authorization is NOT supported on this system\n")
        sys.exit(1)
    
    # Interactive test
    vid = input("Enter USB Vendor ID (VID) in hex (e.g., 0781): ").strip()
    pid = input("Enter USB Product ID (PID) in hex (e.g., 5567): ").strip()
    action = input("Type 'block' to disable or 'allow' to enable: ").strip().lower()
    
    print()
    
    if action == "block":
        success = block_device_linux(vid, pid)
        if success:
            print("\n✅ Block operation completed")
        else:
            print("\n⚠️  Block operation completed with warnings")
    
    elif action == "allow":
        success = allow_device_linux(vid, pid)
        if success:
            print("\n✅ Allow operation completed")
        else:
            print("\n⚠️  Allow operation completed with warnings")
    
    elif action == "status":
        status = get_device_status(vid, pid)
        print(f"\n📊 Device Status:")
        print(f"   Connected: {status['connected']}")
        if status['connected']:
            print(f"   Authorized: {status['authorized']}")
            print(f"   Device count: {status['count']}")
            print(f"   Authorized count: {status['authorized_count']}")
    
    else:
        print("❌ Invalid action. Use 'block', 'allow', or 'status'")
