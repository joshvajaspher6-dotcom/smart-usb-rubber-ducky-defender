import time
import sqlite3
import threading
import webbrowser
import os
import sys
from usbmonitor import USBMonitor
from usbmonitor.attributes import ID_MODEL_ID, ID_VENDOR_ID, ID_SERIAL
import server


DB_PATH = os.path.join(os.path.dirname(__file__), "usb_devices.db")


# ---------------- SQLite Setup ----------------
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute('''
CREATE TABLE IF NOT EXISTS device_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usb_vid TEXT,
    usb_pid TEXT,
    usb_serial TEXT,
    device_type TEXT
)
''')
conn.commit()
cur.close()
conn.close()


# ---------------- Helper Functions ----------------
def normalize_serial(serial):
    return serial.split('&')[0] if serial else 'NoSerial'


def print_device_info(vid, pid, serial):
    print(f"Device Detected:")
    print(f"  VID: {vid}")
    print(f"  PID: {pid}")
    print(f"  Serial Number: {serial}\n")


def check_or_insert_device(vid, pid, serial):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM device_details WHERE usb_vid=? AND usb_pid=? AND usb_serial=?",
        (vid, pid, serial)
    )
    if cur.fetchone():
        print("Existing device detected.\n")
    else:
        cur.execute(
            "INSERT INTO device_details (usb_vid, usb_pid, usb_serial, device_type) VALUES (?, ?, ?, ?)",
            (vid, pid, serial, "unknown")
        )
        conn.commit()
        print("New device inserted.\n")
    conn.close()


# ---------------- USB Monitoring ----------------
def usb_monitor_loop():
    print("USB monitoring started...")
    monitor = USBMonitor()
    seen_devices = set()  # Track unique devices in this session


    while True:
        removed, added = monitor.changes_from_last_check(update_last_check_devices=True)
        for device_id, device_info in added.items():
            vid = device_info.get(ID_VENDOR_ID, 'UnknownVID')
            pid = device_info.get(ID_MODEL_ID, 'UnknownPID')
            serial = normalize_serial(device_info.get(ID_SERIAL, 'NoSerial'))


            # Skip non-hex VID/PID
            if not all(c in "0123456789abcdefABCDEF" for c in vid) or not all(c in "0123456789abcdefABCDEF" for c in pid):
                continue


            device_key = (vid, pid, serial)
            if device_key not in seen_devices:
                seen_devices.add(device_key)
                print_device_info(vid, pid, serial)
                check_or_insert_device(vid, pid, serial)


        time.sleep(1)


# ---------------- Start Dashboard ----------------
def start_dashboard():
    threading.Thread(target=server.start_server, daemon=True).start()
    webbrowser.open("http://localhost:8000/")


# ---------------- Main ----------------
if __name__ == "__main__":
    start_dashboard()
    try:
        usb_monitor_loop()
    except KeyboardInterrupt:
        print("\nUSB monitoring stopped by user.")
        sys.exit(0)
