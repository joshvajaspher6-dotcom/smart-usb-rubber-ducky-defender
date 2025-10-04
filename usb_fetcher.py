import time
import sqlite3
from usbmonitor import USBMonitor
from usbmonitor.attributes import ID_MODEL, ID_MODEL_ID, ID_VENDOR_ID, ID_SERIAL

# ---------------- SQLite Database Setup ----------------
conn = sqlite3.connect("usb_devices.db")
cur = conn.cursor()

# Create table if not exists
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

# ---------------- Helper Functions ----------------
def normalize_serial(serial):
    """Normalize serial number by removing trailing parts"""
    return serial.split('&')[0] if serial else 'NoSerial'

def print_device_info(device_info):
    """Print USB device information"""
    print(f"Device Found: {device_info.get(ID_MODEL, 'Unknown Device')}")
    print(f"  VID: {device_info.get(ID_VENDOR_ID, 'Unknown')}")
    print(f"  PID: {device_info.get(ID_MODEL_ID, 'Unknown')}")
    print(f"  Serial Number: {normalize_serial(device_info.get(ID_SERIAL, 'N/A'))}")

def check_or_insert_device(vid, pid, serial):
    """
    Check if a device with the same VID, PID, and Serial exists.
    If yes -> print existing device.
    If no -> insert into DB and print new device.
    """
    cur.execute(
        "SELECT * FROM device_details WHERE usb_vid=? AND usb_pid=? AND usb_serial=?",
        (vid, pid, serial)
    )
    row = cur.fetchone()
    if row:
        print("Existing device detected.\n")
    else:
        cur.execute(
            "INSERT INTO device_details (usb_vid, usb_pid, usb_serial, device_type) VALUES (?, ?, ?, ?)",
            (vid, pid, serial, "unknown")
        )
        conn.commit()
        print("New device inserted.\n")

# ---------------- USB Monitoring ----------------
print(".......USB monitoring started. Waiting for a new device.......")
monitor = USBMonitor()

new_device_detected = False
start_time = time.time()
timeout = 30  # seconds

while not new_device_detected:
    removed, added = monitor.changes_from_last_check(update_last_check_devices=True)

    for device_id, device_info in added.items():
        vid = device_info.get(ID_VENDOR_ID, 'UnknownVID')
        pid = device_info.get(ID_MODEL_ID, 'UnknownPID')
        serial = normalize_serial(device_info.get(ID_SERIAL, 'NoSerial'))

        print_device_info(device_info)
        check_or_insert_device(vid, pid, serial)

        new_device_detected = True
        break

    if time.time() - start_time > timeout:
        print("No new USB device detected within the timeout period.")
        break

    time.sleep(0.5)

cur.close()
conn.close()
print("USB monitoring stopped.")