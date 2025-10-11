import sqlite3
import os
import sys
import time

try:
    import usb.core
    import usb.util
except ImportError:
    print("PyUSB not installed. Run 'pip install pyusb'")
    sys.exit(1)

DB_PATH = os.path.join(os.path.dirname(file), "usb_devices.db")

# ---------------- SQLite Setup ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS device_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usb_vid TEXT,
        usb_pid TEXT,
        usb_serial TEXT
    )
    ''')
    conn.commit()
    cur.close()
    conn.close()

# ---------------- Helper Functions ----------------
def normalize_serial(serial):
    """Clean serial number and remove garbage."""
    if not serial:
        return "NoSerial"
    try:
        serial = "".join(c for c in serial if c.isprintable()).strip()
        return serial if serial else "NoSerial"
    except Exception:
        return "NoSerial"

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
            "INSERT INTO device_details (usb_vid, usb_pid, usb_serial) VALUES (?, ?, ?)",
            (vid, pid, serial)
        )
        conn.commit()
        print("New device inserted.\n")
    conn.close()

# ---------------- USB Monitoring ----------------
def usb_monitor_loop():
    print("USB monitoring started...\n")
    
    # Step 1: preload currently connected devices
    seen_devices = set()
    devices = usb.core.find(find_all=True)
    for dev in devices:
        vid = f"{dev.idVendor:04X}"
        pid = f"{dev.idProduct:04X}"
        try:
            serial = usb.util.get_string(dev, dev.iSerialNumber)
        except Exception:
            serial = None
        serial = normalize_serial(serial)
        seen_devices.add((vid, pid, serial))
    print(f"{len(seen_devices)} device(s) already connected. Waiting for new devices...\n")
    
    # Step 2: monitor for new devices
    while True:
        devices = usb.core.find(find_all=True)
        for dev in devices:
            vid = f"{dev.idVendor:04X}"
            pid = f"{dev.idProduct:04X}"
            try:
                serial = usb.util.get_string(dev, dev.iSerialNumber)
            except Exception:
                serial = None
            serial = normalize_serial(serial)

            device_key = (vid, pid, serial)

            if device_key not in seen_devices:
                seen_devices.add(device_key)
                print("New Device Detected:")
                print(f"VID: {vid}")
                print(f"PID: {pid}")
                print(f"Serial Number: {serial}\n")
                check_or_insert_device(vid, pid, serial)
        
        time.sleep(1)  # small delay to reduce CPU usage

# ---------------- Main ----------------
if name == "main":
    init_db()
    try:
        usb_monitor_loop()
    except KeyboardInterrupt:
        print("\nUSB monitoring stopped by user.")
        sys.exit(0)
