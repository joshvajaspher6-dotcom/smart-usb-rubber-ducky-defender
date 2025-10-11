import sqlite3
import os
import sys
import time
import threading
import webbrowser

try:
    import usb.core
    import usb.util
except ImportError:
    print("PyUSB not installed. Run 'pip install pyusb'")
    sys.exit(1)

import logging
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# ---------------- Database Path ----------------
DB_PATH = os.path.join(os.path.dirname(__file__), "usb_devices.db")

# ---------------- Flask Server Setup ----------------

app = Flask(__name__)
CORS(app)

@app.route("/")
def index():
    return send_from_directory(os.path.dirname(__file__), "index.html")

@app.route("/devices", methods=["GET"])
def get_devices():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM device_details")
    rows = cur.fetchall()
    conn.close()

    seen = set()
    devices = []
    for r in rows:
        key = (r["usb_vid"], r["usb_pid"], r["usb_serial"])
        if key not in seen:
            seen.add(key)
            devices.append({
                "id": r["id"],
                "usb_vid": r["usb_vid"],
                "usb_pid": r["usb_pid"],
                "usb_serial": r["usb_serial"],
                "device_type": r.get("device_type", "unknown")
            })
    return jsonify(devices)

@app.route("/device/<int:device_id>/action", methods=["POST"])
def update_device(device_id):
    data = request.json
    action = data.get("action")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if action == "allow":
        cur.execute("UPDATE device_details SET device_type='whitelisted' WHERE id=?", (device_id,))
    elif action == "block":
        cur.execute("UPDATE device_details SET device_type='blocked' WHERE id=?", (device_id,))
    elif action == "remove":
        cur.execute("DELETE FROM device_details WHERE id=?", (device_id,))
    else:
        conn.close()
        return jsonify({"error": "Invalid action"}), 400
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

def start_server():
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)
    app.run(port=8000)

# ---------------- USB Monitor ----------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS device_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usb_vid TEXT,
        usb_pid TEXT,
        usb_serial TEXT,
        device_type TEXT DEFAULT 'unknown'
    )
    ''')
    conn.commit()
    cur.close()
    conn.close()

def normalize_serial(serial):
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

def usb_monitor_loop():
    print("USB monitoring started...\n")

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

        time.sleep(1)

# ---------------- Main ----------------

if __name__ == "__main__":
    init_db()

    # Start Flask server thread
    threading.Thread(target=start_server, daemon=True).start()

    # Open dashboard in default browser
    webbrowser.open("http://localhost:8000/")

    # Start monitoring
    try:
        usb_monitor_loop()
    except KeyboardInterrupt:
        print("\nUSB monitoring stopped by user.")
        sys.exit(0)
