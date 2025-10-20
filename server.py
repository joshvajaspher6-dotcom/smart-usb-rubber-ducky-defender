#server.py
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import sqlite3
import os
import logging
from allow_block import block_device, allow_device, find_devcon

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(_file_)), "usb_devices.db")

app = Flask(_name_)
CORS(app)

devcon_path = find_devcon()

@app.route("/")
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(_file_)), "index.html")

@app.route("/devices", methods=["GET"])
def get_devices():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM device_details ORDER BY last_seen DESC")
    rows = cur.fetchall()
    conn.close()
    
    # ✅ Remove duplicates by VID, PID, Serial
    seen = set()
    devices = []
    for r in rows:
        key = (r["usb_vid"], r["usb_pid"], r["usb_serial"])
        if key not in seen:
            seen.add(key)
            # ✅ sqlite3.Row doesn't support .get(), use dict()
            device_dict = dict(r)
            devices.append({
                "id": device_dict["id"],
                "usb_vid": device_dict["usb_vid"],
                "usb_pid": device_dict["usb_pid"],
                "usb_serial": device_dict["usb_serial"],
                "device_type": device_dict["device_type"],
                "threat_level": device_dict.get("threat_level", "unknown")
            })
    
    return jsonify(devices)

@app.route("/device/<int:device_id>/action", methods=["POST"])
def update_device(device_id):
    """Handle dashboard actions: allow, block, remove"""
    data = request.get_json(force=True)
    action = data.get("action")
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # ✅ Fetch device info safely
    cur.execute("SELECT usb_vid, usb_pid FROM device_details WHERE id=?", (device_id,))
    device = cur.fetchone()
    
    if not device:
        conn.close()
        return jsonify({"error": "Device not found"}), 404
    
    vid, pid = device
    
    if action == "allow":
        print(f"\n🔓 Dashboard: Allowing device VID={vid}, PID={pid}")
        cur.execute(
            "UPDATE device_details SET device_type='whitelisted', threat_level='low' WHERE id=?", 
            (device_id,)
        )
        conn.commit()
        if devcon_path:
            allow_device(vid, pid, devcon_path)
            print("✅ Device physically enabled")
        else:
            print("⚠ Cannot physically enable - devcon.exe not found")
    
    elif action == "block":
        print(f"\n🔒 Dashboard: Blocking device VID={vid}, PID={pid}")
        cur.execute(
            "UPDATE device_details SET device_type='blocked', threat_level='high' WHERE id=?", 
            (device_id,)
        )
        conn.commit()
        if devcon_path:
            block_device(vid, pid, devcon_path)
            print("✅ Device physically blocked")
        else:
            print("⚠ Cannot physically block - devcon.exe not found")
    
    elif action == "remove":
        print(f"\n🗑 Dashboard: Removing device VID={vid}, PID={pid} from database")
        cur.execute("DELETE FROM device_details WHERE id=?", (device_id,))
        conn.commit()
        print("✅ Device removed from database")
    
    else:
        conn.close()
        return jsonify({"error": "Invalid action"}), 400
    
    conn.close()
    return jsonify({"status": "success", "vid": vid, "pid": pid})

def start_server():
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.logger.setLevel(logging.ERROR)
    app.run(port=8000, debug=False)

# ✅ Ensure it can run directly
if _name_ == "_main_":
    print("📂 Using database:", DB_PATH)
    start_server()
