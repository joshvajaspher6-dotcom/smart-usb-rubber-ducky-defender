# server.py
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(_file_), "usb_devices.db")

app = Flask(_name_)
CORS(app)

@app.route("/")
def index():
    return send_from_directory(os.path.dirname(_file_), "index.html")

@app.route("/devices", methods=["GET"])
def get_devices():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM device_details")
    rows = cur.fetchall()
    conn.close()

    # Remove duplicates by VID, PID, Serial
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
                "device_type": r["device_type"]
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
    app.run(port=8000)