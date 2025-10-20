#usb_monitor.py
import time
import sqlite3
import threading
import webbrowser
import os
import sys
from usbmonitor import USBMonitor
from usbmonitor.attributes import ID_MODEL_ID, ID_VENDOR_ID, ID_SERIAL
import server
from ml import USBRubberDuckyDetector, capture_5_seconds
from allow_block import block_device, allow_device, find_devcon

DB_PATH = os.path.join(os.path.dirname(_file_), "usb_devices.db")

# ---------------- SQLite Setup ----------------
def initialize_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS device_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usb_vid TEXT,
            usb_pid TEXT,
            usb_serial TEXT,
            device_type TEXT DEFAULT 'unknown',
            threat_level TEXT DEFAULT 'unknown',
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

initialize_database()

# ---------------- ML Detector Setup ----------------
ml_detector = USBRubberDuckyDetector()
if not ml_detector.load_model():
    print("Training ML model for first-time use...")
    ml_detector.train_model()
else:
    print("✅ ML model loaded successfully.")

# ---------------- DevCon Setup ----------------
devcon_path = find_devcon()
if not devcon_path:
    print("⚠  Warning: devcon.exe not found. Physical blocking will not work.")
    print("   Download Windows Driver Kit and place devcon.exe in project folder.")
else:
    print(f"✅ DevCon found at: {devcon_path}")

# ---------------- Helper Functions ----------------
def normalize_serial(serial):
    return serial.split('&')[0] if serial else 'NoSerial'

def print_device_info(vid, pid, serial):
    print(f"\n{'='*60}")
    print(f"📱 Device Detected:")
    print(f"   VID: {vid}")
    print(f"   PID: {pid}")
    print(f"   Serial: {serial}")
    print(f"{'='*60}")

def check_or_insert_device(vid, pid, serial):
    """Check if device exists, insert if new, run ML if unknown"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Check if device exists
    cur.execute(
        "SELECT id, device_type FROM device_details WHERE usb_vid=? AND usb_pid=? AND usb_serial=?",
        (vid, pid, serial)
    )
    existing = cur.fetchone()
    
    if existing:
        device_id, device_type = existing
        print(f"✅ Existing device detected (Type: {device_type})")
        
        # Update last_seen timestamp
        cur.execute(
            "UPDATE device_details SET last_seen=CURRENT_TIMESTAMP WHERE id=?",
            (device_id,)
        )
        conn.commit()
        
        # If device is already whitelisted or blocked, skip ML analysis
        if device_type in ["whitelisted", "blocked"]:
            print(f"   Skipping ML analysis (device already {device_type})")
            conn.close()
            return
        
        # If device is unknown, run ML analysis
        if device_type == "unknown":
            print(f"⚠  Unknown device - triggering ML analysis...")
            conn.close()
            analyze_device_with_ml(vid, pid, serial)
            return
    else:
        # New device - insert with "unknown" status
        cur.execute(
            "INSERT INTO device_details (usb_vid, usb_pid, usb_serial, device_type, threat_level) VALUES (?, ?, ?, ?, ?)",
            (vid, pid, serial, "unknown", "unknown")
        )
        conn.commit()
        print("🆕 New device inserted into database")
        conn.close()
        
        # Run ML analysis for new unknown device
        print("🔍 Triggering ML analysis for new device...")
        analyze_device_with_ml(vid, pid, serial)

def analyze_device_with_ml(vid, pid, serial):
    """Run ML analysis ONLY for unknown devices"""
    print(f"\n{'='*60}")
    print(f"🤖 Starting ML Analysis")
    print(f"{'='*60}")
    print("📊 Monitoring keystrokes for 5 seconds...")
    print("   (Start typing or wait for device activity)")
    
    keystrokes = capture_5_seconds()
    features = ml_detector.extract_features(keystrokes)
    
    if not features or features['total_keys_5sec'] < 5:
        print("   Normal USB Detected.")
        print("   Device remains as 'unknown' - manual review recommended.")
        return
    
    # Run ML prediction
    result, confidence, reasons = ml_detector.predict(features)
    
    print(f"\n{'='*60}")
    print(f"📊 ML Analysis Results")
    print(f"{'='*60}")
    print(f"Classification:  {result}")
    print(f"Confidence:      {confidence:.2f}%")
    print(f"Typing Speed:    {features['avg_speed']:.2f} keys/sec")
    print(f"Error Rate:      {features['error_rate']*100:.2f}%")
    print(f"Command Rate:    {features['command_rate']*100:.2f}%")
    
    if reasons:
        print(f"\n⚠  Threat Indicators Detected:")
        for reason in reasons:
            print(f"   • {reason}")
    
    # Update database based on ML result
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    if result == "USB_DUCKY":
        # Detected as threat - AUTO BLOCK
        print(f"\n{'='*60}")
        print(f"🚨 THREAT DETECTED!")
        print(f"{'='*60}")
        print(f"🔒 Auto-blocking device VID={vid}, PID={pid}...")
        
        # Update database
        cur.execute(
            "UPDATE device_details SET threat_level=?, device_type=? WHERE usb_vid=? AND usb_pid=? AND usb_serial=?",
            ("high", "blocked", vid, pid, serial)
        )
        conn.commit()
        conn.close()
        
        # Physically block the device
        if devcon_path:
            block_device(vid, pid, devcon_path)
            print("✅ Device physically blocked via devcon")
        else:
            print("⚠  Cannot physically block - devcon.exe not found")
    else:
        # Detected as human - keep as unknown (manual review)
        print(f"\n✅ Normal USB/Driver detected")
        print(f"   Device remains as 'unknown' for manual review")
        
        cur.execute(
            "UPDATE device_details SET threat_level=? WHERE usb_vid=? AND usb_pid=? AND usb_serial=?",
            ("low", vid, pid, serial)
        )
        conn.commit()
        conn.close()
    
    print(f"{'='*60}\n")

# ---------------- USB Monitoring Loop ----------------
def usb_monitor_loop():
    print(f"\n{'='*60}")
    print("🔄 USB Monitoring Active")
    print(f"{'='*60}\n")
    
    monitor = USBMonitor()
    seen_devices = set()
    
    while True:
        removed, added = monitor.changes_from_last_check(update_last_check_devices=True)
        
        for device_id, device_info in added.items():
            vid = device_info.get(ID_VENDOR_ID, 'UnknownVID')
            pid = device_info.get(ID_MODEL_ID, 'UnknownPID')
            serial = normalize_serial(device_info.get(ID_SERIAL, 'NoSerial'))
            
            # Skip non-hex VID/PID
            if not all(c in "0123456789abcdefABCDEF" for c in vid) or \
               not all(c in "0123456789abcdefABCDEF" for c in pid):
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
    time.sleep(1)
    print(f"\n🌐 Dashboard started at: http://localhost:8000")
    webbrowser.open("http://localhost:8000/")

# ---------------- Main ----------------
if _name_ == "_main_":
    print(f"\n{'='*60}")
    print("🛡  USB Rubber Ducky Intrusion Detection System")
    print(f"{'='*60}\n")
    
    start_dashboard()
    
    try:
        usb_monitor_loop()
    except KeyboardInterrupt:
        print(f"\n\n{'='*60}")
        print("⏹  USB monitoring stopped by user")
        print(f"{'='*60}\n")
        sys.exit(0)
