import numpy as np
import time
import os
import pickle
import re
import threading
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from pynput import keyboard

COMMAND KEYWORDS = [
    "net",
    "tasklist",
    "taskkill",
    "reg",
    "wmic",
    "schtasks",
    "sc",
    "at",
    "rundll32",
    "del",
    "copy",
    "attrib",
    "netsh",
    "certutil",
    "cmd",
    "powershell",
    "powershell.exe",
    "ping",
    "tracert",
    "nslookup",
    "net use",
    "net session",
    "net view",
    "net user",
    "whoami",
    "ipconfig",
    "shutdown",
    "diskpart",
    "reg query",
    "reg add",
    "reg delete",
    "regedit",
    "curl",
    "wget",
    "-nop",               # powershell arguments commonly used maliciously
    "-noni",
    "-enc",
    "iex",                # Invoke-Expression
    ".downloadstring",
    "downloadfile",
    "Base64-encoded commands",
    "Reflection.Assembly",
    "WebClient",
    "Invoke-WebRequest",
    # Additional advanced or context-specific malicious commands:
    "reagentc",            # configure Windows Recovery Environment (can be abused)
    "recover",             # data recovery tool abused for hiding activity
    "MpCmdRun -Scan -ScanType 2", # Windows Defender command-line malware scan (attackers may spoof or toggle)
    "whoami /groups",      # check group privileges
    "qprocess",            # query processes (used in reconnaissance)
    "query",               # general query utilities
    "net start",           # start services potentially maliciously
    "net group",           # enumerate groups
    "net config",          # network configuration info
    "net share",           # list shared resources
    "dsquery",             # Active Directory queries
    "csvde",               # export AD info
    "wusa",                # update installation (abused for patches/tampering)
    "powershell -Command Start-Process cmd -ArgumentList '/c ...'", # command chaining and evasion
    "PsExec",              # remote command execution tool often abused
    "WMIExec",             # remote execution via WMI
    "SMBExec",             # remote SMB execution
    "mshta",               # HTA execution often abused for payloads
    "ssh",                 # Remote secure shell usage on Windows for lateral movement
    "scp",                 # Secure copy for payload transfer
    "Invoke-Command",      # PowerShell remote command execution
    "Get-ADUser",          # PowerShell AD reconnaissance
    "Get-ADGroup",         # PowerShell AD group enumeration
    "Get-Credential",      # Credential harvesting in PowerShell
    "Invoke-Expression",   # code execution
    "Set-ExecutionPolicy"  # to bypass PowerShell script execution restrictions
]


class USBRubberDuckyDetector:
    def __init__(self, model_file='usb_ducky_detector.pkl'):
        self.model_file = model_file
        self.model = None
        self.ducky_threshold_5sec = 100 * 5      # 500 keys/5 sec threshold
        self.rubberducky_speed_threshold = 100   # 100 keys/sec threshold for speed
        self.error_rate_threshold = 0.02
        self.command_rate_threshold = 0.20
        self.keyword_rate_threshold = 0.10

    def generate_training_data(self):
        np.random.seed(42)
        h_avg = np.random.normal(3, 1.5, 500)
        h_err = np.random.normal(0.08, 0.04, 500)
        h_cmd = np.random.normal(0.03, 0.02, 500)
        h_kw = np.random.normal(0.01, 0.01, 500)
        h_max5 = np.random.normal(15, 5, 500)
        h_var = np.random.normal(0.4, 0.15, 500)
        d_avg = np.random.normal(120, 20, 500)
        d_err = np.random.normal(0.005, 0.003, 500)
        d_cmd = np.random.normal(0.25, 0.1, 500)
        d_kw = np.random.normal(0.20, 0.05, 500)
        d_max5 = np.random.normal(500, 50, 500)
        d_var = np.random.normal(0.05, 0.02, 500)

        human = np.column_stack([h_avg,h_err,h_cmd,h_kw,h_max5,h_var])
        ducky = np.column_stack([d_avg,d_err,d_cmd,d_kw,d_max5,d_var])
        X = np.vstack([human, ducky])
        y = np.array([0]*500 + [1]*500)
        return X, y

    def train_model(self):
        X, y = self.generate_training_data()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
        model.fit(X_train, y_train)
        acc = model.score(X_test, y_test)
        print(f"Training complete. Test accuracy: {acc*100:.2f}%")
        with open(self.model_file, 'wb') as f:
            pickle.dump(model, f)
        self.model = model

    def load_model(self):
        if os.path.exists(self.model_file):
            with open(self.model_file,'rb') as f:
                self.model = pickle.load(f)
            return True
        return False

    def extract_features(self, keystrokes):
        n = len(keystrokes)
        if n < 2:
            return None
        ts = [t for t, _ in keystrokes]
        diffs = np.diff(ts)
        duration = ts[-1] - ts[0]
        avg_speed = n / (duration + 1e-3)
        keys_raw = [k for _, k in keystrokes]
        keys = []
        word = ""
        for k in keys_raw:
            klow = k.lower().replace('key.', '').replace('win_l','win').replace('win_r','win')
            if klow == 'space':
                if word: 
                    keys.append(word)
                word = ""
            elif len(klow) == 1 and klow.isprintable():
                word += klow
            else:
                if word: 
                    keys.append(word)
                word = ""
                keys.append(klow)
        if word:
            keys.append(word)
        total_keys = n
        error_keys = ['backspace', 'delete']
        error_rate = sum(k in error_keys for k in keys) / max(1, total_keys)
        command_keys = ['enter', 'return']
        command_rate = sum(k in command_keys for k in keys) / max(1, total_keys)
        typed_text = " ".join(keys)
        terminal_triggered = False
        terminal_commands = ["cmd", "powershell", "terminal", "bash", "sh", "zsh"]
        for idx in range(len(keys)-1):
            k1 = keys[idx]
            k2 = keys[idx+1]
            if (k1 == "cmd" and k2 == "r") or (k1 == "win" and k2 == "r"):
                terminal_triggered = True
            if k1 in terminal_commands and k2 in command_keys:
                terminal_triggered = True
            if k1 == "sudo" and k2 == "apt":
                terminal_triggered = True
        keyword_count = sum([len(re.findall(r"\b{}\b".format(re.escape(kw)), typed_text)) for kw in COMMAND_KEYWORDS])
        keyword_rate = keyword_count / max(1, len(typed_text.replace(" ", "")))
        variance = np.var(diffs) if diffs.size > 0 else 0
        return {
            'total_keys_5sec': total_keys,
            'avg_speed': avg_speed,
            'error_rate': error_rate,
            'command_rate': command_rate,
            'keyword_rate': keyword_rate,
            'variance': variance,
            'terminal_triggered': terminal_triggered,
            'typed_text': typed_text
        }

    def predict(self, features):
        trigger_reason = []
        if features['avg_speed'] >= self.rubberducky_speed_threshold:
            trigger_reason.append(f"Extreme typing speed ({features['avg_speed']:.2f} keys/sec)")
            return 'USB_DUCKY', 100.0, trigger_reason
        if features.get('terminal_triggered', False):
            trigger_reason.append("Terminal open sequence detected")
            return 'USB_DUCKY', 100.0, trigger_reason
        if self.model is None:
            return None, None, []
        vector = np.array([
            features['avg_speed'],
            features['error_rate'],
            features['command_rate'],
            features['keyword_rate'],
            features['total_keys_5sec'],
            features['variance']
        ]).reshape(1, -1)
        pred = self.model.predict(vector)[0]
        conf = self.model.predict_proba(vector)[0][pred] * 100
        if pred == 1:
            if features['total_keys_5sec'] > self.ducky_threshold_5sec:
                trigger_reason.append(f"High number of keys ({features['total_keys_5sec']})")
            if features['error_rate'] < self.error_rate_threshold:
                trigger_reason.append(f"Very low error rate ({features['error_rate']*100:.2f}%)")
            if features['command_rate'] > self.command_rate_threshold:
                trigger_reason.append(f"High command rate ({features['command_rate']*100:.2f}%)")
            if features['keyword_rate'] > self.keyword_rate_threshold:
                trigger_reason.append(f"High keyword rate ({features['keyword_rate']*100:.2f}%)")
            if not trigger_reason:
                trigger_reason.append("ML model classification")
        return ('USB_DUCKY' if pred else 'HUMAN'), conf, trigger_reason


def capture_5_seconds():
    keystrokes = []

    def on_press(key):
        keystrokes.append((time.time(), getattr(key, 'char', str(key))))

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    time.sleep(5)   
    listener.stop()
    listener.join()

    return keystrokes


if __name__ == '__main__':
    detector = USBRubberDuckyDetector()
    if not detector.load_model():
        print("Training model for USB Rubber Ducky detection (first run only)...")
        detector.train_model()
    else:
        print("Loaded pre-trained USB Rubber Ducky model.")

    print("Start typing for 5 seconds...")
    data = capture_5_seconds()
    features = detector.extract_features(data)
    if not features:
        print("Normal USB Device Detected.")
        exit()

    print("\n--- Feature Calculation ---")
    print(f"Typed text:        {features.get('typed_text', 'N/A')}")
    print(f"Total keys (5s):   {features['total_keys_5sec']}")
    print(f"Average speed:     {features['avg_speed']:.2f} keys/sec")
    print(f"Error rate:        {features['error_rate']*100:.2f}%")
    print(f"Command rate:      {features['command_rate']*100:.2f}%")
    print(f"Keyword rate:      {features['keyword_rate']*100:.2f}%")
    print(f"Timing variance:   {features['variance']:.5f}")
    print(f"Terminal opened:   {'YES' if features['terminal_triggered'] else 'NO'}")

    if features['terminal_triggered']:
        print("!!! ALERT: Terminal opening pattern detected in typed text !!!")

    result, confidence, reasons = detector.predict(features)

    print("\n--- Detection Result ---")
    print(f"Classification: {result}")
    if confidence is not None:
        print(f"Confidence:     {confidence:.2f}%")
    if reasons:
        print("\nTrigger Reasons:")
        for reason in reasons:
            print(f"  - {reason}")

    if result == 'HUMAN':
        print("\n✓ Normal USB/Drivers detected.")
    else:
        print("\n⚠ WARNING: Potential USB Rubber Ducky attack detected!")
