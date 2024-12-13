from flask import Flask, jsonify, render_template
import re
import json
import winreg
import os
import subprocess
from datetime import datetime

app = Flask(__name__)

# --- Configuration Section ---
EVENT_LOG_PATTERNS = {
    "Unauthorized Access": r"(Logon failure|Unauthorized access)",
    "Registry Tampering": r"(Registry key modified|Unauthorized registry access)",
    "Privilege Escalation": r"(SeDebugPrivilege|Administrator rights enabled)",
    "Malware Execution": r"(Powershell\.(exe|ps1)|suspicious executable)"
}

REGISTRY_PATTERNS = {
    "Startup Persistence": r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Malicious Script": r"\\Software\\Classes\\ms-settings|shellcode"
}

# --- Log Parsing Functions ---
def parse_event_logs():
    anomalies = []
    try:
        command = "wevtutil qe System /f:text"
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            logs = result.stdout.splitlines()
            for line in logs:
                for attack, pattern in EVENT_LOG_PATTERNS.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        anomalies.append({
                            "timestamp": str(datetime.now()),
                            "type": "Event Log",
                            "attack_type": attack,
                            "details": line.strip(),
                            "link": f"eventvwr.msc /s:{line}"
                        })
    except Exception as e:
        print(f"Error parsing event logs: {e}")
    return anomalies

def parse_registry():
    anomalies = []
    try:
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CLASSES_ROOT, r"Software"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        ]
        for hive, path in hives:
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            value = winreg.EnumValue(key, i)
                            value_name, value_data = value[0], value[1]
                            for attack, pattern in REGISTRY_PATTERNS.items():
                                if re.search(pattern, value_name, re.IGNORECASE) or re.search(pattern, str(value_data), re.IGNORECASE):
                                    anomalies.append({
                                        "timestamp": str(datetime.now()),
                                        "type": "Registry",
                                        "attack_type": attack,
                                        "details": f"{value_name}: {value_data}",
                                        "link": f"regedit.exe /e {path}\\{value_name}"
                                    })
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                print(f"Registry path {path} not found, skipping.")
            except Exception as e:
                print(f"Error accessing registry path {path}: {e}")
    except Exception as e:
        print(f"Error parsing registry: {e}")
    return anomalies

def simulate_and_validate():
    event_log_anomalies = parse_event_logs()
    registry_anomalies = parse_registry()

    all_anomalies = event_log_anomalies + registry_anomalies

    report = {
        "summary": {
            "total_anomalies": len(all_anomalies),
            "event_log_anomalies": len(event_log_anomalies),
            "registry_anomalies": len(registry_anomalies)
        },
        "details": all_anomalies
    }

    return report

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_detection():
    detection_report = simulate_and_validate()
    return render_template('report.html', report=detection_report)

if __name__ == "__main__":
    app.run(debug=True)
