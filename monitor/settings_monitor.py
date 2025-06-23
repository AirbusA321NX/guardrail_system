import time
import subprocess
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

def _get_firewall_state():
    # Returns a dict of Name→Enabled/Disabled for each profile
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        import json
        data = json.loads(out)
        state = {}
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and "Name" in entry and "Enabled" in entry:
                    state[entry["Name"]] = entry["Enabled"]
        else:
            if isinstance(data, dict) and "Name" in data and "Enabled" in data:
                state[data["Name"]] = data["Enabled"]

        return state
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"Firewall query failed: {str(e)}")
        return {}

def _get_defender_realtime_state():
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-MpPreference | Select-Object DisableRealtimeMonitoring | ConvertTo-Json"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        import json
        data = json.loads(out)
        # If DisableRealtimeMonitoring == true → protection is OFF
        return not data.get("DisableRealtimeMonitoring", False)
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"Defender query failed: {str(e)}")
        return None

def _monitor_loop():
    prev_fw = _get_firewall_state()
    prev_def = _get_defender_realtime_state()
    while True:
        time.sleep(10)
        fw = _get_firewall_state()
        def_state = _get_defender_realtime_state()
        # Compare firewall
        for profile, status in fw.items():
            old = prev_fw.get(profile)
            if old is not None and old != status:
                detail = f"Firewall profile '{profile}' changed from {old} to {status}"
                _flag_settings_change(detail)
        # Compare defender
        if prev_def is not None and def_state is not None and prev_def != def_state:
            detail = f"Defender RealTimeProtection changed from {prev_def} to {def_state}"
            _flag_settings_change(detail)
        prev_fw = fw
        prev_def = def_state

def _flag_settings_change(detail: str):
    try:
        result = analyze_text(f"SETTINGS_CHANGE: {detail}")
    except Exception:
        show_popup("Guardrail AI Failure", "AI analysis failed for settings change. Restarting AI service.")
        try:
            analyze_text("ping")
        except:
            pass
        return
    lower = result.lower()
    if any(k in lower for k in ["danger", "disabled", "unauthorized", "vulnerable"]):
        show_popup("Guardrail Alert: Settings Change", result)
        log_event("SETTINGS_FLAGGED", f"{detail} | AI: {result}")

def start_monitor():
    _monitor_loop()
