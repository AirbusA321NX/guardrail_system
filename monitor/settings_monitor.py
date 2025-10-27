import time
import subprocess
import json
import psutil
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

def _get_defender_comprehensive_state():
    """Get comprehensive Windows Defender settings including real-time protection and other critical settings"""
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        $prefs = Get-MpPreference
        @{
            DisableRealtimeMonitoring = $prefs.DisableRealtimeMonitoring
            DisableBehaviorMonitoring = $prefs.DisableBehaviorMonitoring
            DisableIOAVProtection = $prefs.DisableIOAVProtection
            DisablePrivacyMode = $prefs.DisablePrivacyMode
            SignatureDisableUpdateOnStartupWithoutEngine = $prefs.SignatureDisableUpdateOnStartupWithoutEngine
            DisableArchiveScanning = $prefs.DisableArchiveScanning
            DisableIntrusionPreventionSystem = $prefs.DisableIntrusionPreventionSystem
            DisableScriptScanning = $prefs.DisableScriptScanning
            DisableRemovableDriveScanning = $prefs.DisableRemovableDriveScanning
            DisableEmailScanning = $prefs.DisableEmailScanning
            DisableBlockAtFirstSeen = $prefs.DisableBlockAtFirstSeen
            DisableScanningNetworkFiles = $prefs.DisableScanningNetworkFiles
        } | ConvertTo-Json
        """
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        data = json.loads(out)
        return data
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"Defender comprehensive query failed: {str(e)}")
        return {}

def _get_recent_processes():
    """Get recently running processes that might have modified Defender settings"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                # Get processes created in the last 60 seconds
                create_time = proc.info['create_time']
                if time.time() - create_time < 60:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'cmdline': proc.info['cmdline']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"Process enumeration failed: {str(e)}")
        return []

def _get_defender_service_status():
    """Get Windows Defender service status"""
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-Service WinDefend | Select-Object Status | ConvertTo-Json"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
        data = json.loads(out)
        return data.get("Status", "Unknown")
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"Defender service query failed: {str(e)}")
        return "Unknown"

def _monitor_loop():
    prev_fw = _get_firewall_state()
    prev_def = _get_defender_comprehensive_state()
    prev_def_service = _get_defender_service_status()
    
    while True:
        time.sleep(10)
        fw = _get_firewall_state()
        def_state = _get_defender_comprehensive_state()
        def_service = _get_defender_service_status()
        recent_processes = _get_recent_processes()
        
        # Compare firewall
        for profile, status in fw.items():
            old = prev_fw.get(profile)
            if old is not None and old != status:
                detail = f"Firewall profile '{profile}' changed from {old} to {status}"
                _flag_settings_change(detail, recent_processes)
        
        # Compare defender comprehensive settings
        if prev_def and def_state:
            # Check each Defender setting
            for key, value in def_state.items():
                old_value = prev_def.get(key)
                if old_value is not None and old_value != value:
                    status_text = "DISABLED" if value else "ENABLED"
                    detail = f"Defender {key} changed to {status_text}"
                    _flag_settings_change(detail, recent_processes)
        
        # Compare defender service
        if prev_def_service != def_service:
            detail = f"Defender service status changed from {prev_def_service} to {def_service}"
            _flag_settings_change(detail, recent_processes)
            
        prev_fw = fw
        prev_def = def_state
        prev_def_service = def_service

def _flag_settings_change(detail: str, recent_processes=None):
    try:
        # Include recent processes in the analysis context
        context = f"SETTINGS_CHANGE: {detail}"
        if recent_processes:
            context += "\nRecent processes that might be responsible:\n"
            for proc in recent_processes[:10]:  # Limit to first 10 processes
                context += f"- {proc['name']} (PID: {proc['pid']}) - {proc['exe']}\n"
        
        # Send to AI for analysis
        result = analyze_text(context)
        
        # Parse AI result to extract specific threat information
        ai_analysis = _parse_ai_analysis(result, detail, recent_processes)
        
        # Ensure ai_analysis is a string before passing to show_popup
        if not isinstance(ai_analysis, str):
            ai_analysis = str(ai_analysis)
        
        # Show popup with detailed information
        show_popup("Guardrail Alert: Security Settings Changed", ai_analysis)
        log_event("SETTINGS_FLAGGED", f"{detail} | AI: {result}")
        
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"AI analysis failed for settings change: {str(e)}")
        show_popup("Guardrail AI Failure", f"AI analysis failed for settings change: {str(e)}")
        try:
            analyze_text("ping")
        except:
            pass
        return

def _parse_ai_analysis(ai_result, setting_detail, recent_processes):
    """Parse AI analysis result to extract specific threat information"""
    try:
        # Create a prompt for the AI to analyze the setting change with more context
        prompt = f"""
        Analyze this security setting change and identify the most likely culprit:
        
        Setting Changed: {setting_detail}
        
        Recent Processes:
        {json.dumps(recent_processes[:10], indent=2) if recent_processes else "No recent processes found"}
        
        AI Initial Analysis: {ai_result}
        
        Please provide a concise response in this format:
        1. Threat Assessment: [BRIEF assessment of the threat level]
        2. Likely Culprit: [Specific process/file name if identifiable, otherwise "Unknown"]
        3. Recommendation: [Brief recommendation on what to do]
        
        If a specific process or file is responsible for this change, please identify it by name.
        """
        
        detailed_analysis = analyze_text(prompt)
        # Ensure we always return a string
        return str(detailed_analysis) if detailed_analysis else f"Setting Changed: {setting_detail}\nAI Analysis: {ai_result}"
    except Exception as e:
        log_event("SETTINGS_MONITOR_ERROR", f"AI detailed analysis failed: {str(e)}")
        return f"Setting Changed: {setting_detail}\nAI Analysis: {ai_result}"

def start_monitor():
    _monitor_loop()