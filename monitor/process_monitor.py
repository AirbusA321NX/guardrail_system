import threading
import time
import psutil
import wmi
import hashlib
import json
from datetime import datetime
from pathlib import Path
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

_c = wmi.WMI()
AI_LOG_FILE = Path("D:/pycharm/guardrail_system/logs/ai_interactions.log")


def _ensure_log_dir():
    """Ensure the log directory exists."""
    AI_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def _log_ai_interaction(process_info: dict, ai_response: str, analysis_type: str):
    """Log AI interaction to a dedicated log file."""
    _ensure_log_dir()
    try:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": analysis_type,
            "process_info": process_info,
            "ai_response": ai_response
        }

        with open(AI_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        log_event("AI_LOG_ERROR", f"Failed to log AI interaction: {str(e)}")


def _compute_sha256(path: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return "N/A"


def _monitor_loop():
    process_watcher = _c.Win32_Process.watch_for("creation")
    while True:
        # Initialize variables with default values at the start of each iteration
        proc = None
        process_info = {
            "pid": 0,
            "name": "Unknown",
            "parent_pid": 0,
            "command_line": "",
            "executable": "",
            "sha256": "N/A",
            "username": "N/A",
            "parent_name": "Unknown"
        }
        to_ai = ""
        parent_name = "Unknown"
        cmdline = ""

        try:
            new_proc = process_watcher()
            pid = int(new_proc.ProcessId)
            parent_pid = int(new_proc.ParentProcessId)

            # Update basic process info
            process_info.update({
                "pid": pid,
                "parent_pid": parent_pid
            })

            try:
                proc = psutil.Process(pid)

                # Update process_info with actual process data
                cmdline = " ".join(proc.cmdline()) if proc and proc.cmdline() else ""
                exe = proc.exe() if proc else ""
                sha256 = _compute_sha256(exe) if exe else "N/A"
                process_name = proc.name() if proc else 'Unknown'

                process_info.update({
                    "name": process_name,
                    "command_line": cmdline,
                    "executable": exe,
                    "sha256": sha256,
                    "username": proc.username() if hasattr(proc, 'username') and callable(proc.username) else "N/A"
                })

                # Get parent process name if possible
                try:
                    parent = psutil.Process(parent_pid)
                    parent_name = parent.name().lower()
                    process_info["parent_name"] = parent_name
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    log_event("PARENT_PROCESS_ERROR", f"Failed to access parent process {parent_pid}: {str(e)}")

                # Prepare AI analysis text
                to_ai = f"NewProcess Name: {process_name} PID: {pid}"

                def check_lifetime():
                    nonlocal process_info, to_ai
                    start_time = time.time()
                    while True:
                        if not psutil.pid_exists(pid):
                            duration = time.time() - start_time
                            if duration < 5:
                                try:
                                    analysis_text = f"SHORT_LIVED from {process_info['parent_name']}: {to_ai}"
                                    result = analyze_text(analysis_text)

                                    _log_ai_interaction(process_info, result, "SHORT_LIVED_ANALYSIS")

                                    lower = result.lower()
                                    if any(k in lower for k in ["danger", "malware", "suspicious", "harm"]):
                                        show_popup("Guardrail Alert: Short-lived Process", result)
                                        log_event("SHORT_LIVED_FLAGGED",
                                                  f"PID: {pid} Parent: {process_info['parent_name']} Cmd: {process_info['command_line']} SHA256: {process_info['sha256']} | AI: {result}")
                                except Exception as e:
                                    error_msg = f"AI analysis failed for short-lived process: {str(e)}"
                                    log_event("AI_ANALYSIS_ERROR", error_msg)
                                    show_popup("Guardrail AI Failure",
                                               "AI analysis failed for short-lived process. Restarting AI service.")
                                    try:
                                        analyze_text("ping")
                                    except Exception as e:
                                        log_event("AI_SERVICE_RESTART_FAILED", str(e))
                            return
                        time.sleep(0.5)

                # Spawn a thread to watch lifetime
                threading.Thread(target=check_lifetime, daemon=True).start()

                # Immediately analyze creation
                try:
                    analysis_text = f"PROCESS_CREATION: {to_ai}"
                    result = analyze_text(analysis_text)

                    _log_ai_interaction(process_info, result, "PROCESS_CREATION_ANALYSIS")

                    lower = result.lower()
                    if any(k in lower for k in ["danger", "suspicious", "unauthorized"]):
                        show_popup("Guardrail Alert: New Process Flagged", result)
                        log_event("PROCESS_FLAGGED",
                                  f"PID: {pid} Parent: {process_info['parent_name']} Cmd: {process_info['command_line']} SHA256: {process_info['sha256']} | AI: {result}")
                except Exception as e:
                    error_msg = f"AI analysis failed for process creation: {str(e)}"
                    log_event("AI_ANALYSIS_ERROR", error_msg)
                    show_popup("Guardrail AI Failure",
                               "AI analysis failed for process creation. Restarting AI service.")
                    try:
                        analyze_text("ping")
                    except Exception as e:
                        log_event("AI_SERVICE_RESTART_FAILED", str(e))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                log_event("PROCESS_ERROR", f"Failed to access process {pid}: {str(e)}")
                continue

        except Exception as e:
            log_event("PROCESS_MONITOR_ERROR", str(e))
            time.sleep(1)

def start_monitor():
    _monitor_loop()