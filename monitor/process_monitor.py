import sys
from pathlib import Path
# Add the project root to the Python path to allow for absolute imports
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.append(str(project_root))

import threading
import time
import psutil
import wmi
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from utils.logger import get_logger, setup_logging, log_event
from utils.popups import show_popup
import requests

@dataclass
class ProcessFeatures:
    """Structured process information for analysis."""
    pid: int
    name: str
    parent_pid: int
    parent_name: str
    command_line: str
    executable: str
    sha256: str
    username: str
    api_calls: List[Dict] = field(default_factory=list)
    file_operations: List[Dict] = field(default_factory=list)
    registry_ops: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging and serialization."""
        return {
            'pid': self.pid,
            'name': self.name,
            'parent_pid': self.parent_pid,
            'parent_name': self.parent_name,
            'command_line': self.command_line,
            'executable': self.executable,
            'sha256': self.sha256,
            'username': self.username,
            'api_calls': self.api_calls,
            'file_operations': self.file_operations,
            'registry_ops': self.registry_ops,
            'network_connections': self.network_connections
        }

setup_logging("process_monitor.log")
logger = get_logger(__name__)

# Try to import the AI analysis functions from the mistral_analysis module.
# If the import fails, create placeholder (dummy) functions so the rest of the script can run without crashing.
try:
    from ai.mistral_analysis import analyze_text
except ImportError as e:
    logger.error("AI analysis module could not be imported: %s", e)
    logger.info("Creating placeholder AI functions to allow the monitor to run without AI analysis.")
    def analyze_text(prompt: str, **metadata) -> dict: 
        logger.error("AI analysis module not found.")
        return {"DANGEROUS": False, "reason": "Error: AI module missing."}

_c = wmi.WMI()
AI_LOG_FILE = Path("D:/pycharm/guardrail_system/logs/ai_interactions.log")


def _log_ai_interaction(process_info: dict, ai_response: str, analysis_type: str):
    """Log AI interaction to a dedicated log file."""
    AI_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
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
        logger.error("Failed to log AI interaction: %s", str(e))


def _compute_sha256(path: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return "N/A"


def _get_process_features(pid: int, parent_pid: int) -> Optional[ProcessFeatures]:
    """Safely gathers all features for a given process PID."""
    try:
        proc = psutil.Process(pid)
        cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
        exe = proc.exe()
        sha256 = _compute_sha256(exe) if exe else "N/A"
        process_name = proc.name()
        username = proc.username() if hasattr(proc, 'username') and callable(proc.username) else "N/A"

        parent_name = "Unknown"
        try:
            parent = psutil.Process(parent_pid)
            parent_name = parent.name().lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # This is common for system processes, so we just log it lightly
            logger.debug("Could not access parent process %d for PID %d.", parent_pid, pid)

        return ProcessFeatures(
            pid=pid,
            name=process_name,
            parent_pid=parent_pid,
            parent_name=parent_name,
            command_line=cmdline,
            executable=exe,
            sha256=sha256,
            username=username
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logger.warning("Failed to gather features for process %d: %s", pid, e)
        return None


def _monitor_loop():
    process_watcher = None
    try:
        logger.info("Starting process creation watcher...")
        process_watcher = _c.Win32_Process.watch_for("creation")
        while True:
            try:
                new_proc_event = process_watcher(timeout_ms=1000)
                if not new_proc_event:
                    continue

                pid = int(new_proc_event.ProcessId)
                parent_pid = int(new_proc_event.ParentProcessId)

                process_features = _get_process_features(pid, parent_pid)
                if not process_features:
                    continue

                # Prepare AI analysis text
                to_ai = f"Analyze the following process creation event for malicious activity. Process Name: {process_features.name}, PID: {process_features.pid}, Command: {process_features.command_line}"

                def check_lifetime():
                    nonlocal process_features, to_ai
                    # Add a safety check to ensure process_features is not None
                    if process_features is None:
                        return
                    start_time = time.time()
                    while True:
                        # Add a safety check to ensure process_features is still valid
                        if process_features is None:
                            return
                        if not psutil.pid_exists(process_features.pid):
                            duration = time.time() - start_time
                            if duration < 5:
                                try:
                                    analysis_text = f"SHORT_LIVED from {process_features.parent_name}: {to_ai}"
                                    result = analyze_text(analysis_text)
                                    
                                    # Convert result to string for logging
                                    result_str = json.dumps(result) if isinstance(result, dict) else str(result)

                                    _log_ai_interaction(process_features.to_dict(), result_str, "SHORT_LIVED_ANALYSIS")

                                    # Check if the result indicates danger
                                    is_dangerous = False
                                    if isinstance(result, dict):
                                        is_dangerous = result.get("DANGEROUS", False)
                                    else:
                                        lower = result.lower()
                                        is_dangerous = any(k in lower for k in ["danger", "malware", "suspicious", "harm"])

                                    if is_dangerous:
                                        show_popup("Guardrail Alert: Short-lived Process", result_str)
                                        log_event("SHORT_LIVED_FLAGGED",
                                                  f"PID: {process_features.pid} Parent: {process_features.parent_name} Cmd: {process_features.command_line} SHA256: {process_features.sha256} | AI: {result_str}")
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
                    
                    # Convert result to string for logging
                    result_str = json.dumps(result) if isinstance(result, dict) else str(result)

                    _log_ai_interaction(process_features.to_dict(), result_str, "PROCESS_CREATION_ANALYSIS")

                    # Check if the result indicates danger
                    is_dangerous = False
                    if isinstance(result, dict):
                        is_dangerous = result.get("DANGEROUS", False)
                    else:
                        lower = result.lower()
                        is_dangerous = any(k in lower for k in ["danger", "suspicious", "unauthorized"])

                    if is_dangerous:
                        show_popup("Guardrail Alert: New Process Flagged", result_str)
                        log_event("PROCESS_FLAGGED",
                                  f"PID: {process_features.pid} Parent: {process_features.parent_name} Cmd: {process_features.command_line} SHA256: {process_features.sha256} | AI: {result_str}")
                except Exception as e:
                    error_msg = f"AI analysis failed for process creation: {str(e)}"
                    log_event("AI_ANALYSIS_ERROR", error_msg)

            except Exception as e:
                # This handles errors in the main loop, like issues with the watcher itself
                if "WMI" in str(e):
                    logger.error("WMI watcher error: %s. Restarting watcher.", e)
                    if process_watcher:
                        process_watcher.stop()
                    process_watcher = _c.Win32_Process.watch_for("creation")
                else:
                    logger.error("Unhandled error in monitor loop: %s", e)
                time.sleep(1)
    finally:
        if process_watcher:
            process_watcher.stop()
            logger.info("Process creation watcher stopped.")

def start_monitor():
    _monitor_loop()