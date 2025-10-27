# monitor/forensics/memory_capture.py

import os
import tempfile
import platform
import subprocess
import shutil
from datetime import datetime
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

DUMP_DIR = os.path.join(tempfile.gettempdir(), "guardrail_memory_dumps")
os.makedirs(DUMP_DIR, exist_ok=True)

def capture_memory():
    """
    Capture system memory for forensic analysis on Windows.
    Returns the path to the memory dump file, or None if capture failed.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    os_type = platform.system().lower()
    dump_path = os.path.join(DUMP_DIR, f"memdump_{timestamp}.raw")

    try:
        if "windows" in os_type:
            # Try different Windows memory capture tools
            # First, check if Magnet DumpIt is available
            dumpit_path = shutil.which("DumpIt.exe")
            if dumpit_path:
                # Use DumpIt for memory capture
                result = subprocess.run([dumpit_path, "/Q", "/O", dump_path], 
                                      capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    log_event("MEMORY_CAPTURE_SUCCESS", f"Memory dump created: {dump_path}")
                    return dump_path
                else:
                    log_event("MEMORY_CAPTURE_FAIL", f"DumpIt failed: {result.stderr}")
            
            # If DumpIt not available, try WinPmem
            winpmem_path = shutil.which("winpmem.exe")
            if winpmem_path:
                result = subprocess.run([winpmem_path, "-o", dump_path], 
                                      capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    log_event("MEMORY_CAPTURE_SUCCESS", f"Memory dump created: {dump_path}")
                    return dump_path
                else:
                    log_event("MEMORY_CAPTURE_FAIL", f"WinPmem failed: {result.stderr}")
            
            # If no tools available, log error
            log_event("MEMORY_CAPTURE_UNSUPPORTED", 
                     "No Windows memory capture tools found. Please install DumpIt or WinPmem.")
            return None

        else:
            log_event("MEMORY_CAPTURE_UNSUPPORTED", f"Unsupported OS: {os_type}. Only Windows is supported.")
            return None

    except subprocess.TimeoutExpired:
        log_event("MEMORY_CAPTURE_FAIL", "Memory capture timed out")
        return None
    except Exception as e:
        log_event("MEMORY_CAPTURE_FAIL", str(e))
        return None

def analyze_memory_dump(dump_path):
    """
    Analyze a memory dump file for signs of malware or suspicious activity.
    """
    try:
        # Check if file exists and is not empty
        if not os.path.exists(dump_path):
            log_event("MEMORY_ANALYSIS_FAIL", f"Memory dump file not found: {dump_path}")
            return
            
        if os.path.getsize(dump_path) == 0:
            log_event("MEMORY_ANALYSIS_FAIL", f"Memory dump file is empty: {dump_path}")
            return

        # Read a sample of the memory dump to avoid huge prompts
        with open(dump_path, "rb") as f:
            # Read 2KB from the beginning
            sample_start = f.read(1024)
            # Seek to middle and read another 1KB
            try:
                f.seek(os.path.getsize(dump_path) // 2)
                sample_middle = f.read(1024)
            except:
                sample_middle = b""

        # Combine samples
        sample = sample_start + sample_middle

        prompt = f"""
You are an AI malware forensic agent.
Analyze the following binary memory snippet and determine if it shows signs of:

- Fileless malware
- Reflective DLL injection
- Cobalt Strike beacon
- Obfuscated shellcode
- Sleep skipping or memory unhooking
- Process hollowing
- Direct System Calls
- API hashing
- Encrypted or encoded payloads

Memory Snapshot (hex view):
{sample.hex()[:2000]}

Respond ONLY in this strict JSON format:
{{
  "DANGEROUS": true/false,
  "reason": "Detailed explanation of findings or why it appears clean"
}}

If you find suspicious patterns, explain what they indicate and why they are concerning.
If the memory appears clean, explain why you believe so.
"""

        result = analyze_text(prompt)

        if isinstance(result, dict) and result.get("DANGEROUS"):
            reason = result.get("reason", "Malicious behavior in memory detected.")
            show_popup("Memory Threat Detected", f"{os.path.basename(dump_path)}\n\n{reason}")
            log_event("MEMORY_DUMP_MALWARE", f"{dump_path} | {reason}")
        else:
            reason = result.get("reason", "No malicious patterns detected.") if isinstance(result, dict) else str(result)
            log_event("MEMORY_DUMP_CLEAN", f"{dump_path} | {reason}")

    except Exception as e:
        log_event("MEMORY_ANALYSIS_FAIL", f"{dump_path}: {str(e)}")

def run_memory_capture_workflow():
    """
    Run the complete memory capture and analysis workflow.
    """
    log_event("MEMORY_WORKFLOW_START", "Starting memory capture workflow")
    dump_path = capture_memory()
    if dump_path:
        analyze_memory_dump(dump_path)
        log_event("MEMORY_WORKFLOW_COMPLETE", "Memory capture workflow completed")
    else:
        log_event("MEMORY_WORKFLOW_FAIL", "Memory capture workflow failed")