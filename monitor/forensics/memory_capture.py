# monitor/forensics/memory_capture.py

import os
import tempfile
import platform
import subprocess
from datetime import datetime
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

DUMP_DIR = os.path.join(tempfile.gettempdir(), "guardrail_memory_dumps")
os.makedirs(DUMP_DIR, exist_ok=True)

def capture_memory():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    os_type = platform.system().lower()
    dump_path = os.path.join(DUMP_DIR, f"memdump_{timestamp}.raw")

    try:
        if "windows" in os_type:
            # Use Windows built-in tool or DumpIt if available
            dump_cmd = ["powershell", "-Command", f"rundll32.exe advapi32.dll,ProcessIdleTasks;"]
            subprocess.run(dump_cmd, timeout=10)
            log_event("MEMORY_CAPTURE_INFO", "Run memory dump using external tool like DumpIt")
            return None

        elif "linux" in os_type:
            subprocess.run(["sudo", "dd", "if=/dev/mem", f"of={dump_path}", "bs=1M"], check=True)
            log_event("MEMORY_CAPTURE_SUCCESS", dump_path)
            return dump_path

        elif "darwin" in os_type:
            log_event("MEMORY_CAPTURE_UNSUPPORTED", "macOS memory acquisition not implemented")
            return None

    except Exception as e:
        log_event("MEMORY_CAPTURE_FAIL", str(e))
        return None

def analyze_memory_dump(dump_path):
    try:
        with open(dump_path, "rb") as f:
            sample = f.read(2048)  # Read partial memory to avoid huge prompt

        prompt = f"""
You are an AI malware forensic agent.
Analyze the following binary memory snippet and determine if it shows signs of:

- Fileless malware
- Reflective DLL injection
- Cobalt Strike beacon
- Obfuscated shellcode
- Sleep skipping or memory unhooking

Memory Snapshot (hex view):
{sample.hex()[:2000]}

Flag if suspicious and explain why.
"""
        result = analyze_text(prompt)

        if isinstance(result, dict) and result.get("DANGEROUS"):
            reason = result.get("reason", "Malicious behavior in memory detected.")
            show_popup("Memory Threat Detected", f"{os.path.basename(dump_path)}\n\n{reason}")
            log_event("MEMORY_DUMP_MALWARE", f"{dump_path} | {reason}")
        else:
            log_event("MEMORY_DUMP_CLEAN", f"{dump_path} | {result}")

    except Exception as e:
        log_event("MEMORY_ANALYSIS_FAIL", f"{dump_path}: {str(e)}")

def run_memory_capture_workflow():
    dump_path = capture_memory()
    if dump_path:
        analyze_memory_dump(dump_path)
