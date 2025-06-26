# monitor/forensics/forensics_timeline.py

import os
import time
import json
import platform
from datetime import datetime
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

# Cross-platform file timestamp extractor
def get_file_metadata(path):
    try:
        stat = os.stat(path)
        return {
            "path": path,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "size": stat.st_size
        }
    except Exception as e:
        log_event("FORENSICS_FILE_META_FAIL", f"{path} - {str(e)}")
        return None

# Walk file system and collect metadata
def build_file_timeline(directory):
    timeline = []
    for root, _, files in os.walk(directory):
        for f in files:
            full_path = os.path.join(root, f)
            meta = get_file_metadata(full_path)
            if meta:
                timeline.append(meta)
    return sorted(timeline, key=lambda x: x["modified"], reverse=True)

# Send to Mistral for anomaly detection
def analyze_timeline_with_ai(timeline):
    prompt = f"""
You are a digital forensics AI. Review this file activity timeline and detect anomalies.

Timeline (recent first):
{json.dumps(timeline[:50], indent=2)}

Identify suspicious patterns, such as rapid file changes, staged malware, data staging, or attack progression.
"""
    return analyze_text(prompt)

# Main function to scan and analyze a given directory
def scan_and_analyze_timeline(directory):
    log_event("FORENSICS_TIMELINE_SCAN_START", directory)
    try:
        timeline = build_file_timeline(directory)
        if not timeline:
            log_event("FORENSICS_TIMELINE_EMPTY", directory)
            return

        result = analyze_timeline_with_ai(timeline)
        if isinstance(result, dict) and result.get("DANGEROUS"):
            reason = result.get("reason", "Suspicious file timeline activity detected.")
            show_popup("Forensic Alert", f"{directory}\n\n{reason}")
            log_event("FORENSICS_TIMELINE_SUSPICIOUS", f"{directory} | {reason}")
        else:
            log_event("FORENSICS_TIMELINE_CLEAN", f"{directory} | {result}")
    except Exception as e:
        log_event("FORENSICS_TIMELINE_FAIL", f"{directory}: {str(e)}")
