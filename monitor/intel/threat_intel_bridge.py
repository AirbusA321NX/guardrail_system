# monitor/intel/threat_intel_bridge.py

import os
import time
import json
import requests
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

# --- Config ---
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY") or "YOUR_API_KEY_HERE"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{}"
HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}

# Optional MISP or TAXII integration config placeholders
MISP_ENABLED = False
TAXII_ENABLED = False

# --- VirusTotal Lookup ---
def vt_lookup_file_hash(file_hash):
    try:
        url = VIRUSTOTAL_URL.format(file_hash)
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            log_event("VT_LOOKUP_FAIL", f"{file_hash}: HTTP {response.status_code}")
    except Exception as e:
        log_event("VT_ERROR", f"{file_hash}: {str(e)}")
    return {}

# --- AI Risk Inference from Threat Intel ---
def analyze_threat_intel(file_hash, vt_data):
    if not vt_data:
        return

    attributes = vt_data.get("data", {}).get("attributes", {})
    detections = attributes.get("last_analysis_stats", {})
    total_engines = sum(detections.values())
    malicious_count = detections.get("malicious", 0)

    prompt = f"""
You are an AI malware analyst. Determine if this file is likely malicious based on its threat intelligence.

File Hash: {file_hash}
Detected by: {malicious_count}/{total_engines} antivirus engines
Tags: {attributes.get('tags', [])}
Meaningful Names: {attributes.get('meaningful_name', '')}
Type Description: {attributes.get('type_description', '')}
Threat Classification: {attributes.get('popular_threat_classification', {}).get('suggested_threat_label', '')}
Behaviors: {attributes.get('behaviour_summary', {})}

Is this file malicious or suspicious? Justify your answer with a reason.
"""

    result = analyze_text(prompt)

    if isinstance(result, dict) and result.get("DANGEROUS"):
        reason = result.get("reason", "Flagged via threat intelligence correlation.")
        show_popup("Threat Intel Alert", f"{file_hash}\n\n{reason}")
        log_event("THREAT_INTEL_MALICIOUS", f"{file_hash} | {reason}")
    else:
        log_event("THREAT_INTEL_CLEAN", f"{file_hash} | {result}")


# --- Entry Point for External Hash Scanning ---
def scan_file_hash(file_hash):
    log_event("THREAT_INTEL_SCAN_START", file_hash)
    vt_data = vt_lookup_file_hash(file_hash)
    analyze_threat_intel(file_hash, vt_data)

# --- Example usage for testing ---
if __name__ == "__main__":
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test string hash
    scan_file_hash(test_hash)
