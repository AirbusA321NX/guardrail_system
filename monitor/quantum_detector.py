# monitor/quantum_detector.py

import os
import re
import shutil
import magic
from math import log2
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

# Known post-quantum libraries and algorithms
POST_QUANTUM_LIBS = [
    "liboqs", "kyber", "ntru", "dilithium", "frodo", "sphincs", "bike", "hqc",
    "falcon", "rainbow", "lattice", "mceliece", "newhope"
]

# Exfil/harvest-now/decrypt-later patterns
HARVEST_PATTERNS = [
    r"rsa_public_key", r"exfiltrated_data", r"temp_exfil", r"harvested_key",
    r"ecdh_payload", r"pqc_key", r"backup_chunk", r"encrypted_buffer"
]

# MIME types that are high-entropy but benign
WHITELIST_MIME = (
    "image/", "audio/", "video/", "application/zip",
    "application/x-font", "application/vnd.ms-cab-compressed"
)

# Optional quarantine directory
QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")

os.makedirs(QUARANTINE_DIR, exist_ok=True)

def is_post_quantum_reference(text):
    for lib in POST_QUANTUM_LIBS:
        if lib in text.lower():
            return True
    return False

def is_harvest_now_pattern(text):
    return any(re.search(pat, text.lower()) for pat in HARVEST_PATTERNS)

def is_high_entropy(data, threshold=7.8):
    if not data:
        return False
    probabilities = [float(data.count(byte)) / len(data) for byte in set(data)]
    entropy = -sum(p * log2(p) for p in probabilities if p > 0)
    return entropy > threshold

def quarantine_file(file_path):
    try:
        base_name = os.path.basename(file_path)
        dest_path = os.path.join(QUARANTINE_DIR, base_name)
        shutil.copy2(file_path, dest_path)
        log_event("QUANTUM_FILE_QUARANTINED", f"{file_path} → {dest_path}")
    except Exception as e:
        log_event("QUARANTINE_FAIL", f"{file_path}: {str(e)}")

def scan_for_quantum_threats(folder_path):
    for root, _, files in os.walk(folder_path):
        for file in files:
            try:
                full_path = os.path.join(root, file)
                file_type = magic.from_file(full_path, mime=True)

                # Read content based on file type
                if not file_type or "text" in file_type:
                    with open(full_path, "r", errors="ignore") as f:
                        content = f.read(10000)
                else:
                    with open(full_path, "rb") as f:
                        content = f.read(10000)

                flags = []

                if isinstance(content, bytes):
                    if is_high_entropy(content) and not any(file_type.startswith(m) for m in WHITELIST_MIME):
                        flags.append("High entropy — potential encrypted payload")
                elif isinstance(content, str):
                    if is_post_quantum_reference(content):
                        flags.append("Mentions post-quantum crypto libraries")
                    if is_harvest_now_pattern(content):
                        flags.append("Harvest-now-decrypt-later signature detected")

                if not flags:
                    continue

                # AI analysis
                prompt = f"""
You are a security AI. Analyze this file for signs of quantum-resistant encryption or delayed decryption tactics.

File: {file}
MIME Type: {file_type}
Flags: {', '.join(flags)}

Content (partial):
{content[:2000]}

Does this file indicate a 'harvest-now-decrypt-later' attack or any cryptographic obfuscation beyond standard compression?
"""

                result = analyze_text(prompt)

                if isinstance(result, dict) and result.get("DANGEROUS"):
                    reason = result.get("reason", "AI flagged as quantum malware.")
                    show_popup("Quantum Threat Detected", f"{file}\n\n{reason}")
                    log_event("QUANTUM_MALWARE_FLAGGED", f"{file} | {reason}")
                    quarantine_file(full_path)
                else:
                    log_event("QUANTUM_SAFE", f"{file} | {result}")
            except Exception as e:
                log_event("QUANTUM_SCAN_FAIL", f"{file}: {str(e)}")
