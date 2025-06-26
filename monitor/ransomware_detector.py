# monitor/ransomware_detector.py

import os
import time
import threading
import hashlib
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

MONITORED_EXTENSIONS = ('.docx', '.xlsx', '.pptx', '.pdf', '.jpg', '.txt', '.csv', '.zip')
SUSPICIOUS_RENAME_SUFFIXES = ('.locked', '.crypted', '.encrypted', '.enc')
ENTROPY_THRESHOLD = 7.6
EVENT_BUFFER_TIME = 5  # seconds
RANSOM_NOTE_KEYWORDS = ("bitcoin", "decrypt", "payment", "ransom")

event_cache = {}

def calculate_entropy(data):
    from math import log2
    if not data:
        return 0
    probabilities = [float(data.count(byte)) / len(data) for byte in set(data)]
    entropy = -sum([p * log2(p) for p in probabilities if p > 0])
    return entropy

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def analyze_ransom_note(file_path):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read(5000)

        prompt = f"""
You are a security LLM. Analyze this text file to determine if it's a ransom note associated with ransomware.

File: {os.path.basename(file_path)}
Content:
{content[:2000]}

Does this file indicate ransomware behavior?
"""

        result = analyze_text(prompt)

        if isinstance(result, dict) and result.get("DANGEROUS"):
            reason = result.get("reason", "Detected ransom demand.")
            show_popup("Ransomware Note Detected", f"{file_path}\n\n{reason}")
            log_event("RANSOM_NOTE_FOUND", f"{file_path} | {reason}")
        else:
            log_event("RANSOM_NOTE_SAFE", f"{file_path} | {result}")
    except Exception as e:
        log_event("RANSOM_NOTE_ERROR", f"{file_path}: {str(e)}")

class RansomwareEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory or not event.src_path.lower().endswith(MONITORED_EXTENSIONS):
            return

        now = time.time()
        path = event.src_path

        # File entropy check
        try:
            with open(path, 'rb') as f:
                data = f.read(4096)
            entropy = calculate_entropy(data)
            if entropy > ENTROPY_THRESHOLD:
                log_event("HIGH_ENTROPY_WRITE", f"{path} | {entropy:.2f}")
        except Exception as e:
            log_event("ENTROPY_READ_FAIL", f"{path}: {str(e)}")

        # Cache file write events
        event_cache.setdefault(path, []).append(now)

    def on_created(self, event):
        if event.is_directory:
            return
        if any(keyword in event.src_path.lower() for keyword in RANSOM_NOTE_KEYWORDS):
            analyze_ransom_note(event.src_path)

    def on_moved(self, event):
        if any(event.dest_path.endswith(sfx) for sfx in SUSPICIOUS_RENAME_SUFFIXES):
            log_event("SUSPICIOUS_FILE_RENAMED", f"{event.src_path} → {event.dest_path}")
            show_popup("Suspicious Rename", f"{event.dest_path} appears ransomware-modified.")

def monitor_filesystem(folder_to_watch):
    observer = Observer()
    event_handler = RansomwareEventHandler()
    observer.schedule(event_handler, folder_to_watch, recursive=True)
    observer.start()
    log_event("RANSOMWARE_MONITOR_STARTED", folder_to_watch)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
