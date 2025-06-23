import threading
import datetime
import os

_lock = threading.Lock()
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'guardrail_log.txt')

def log_event(event_type: str, detail: str):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f'[{timestamp}] [{event_type}] {detail}\n'
    with _lock:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(entry)
