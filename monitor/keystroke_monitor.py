import threading
import keyboard
import pyperclip
import time
import win32gui
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

buffer = ""
buffer_lock = threading.Lock()

def get_active_window_class():
    try:
        hwnd = win32gui.GetForegroundWindow()
        return win32gui.GetClassName(hwnd) if hwnd else None
    except:
        return None

def analyze_input_async(source, content):
    try:
        result = analyze_text(f"{source}: {content}")
        if any(word in result.lower() for word in ["danger", "risky", "harm", "breach", "unauthorized"]):
            show_popup(f"Guardrail Alert: Suspicious Input ({source})", result)
            log_event("KEYSTROKE_FLAGGED", f"{source}: {content} | AI_response: {result}")
    except Exception as e:
        log_event("ANALYSIS_ERROR", str(e))

def flush_buffer():
    global buffer
    with buffer_lock:
        content = buffer.strip()
        buffer = ""
    return content

def handle_key(event):
    global buffer
    try:
        if event.event_type != "down":
            return

        if get_active_window_class() == "ConsoleWindowClass":
            return  # Ignore CMD input

        key = event.name

        with buffer_lock:
            if key == "enter":
                content = flush_buffer()
                if content:
                    threading.Thread(
                        target=analyze_input_async,
                        args=("NON-CMD_WINDOW", content),
                        daemon=True
                    ).start()
            elif key == "backspace":
                buffer = buffer[:-1]
            elif key == "v" and keyboard.is_pressed("ctrl"):
                try:
                    buffer += pyperclip.paste()
                except:
                    pass
            elif len(key) == 1:
                buffer += key
    except Exception as e:
        log_event("KEY_HANDLER_ERROR", str(e))

def start_monitor():
    keyboard.hook(handle_key, suppress=False)
    print("[Guardrail] Keystroke monitor is running.")
    while True:
        time.sleep(0.2)
