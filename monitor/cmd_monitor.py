import threading
import keyboard
import pyperclip
import time
import ctypes
import win32gui
from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

cmd_buffer = ""
buffer_lock = threading.Lock()

def _get_active_window_class():
    hwnd = win32gui.GetForegroundWindow()
    if hwnd == 0:
        return None
    return win32gui.GetClassName(hwnd)

def _analyze_and_prompt(command: str):
    log_event("CMD_ANALYZE", f"Analyzing command: {command}")
    try:
        result = analyze_text(f"CMD: {command}")
    except Exception as e:
        log_event("AI_FAIL", f"AI failed: {e}")
        show_popup("Guardrail AI Failure", "AI analysis failed for command.")
        return

    result_lower = result.lower()
    if any(word in result_lower for word in ["danger", "delete", "harm", "unstable", "risk", "breach"]):
        log_event("CMD_FLAGGED", f"Command: {command} | AI Response: {result}")
        response = ctypes.windll.user32.MessageBoxW(
            0,
            f"Dangerous Command Detected:\n\n{command}\n\nAI: {result}\n\nContinue?",
            "⚠️ Guardrail",
            1
        )
        if response == 2:
            log_event("CMD_BLOCKED", f"User blocked command: {command}")
            return
        log_event("CMD_ALLOWED", f"User allowed command: {command}")
    else:
        log_event("CMD_SAFE", f"Command deemed safe: {command}")

def _on_key(event):
    global cmd_buffer
    try:
        active_class = _get_active_window_class()
        log_event("KEY_EVENT", f"Key: {event.name} | WindowClass: {active_class}")
        if active_class in ("ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS"):
            if event.event_type == "down":
                if event.name == "enter":
                    with buffer_lock:
                        cmd = cmd_buffer.strip()
                        cmd_buffer = ""
                    if cmd:
                        _analyze_and_prompt(cmd)
                elif event.name == "backspace":
                    with buffer_lock:
                        cmd_buffer = cmd_buffer[:-1]
                elif event.name == "v" and keyboard.is_pressed("ctrl"):
                    try:
                        clip = pyperclip.paste()
                        with buffer_lock:
                            cmd_buffer += clip
                    except Exception as e:
                        log_event("CLIPBOARD_FAIL", str(e))
                elif len(event.name) == 1:
                    with buffer_lock:
                        cmd_buffer += event.name
    except Exception as e:
        log_event("KEY_HOOK_ERROR", str(e))

def start_monitor():
    log_event("CMD_MONITOR", "Starting keyboard hook...")
    keyboard.hook(_on_key, suppress=False)
    while True:
        time.sleep(1)
