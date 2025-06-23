import time
import win32api
import win32con
import winreg
import hashlib
import os
import winerror  # <--- ADDED THIS IMPORT for ERROR_NO_MORE_ITEMS

from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_NAME = 0x00000001

_SERVICES_PATH = r"SYSTEM\CurrentControlSet\Services"


def _hash_key_values(root, subkey_path):
    r"""
Returns a dict: { value_name: sha256_of_value_data } for all values under root\subkey_path.
"""

    result = {}
    try:
        key = winreg.OpenKey(root, subkey_path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return result
    except Exception as e:
        log_event("REGISTRY_HASH_OPEN_ERROR", f"Error opening key {subkey_path}: {e}")
        return result

    try:
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                if isinstance(data, str):   
                    raw = data.encode('utf-16le')
                elif isinstance(data, bytes):
                    raw = data
                else:
                    raw = str(data).encode()
                h = hashlib.sha256(raw).hexdigest()
                result[name] = h
                i += 1
            except OSError as e:
                # Use winerror.ERROR_NO_MORE_ITEMS
                if e.winerror == winerror.ERROR_NO_MORE_ITEMS:  # <--- CHANGED HERE
                    break
                else:
                    log_event("REGISTRY_HASH_ENUM_ERROR", f"Error enumerating value {i} under {subkey_path}: {e}")
                    break
    finally:
        winreg.CloseKey(key)
    return result


def _snapshot_all_services():
    """
    Takes a snapshot of all service keys and their hashed values.
    """
    snapshot = {}
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES_PATH, 0, winreg.KEY_READ)
    except FileNotFoundError:
        log_event("REGISTRY_SNAPSHOT_ROOT_NOT_FOUND", f"Services root path {_SERVICES_PATH} not found.")
        return snapshot
    except Exception as e:
        log_event("REGISTRY_SNAPSHOT_OPEN_ERROR", f"Error opening services root: {e}")
        return snapshot

    try:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
                full = os.path.join(_SERVICES_PATH, sub)
                snapshot[full] = _hash_key_values(winreg.HKEY_LOCAL_MACHINE, full)
                i += 1
            except OSError as e:
                # Use winerror.ERROR_NO_MORE_ITEMS
                if e.winerror == winerror.ERROR_NO_MORE_ITEMS:  # <--- CHANGED HERE
                    break
                else:
                    log_event("REGISTRY_SNAPSHOT_ENUM_ERROR",
                              f"Error enumerating subkey {i} under {_SERVICES_PATH}: {e}")
                    break
    finally:
        winreg.CloseKey(root)
    return snapshot


def _monitor_loop():
    prev_snapshot = _snapshot_all_services()
    hkey = None

    try:
        hkey = win32api.RegOpenKeyEx(
            int(win32con.HKEY_LOCAL_MACHINE),
            _SERVICES_PATH,
            0,
            int(win32con.KEY_READ | win32con.KEY_NOTIFY)
        )

        while True:
            try:
                # Expected type 'PyHKEY', got 'int' instead
                # Expected type 'bool', got 'int' instead (for True/False)
                # These warnings are likely static analysis issues with win32api stubs,
                # the runtime behavior should be correct as PyHANDLE objects are often
                # implicitly castable or handled correctly by the underlying C functions.
                win32api.RegNotifyChangeKeyValue(
                    hkey,
                    True,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                    0,
                    False
                )

                time.sleep(0.01)
                new_snapshot = _snapshot_all_services()

                # Compare snapshots
                for key_path, new_vals in new_snapshot.items():
                    old_vals = prev_snapshot.get(key_path, {})
                    for name, h in new_vals.items():
                        if name not in old_vals:
                            detail = f"New registry value '{name}' under '{key_path}'"
                            _flag_registry_change(detail)
                        elif old_vals[name] != h:
                            detail = f"Modified registry value '{name}' under '{key_path}'"
                            _flag_registry_change(detail)
                    for name in old_vals:
                        if name not in new_vals:
                            detail = f"Deleted registry value '{name}' under '{key_path}'"
                            _flag_registry_change(detail)

                for key_path in set(prev_snapshot) - set(new_snapshot):
                    detail = f"Deleted registry key '{key_path}' under Services"
                    _flag_registry_change(detail)

                for key_path in set(new_snapshot) - set(prev_snapshot):
                    detail = f"New registry key '{key_path}' under Services"
                    _flag_registry_change(detail)

                prev_snapshot = new_snapshot

            except Exception as e:
                log_event("REGISTRY_MONITOR_ERROR", str(e))
                time.sleep(5)

    finally:
        if hkey:
            win32api.RegCloseKey(hkey)


def _flag_registry_change(detail: str):
    if not any(term in detail.lower() for term in
               ["cmd.exe", "powershell", "terminal", "shell", "bash", "command prompt"]):
        log_event("IGNORED_CHANGE", f"Ignoring: {detail}")
        return
    try:
        result = analyze_text(f"REGISTRY_CHANGE: {detail}")
    except Exception as e:
        log_event("AI_ANALYSIS_FAILURE", f"AI analysis failed for registry change '{detail}': {e}")
        show_popup("Guardrail AI Failure", "AI analysis failed for registry change. Restarting AI service.")
        try:
            analyze_text("ping")
        except:
            pass
        return

    lower = result.lower()
    if any(k in lower for k in
           ["danger", "disable", "malicious", "unauthorized", "suspicious", "threat", "compromised"]):
        show_popup("Guardrail Alert: Registry Change", result)
        log_event("REGISTRY_FLAGGED", f"{detail} | AI: {result}")
    else:
        log_event("REGISTRY_INFO", f"{detail} | AI: {result}")


def start_monitor():
    _monitor_loop()