# monitor/usb_guardian.py

import os
import platform
import subprocess
import json
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

# Cache to avoid re-flagging same devices
SEEN_USB_SERIALS = set()

def get_usb_devices():
    os_type = platform.system().lower()
    log_event("USB_SCAN_START", f"Scanning USB on {os_type}")

    try:
        if "windows" in os_type:
            cmd = [
                'powershell', '-Command',
                "Get-WmiObject Win32_USBHub | Select-Object DeviceID, PNPDeviceID, Name, Status, SystemName, Description | ConvertTo-Json"
            ]
            result = subprocess.check_output(cmd, text=True)
            return json.loads(result)
        elif "linux" in os_type:
            result = subprocess.check_output(['lsusb', '-v'], stderr=subprocess.DEVNULL).decode()
            return result.split("\n\n")
        elif "darwin" in os_type:
            result = subprocess.check_output(['system_profiler', 'SPUSBDataType', '-json'], text=True)
            return json.loads(result)
    except Exception as e:
        log_event("USB_SCAN_ERROR", str(e))
        return []

def extract_serial(device_info):
    if isinstance(device_info, dict):
        return device_info.get("DeviceID") or device_info.get("PNPDeviceID")
    elif isinstance(device_info, str):
        lines = device_info.splitlines()
        for line in lines:
            if "SerialNumber" in line or "iSerial" in line:
                return line.strip()
    return None

def analyze_usb(device_info):
    serial = extract_serial(device_info)
    if serial and serial in SEEN_USB_SERIALS:
        log_event("USB_SKIP_REPEAT", f"Device {serial} already scanned.")
        return

    prompt = f"""
You are an AI-based USB threat detector. Analyze the following USB descriptor or metadata and determine if this USB device is behaving like a malicious BadUSB.

- Look for signs of: HID keyboard injection, spoofed Ethernet interfaces, mass storage with executables, fake serial numbers.

Device Info:
{device_info}

Is this device dangerous? If yes, explain why and suggest whether to block, quarantine, or monitor it.
"""

    result = analyze_text(prompt)

    if isinstance(result, dict):
        reason = result.get("reason", "AI flagged the USB device.")
        if result.get("DANGEROUS"):
            show_popup("⚠️ Malicious USB Detected", reason)
            log_event("USB_DEVICE_FLAGGED", f"{device_info} | {reason}")
        else:
            log_event("USB_DEVICE_SAFE", f"{device_info} | {result}")
    else:
        log_event("USB_ANALYSIS_FAILED", f"{device_info} | Unexpected AI output")

    if serial:
        SEEN_USB_SERIALS.add(serial)

def scan_usb_devices():
    devices = get_usb_devices()

    if not devices:
        log_event("USB_SCAN", "No USB devices found.")
        return

    if isinstance(devices, list):
        for dev in devices:
            analyze_usb(dev)
    elif isinstance(devices, dict):
        for v in devices.values():
            analyze_usb(v)
    elif isinstance(devices, str):
        for block in devices.strip().split("\n\n"):
            analyze_usb(block)

    log_event("USB_SCAN_END", "USB scan completed.")
