import platform
import time

try:
    import psutil
except ImportError:
    print("Please install psutil with: pip install psutil")
    exit()

def get_cpu_temp():
    system = platform.system()

    if system == 'Windows':
        try:
            import wmi
            w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
            temps = w.Sensor()
            for sensor in temps:
                if sensor.SensorType == u'Temperature' and 'CPU' in sensor.Name:
                    return sensor.Value
            return None
        except ImportError:
            print("Install wmi: pip install wmi")
            return None
        except Exception as e:
            print(f"Error using WMI: {e}")
            return None

    elif system in ['Linux', 'Darwin']:  # macOS/Debian/Ubuntu/Arch etc.
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if not temps:
                return None
            for name, entries in temps.items():
                for entry in entries:
                    if entry.label.lower().startswith("package") or "core" in entry.label.lower():
                        return entry.current
            return None
        else:
            return None

    else:
        return None

# Simple monitor loop
try:
    while True:
        temp = get_cpu_temp()
        if temp:
            print(f"\rCPU Temperature: {temp:.1f}°C", end='', flush=True)
        else:
            print("\rCPU Temperature: Not Available", end='', flush=True)
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopped.")
