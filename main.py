import os
import sys
import threading
from utils.logger import log_event
from utils.watchdog_timer import Watchdog

# Ensure we can import from subdirectories
root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(root)

# Import monitor entrypoints
from monitor.cmd_monitor import start_monitor as start_cmd_monitor
from monitor.keystroke_monitor import start_monitor as start_keystroke_monitor
from monitor.process_monitor import start_monitor as start_process_monitor
from monitor.registry_monitor import start_monitor as start_registry_monitor
from monitor.settings_monitor import start_monitor as start_settings_monitor

def main():
    log_event("SYSTEM_START", "Guardrail System is starting.")
    wd = Watchdog()
    # Register each monitor. Name must be unique.
    wd.register("CMD_MONITOR", start_cmd_monitor)
    wd.register("KEYSTROKE_MONITOR", start_keystroke_monitor)
    wd.register("PROCESS_MONITOR", start_process_monitor)
    wd.register("REGISTRY_MONITOR", start_registry_monitor)
    wd.register("SETTINGS_MONITOR", start_settings_monitor)

    wd.start()

    # Main thread simply sleeps; everything else is in daemon threads
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        log_event("SYSTEM_STOP", "Guardrail System is shutting down.")
        wd.stop()

if __name__ == "__main__":
    main()
