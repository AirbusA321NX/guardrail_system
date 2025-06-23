import threading
import time

class Watchdog:
    def __init__(self):
        self.monitors = []  # List of tuples: (name:str, target_func:callable)
        self.threads = {}   # name → Thread object
        self._lock = threading.Lock()
        self._running = False

    def register(self, name: str, target: callable):
        self.monitors.append((name, target))

    def _start_thread(self, name: str, target: callable):
        thread = threading.Thread(target=self._monitor_wrapper, args=(name, target), daemon=True)
        self.threads[name] = thread
        thread.start()

    def _monitor_wrapper(self, name: str, target: callable):
        while self._running:
            try:
                target()
                # If target returns (i.e. exits), we log and restart
            except Exception as e:
                # Swallow exception, but sleep briefly before restart
                time.sleep(1)
            # If it naturally exits, restart after a short delay
            time.sleep(1)

    def start(self):
        self._running = True
        for name, target in self.monitors:
            self._start_thread(name, target)

    def stop(self):
        self._running = False
        # Threads are daemonized; they’ll exit on process end.
