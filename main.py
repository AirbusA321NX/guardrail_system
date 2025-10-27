#!/usr/bin/env python3

import atexit
import logging
import msvcrt
import os
import platform
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import List, Optional

import psutil
# Third-party imports
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# Local imports
from stats import SystemMonitor
# Local imports
from utils.logger import log_event, setup_logging

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize monitor with error handling
monitor = None
try:
    monitor = SystemMonitor()
    # Test if we can get system stats
    test_stats = monitor.get_all_stats()
    log_event("INFO", "System monitoring is working correctly")
except Exception as e:
    log_event("ERROR", "Failed to initialize system monitor: {error}", error=str(e))
    print(f"Error: Failed to initialize system monitor: {str(e)}")
    print("Please make sure all required dependencies are installed:")
    print("pip install psutil wmi GPUtil")
    # Don't exit here, let the application handle the error gracefully


# Global state
class AppState:
    """Global application state"""

    def __init__(self):
        self.running = True
        self.ollama_status = "[yellow]Checking...[/]"
        self.detected_ollama_status = False
        self.last_ollama_check = 0
        self.input_buffer = ""
        self.last_input_time = 0
        self.input_timeout = 0.1  # seconds between input checks
        # Force a color-capable console
        self.console = Console(force_terminal=True, color_system="auto")
        self.term_width = 80
        self._init_terminal()

    def _init_terminal(self):
        """Initialize terminal settings"""
        try:
            self.term_width = shutil.get_terminal_size().columns
        except OSError:
            self.term_width = 80

        # Enable ANSI support on Windows
        if platform.system() == 'Windows':
            os.system('')

    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        # Add any cleanup code here


# Initialize global state
app_state = AppState()

# Use the imported monitor instance from stats.py
# The monitor is already initialized in stats.py
logger.debug("Using global monitor instance from stats.py")


# Register cleanup handlers
def handle_exit(signum=None, frame=None):
    """
    Handle application exit.
    
    Args:
        signum: Signal number (for signal handlers)
        frame: Current stack frame (for signal handlers) - intentionally unused
    """
    # Intentionally unused parameter to satisfy signal handler signature
    _ = frame

    try:
        app_state.cleanup()
    except (RuntimeError, OSError) as e:
        log_event(event_type="ERROR", message="Error during cleanup: %s", error=str(e))

    # Don't call sys.exit() in atexit handler to avoid the exception
    if signum is not None:
        sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# Register cleanup function with atexit
atexit.register(handle_exit)

# Configure logging
setup_logging()

# Initialize WMI if on Windows
_wmi_conn = None
if platform.system() == 'Windows':
    try:
        import wmi
        _wmi_conn = wmi.WMI(namespace='root\\OpenHardwareMonitor')
    except ImportError:
        pass
    except Exception:
        try:
            import wmi
            _wmi_conn = wmi.WMI(namespace='root\\wmi')
        except ImportError:
            pass
        except Exception:
            _wmi_conn = None


# System monitoring
def check_ollama_status(app_state):
    """Check if Ollama service is running and update status."""
    try:
        # First check if ollama process is running (fast check)
        if monitor is not None:
            processes = monitor.get_process_list('ollama')  # Pass the process name directly
            if processes:  # If we found any matching processes
                app_state.detected_ollama_status = True
                return True, "[green]ON[/]"

        # If process not found, try to ping the service (slower but more reliable)
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)  # 1 second timeout
                if s.connect_ex(('localhost', 11434)) == 0:
                    app_state.detected_ollama_status = True
                    return True, "[green]ON[/]"
        except ImportError:
            pass
        except Exception as e:
            # Handle both socket.error and OSError
            log_event(event_type="DEBUG", message="Socket check failed: {error}", error=str(e))

        # If we get here, Ollama is not running
        app_state.detected_ollama_status = False
        return False, "[red]OFF[/]"

    except NameError:
        # Fallback if psutil is not available
        app_state.detected_ollama_status = False
        return False, "[red]OFF[/] (psutil not available)"
    except (RuntimeError, OSError) as e:
        log_event(event_type="ERROR", message="Error checking Ollama status: {error}", error=str(e))
        # Return the last known status if available
        if hasattr(app_state, 'detected_ollama_status') and app_state.detected_ollama_status:
            return True, "[green]ON[/]"
    except Exception as e:
        log_event(event_type="ERROR", message="Unexpected error checking Ollama status: {error}", error=str(e))
        # Return the last known status if available
        if hasattr(app_state, 'detected_ollama_status') and app_state.detected_ollama_status:
            return True, "[green]ON[/]"
        return False, "[red]OFF[/]"


# Global variables for system stats and monitoring
_system_stats_cache = None
_last_stats_update = 0
_stats_lock = threading.Lock()
monitor = None  # Will be initialized later


# Input handling
input_queue = queue.Queue()
stop_input_thread = False  # Move this BEFORE the function that uses it
input_thread_handle = None  # Global reference to the input threading handle


def input_thread():
    """
    Background thread for handling keyboard input without blocking the main thread.
    Puts key presses into a queue for the main thread to process.
    """
    global stop_input_thread

    while not stop_input_thread:
        try:
            # Check for key press (non-blocking)
            if os.name == 'nt':  # Windows
                if msvcrt.kbhit():
                    char = msvcrt.getch().decode('utf-8', errors='ignore')
                    if char == '\x03':  # Handle Ctrl+C
                        raise KeyboardInterrupt()
                    if char:
                        input_queue.put(char)
            else:  # Unix-like systems
                import select
                import sys
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)
                    if char:
                        input_queue.put(char)

            # Small sleep to prevent high CPU usage
            time.sleep(0.01)

        except Exception as e:
            logger.error("Error in input thread: %s", e)
            time.sleep(0.1)  # Prevent tight loop on error


# Input handling

def get_system_stats():
    """
    Get system statistics with caching to avoid excessive WMI/psutil calls.
    
    Returns:
        dict: Dictionary containing system statistics
    """
    global _system_stats_cache, _last_stats_update, monitor

    # Use cached stats if they're less than 0.1 seconds old (instead of 1.0)
    current_time = time.time()
    if _system_stats_cache and (current_time - _last_stats_update) < 0.1:
        logger.debug("Returning cached stats")
        return _system_stats_cache

    logger.debug("Getting fresh stats")
    try:
        # Ensure monitor is initialized
        if monitor is None:
            try:
                monitor = SystemMonitor()
            except Exception as e:
                logger.error("Failed to initialize monitor: %s", str(e))
                # Return default stats if monitor can't be initialized
                return {
                    'cpu': {'percent': 0.0, 'temperature': None},
                    'memory': {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0},
                    'disk': {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0, 'free_gb': 0.0},
                    'gpu': {'load': 0.0, 'temperature': None},
                    'timestamp': time.strftime('%H:%M:%S')
                }

        # Get all stats from the monitor
        stats = monitor.get_all_stats()
        logger.debug("Raw stats from monitor: %s", stats)

        # Ensure all required fields exist
        if not isinstance(stats, dict):
            logger.error("Expected dict from get_all_stats(), got %s", type(stats))
            stats = {}

        # Set default values if not present
        if 'cpu' not in stats or not isinstance(stats['cpu'], dict):
            stats['cpu'] = {'percent': 0.0, 'temperature': None}
        if 'memory' not in stats or not isinstance(stats['memory'], dict):
            stats['memory'] = {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0}
        if 'disk' not in stats or not isinstance(stats['disk'], dict):
            stats['disk'] = {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0, 'free_gb': 0.0}
        if 'gpu' not in stats:
            stats['gpu'] = {'load': 0.0, 'temperature': None}
        if 'timestamp' not in stats:
            stats['timestamp'] = time.strftime('%H:%M:%S')

        # Log the stats for debugging
        logger.debug("Processed stats: %s", stats)

        # Update cache and timestamp
        _system_stats_cache = stats
        _last_stats_update = current_time

        return stats

    except (RuntimeError, OSError) as e:
        logger.error("Error in get_system_stats: %s", str(e), exc_info=True)
        # Return default stats on error
        return {
            'cpu': {'percent': 0.0, 'temperature': None},
            'memory': {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0},
            'disk': {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0, 'free_gb': 0.0},
            'gpu': {'load': 0.0, 'temperature': None},
            'timestamp': time.strftime('%H:%M:%S'),
            'error': str(e)
        }


def get_ollama_status():
    """Get Ollama status with detailed information."""
    result = check_ollama_status(app_state)
    if result is None:
        return "[red]Error[/]"
    is_running, status = result

    # Add more detailed status information
    try:
        import requests
        response = requests.get('http://localhost:11434/api/version', timeout=2)
        if response.status_code == 200:
            version_info = response.json()
            version = version_info.get('version', 'unknown')
            return f"[green]●[/] [bold]Running[/] (v{version})"
    except ImportError:
        pass
    except Exception as e:
        # Handle both requests.RequestException and ValueError
        pass

    return status


def display_system_stats() -> str:
    """Display system stats as a formatted string with Ollama status."""
    try:
        logger.debug("Getting system stats from monitor...")
        # Use the cached function instead of directly calling monitor.get_all_stats()
        stats = get_system_stats()
        logger.debug("Raw stats from monitor: %s", stats)
        
        cpu = stats.get('cpu', {})
        memory = stats.get('memory', {})
        disk = stats.get('disk', {})
        gpu = stats.get('gpu', {})

        # CPU temperature handling - improved with better logging
        cpu_temp = cpu.get('temperature')
        logger.debug("CPU temperature from stats dict: %s", cpu_temp)
        if cpu_temp is not None and isinstance(cpu_temp, (int, float)) and cpu_temp > 0:
            cpu_temp_str = f"{float(cpu_temp):.1f}°C"
            logger.debug("CPU temperature from stats: %s", cpu_temp_str)
        else:
            # Try to get temperature using the standalone function
            try:
                temp = get_cpu_temperature()  # Use the standalone function we fixed
                logger.debug("CPU temperature from standalone function: %s", temp)
                if temp is not None and temp > 0:
                    cpu_temp_str = f"{temp:.1f}°C"
                    logger.debug("CPU temperature from standalone function: %s", cpu_temp_str)
                else:
                    cpu_temp_str = "N/A"
                    logger.debug("CPU temperature not available from standalone function")
            except Exception as e:
                cpu_temp_str = "N/A"
                logger.debug("Error getting CPU temperature from standalone function: %s", e)

        # Memory
        mem_used = memory.get('used_gb', 0)
        mem_total = memory.get('total_gb', 0)
        mem_percent = memory.get('percent', 0)

        # Disk
        disk_used = disk.get('used_gb', 0)
        disk_total = disk.get('total_gb', 0)
        disk_percent = disk.get('percent', 0)

        # GPU with better error handling and bounds checking
        gpu_load = min(100, gpu.get('load', 0) * 100)  # Convert to percentage and cap at 100%
        gpu_temp = gpu.get('temperature')
        try:
            if gpu_temp is not None and isinstance(gpu_temp, (int, float)):
                gpu_temp_str = f"{float(gpu_temp):.1f}°C"
            else:
                gpu_temp_str = "N/A"
                logger.debug("GPU temperature not available or invalid")
        except (TypeError, ValueError) as e:
            gpu_temp_str = "N/A"
            logger.debug("Error processing GPU temperature: %s", e)

        # Ollama status
        ollama_status = get_ollama_status()

        # Get terminal width for alignment
        width = shutil.get_terminal_size().columns - 4

        # Ollama status in top-left, timestamp in top-right
        time_line = str(stats.get('timestamp', ''))
        # Ensure both width and len(time_line) are treated as integers
        padding = max(0, int(width) - len(time_line))
        # Ensure ollama_status is a string before using in f-string
        ollama_status_str = str(
            ollama_status[1] if isinstance(ollama_status, tuple) and len(ollama_status) > 1 else ollama_status)
        status_line = f"Ollama: {ollama_status_str}".ljust(padding) + time_line + "\n"
        separator = "-" * int(width) + "\n"

        # Build the stats lines with colored bars
        bar_width = 15  # Fixed width for all bars
        stats_lines = [
            # CPU: Show percentage and temperature
            f"CPU : {create_horizontal_bar(cpu.get('percent', 0), bar_width)}  {cpu.get('percent', 0):5.1f}%  |  Temp: {cpu_temp_str}",
            # Memory: Show used/total with bar and percentage
            f"MEM : {create_horizontal_bar(mem_percent, bar_width)}  {mem_used:5.1f}/{mem_total:.1f} GB ({mem_percent:.1f}%)",
            # Disk: Show used/total with bar and percentage (capped at 100%)
            f"DISK: {create_horizontal_bar(min(100, disk_percent), bar_width)}  {disk_used:5.1f}/{disk_total:.1f} GB ({min(100, disk_percent):.1f}%)",
            # GPU: Show load and temperature
            f"GPU : {create_horizontal_bar(min(100, gpu_load), bar_width)}  {min(100, gpu_load):5.1f}%  |  Temp: {gpu_temp_str}"
        ]

        result = status_line + separator + "\n".join(stats_lines) + "\n"
        logger.debug("Display stats result: %s", result)
        return result

    except (RuntimeError, OSError) as e:
        logger.error("Error in display_system_stats: %s", str(e))
        return "System stats unavailable\n"


def create_horizontal_bar(percent: float, width: int = 20) -> str:
    """Create a colored horizontal bar graph for visualization."""
    try:
        # Ensure percent is within valid range
        percent = max(0, min(100, percent))
        
        # Determine color based on percentage
        if percent >= 90:
            color = "red"
        elif percent >= 75:
            color = "yellow"
        elif percent >= 40:
            color = "blue"
        else:
            color = "green"
            
        # Calculate filled and empty parts
        filled = int(round(percent / 100 * width))
        empty = width - filled
        
        # Create the bar with rich color markup
        bar = f"[{color}]" + '█' * filled + "[/]" + '░' * empty
        
        return f"{bar} {percent:.1f}%"
    except Exception as e:
        logger.error("Error creating progress bar: %s", e)
        return "[red]Error[/]"

def format_with_bar(label: str, value: float, total: float, unit: str = '%', bar_width: int = 15) -> str:
    """Format a metric with a colored bar on the right side."""
    if total == 0:
        percent = 0
    else:
        percent = (value / total) * 100 if unit == '%' else value

    # Ensure percent is within 0-100 range for display
    percent = max(0, min(100, percent))

    bar = create_horizontal_bar(percent, bar_width)

    # Format the value text with consistent spacing
    if unit == '%':
        value_text = f"{value:5.1f}{unit}"
        return f"{label}: {value_text} {bar}"
    else:
        value_text = f"{value:5.1f}/{total:.1f} {unit} ({percent:4.1f}%)"
        return f"{label}: {value_text} {bar}"


# Animation utilities
class Animation:

    @staticmethod
    def progress_bar(progress: float, total: float, length: int = 40, message: str = "") -> None:
        """Display a progress bar.
        
        Args:
            progress: Current progress value
            total: Total value for completion
            length: Length of the progress bar in characters
            message: Optional message to display before the progress bar
        """
        try:
            # Ensure we have valid numeric values
            progress_val = float(progress)
            total_val = float(total)
            length_val = int(length)

            # Calculate progress percentage and filled length
            percent = min(100.0 * (progress_val / total_val) if total_val > 0 else 0, 100.0)
            filled_length = int(length_val * progress_val // total_val) if total_val > 0 else 0

            # Create the progress bar string
            bar = '█' * filled_length + '-' * max(0, length_val - filled_length)

            # Output the progress bar
            sys.stdout.write(f"\r{message} |{bar}| {percent:.1f}%")
            # Ensure percent is within the valid 0-100 range
            percent = max(0, min(100, percent))

            # Determine the color name based on the percentage for rich markup
            if percent >= 90:
                color = "bright_red"
            elif percent >= 75:
                color = "red"
            elif percent >= 40:
                color = "blue"
            else:
                color = "green"

            # Calculate the bar's filled length using the length_val parameter
            filled_len = int(round(length_val * percent / 100))
            bar = '█' * filled_len + '░' * (length_val - filled_len)

            # Print the bar wrapped in rich's color markup instead of returning it
            sys.stdout.write(f"\r{message} |[{color}]{bar}[white]| {percent:.1f}%")

            # Add newline if complete
            if progress_val >= total_val and total_val > 0:
                sys.stdout.write("\n")

        except (TypeError, ValueError) as e:
            # Fallback to simple progress display if there's an error
            sys.stdout.write(f"\r{message} Progress: {progress}/{total}")

        sys.stdout.flush()

    @staticmethod
    def typewriter_effect(text: str, delay: float = 0.03):
        """Print text with a typewriter effect."""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

    @staticmethod
    def color_cycle(text: str, colors: List[str], delay: float = 0.1):
        """Cycle through colors for text."""
        for color in colors * 3:  # Repeat colors 3 times
            sys.stdout.write(f"\r{color}{text}\033[0m")
            sys.stdout.flush()
            time.sleep(delay)
        sys.stdout.write("\r" + " " * (len(text) + 10) + "\r")
        sys.stdout.flush()

    @staticmethod
    def startup_animation():
        """Show a simple startup message without any animations."""
        from rich.console import Console

        console = Console()
        clear_screen()

        # Show a simple message
        console.print("\n" * 2)
        console.print("Initializing Guardrail Security System...")

        # Small delay to simulate loading
        import time
        time.sleep(1)

        console.print("\nSystem ready. Press any key to continue...")
        input()
        clear_screen()


# Simple banner text
BANNER = """
=== GUARDRAIL SECURITY SYSTEM ===
"""


def clear_screen():
    """Clear the terminal screen with a smooth wipe effect."""
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Unix/Linux/MacOS
        os.system('clear')
    print("\033[?25l", end="")  # Hide cursor

    # Add a subtle wipe effect
    width = shutil.get_terminal_size().columns
    for i in range(0, shutil.get_terminal_size().lines, 2):
        print("\033[0m" + " " * width)
        time.sleep(0.01)
    sys.stdout.write("\033[0m\033[H")
    sys.stdout.flush()
    print("\033[?25h", end="")  # Show cursor


def print_banner():
    """Print a simple system banner."""
    clear_screen()
    width = shutil.get_terminal_size().columns

    # Print a simple header
    header = "=== GUARDRAIL SECURITY SYSTEM ==="
    timestamp = f"[+] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    print("\n" + header.center(width))
    print(timestamp.center(width) + "\n")


def generate_dashboard() -> Panel:
    """
    Generate the complete dashboard UI with current system stats and menu.
    This function is called by the Live display to update the UI.
    """
    logger.debug("Generating dashboard...")
    # Get fresh system stats
    stats_output = display_system_stats()

    # Build menu sections
    menu_sections = {
        "Security Tools": [
            ("1", "Secure Shell", "Access secure command line interface"),
            ("2", "AI Folder Scan", "Scan folders for suspicious content")
        ],
        "Monitoring": [
            ("3", "System Monitor", "View real-time system metrics"),
            ("4", "Registry Monitor", "Monitor Windows registry changes")
        ],
        "Configuration": [
            ("S", "Settings", "Configure system settings")
        ]
    }

    # Build menu content
    menu_content = ""
    for section, options in menu_sections.items():
        menu_content += f"\n[bold cyan]{section}:[/]"
        for key, title, description in options:
            menu_content += f"\n  [bold yellow]{key}.[/] [bold]{title}[/] - {description}"

    # Add exit option
    menu_content += "\n\n[bold cyan]Other Options:[/]"
    menu_content += "\n  [bold yellow]Q.[/] [bold]Quit[/] - Exit the application"

    # Create visual keypad for input instructions
    keypad = """
[bold cyan]Input Keypad:[/]
┌─────┬─────┬─────┬─────┐
│ [bold yellow]1[/]   │ [bold yellow]2[/]   │ [bold yellow]3[/]   │ [bold yellow]4[/]   │
│ Sec │ AI  │ Sys │ Reg │
└─────┴─────┴─────┴─────┘
┌─────┬─────┐
│ [bold yellow]S[/]   │ [bold yellow]Q[/]   │
│ Set │ Quit│
└─────┴─────┘
"""

    # Create input prompt with a box
    input_prompt = "╔" + "═" * 40 + "╗\n"
    input_prompt += "║ " + "[bold cyan]Enter your choice:[/]" + " " * 14 + "║\n"
    input_prompt += "╚" + "═" * 40 + "╝\n> "

    # Combine everything into a panel
    result = Panel(
        f"[bold blue]System Status[/]\n{stats_output}\n[bold blue]Menu Options[/]{menu_content}\n\n{keypad}\n{input_prompt}",
        title="[bold green]Guardrail Security[/]",
        border_style="blue",
        padding=(1, 2)
    )
    logger.debug("Dashboard generated")
    return result


def get_key_press() -> Optional[str]:
    """
    Get a single key press without blocking the main thread.
    Returns the key pressed or None if no key was pressed.
    """
    try:
        # First check our input queue from the background thread
        try:
            char = input_queue.get_nowait()
            logger.debug("Key from input queue: %s", repr(char))
            return char.lower()
        except queue.Empty:
            pass
        
        # Fallback to direct keyboard check
        if platform.system() == 'Windows':
            if msvcrt.kbhit():
                logger.debug("Key detected with kbhit")
                try:
                    char = msvcrt.getch().decode('utf-8').lower()
                    logger.debug("Key character: %s", repr(char))
                    return char
                except UnicodeDecodeError:
                    logger.debug("Unicode decode error for key")
                    return None
        else:
            # For Unix-like systems (Linux, macOS)
            import sys, select
            if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                char = sys.stdin.read(1).lower()
                logger.debug("Unix key character: %s", repr(char))
                return char
        return None
    except Exception as e:
        logger.error("Error in get_key_press: %s", e)
        return None


def print_menu():
    """Legacy menu function - now just calls generate_dashboard for backward compatibility."""
    console = Console()
    console.print(generate_dashboard())


def open_in_new_window(command: str) -> bool:
    """Open a command in a new terminal window."""
    try:
        if platform.system() == "Windows":
            subprocess.Popen(f'start cmd /k {command}', shell=True)
        elif platform.system() == "Darwin":  # macOS
            subprocess.Popen([
                'osascript',
                '-e', f'tell app "Terminal" to do script "cd {os.getcwd()} && {command}"'
            ])
        else:  # Linux and others
            subprocess.Popen(['x-terminal-emulator', '-e', command])
        return True
    except (subprocess.SubprocessError, OSError) as e:
        log_event(event_type="ERROR", message="Failed to open new window: %s", error=str(e))
        return False

    # Clear any pending input
    while msvcrt.kbhit():
        msvcrt.getch()

    return True


def handle_secure_shell():
    """Handle the secure shell option."""
    console = Console()

    try:
        console.print("\n[bold yellow]Starting Secure Shell...[/]")
        console.print("[dim]Type 'exit' or press Ctrl+C to return to the menu.\n[/]")

        # The secure_shell.py is in the same directory as main.py
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secure_shell.py')

        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Secure shell script not found at: {script_path}")

        # Try to open in a new window first
        success = open_in_new_window(f'python "{script_path}"')

        if not success:
            console.print("[yellow]Could not open new window. Using current window...[/]")

            # Fallback to running in current window
            try:
                # Run the secure shell script in the current window
                subprocess.run([sys.executable, script_path], check=True)
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Error running secure shell: {e}[/]")
            except KeyboardInterrupt:
                pass  # User pressed Ctrl+C to return to menu

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        console.print("\nPress Enter to return to the menu...")
        input()

    return True


def handle_ai_scan():
    """Handle the AI folder scan option."""
    console = Console()

    try:
        console.print("\n[bold yellow]Starting AI Folder Scanner...[/]")
        console.print("[dim]This feature is under development.\n[/]")

        # Simple implementation that doesn't freeze the menu
        console.print("\n[green]Scan complete![/]")
        console.print("\n[dim]Press any key to return to the menu...[/]")

        # Wait for any key press
        if os.name == 'nt':  # Windows
            msvcrt.getch()
        else:  # Unix/Linux/MacOS
            import sys
            try:
                import tty, termios
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(sys.stdin.fileno())
                    sys.stdin.read(1)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except ImportError:
                # termios not available on this platform
                input()

    except (RuntimeError, OSError) as e:
        console.print(f"\n[red]Error: {str(e)}[/]")
        time.sleep(2)

    return True


def handle_registry_monitor():
    """Handle the registry monitor option."""
    print("\n\033[93m[!] Starting Registry Monitor in a new window...\033[0m")
    success = open_in_new_window('python -m monitor.registry_monitor')
    if not success:
        print("\n\033[91m[!] Failed to open registry monitor.\033[0m")
    input("\nPress Enter to return to the main menu...")


def handle_settings():
    """Handle the settings menu."""
    while True:
        clear_screen()
        print("\n\033[95mSettings Menu:\033[0m")
        print("\033[93m1. View Logs")
        print("2. Clear Logs")
        print("3. View System Info")
        print("0. Back to Main Menu\033[0m")

        choice = input("\nEnter your choice (0-3): ").strip()

        if choice == '1':
            # View logs
            log_file = 'logs/guardrail_system.log'
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        print(f"\n\033[94m=== Log File: {log_file} ===\033[0m")
                        print(f.read()[-2000:])  # Show last 2000 chars
                except (IOError, OSError) as e:
                    print(f"\n\033[91m[!] Error reading log file: {str(e)}\033[0m")
            else:
                print("\n\033[91m[!] Log file not found.\033[0m")
            input("\nPress Enter to continue...")

        elif choice == '2':
            # Clear logs
            log_file = 'logs/guardrail_system.log'
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'w'):
                        pass
                    print("\n\033[92m[+] Logs cleared successfully.\033[0m")
                except (IOError, OSError) as e:
                    print(f"\n\033[91m[!] Error clearing logs: {str(e)}\033[0m")
            else:
                print("\n\033[91m[!] Log file not found.\033[0m")
            input("\nPress Enter to continue...")

        elif choice == '3':
            # System info
            print("\n\033[94m=== System Information ===\033[0m")
            print(f"OS: {platform.system()} {platform.release()}")
            print(f"Python: {platform.python_version()}")
            print(f"CPU Cores: {os.cpu_count()}")
            print(f"Current Directory: {os.getcwd()}")
            input("\nPress Enter to continue...")

        elif choice == '0':
            break

        else:
            print("\n\033[91m[!] Invalid choice. Please try again.\033[0m")


def animate_menu_transition():
    """Show a smooth transition effect between menu states."""
    width = shutil.get_terminal_size().columns
    print("\n" + " " * ((width - 20) // 2), end="")

    # Show a loading bar animation
    for i in range(21):
        progress = i / 20
        bar = "[" + "=" * i + " " * (20 - i) + "]"
        color = f"\033[38;2;{int(255 * progress)};{int(255 * (1 - progress))};0m"
        sys.stdout.write(f"\r{color}{bar} {int(progress * 100)}%\033[0m")
        sys.stdout.flush()
        time.sleep(0.05)

    # Clear the line after animation
    sys.stdout.write("\r" + " " * (width + 10) + "\r")
    sys.stdout.flush()


# Global variables for CPU percent calculation
last_cpu_percent = 0.0
last_update = time.time()

# Global input thread handle
input_thread_handle = None


def get_cpu_usage():
    """Get CPU usage percentage with minimal caching for real-time monitoring.
    
    Returns:
        float: Current CPU usage percentage (0-100)
    """
    global last_cpu_percent, last_update

    current_time = time.time()
    # Update CPU usage at most once every 0.2 seconds for smoother updates
    if current_time - last_update >= 0.2:  # Reduced from 1.0 to 0.2 seconds
        # Use a very small interval for quicker response
        last_cpu_percent = psutil.cpu_percent(interval=0.05)  # Reduced interval for faster updates
        last_update = current_time

    return last_cpu_percent


def get_cpu_temperature() -> Optional[float]:
    """Get CPU temperature in Celsius using multiple methods."""
    logger.debug("Attempting to get CPU temperature...")
    try:
        # Method 1: Try psutil first (works on most systems)
        if hasattr(psutil, 'sensors_temperatures'):
            temps = psutil.sensors_temperatures()
            logger.debug("psutil sensors_temperatures result: %s", temps)
            if temps:
                # Try common temperature sensor names
                for name in ['coretemp', 'k10temp', 'cpu-thermal', 'cpu_thermal', 'soc_thermal']:
                    if name in temps and temps[name]:
                        result = max([entry.current for entry in temps[name] if hasattr(entry, 'current')])
                        logger.debug("Got CPU temperature from psutil %s: %.1f°C", name, result)
                        return result
                # If no known sensor found, try any temperature sensor
                for name, entries in temps.items():
                    if entries and hasattr(entries[0], 'current'):
                        result = max([entry.current for entry in entries if hasattr(entry, 'current')])
                        logger.debug("Got CPU temperature from psutil %s: %.1f°C", name, result)
                        return result

        # Method 2: Windows-specific methods
        if platform.system() == 'Windows':
            logger.debug("Trying Windows-specific temperature methods...")
            # Try using OpenHardwareMonitor if available
            try:
                # Try to import comtypes, but handle if it's not available
                try:
                    import comtypes.client
                    # No need for explicit COM initialization in this case
                    # Use comtypes.client.CoGetObject instead of client.GetObject
                    wmi = comtypes.client.CoGetObject(r"winmgmts:\\.\root\OpenHardwareMonitor")
                    temperature_infos = wmi.ExecQuery(
                        "SELECT * FROM Sensor WHERE SensorType='Temperature'"
                    )
                    cpu_temps = [float(sensor.Value) for sensor in temperature_infos 
                               if 'cpu' in sensor.Name.lower() and 'temperature' in sensor.Name.lower()]
                    if cpu_temps:
                        result = max(cpu_temps)
                        logger.debug("Got CPU temperature from OpenHardwareMonitor: %.1f°C", result)
                        return result
                except ImportError:
                    # comtypes not available, skip this method
                    logger.debug("comtypes not available for OpenHardwareMonitor")
                    pass
                except Exception as e:
                    logger.debug("OpenHardwareMonitor failed: %s", e)
            except ImportError:
                pass

            # Try LibreHardwareMonitor
            try:
                import comtypes.client
                # Use comtypes.client.CoGetObject instead of client.GetObject
                wmi = comtypes.client.CoGetObject(r"winmgmts:\\.\root\LibreHardwareMonitor")
                temperature_infos = wmi.ExecQuery(
                    "SELECT * FROM Sensor WHERE SensorType='Temperature'"
                )
                cpu_temps = [float(sensor.Value) for sensor in temperature_infos 
                           if 'cpu' in sensor.Name.lower() and 'temperature' in sensor.Name.lower()]
                if cpu_temps:
                    result = max(cpu_temps)
                    logger.debug("Got CPU temperature from LibreHardwareMonitor: %.1f°C", result)
                    return result
            except ImportError:
                logger.debug("comtypes not available for LibreHardwareMonitor")
                pass
            except Exception as e:
                logger.debug("LibreHardwareMonitor failed: %s", e)

            # Fallback to wmic command
            try:
                import subprocess
                output = subprocess.check_output(
                    'wmic /namespace:\\\\root\\cimv2 PATH Win32_PerfFormattedData_Counters_ThermalZoneInformation get Temperature',
                    shell=True, stderr=subprocess.DEVNULL)
                if output:
                    lines = output.decode().strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        if line.strip() and line.strip().isdigit():
                            temp = (float(line.strip()) / 10.0) - 273.15  # Convert from decikelvin to Celsius
                            if temp > 0 and temp < 150:  # Reasonable range
                                logger.debug("Got CPU temperature from WMIC: %.1f°C", temp)
                                return temp
            except Exception as e:
                logger.debug("WMIC temperature check failed: %s", e)

        # Method 3: Try reading from sysfs (Linux)
        if platform.system() == 'Linux':
            import os
            temp_paths = [
                '/sys/class/thermal/thermal_zone0/temp',
                '/sys/class/hwmon/hwmon0/temp1_input',
                '/sys/class/hwmon/hwmon1/temp1_input'
            ]
            for path in temp_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r') as f:
                            temp = float(f.read().strip()) / 1000.0
                            if 0 < temp < 120:  # Sanity check
                                logger.debug("Got CPU temperature from sysfs: %.1f°C", temp)
                                return temp
                    except (ValueError, IOError):
                        continue

        logger.debug("Could not retrieve CPU temperature from any method")
        return None
    except Exception as e:
        logger.error("Error getting CPU temperature: %s", e)
        return None


def get_gpu_temperature() -> Optional[float]:
    """Get GPU temperature in Celsius."""
    try:
        if platform.system() == 'Windows':
            # Windows: Use nvidia-smi if available
            try:
                output = subprocess.check_output('nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader',
                                                 shell=True)
                return float(output.decode().strip())
            except (subprocess.SubprocessError, OSError):
                # Try AMD GPU
                try:
                    output = subprocess.check_output(
                        'wmic /namespace:\\root\cimv2 PATH Win32_VideoController GET AdapterCompatibility, Name, DriverVersion',
                        shell=True)
                    if 'AMD' in output.decode():
                        # For AMD, we might need to use a different method
                        return None
                except (subprocess.SubprocessError, OSError):
                    return None
        else:
            # Linux: Try nvidia-smi
            try:
                output = subprocess.check_output(['nvidia-smi', '--query-gpu=temperature.gpu', '--format=csv,noheader'])
                return float(output.decode().strip())
            except (subprocess.SubprocessError, OSError):
                return None
    except (RuntimeError, OSError):
        return None


def get_enhanced_system_stats_dict() -> dict:
    """Get system statistics as a dictionary with enhanced metrics."""
    try:
        # Get all stats from monitor
        if monitor is not None:
            stats = monitor.get_all_stats()
        else:
            stats = {}

        # Get temperatures
        cpu_temp = get_cpu_temperature()
        gpu_temp = get_gpu_temperature()

        # Get GPU memory usage if available
        gpu_mem_used = gpu_mem_total = gpu_mem_percent = None
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output(
                    'nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader,nounits',
                    shell=True
                )
                used, total = map(int, output.decode().strip().split(','))
                gpu_mem_used = used / 1024  # Convert to GB
                gpu_mem_total = total / 1024  # Convert to GB
                gpu_mem_percent = (used / total) * 100
        except (subprocess.SubprocessError, OSError):
            # Fall back to GPUtil if available
            if 'gpu' in stats and stats['gpu']:
                gpu_mem_used = stats['gpu'].get('memory_used')
                gpu_mem_total = stats['gpu'].get('memory_total')
                gpu_mem_percent = stats['gpu'].get('memory_percent')

        # Format uptime
        uptime_seconds = time.time() - psutil.boot_time()
        days, remainder = divmod(int(uptime_seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, _ = divmod(remainder, 60)

        # Extract values from stats
        cpu_percent = stats.get('cpu', {}).get('percent', 0.0)
        mem_percent = stats.get('memory', {}).get('percent', 0.0)
        mem_used = stats.get('memory', {}).get('used_gb', 0.0)
        mem_total = stats.get('memory', {}).get('total_gb', 0.0)
        disk_percent = stats.get('disk', {}).get('percent', 0.0)
        disk_used = stats.get('disk', {}).get('used_gb', 0.0)
        disk_total = stats.get('disk', {}).get('total_gb', 0.0)

        # Check Ollama status safely
        ollama_status_result = check_ollama_status(app_state)
        ollama_status = "[red]Unknown[/]"
        if ollama_status_result is not None and len(ollama_status_result) >= 2:
            ollama_status = ollama_status_result[1]

        return {
            'cpu_percent': cpu_percent,
            'cpu_temp': cpu_temp,
            'cpu_cores': os.cpu_count(),
            'memory_percent': mem_percent,
            'memory_used': mem_used,
            'memory_total': mem_total,
            'disk_percent': disk_percent,
            'disk_used': disk_used,
            'disk_total': disk_total,
            'gpu_temp': gpu_temp,
            'gpu_mem_used': gpu_mem_used,
            'gpu_mem_total': gpu_mem_total,
            'gpu_mem_percent': gpu_mem_percent,
            'uptime': f"{days}d {hours}h {minutes}m",
            'current_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ollama_status': ollama_status  # Get the display status
        }
    except (RuntimeError, OSError) as e:
        print(f"\n\033[91m[!] Error getting system stats: {str(e)}\033[0m")
        return {}


def get_enhanced_system_stats() -> dict:
    """Get enhanced system statistics with additional metrics."""
    try:
        # Get base stats from monitor
        stats = get_system_stats()

        # Add additional metrics
        disk_io = psutil.disk_io_counters()
        stats['disk_io'] = {
            'read_mb': disk_io.read_bytes / (1024 * 1024) if disk_io else 0,
            'write_mb': disk_io.write_bytes / (1024 * 1024) if disk_io else 0
        }

        net_io = psutil.net_io_counters()
        stats['network'] = {
            'sent_mb': net_io.bytes_sent / (1024 * 1024),
            'recv_mb': net_io.bytes_recv / (1024 * 1024),
            'connections': len(psutil.net_connections())
        }

        # Add process count
        stats['system'] = {
            'processes': len(psutil.pids()),
            'boot_time': psutil.boot_time(),
            'uptime': str(timedelta(seconds=int(time.time() - psutil.boot_time())))
        }

        return stats

    except (RuntimeError, OSError) as e:
        logger.error("Error in get_enhanced_system_stats: %s", e)
        return {'error': str(e)}


def create_stats_table(stats: dict) -> Table:
    """Create a rich Table with system statistics including horizontal bars and temperatures."""
    if not stats:
        return Table(title="System Stats (Error)")

    # Create a table with 2 columns
    table = Table(title="System Statistics")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")
    
    # Add rows for each metric
    for key, value in stats.items():
        table.add_row(key, str(value))
    
    return table


def show_initialization_screen():
    """Show initialization screen with system check."""
    console = Console()

    console.print("\n[bold blue]Initializing Guardrail Security System...[/]")

    # Check if monitor is initialized
    global monitor
    if monitor is None:
        try:
            monitor = SystemMonitor()
        except Exception as e:
            console.print(f"[red]Error:[/] Failed to initialize system monitor: {str(e)}")
            logger.error("Failed to initialize system monitor: %s", str(e))
            return False

    try:
        # Test system monitoring
        try:
            test_stats = monitor.get_all_stats()
            if not test_stats:
                console.print("[yellow]Warning:[/] System statistics returned empty")
                logger.warning("System statistics returned empty")
            else:
                # Check for None values in stats
                for key, value in test_stats.items():
                    if value is None:
                        logger.warning("Got None value for key: %s", key)
                    elif isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            if subvalue is None:
                                logger.warning("Got None value for %s.%s", key, subkey)
        except Exception as e:
            logger.error("Failed to test system monitor: %s", e, exc_info=True)
            raise

        # Check Ollama status
        try:
            logger.debug("Checking Ollama status...")
            status_result = check_ollama_status(app_state)
            if status_result is None or len(status_result) < 2:
                logger.error("Unexpected status result: %s", status_result)
                app_state.ollama_status = "[yellow]Unknown[/]"
            else:
                app_state.ollama_status = status_result[1]
                logger.debug("Ollama status set to: %s", app_state.ollama_status)
        except Exception as e:
            logger.error("Error checking Ollama status: %s", e, exc_info=True)
            app_state.ollama_status = "[red]Error[/]"

        time.sleep(0.5)  # Brief pause
        return True

    except Exception as e:
        app_state.console.print(f"[red]Initialization error: {e}")
        time.sleep(1)
        return False


def handle_menu_selection(choice: str) -> None:
    """
    Handle the user's menu selection.
    
    Args:
        choice: The user's menu selection
    """
    console = Console()

    try:
        if choice == '1':
            handle_secure_shell()
        elif choice == '2':
            handle_ai_scan()
        elif choice == '3':
            # System Monitor option
            console.print("\n[bold blue]System Monitor[/]")
            console.print("This feature is not yet implemented.")
            console.input("\nPress Enter to continue...")
        elif choice == '4':
            handle_registry_monitor()
        elif choice.lower() == 's':
            handle_settings()
        else:
            console.print("\n[red]Invalid selection. Please try again.[/]")
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/]")
        log_event("ERROR", "Menu selection error: {error}", error=str(e))


def main() -> int:
    """
    Main entry point for the Guardrail Security System.
    
    Returns:
        int: Exit code (0 for success, non-zero for error)
    """
    global stop_input_thread, input_thread_handle

    logger.debug("Starting main application")

    # Start the input thread
    global input_thread_handle
    input_thread_handle = threading.Thread(target=input_thread, daemon=True)
    input_thread_handle.start()

    try:
        # Show initialization
        clear_screen()
        if not show_initialization_screen():
            app_state.console.print("\n[red]Initialization failed. Exiting...[/]")
            return 1

        # Main menu loop
        try:
            # Create and start the live display with the configured console
            with Live(generate_dashboard(),
                      refresh_per_second=10,  # Increased from 4 to 10 refreshes per second
                      screen=True,
                      console=app_state.console) as live:

                last_update = 0
                while app_state.running:
                    current_time = time.time()

                    # Update the display at most 30 times per second (every ~33ms)
                    if current_time - last_update >= 0.033:  # ~30fps update rate
                        live.update(generate_dashboard())
                        last_update = current_time

                    # Check for key press using both methods for reliability
                    key = get_key_press()
                    if key is not None:
                        logger.debug("Key pressed: %s", key)
                    
                    # Process all available keys in the queue
                    processed_key = False
                    while key or not processed_key:  # Process at least once if we had a key
                        if key is not None:
                            logger.debug("Processing key: %s", key)
                            if key == 'q':
                                app_state.console.print("\n[yellow]Shutting down...[/]")
                                app_state.running = False
                                break
                            elif key in ['1', '2', '3', '4', 's']:
                                # Instead of stopping/starting live display, just handle the selection directly
                                # This avoids the delay caused by stopping and starting the live display
                                handle_menu_selection(key)
                                # Force an immediate refresh after handling menu selection
                                live.update(generate_dashboard())
                                break  # Only handle one menu selection per frame
                            elif key == '\x03':  # Ctrl+C
                                app_state.console.print("\n[yellow]Shutting down...[/]")
                                app_state.running = False
                                break

                        # Get next key if available
                        key = get_key_press()
                        processed_key = True
                        if key is not None:
                            logger.debug("Next key: %s", key)

                    # Small sleep to prevent high CPU usage
                    time.sleep(0.005)  # 5ms sleep for even more responsive input

        except KeyboardInterrupt:
            app_state.console.print("\n[yellow]Operation cancelled by user.[/]")
        except Exception as e:
            app_state.console.print(f"\n[red]An error occurred: {str(e)}[/]")
            log_event("ERROR", "Application error: {error}", error=str(e))
            time.sleep(2)
            return 1

        return 0

    except Exception as e:
        app_state.console.print(f"\n[red]Fatal error: {str(e)}[/]")
        log_event(event_type="FATAL", message="Application crashed: {error}", error=str(e))
        return 1
    finally:
        # Ensure cleanup always runs
        app_state.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[yellow]Shutdown requested. Cleaning up...[/]")
    except Exception as e:
        print(f"\n\033[91m[!] Fatal error: {str(e)}\033[0m")
        log_event(event_type="FATAL", message="Application crashed: {error}", error=str(e))
    finally:
        # Signal input thread to stop and wait for it
        stop_input_thread = True
        if 'input_thread_handle' in globals() and input_thread_handle is not None:
            input_thread_handle.join(timeout=1.0)

        # Ensure the terminal is reset
        print("\033[0m", end="")  # Reset any formatting
        print("\nThank you for using Guardrail Security System. Goodbye!")
        sys.exit(0)
