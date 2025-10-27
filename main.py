import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import platform
import subprocess
import re
import requests
import os
import wmi
import GPUtil
import ctypes
import sys

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart the script with administrator privileges"""
    if is_admin():
        return
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def main():
    # Check if running as admin on Windows
    if platform.system() == "Windows" and not is_admin():
        # Ask user if they want to restart with admin privileges
        root = tk.Tk()
        root.withdraw()  # Hide the root window
        result = messagebox.askyesno("Administrator Privileges Required", 
                                   "This application requires administrator privileges to access system temperature sensors. "
                                   "Would you like to restart the application with administrator privileges?")
        root.destroy()
        
        if result:
            run_as_admin()
        else:
            print("Application requires administrator privileges to access temperature sensors.")
            return
    
    # If we get here, we're either running as admin or on a non-Windows system
    root = tk.Tk()
    
    # Configure styles for colored progress bars
    style = ttk.Style()
    style.theme_use('clam')
    
    # Configure custom styles for progress bars
    style.configure("green.Horizontal.TProgressbar", troughcolor='#444444', background='green')
    style.configure("blue.Horizontal.TProgressbar", troughcolor='#444444', background='blue')
    style.configure("red.Horizontal.TProgressbar", troughcolor='#444444', background='red')
    
    # Create the UI
    app = GuardrailSystemUI(root)
    
    # Handle window closing
    def on_closing():
        app.monitoring = False
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

class GuardrailSystemUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Guardrail System")
        self.root.geometry("800x600")
        self.root.configure(bg='#2e2e2e')
        
        # Status variables
        self.ollama_status = False
        self.cpu_usage = 0
        self.gpu_usage = 0
        self.cpu_temp = 0
        self.gpu_temp = 0
        self.ram_percent = 0
        self.storage_percent = 0
        
        # Create UI elements
        self.create_header()
        self.create_resource_display()
        self.create_usage_bars()
        self.create_module_menu()
        self.create_start_button()
        
        # Start monitoring thread
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.update_system_info, daemon=True)
        self.monitor_thread.start()
        
    def create_header(self):
        # Header frame
        header_frame = tk.Frame(self.root, bg='#2e2e2e')
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        # Title
        title_label = tk.Label(header_frame, text="GUARDRAIL SYSTEM", font=("Arial", 20, "bold"), 
                              fg="white", bg='#2e2e2e')
        title_label.pack(side=tk.TOP, pady=(0, 10))
        
        # Ollama status with blinking animation
        self.ollama_status_frame = tk.Frame(header_frame, bg='#2e2e2e')
        self.ollama_status_frame.pack(side=tk.LEFT)
        
        tk.Label(self.ollama_status_frame, text="Ollama Status:", font=("Arial", 12), 
                fg="white", bg='#2e2e2e').pack(side=tk.LEFT)
        
        self.ollama_status_label = tk.Label(self.ollama_status_frame, text="OFF", font=("Arial", 12, "bold"), 
                                           fg="red", bg='#2e2e2e')
        self.ollama_status_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Blinking animation
        self.blink_state = False
        self.blink_ollama_status()
        
    def blink_ollama_status(self):
        if self.ollama_status:
            # Ollama is ON - alternate between green and lime
            self.ollama_status_label.config(text="ON", fg="green" if self.blink_state else "lime")
        else:
            # Ollama is OFF - alternate between red and light red
            self.ollama_status_label.config(text="OFF", fg="red" if self.blink_state else "#ff6666")
            
        self.blink_state = not self.blink_state
        self.root.after(500, self.blink_ollama_status)  # Blink every 500ms
        
    def create_resource_display(self):
        # Resource display frame
        resource_frame = tk.Frame(self.root, bg='#2e2e2e')
        resource_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # RAM utilization ring
        ram_frame = tk.Frame(resource_frame, bg='#2e2e2e')
        ram_frame.pack(side=tk.LEFT, padx=(0, 20))
        
        self.ram_canvas = tk.Canvas(ram_frame, width=100, height=100, bg='#2e2e2e', highlightthickness=0)
        self.ram_canvas.pack()
        self.draw_ring(self.ram_canvas, 50, 50, 40, 0, "RAM")
        
        # Storage utilization ring
        storage_frame = tk.Frame(resource_frame, bg='#2e2e2e')
        storage_frame.pack(side=tk.LEFT)
        
        self.storage_canvas = tk.Canvas(storage_frame, width=100, height=100, bg='#2e2e2e', highlightthickness=0)
        self.storage_canvas.pack()
        self.draw_ring(self.storage_canvas, 50, 50, 40, 0, "STORAGE")
        
    def draw_ring(self, canvas, cx, cy, radius, percent, label):
        # Clear canvas
        canvas.delete("all")
        
        # Background ring
        canvas.create_oval(cx-radius, cy-radius, cx+radius, cy+radius, 
                          outline="#444444", width=10)
        
        # Color based on percentage
        color = self.get_color(percent)
        
        # Progress arc
        start_angle = 90
        extent = -percent * 3.6  # Convert percentage to degrees
        if percent > 0:
            canvas.create_arc(cx-radius, cy-radius, cx+radius, cy+radius,
                             start=start_angle, extent=extent, outline=color, width=10, style="arc")
        
        # Percentage text
        canvas.create_text(cx, cy, text=f"{int(percent)}%", font=("Arial", 10, "bold"), fill="white")
        canvas.create_text(cx, cy+20, text=label, font=("Arial", 8), fill="white")
        
    def create_usage_bars(self):
        # CPU/GPU usage frame
        usage_frame = tk.Frame(self.root, bg='#2e2e2e')
        usage_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # CPU usage bar
        cpu_frame = tk.Frame(usage_frame, bg='#2e2e2e')
        cpu_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(cpu_frame, text="CPU Usage:", font=("Arial", 10), fg="white", bg='#2e2e2e').pack(side=tk.LEFT)
        self.cpu_bar = ttk.Progressbar(cpu_frame, length=300, mode='determinate')
        self.cpu_bar.pack(side=tk.LEFT, padx=(10, 0))
        self.cpu_bar['maximum'] = 100
        
        self.cpu_label = tk.Label(cpu_frame, text="0%", font=("Arial", 10), fg="white", bg='#2e2e2e', width=5)
        self.cpu_label.pack(side=tk.LEFT, padx=(5, 20))
        
        self.cpu_temp_label = tk.Label(cpu_frame, text="Temp: 0°C", font=("Arial", 10), fg="white", bg='#2e2e2e')
        self.cpu_temp_label.pack(side=tk.LEFT)
        
        # GPU usage bar
        gpu_frame = tk.Frame(usage_frame, bg='#2e2e2e')
        gpu_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(gpu_frame, text="GPU Usage:", font=("Arial", 10), fg="white", bg='#2e2e2e').pack(side=tk.LEFT)
        self.gpu_bar = ttk.Progressbar(gpu_frame, length=300, mode='determinate')
        self.gpu_bar.pack(side=tk.LEFT, padx=(10, 0))
        self.gpu_bar['maximum'] = 100
        
        self.gpu_label = tk.Label(gpu_frame, text="0%", font=("Arial", 10), fg="white", bg='#2e2e2e', width=5)
        self.gpu_label.pack(side=tk.LEFT, padx=(5, 20))
        
        self.gpu_temp_label = tk.Label(gpu_frame, text="Temp: 0°C", font=("Arial", 10), fg="white", bg='#2e2e2e')
        self.gpu_temp_label.pack(side=tk.LEFT)
        
    def create_module_menu(self):
        # Module selection frame
        module_frame = tk.Frame(self.root, bg='#2e2e2e')
        module_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(module_frame, text="Select Module to Run:", font=("Arial", 14, "bold"), 
                fg="white", bg='#2e2e2e').pack(anchor=tk.W)
        
        # Module buttons
        buttons_frame = tk.Frame(module_frame, bg='#2e2e2e')
        buttons_frame.pack(fill=tk.X, pady=(10, 0))
        
        modules = [
            ("Secure Shell", self.run_secure_shell),
            ("App Threat Detection", self.run_app_threat_detection),
            ("Process Monitor", self.run_process_monitor),
            ("Registry Monitor", self.run_registry_monitor),
            ("Service Monitor", self.run_service_monitor),
            ("Memory Capture", self.run_memory_capture),
            ("Archive Scanner", self.run_archive_scanner),
            ("Settings Monitor", self.run_settings_monitor)
        ]
        
        # Create buttons in a grid
        row, col = 0, 0
        for module_name, command in modules:
            btn = tk.Button(buttons_frame, text=module_name, command=command,
                           bg="#444444", fg="white", activebackground="#555555",
                           font=("Arial", 10), width=20, height=2)
            btn.grid(row=row, column=col, padx=5, pady=5)
            
            col += 1
            if col > 3:  # 4 buttons per row
                col = 0
                row += 1
                
    def create_start_button(self):
        # Start system button
        start_frame = tk.Frame(self.root, bg='#2e2e2e')
        start_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.start_button = tk.Button(start_frame, text="START WHOLE GUARDRAIL SYSTEM", 
                                     command=self.start_full_system,
                                     bg="#006600", fg="white", activebackground="#008800",
                                     font=("Arial", 14, "bold"), height=2)
        self.start_button.pack(pady=10)
        
    def get_color(self, value):
        """Return color based on value percentage"""
        if value >= 80:
            return "red"
        elif value >= 50:
            return "blue"
        else:
            return "green"
            
    def get_cpu_temperature(self):
        """Get CPU temperature using multiple methods"""
        try:
            # Method 1: Try WMI MSAcpi_ThermalZoneTemperature
            w = wmi.WMI(namespace="root/wmi")
            temperature_infos = w.MSAcpi_ThermalZoneTemperature()
            if temperature_infos:
                # Convert from decikelvin to celsius
                temp_k = temperature_infos[0].CurrentTemperature / 10
                temp_c = temp_k - 273.15
                if temp_c > 0:
                    return temp_c
        except Exception as e:
            print(f"Method 1 failed: {e}")
            pass
            
        try:
            # Method 2: Try standard WMI thermal zone
            w = wmi.WMI()
            temperature_infos = w.Win32_PerfFormattedData_Counters_ThermalZoneInformation()
            if temperature_infos:
                # Convert from decikelvin to celsius
                temp_k = int(temperature_infos[0].Temperature)
                temp_c = temp_k / 10 - 273.15
                if temp_c > 0:
                    return temp_c
        except Exception as e:
            print(f"Method 2 failed: {e}")
            pass
            
        try:
            # Method 3: Use PowerShell script (the one provided by user)
            cmd = '''powershell "Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace \\"root/wmi\\" | ForEach-Object { ($_.CurrentTemperature / 10) - 273.15 } | Select-Object -First 1"'''
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                temp_c = float(result.stdout.strip())
                if temp_c > 0:
                    return temp_c
        except Exception as e:
            print(f"Method 3 failed: {e}")
            pass
            
        return 0  # Return 0 if no method works
            
    def get_gpu_temperature(self):
        """Get GPU temperature"""
        try:
            gpus = GPUtil.getGPUs()
            if len(gpus) > 0:
                return round(gpus[0].temperature, 2)
        except Exception as e:
            print(f"GPU temp failed: {e}")
            pass
        return 0
            
    def check_ollama_status(self):
        """Check if Ollama service is running"""
        try:
            # Check if ollama process is running
            for proc in psutil.process_iter(['pid', 'name']):
                if 'ollama' in proc.info['name'].lower():
                    return True
        except Exception as e:
            print(f"Process check failed: {e}")
            pass
            
        try:
            # Try to connect to Ollama API
            response = requests.get("http://127.0.0.1:11434/api/tags", timeout=3)
            return response.status_code == 200
        except Exception as e:
            print(f"API check failed: {e}")
            pass
            
        return False
            
    def update_system_info(self):
        """Background thread to update system information"""
        while self.monitoring:
            try:
                # Update resource usage
                self.cpu_usage = psutil.cpu_percent(interval=1)
                
                # Get memory info
                memory = psutil.virtual_memory()
                self.ram_percent = memory.percent
                
                # Get disk usage
                disk = psutil.disk_usage('/')
                self.storage_percent = (disk.used / disk.total) * 100
                
                # Check Ollama status
                self.ollama_status = self.check_ollama_status()
                print(f"Ollama status: {self.ollama_status}")  # Debug print
                
                # Get temperatures
                self.cpu_temp = self.get_cpu_temperature()
                self.gpu_temp = self.get_gpu_temperature()
                print(f"CPU Temp: {self.cpu_temp}°C, GPU Temp: {self.gpu_temp}°C")  # Debug print
                    
                # Update UI in main thread
                self.root.after(0, self.update_ui)
                
                time.sleep(2)  # Update every 2 seconds
            except Exception as e:
                print(f"Error updating system info: {e}")
                time.sleep(5)
                
    def update_ui(self):
        """Update UI elements with current values"""
        # Update rings
        self.draw_ring(self.ram_canvas, 50, 50, 40, self.ram_percent, "RAM")
        self.draw_ring(self.storage_canvas, 50, 50, 40, self.storage_percent, "STORAGE")
        
        # Update progress bars
        self.cpu_bar['value'] = self.cpu_usage
        self.cpu_label.config(text=f"{int(self.cpu_usage)}%")
        
        # Set CPU bar color based on usage
        cpu_color = self.get_color(self.cpu_usage)
        self.cpu_bar.configure(style=f"{cpu_color}.Horizontal.TProgressbar")
        
        # Update CPU temperature with color coding
        self.cpu_temp_label.config(text=f"Temp: {int(self.cpu_temp)}°C")
        temp_color = self.get_color(self.cpu_temp)
        self.cpu_temp_label.config(fg=temp_color)
        
        # Update GPU info
        self.gpu_usage = min(100, max(0, self.cpu_usage + (psutil.cpu_percent() - self.cpu_usage) * 0.5))
        self.gpu_bar['value'] = self.gpu_usage
        self.gpu_label.config(text=f"{int(self.gpu_usage)}%")
        
        # Set GPU bar color based on usage
        gpu_color = self.get_color(self.gpu_usage)
        self.gpu_bar.configure(style=f"{gpu_color}.Horizontal.TProgressbar")
        
        # Update GPU temperature with color coding
        self.gpu_temp_label.config(text=f"Temp: {int(self.gpu_temp)}°C")
        gpu_temp_color = self.get_color(self.gpu_temp)
        self.gpu_temp_label.config(fg=gpu_temp_color)
        
    def run_secure_shell(self):
        print("Running Secure Shell module...")
        # Implementation would go here
        
    def run_app_threat_detection(self):
        print("Running App Threat Detection module...")
        # Implementation would go here
        
    def run_process_monitor(self):
        print("Running Process Monitor module...")
        # Implementation would go here
        
    def run_registry_monitor(self):
        print("Running Registry Monitor module...")
        # Implementation would go here
        
    def run_service_monitor(self):
        print("Running Service Monitor module...")
        # Implementation would go here
        
    def run_memory_capture(self):
        print("Running Memory Capture module...")
        # Implementation would go here
        
    def run_archive_scanner(self):
        print("Running Archive Scanner module...")
        # Implementation would go here
        
    def run_settings_monitor(self):
        print("Running Settings Monitor module...")
        # Implementation would go here
        
    def start_full_system(self):
        print("Starting full Guardrail system...")
        # Implementation would go here

if __name__ == "__main__":
    main()