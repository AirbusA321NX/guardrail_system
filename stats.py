import time
import logging
import platform
import os
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, List

# Try to import WMI for Windows
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

# Try to import psutil as fallback
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self):
        self.wmi = None
        self.gputil_available = False  # Add this flag
        self.cpu_usage = 0.0
        self.last_cpu_times = None
        self.last_cpu_update = 0
        
        if platform.system() == 'Windows' and WMI_AVAILABLE:
            try:
                import wmi
                self.wmi = wmi.WMI()
                # Test WMI connection
                self.wmi.Win32_ComputerSystem()[0]
                logger.info("WMI initialized successfully")
            except Exception as e:
                logger.error("Failed to initialize WMI: %s", e)
                self.wmi = None
        
        # Check for GPUtil availability once
        try:
            import GPUtil
            self.gputil_available = True
            logger.debug("GPUtil is available for GPU info")
        except ImportError:
            self.gputil_available = False
            logger.debug("GPUtil not available for GPU info")
        
        # Fallback to psutil if WMI is not available
        if not self.wmi and PSUTIL_AVAILABLE:
            logger.info("Using psutil as fallback")

    def get_cpu_temperature(self) -> Optional[float]:
        """Get CPU temperature if available."""
        logger.debug("SystemMonitor: Attempting to get CPU temperature...")
        try:
            # Try platform-specific methods first
            system = platform.system()
            logger.debug("System type: %s", system)
            
            # For Linux and macOS, try psutil sensors
            if system in ['Linux', 'Darwin']:
                try:
                    import psutil
                    if PSUTIL_AVAILABLE and hasattr(psutil, "sensors_temperatures"):
                        temps = psutil.sensors_temperatures()
                        logger.debug("psutil sensors_temperatures result: %s", temps)
                        if temps:
                            # Try common temperature sensor names
                            for name in ['coretemp', 'k10temp', 'cpu-thermal', 'cpu_thermal', 'soc_thermal']:
                                if name in temps and temps[name]:
                                    # Get the current temperature from the first entry
                                    for entry in temps[name]:
                                        if hasattr(entry, 'current') and entry.current is not None:
                                            temp = float(entry.current)
                                            if temp > 0 and temp < 150:  # Reasonable range check
                                                logger.debug("SystemMonitor: Got CPU temperature from psutil %s: %.1f°C", name, temp)
                                                return temp
                            # If no known sensor found, try any temperature sensor
                            for name, entries in temps.items():
                                if entries:
                                    for entry in entries:
                                        if hasattr(entry, 'current') and entry.current is not None:
                                            temp = float(entry.current)
                                            if temp > 0 and temp < 150:  # Reasonable range check
                                                logger.debug("SystemMonitor: Got CPU temperature from psutil %s: %.1f°C", name, temp)
                                                return temp
                except Exception as e:
                    logger.debug("SystemMonitor: Error getting CPU temperature via psutil: %s", e)
            
            # For Windows, try multiple WMI methods
            elif system == 'Windows' and WMI_AVAILABLE and self.wmi:
                logger.debug("SystemMonitor: Trying Windows WMI methods...")
                # Method 1: Try standard WMI thermal zone
                try:
                    temperature_info = self.wmi.MSAcpi_ThermalZoneTemperature()
                    if temperature_info:
                        # Convert from tenths of Kelvin to Celsius
                        temp = (temperature_info[0].CurrentTemperature / 10.0) - 273.15
                        if temp > 0 and temp < 150:  # Reasonable range check
                            logger.debug("SystemMonitor: Got CPU temperature from MSAcpi_ThermalZoneTemperature: %.1f°C", temp)
                            return temp
                        else:
                            logger.debug("SystemMonitor: MSAcpi_ThermalZoneTemperature returned invalid temperature: %s", temp)
                except Exception as e:
                    logger.debug("SystemMonitor: MSAcpi_ThermalZoneTemperature failed: %s", e)
                
                # Method 2: Try Win32_PerfFormattedData_Counters_ThermalZoneInformation
                try:
                    thermal_zones = self.wmi.Win32_PerfFormattedData_Counters_ThermalZoneInformation()
                    if thermal_zones:
                        for zone in thermal_zones:
                            if hasattr(zone, 'Temperature') and zone.Temperature is not None:
                                # This is in decikelvin, convert to Celsius
                                temp = (float(zone.Temperature) / 10.0) - 273.15
                                if temp > 0 and temp < 150:  # Reasonable range check
                                    logger.debug("SystemMonitor: Got CPU temperature from ThermalZoneInformation: %.1f°C", temp)
                                    return temp
                                else:
                                    logger.debug("SystemMonitor: ThermalZoneInformation returned invalid temperature: %s", temp)
                except Exception as e:
                    logger.debug("SystemMonitor: Win32_PerfFormattedData_Counters_ThermalZoneInformation failed: %s", e)
                
                # Method 3: Try Win32_TemperatureProbe
                try:
                    probes = self.wmi.Win32_TemperatureProbe()
                    if probes:
                        for probe in probes:
                            if hasattr(probe, 'CurrentReading') and probe.CurrentReading is not None:
                                temp = float(probe.CurrentReading)
                                if temp > 0 and temp < 150:  # Reasonable range check
                                    logger.debug("SystemMonitor: Got CPU temperature from Win32_TemperatureProbe: %.1f°C", temp)
                                    return temp
                                else:
                                    logger.debug("SystemMonitor: Win32_TemperatureProbe returned invalid temperature: %s", temp)
                except Exception as e:
                    logger.debug("SystemMonitor: Win32_TemperatureProbe failed: %s", e)
                
                # Method 4: Try OpenHardwareMonitor WMI namespace
                try:
                    import wmi
                    w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
                    sensors = w.Sensor()
                    cpu_temps = []
                    for sensor in sensors:
                        if (hasattr(sensor, 'SensorType') and 
                            hasattr(sensor, 'Name') and 
                            hasattr(sensor, 'Value') and
                            sensor.SensorType == u'Temperature' and 
                            'CPU' in sensor.Name):
                            temp = float(sensor.Value)
                            if temp > 0 and temp < 150:  # Reasonable range check
                                cpu_temps.append(temp)
                    
                    if cpu_temps:
                        # Return the maximum CPU temperature
                        max_temp = max(cpu_temps)
                        logger.debug("SystemMonitor: Got CPU temperature from OpenHardwareMonitor: %.1f°C", max_temp)
                        return max_temp
                except Exception as e:
                    logger.debug("SystemMonitor: OpenHardwareMonitor WMI failed: %s", e)
                
                # Method 5: Try LibreHardwareMonitor WMI namespace
                try:
                    import wmi
                    w = wmi.WMI(namespace="root\\LibreHardwareMonitor")
                    sensors = w.Sensor()
                    cpu_temps = []
                    for sensor in sensors:
                        if (hasattr(sensor, 'SensorType') and 
                            hasattr(sensor, 'Name') and 
                            hasattr(sensor, 'Value') and
                            sensor.SensorType == u'Temperature' and 
                            'CPU' in sensor.Name):
                            temp = float(sensor.Value)
                            if temp > 0 and temp < 150:  # Reasonable range check
                                cpu_temps.append(temp)
                    
                    if cpu_temps:
                        # Return the maximum CPU temperature
                        max_temp = max(cpu_temps)
                        logger.debug("SystemMonitor: Got CPU temperature from LibreHardwareMonitor: %.1f°C", max_temp)
                        return max_temp
                except Exception as e:
                    logger.debug("SystemMonitor: LibreHardwareMonitor WMI failed: %s", e)
            
            logger.debug("SystemMonitor: Could not retrieve CPU temperature from any method")
            return None
            
        except Exception as e:
            logger.error("SystemMonitor: Unexpected error in get_cpu_temperature: %s", e)
            return None

    def get_process_list(self, process_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get a list of running processes, optionally filtered by name.
        
        Args:
            process_name: Optional name to filter processes by (case-insensitive)
            
        Returns:
            List of process dictionaries with 'pid', 'name', 'cpu_percent', 'memory_percent'
        """
        processes = []
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available for process monitoring")
            return processes
            
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    if process_name:
                        # Ensure both process_name and pinfo['name'] are strings before comparison
                        proc_name = str(pinfo.get('name', '')).lower()
                        search_name = str(process_name).lower()
                        if search_name not in proc_name:
                            continue
                    
                    processes.append({
                        'pid': pinfo.get('pid'),
                        'name': pinfo.get('name', 'unknown'),
                        'cpu_percent': pinfo.get('cpu_percent', 0),
                        'memory_percent': pinfo.get('memory_percent', 0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logger.debug("Skipping process due to error: %s", e)
                    continue
                except Exception as e:
                    logger.warning("Unexpected error processing process: %s", e)
                    continue
        except Exception as e:
            logger.error("Error in process iteration: %s", e)
        
        return processes

    def get_all_stats(self) -> Dict[str, Any]:
        """Get all system statistics in a single call with WMI fallback.
        
        This method forces fresh readings for all metrics to ensure real-time data.
        """
        stats = {
            'cpu': {'percent': 0.0, 'temperature': None},
            'memory': {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0},
            'disk': {'percent': 0.0, 'used_gb': 0.0, 'total_gb': 0.0, 'free_gb': 0.0},
            # Provide a default structure for GPU
            'gpu': {'load': 0.0, 'temperature': None},
            'timestamp': datetime.now().strftime('%H:%M:%S')  # Use datetime for consistent timestamp
        }
        
        try:
            # Get fresh CPU usage with minimal interval
            if PSUTIL_AVAILABLE:
                import psutil
                # Use non-blocking call for CPU percentage to avoid delays
                stats['cpu']['percent'] = psutil.cpu_percent(interval=None)
                
                # Get fresh memory usage
                mem = psutil.virtual_memory()
                stats['memory'] = {
                    'percent': mem.percent,
                    'used_gb': round(mem.used / (1024 ** 3), 1),
                    'total_gb': round(mem.total / (1024 ** 3), 1),
                    'free_gb': round(mem.available / (1024 ** 3), 1)
                }
                
                # Get fresh disk usage
                disk_path = 'C:\\' if platform.system() == 'Windows' else '/'
                disk = psutil.disk_usage(disk_path)
                stats['disk'] = {
                    'percent': disk.percent,
                    'used_gb': round(disk.used / (1024 ** 3), 1),
                    'total_gb': round(disk.total / (1024 ** 3), 1),
                    'free_gb': round(disk.free / (1024 ** 3), 1)
                }
                
                # Get CPU temperature if available (but don't block if it takes too long)
                try:
                    stats['cpu']['temperature'] = self.get_cpu_temperature()
                except Exception as e:
                    logger.debug("Could not get CPU temperature: %s", e)
            
            # Get GPU info if available
            # Use the flag here
            if self.gputil_available:
                try:
                    import GPUtil  # Python caches this import, so it's fast
                    gpus = GPUtil.getGPUs()
                    if gpus:
                        gpu = gpus[0]
                        stats['gpu'] = {
                            # Convert load to a percentage
                            "load": gpu.load * 100,
                            "memory_used": gpu.memoryUsed,
                            "memory_total": gpu.memoryTotal,
                            "memory_percent": (gpu.memoryUsed / gpu.memoryTotal) * 100 if gpu.memoryTotal > 0 else 0,
                            "temperature": gpu.temperature,
                            "name": gpu.name
                        }
                except Exception as e:
                    logger.error("Error getting GPU info: %s", e)
                
            logger.debug("Updated system stats: %s", stats)
            
        except Exception as e:
            logger.error("Error updating system stats: %s", e, exc_info=True)
            
        return stats

# Create a global instance for easy importing
monitor = SystemMonitor()