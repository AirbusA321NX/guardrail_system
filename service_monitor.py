#!/usr/bin/env python3
"""
Windows Service Monitor with AI Analysis

This module monitors Windows services, collects comprehensive metadata,
and uses Mistral AI to analyze services for potential security risks.

Usage:
  python service_monitor.py                           # One-time scan of all services
  python service_monitor.py --mode monitor           # Continuous monitoring only
  python service_monitor.py --mode scan-and-monitor  # Scan all services, then monitor for new ones
"""

import subprocess
import json
import sys
import os
import time
import argparse
import logging
from typing import List, Dict, Any

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/service_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# For continuous monitoring
try:
    import wmi
    WMI_AVAILABLE = True
    _c = wmi.WMI()
except ImportError:
    WMI_AVAILABLE = False
    _c = None
    print("Warning: WMI module not available. Continuous monitoring disabled.")

# Add project root to path for imports
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.append(project_root)

# Ensure logs directory exists
logs_dir = os.path.join(project_root, 'logs')
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

# Import AI analysis function
try:
    from ai.mistral_analysis import analyze_text
    AI_AVAILABLE = True
except ImportError as e:
    print(f"Warning: AI analysis module not available: {e}")
    AI_AVAILABLE = False
    
    # Define a fallback function to prevent "possibly unbound" errors
    def analyze_text(prompt: str, **metadata) -> dict:
        return {"DANGEROUS": False, "reason": "AI analysis not available"}

# Import popup function
try:
    from utils.popups import show_popup
except ImportError as e:
    print(f"Warning: Popup module not available: {e}")
    def show_popup(title: str, message: str):
        print(f"[POPUP] {title}: {message}")

def get_windows_services() -> List[Dict[str, Any]]:
    """
    Get all Windows services with their metadata using PowerShell.
    
    Returns:
        List of dictionaries containing service information
    """
    logger.info("Starting to fetch Windows services...")
    
    # PowerShell command to get service information
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        Get-WmiObject -Class Win32_Service | Select-Object Name, PathName, State, StartMode, Description | ConvertTo-Json
        """
    ]
    
    try:
        # Execute PowerShell command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            logger.error(f"Error executing PowerShell command: {result.stderr}")
            return []
        
        # Parse JSON output
        services = json.loads(result.stdout)
        
        # Ensure we always return a list
        if isinstance(services, dict):
            services = [services]
        elif not isinstance(services, list):
            services = []
            
        logger.info(f"Successfully fetched {len(services)} Windows services")
        return services
        
    except subprocess.TimeoutExpired:
        logger.error("Timeout while fetching Windows services")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON output: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while fetching Windows services: {e}")
        return []

def format_service_for_ai(service: Dict[str, Any]) -> str:
    """
    Format service information for AI analysis.
    
    Args:
        service: Dictionary containing service information
        
    Returns:
        Formatted string for AI analysis
    """
    return f"""
Service Analysis Request:
Please analyze the following Windows service for potential security risks.

Service Name: {service.get('Name', 'Unknown')}
Path to Executable: {service.get('PathName', 'Unknown')}
Status: {service.get('State', 'Unknown')}
Start Mode: {service.get('StartMode', 'Unknown')}
Description: {service.get('Description', 'No description available')}

Instructions:
1. Analyze the service metadata for any signs of malicious or suspicious behavior
2. Pay special attention to:
   - Unusual executable paths (e.g., temp directories, user profiles)
   - Executables with suspicious names
   - Services with no description or generic descriptions
   - Services set to start automatically
3. Respond ONLY in this strict JSON format:
{{ "DANGEROUS": true/false, "reason": "Short explanation of the risk or why it is safe." }}

Service Metadata for Analysis:
"""

def analyze_service_with_ai(service: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a service using Mistral AI.
    
    Args:
        service: Dictionary containing service information
        
    Returns:
        Dictionary with AI analysis results
    """
    if not AI_AVAILABLE:
        return {"DANGEROUS": False, "reason": "AI analysis not available"}
    
    try:
        # Format service information for AI
        prompt = format_service_for_ai(service)
        
        # Get AI analysis
        result = analyze_text(prompt)
        
        # Ensure we return a dictionary
        if isinstance(result, dict):
            return result
        else:
            return {"DANGEROUS": False, "reason": "Unexpected AI response format"}
            
    except Exception as e:
        print(f"Error analyzing service with AI: {e}")
        return {"DANGEROUS": False, "reason": f"AI analysis failed: {e}"}

def process_services(services: List[Dict[str, Any]]) -> None:
    """
    Process all services, analyze them, and show alerts for dangerous ones.
    
    Args:
        services: List of service dictionaries
    """
    dangerous_count = 0
    
    logger.info(f"Analyzing {len(services)} Windows services...")
    print(f"Analyzing {len(services)} Windows services...")
    
    for i, service in enumerate(services, 1):
        service_name = service.get('Name', 'Unknown')
        logger.info(f"Processing service {i}/{len(services)}: {service_name}")
        print(f"Processing service {i}/{len(services)}: {service_name}")
        
        # Analyze service with AI
        analysis = analyze_service_with_ai(service)
        
        # Check if service is dangerous
        if analysis.get("DANGEROUS", False):
            dangerous_count += 1
            reason = analysis.get("reason", "No reason provided")
            
            # Show popup alert
            message = f"""
DANGEROUS SERVICE DETECTED

Service Name: {service_name}
Path: {service.get('PathName', 'Unknown')}
Status: {service.get('State', 'Unknown')}
Start Mode: {service.get('StartMode', 'Unknown')}

Reason: {reason}
"""
            show_popup("Guardrail Alert: Dangerous Service Detected", message.strip())
            
            logger.warning(f"DANGEROUS SERVICE DETECTED: {service_name} - {reason}")
            print(f"[DANGEROUS] {service_name}: {reason}")
        else:
            logger.info(f"SAFE SERVICE: {service_name}")
            print(f"[SAFE] {service_name}")
    
    logger.info(f"Analysis complete. Found {dangerous_count} potentially dangerous services.")
    print(f"\nAnalysis complete. Found {dangerous_count} potentially dangerous services.")

def monitor_new_services():
    """Continuously monitor for new service creation using WMI events."""
    if not WMI_AVAILABLE or _c is None:
        logger.error("WMI module not available. Cannot monitor new services.")
        print("WMI module not available. Cannot monitor new services.")
        return 1
    
    logger.info("Starting continuous service monitoring...")
    print("Starting continuous service monitoring...")
    print("Press Ctrl+C to stop.")
    
    try:
        watcher = _c.Win32_Service.watch_for("creation")
        logger.info("Successfully set up WMI service watcher")
        
        while True:
            try:
                # Wait for new service creation event
                new_service_event = watcher(timeout_ms=5000)
                if new_service_event:
                    # Convert WMI object to dictionary
                    service = {
                        'Name': getattr(new_service_event, 'Name', 'Unknown'),
                        'PathName': getattr(new_service_event, 'PathName', 'Unknown'),
                        'State': getattr(new_service_event, 'State', 'Unknown'),
                        'StartMode': getattr(new_service_event, 'StartMode', 'Unknown'),
                        'Description': getattr(new_service_event, 'Description', 'No description')
                    }
                    
                    service_name = service['Name']
                    logger.info(f"New service detected: {service_name}")
                    print(f"\nNew service detected: {service_name}")
                    
                    # Analyze the new service
                    analysis = analyze_service_with_ai(service)
                    
                    # Report findings
                    if analysis.get("DANGEROUS", False):
                        reason = analysis.get("reason", "No reason provided")
                        message = f"""
DANGEROUS NEW SERVICE DETECTED

Service Name: {service_name}
Path: {service['PathName']}
Status: {service['State']}
Start Mode: {service['StartMode']}

Reason: {reason}
"""
                        show_popup("Guardrail Alert: Dangerous New Service", message.strip())
                        logger.warning(f"DANGEROUS NEW SERVICE DETECTED: {service_name} - {reason}")
                        print(f"[DANGEROUS] {service_name}: {reason}")
                    else:
                        logger.info(f"SAFE NEW SERVICE: {service_name}")
                        print(f"[SAFE] {service_name}")
                        
            except Exception as e:
                logger.error(f"Error processing service event: {e}")
                print(f"Error processing service event: {e}")
                time.sleep(1)
                
    except KeyboardInterrupt:
        logger.info("Stopping service monitor...")
        print("\nStopping service monitor...")
        return 0
    except Exception as e:
        logger.error(f"Error setting up service monitor: {e}")
        print(f"Error setting up service monitor: {e}")
        return 1

def scan_and_monitor():
    """Scan all existing services first, then monitor for new services."""
    print("Windows Service Monitor with AI Analysis")
    print("=" * 50)
    
    # Check if running on Windows
    if os.name != 'nt':
        print("This script is designed to run on Windows systems only.")
        return 1
    
    # First, scan all existing services
    print("Performing initial scan of all existing services...")
    services = get_windows_services()
    
    if not services:
        print("No services found or error occurred while fetching services.")
        return 1
    
    print(f"Found {len(services)} Windows services.")
    
    # Process all existing services
    process_services(services)
    
    # Then, monitor for new services
    print("\nSwitching to continuous monitoring mode for new services...")
    return monitor_new_services()

def main():
    """Main function to run the service monitor."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Windows Service Monitor with AI Analysis")
    parser.add_argument('--mode', choices=['scan', 'monitor', 'scan-and-monitor'], default='scan',
                        help='Mode of operation: scan (one-time), monitor (continuous), scan-and-monitor (both)')
    args = parser.parse_args()
    
    if args.mode == 'monitor':
        # Continuous monitoring mode only
        return monitor_new_services()
    elif args.mode == 'scan-and-monitor':
        # Scan all services first, then monitor for new services
        return scan_and_monitor()
    else:
        # One-time scan mode (default)
        print("Windows Service Monitor with AI Analysis")
        print("=" * 50)
        
        # Check if running on Windows
        if os.name != 'nt':
            print("This script is designed to run on Windows systems only.")
            return 1
        
        # Get Windows services
        services = get_windows_services()
        
        if not services:
            print("No services found or error occurred while fetching services.")
            return 1
        
        print(f"Found {len(services)} Windows services.")
        
        # Process services
        process_services(services)
        
        return 0

if __name__ == "__main__":
    sys.exit(main())