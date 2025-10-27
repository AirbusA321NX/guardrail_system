#!/usr/bin/env python3
"""
Registry Scanner with AI Analysis

This module provides functionality to scan a given registry path and its subkeys,
collect comprehensive metadata, and use AI to analyze the findings for potential
security risks or anomalies.
"""

import time
import json
import hashlib
import os
import sys
import ctypes
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path

# Windows API imports
import win32api
import win32con
import winreg
import win32security
import win32process

# Import AI risk scoring
AI_RISK_SCORING_AVAILABLE = False
score_registry_event = None
try:
    from ai.risk_scoring import RegistryEvent as AIRegistryEvent, score_registry_event
    AI_RISK_SCORING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: AI risk scoring not available: {e}")
    AIRegistryEvent = None

# Import configuration
from registry.config import (
    PROCESS_PATTERNS,
    PATH_PATTERNS,
    COMMANDLINE_PATTERNS,
    MICROSOFT_ALLOWLIST_PROCESSES,
    SYSTEM_NOISE_PATTERNS
)

from utils.logger import log_event


@dataclass
class RegistryScanResult:
    """Complete registry scan result with all metadata"""
    # Scan identifiers
    scan_id: str
    timestamp: float
    timestamp_iso: str
    
    # Registry path details
    hive: str
    key_path: str
    
    # Key metadata
    subkey_count: int
    value_count: int
    last_write_time: Optional[str]
    
    # Subkeys information
    subkeys: List[Dict[str, Any]] = field(default_factory=list)
    
    # Values information
    values: List[Dict[str, Any]] = field(default_factory=list)
    
    # Security information
    owner: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    
    # AI Analysis Results
    risk_score: Optional[float] = None
    risk_reasons: List[str] = field(default_factory=list)
    recommended_action: Optional[str] = None
    threat_summary: Optional[str] = None
    
    def to_json(self) -> str:
        """Convert scan result to JSON string"""
        return json.dumps(asdict(self), indent=2, default=str)


class RegistryScanner:
    """Registry Scanner with AI Analysis"""
    
    def __init__(self):
        self.ai_risk_scoring_enabled = AI_RISK_SCORING_AVAILABLE
        self.hostname = self._get_hostname()
        
    def _get_hostname(self) -> str:
        """Get the hostname of the current machine"""
        try:
            import socket
            return socket.gethostname()
        except:
            return "localhost"
    
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID"""
        return hashlib.sha256(f"{time.time()}_{self.hostname}".encode()).hexdigest()[:16]
    
    def _parse_registry_path(self, path: str) -> Tuple[int, str]:
        """Parse registry path into hive and key path"""
        path = path.strip()
        if path.lower().startswith("hklm\\") or path.lower().startswith("hkey_local_machine\\"):
            hive = winreg.HKEY_LOCAL_MACHINE
            key_path = path.split("\\", 1)[1] if "\\" in path else ""
        elif path.lower().startswith("hkcu\\") or path.lower().startswith("hkey_current_user\\"):
            hive = winreg.HKEY_CURRENT_USER
            key_path = path.split("\\", 1)[1] if "\\" in path else ""
        elif path.lower().startswith("hkcr\\") or path.lower().startswith("hkey_classes_root\\"):
            hive = winreg.HKEY_CLASSES_ROOT
            key_path = path.split("\\", 1)[1] if "\\" in path else ""
        elif path.lower().startswith("hku\\") or path.lower().startswith("hkey_users\\"):
            hive = winreg.HKEY_USERS
            key_path = path.split("\\", 1)[1] if "\\" in path else ""
        elif path.lower().startswith("hkcc\\") or path.lower().startswith("hkey_current_config\\"):
            hive = winreg.HKEY_CURRENT_CONFIG
            key_path = path.split("\\", 1)[1] if "\\" in path else ""
        else:
            # Default to HKLM for paths without explicit hive
            hive = winreg.HKEY_LOCAL_MACHINE
            key_path = path
            
        return hive, key_path
    
    def _get_registry_key_info(self, hive: int, key_path: str) -> Dict[str, Any]:
        """Get comprehensive information about a registry key"""
        try:
            # Open the registry key
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            
            # Get key information
            info = winreg.QueryInfoKey(key)
            subkey_count = info[0]
            value_count = info[1]
            last_write_time = info[2]
            
            # Format last write time
            last_write_iso = None
            if last_write_time:
                # last_write_time is already a timestamp
                last_write_iso = datetime.fromtimestamp(last_write_time).isoformat()
            
            # Get security information (simplified)
            owner = None
            permissions = ["READ"]  # Simplified permissions
            
            winreg.CloseKey(key)
            
            return {
                "subkey_count": subkey_count,
                "value_count": value_count,
                "last_write_time": last_write_iso,
                "owner": owner,
                "permissions": permissions
            }
        except Exception as e:
            log_event("REGISTRY_KEY_INFO_ERROR", f"Failed to get info for {key_path}: {e}")
            return {
                "subkey_count": 0,
                "value_count": 0,
                "last_write_time": None,
                "owner": None,
                "permissions": []
            }
    
    def _enumerate_subkeys(self, hive: int, key_path: str) -> List[Dict[str, Any]]:
        """Enumerate all subkeys of a registry key"""
        subkeys = []
        try:
            # Open the registry key
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            
            # Get key information
            info = winreg.QueryInfoKey(key)
            subkey_count = info[0]
            
            # Enumerate subkeys
            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    full_subkey_path = f"{key_path}\\{subkey_name}" if key_path else subkey_name
                    
                    # Get subkey info
                    subkey_info = self._get_registry_key_info(hive, full_subkey_path)
                    
                    subkeys.append({
                        "name": subkey_name,
                        "path": full_subkey_path,
                        "subkey_count": subkey_info["subkey_count"],
                        "value_count": subkey_info["value_count"],
                        "last_write_time": subkey_info["last_write_time"]
                    })
                except Exception as e:
                    log_event("SUBKEY_ENUM_ERROR", f"Failed to enumerate subkey {i} of {key_path}: {e}")
                    continue
                    
            winreg.CloseKey(key)
        except Exception as e:
            log_event("REGISTRY_KEY_OPEN_ERROR", f"Failed to open key {key_path}: {e}")
            
        return subkeys
    
    def _enumerate_values(self, hive: int, key_path: str) -> List[Dict[str, Any]]:
        """Enumerate all values of a registry key"""
        values = []
        try:
            # Open the registry key
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_QUERY_VALUE)
            
            # Get key information
            info = winreg.QueryInfoKey(key)
            value_count = info[1]
            
            # Enumerate values
            for i in range(value_count):
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    # Convert value type to string
                    type_name = self._get_value_type_name(value_type)
                    
                    # Handle binary data
                    if isinstance(value_data, bytes):
                        try:
                            value_data_str = value_data.decode('utf-8', errors='ignore')
                        except:
                            value_data_str = f"<binary data: {len(value_data)} bytes>"
                    else:
                        value_data_str = str(value_data)
                    
                    values.append({
                        "name": value_name,
                        "data": value_data_str,
                        "type": type_name,
                        "raw_data": value_data,
                        "type_id": value_type
                    })
                except Exception as e:
                    log_event("VALUE_ENUM_ERROR", f"Failed to enumerate value {i} of {key_path}: {e}")
                    continue
                    
            winreg.CloseKey(key)
        except Exception as e:
            log_event("REGISTRY_KEY_OPEN_ERROR", f"Failed to open key {key_path}: {e}")
            
        return values
    
    def _get_value_type_name(self, value_type: int) -> str:
        """Convert registry value type ID to human-readable name"""
        type_names = {
            winreg.REG_NONE: "REG_NONE",
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_DWORD_LITTLE_ENDIAN: "REG_DWORD_LITTLE_ENDIAN",
            winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
            winreg.REG_LINK: "REG_LINK",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
            winreg.REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
            winreg.REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
            winreg.REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
            winreg.REG_QWORD: "REG_QWORD",
            winreg.REG_QWORD_LITTLE_ENDIAN: "REG_QWORD_LITTLE_ENDIAN"
        }
        return type_names.get(value_type, f"UNKNOWN_TYPE_{value_type}")
    
    def _analyze_with_ai(self, scan_result: RegistryScanResult) -> RegistryScanResult:
        """Analyze registry scan result with AI for risk scoring"""
        if not self.ai_risk_scoring_enabled or AIRegistryEvent is None or score_registry_event is None:
            scan_result.risk_score = 0.5
            scan_result.risk_reasons = ["AI analysis not available"]
            scan_result.recommended_action = "info"
            scan_result.threat_summary = "AI analysis not available"
            return scan_result
        
        try:
            # Create a synthetic registry event for AI analysis
            # We'll create multiple events for different aspects of the registry key
            ai_events = []
            
            # Event for the key itself
            ai_event = AIRegistryEvent(
                event_id=scan_result.scan_id,
                timestamp=scan_result.timestamp,
                host=self.hostname,
                user_sid=None,
                hive=scan_result.hive,
                key_path=scan_result.key_path,
                value_name=None,
                value_type=None,
                value_data=None,
                operation="SCAN",
                process_name="RegistryScanner",
                process_cmdline=f"registry_scanner.py {scan_result.hive}\\{scan_result.key_path}",
                pid=os.getpid(),
                ppid=None,
                parent_process_chain=["python.exe", "registry_scanner.py"],
                process_hash=None,
                process_signed=True,
                process_signature_subject="Guardrail Security System",
                process_integrity="high",
                is_wow64=False,
                recent_file_writes=[],
                recent_network_activity=[],
                host_baseline_freq=0.001,
                global_freq=0.0001,
                source_feeds=["registry_scan"],
                signed_log_hmac=""
            )
            ai_events.append(ai_event)
            
            # Events for suspicious values
            for value in scan_result.values:
                # Check if value data looks suspicious
                suspicious_patterns = [
                    'powershell', 'encodedcommand', 'base64', 'certutil', 'mshta',
                    'rundll32', 'regsvr32', 'wscript', 'cscript', 'cmd.exe',
                    '-nop', '-w hidden', '-enc', '-encodedcommand'
                ]
                
                value_data_str = str(value.get("data", ""))
                if any(pattern in value_data_str.lower() for pattern in suspicious_patterns):
                    ai_event = AIRegistryEvent(
                        event_id=f"{scan_result.scan_id}_value_{hash(value.get('name', ''))}",
                        timestamp=scan_result.timestamp,
                        host=self.hostname,
                        user_sid=None,
                        hive=scan_result.hive,
                        key_path=scan_result.key_path,
                        value_name=value.get("name"),
                        value_type=value.get("type"),
                        value_data=value_data_str,
                        operation="SCAN_VALUE",
                        process_name="RegistryScanner",
                        process_cmdline=f"registry_scanner.py {scan_result.hive}\\{scan_result.key_path}",
                        pid=os.getpid(),
                        ppid=None,
                        parent_process_chain=["python.exe", "registry_scanner.py"],
                        process_hash=None,
                        process_signed=True,
                        process_signature_subject="Guardrail Security System",
                        process_integrity="high",
                        is_wow64=False,
                        recent_file_writes=[],
                        recent_network_activity=[],
                        host_baseline_freq=0.001,
                        global_freq=0.0001,
                        source_feeds=["registry_scan"],
                        signed_log_hmac=""
                    )
                    ai_events.append(ai_event)
            
            # Score all events and aggregate results
            risk_scores = []
            all_reasons = []
            threat_summaries = []
            
            for event in ai_events:
                try:
                    risk_result = score_registry_event(event)
                    risk_score = risk_result.get('risk_score', 0.5)
                    # Ensure risk_score is a float
                    if risk_score is None:
                        risk_score = 0.5
                    risk_scores.append(float(risk_score))
                    all_reasons.extend(risk_result.get('top_reasons', []))
                    if risk_result.get('threat_summary'):
                        threat_summaries.append(risk_result.get('threat_summary'))
                except Exception as e:
                    log_event("AI_SCORING_ERROR", f"Failed to score event: {e}")
            
            # Aggregate results
            if risk_scores:
                scan_result.risk_score = max(risk_scores)  # Take the highest risk score
                scan_result.risk_reasons = list(set(all_reasons))  # Remove duplicates
                scan_result.threat_summary = "; ".join(threat_summaries) if threat_summaries else "No specific threats identified"
                
                # Ensure risk_score is a float before comparisons
                if scan_result.risk_score is None:
                    scan_result.risk_score = 0.5
                    
                # Determine recommended action based on risk score
                if scan_result.risk_score >= 0.9:
                    scan_result.recommended_action = "isolate"
                elif scan_result.risk_score >= 0.7:
                    scan_result.recommended_action = "investigate"
                elif scan_result.risk_score >= 0.4:
                    scan_result.recommended_action = "info"
                else:
                    scan_result.recommended_action = "info"
            else:
                scan_result.risk_score = 0.5
                scan_result.risk_reasons = ["No AI analysis results"]
                scan_result.recommended_action = "info"
                scan_result.threat_summary = "No AI analysis performed"

        except Exception as e:
            log_event("AI_ANALYSIS_ERROR", f"Failed to analyze with AI: {e}")
            scan_result.risk_score = 0.5
            scan_result.risk_reasons = [f"AI analysis failed: {str(e)}"]
            scan_result.recommended_action = "info"
            scan_result.threat_summary = f"AI analysis failed: {str(e)}"
        
        # Ensure risk_score is always a float
        if scan_result.risk_score is None:
            scan_result.risk_score = 0.5
            
        return scan_result
    
    def scan_registry_path(self, registry_path: str, enable_ai_analysis: bool = True) -> RegistryScanResult:
        """Scan a registry path and return comprehensive results"""
        # Parse the registry path
        hive, key_path = self._parse_registry_path(registry_path)
        
        # Get hive name for display
        hive_names = {
            winreg.HKEY_LOCAL_MACHINE: "HKLM",
            winreg.HKEY_CURRENT_USER: "HKCU",
            winreg.HKEY_CLASSES_ROOT: "HKCR",
            winreg.HKEY_USERS: "HKU",
            winreg.HKEY_CURRENT_CONFIG: "HKCC"
        }
        hive_name = hive_names.get(hive, "UNKNOWN")
        
        # Create scan result
        timestamp = time.time()
        scan_result = RegistryScanResult(
            scan_id=self._generate_scan_id(),
            timestamp=timestamp,
            timestamp_iso=datetime.fromtimestamp(timestamp).isoformat(),
            hive=hive_name,
            key_path=key_path,
            subkey_count=0,
            value_count=0,
            last_write_time=None
        )
        
        log_event("REGISTRY_SCAN_START", f"Starting scan of {hive_name}\\{key_path}")
        
        try:
            # Get key information
            key_info = self._get_registry_key_info(hive, key_path)
            scan_result.subkey_count = key_info["subkey_count"]
            scan_result.value_count = key_info["value_count"]
            scan_result.last_write_time = key_info["last_write_time"]
            scan_result.owner = key_info["owner"]
            scan_result.permissions = key_info["permissions"]
            
            # Enumerate subkeys
            log_event("SUBKEY_ENUM_START", f"Enumerating {key_info['subkey_count']} subkeys")
            scan_result.subkeys = self._enumerate_subkeys(hive, key_path)
            
            # Enumerate values
            log_event("VALUE_ENUM_START", f"Enumerating {key_info['value_count']} values")
            scan_result.values = self._enumerate_values(hive, key_path)
            
            # Analyze with AI if enabled
            if enable_ai_analysis:
                log_event("AI_ANALYSIS_START", "Starting AI analysis of registry scan")
                scan_result = self._analyze_with_ai(scan_result)
            
            log_event("REGISTRY_SCAN_COMPLETE", f"Completed scan of {hive_name}\\{key_path}")
            
        except Exception as e:
            log_event("REGISTRY_SCAN_ERROR", f"Failed to scan {registry_path}: {e}")
            # Set default values for error case
            scan_result.risk_score = 0.9
            scan_result.risk_reasons = [f"Scan failed: {str(e)}"]
            scan_result.recommended_action = "investigate"
            scan_result.threat_summary = f"Registry scan failed: {str(e)}"
        
        return scan_result
    
    def save_scan_result(self, scan_result: RegistryScanResult, output_dir: str = "logs") -> str:
        """Save scan result to a JSON file"""
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Create filename with timestamp
            timestamp = datetime.fromtimestamp(scan_result.timestamp).strftime("%Y%m%d_%H%M%S")
            filename = f"RegistryScan_{timestamp}_{scan_result.scan_id}.json"
            filepath = os.path.join(output_dir, filename)
            
            # Save scan result
            with open(filepath, "w") as f:
                f.write(scan_result.to_json())
                
            log_event("REGISTRY_SCAN_SAVED", f"Saved scan result to {filepath}")
            return filepath
            
        except Exception as e:
            log_event("REGISTRY_SCAN_SAVE_ERROR", f"Failed to save scan result: {e}")
            return ""  # Return empty string instead of None


def main():
    """Main entry point for registry scanning"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Registry Scanner with AI Analysis')
    parser.add_argument('registry_path', help='Registry path to scan (e.g., HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI analysis')
    parser.add_argument('--output-dir', default='logs', help='Output directory for scan results')
    
    args = parser.parse_args()
    
    print(f"Starting registry scan of: {args.registry_path}")
    print(f"AI analysis: {'Disabled' if args.no_ai else 'Enabled'}")
    print(f"Output directory: {args.output_dir}")
    
    # Create scanner instance
    scanner = RegistryScanner()
    
    # Scan the registry path
    scan_result = scanner.scan_registry_path(args.registry_path, enable_ai_analysis=not args.no_ai)
    
    # Display results
    print("\n" + "="*80)
    print("REGISTRY SCAN RESULTS")
    print("="*80)
    print(f"Scan ID: {scan_result.scan_id}")
    print(f"Timestamp: {scan_result.timestamp_iso}")
    print(f"Registry Path: {scan_result.hive}\\{scan_result.key_path}")
    print(f"Subkeys: {scan_result.subkey_count}")
    print(f"Values: {scan_result.value_count}")
    print(f"Last Write Time: {scan_result.last_write_time}")
    
    if scan_result.risk_score is not None:
        print(f"\nAI Risk Score: {scan_result.risk_score:.2f}")
        print(f"Recommended Action: {scan_result.recommended_action}")
        print(f"Risk Reasons: {', '.join(scan_result.risk_reasons)}")
        print(f"Threat Summary: {scan_result.threat_summary}")
    
    # Show subkeys
    if scan_result.subkeys:
        print(f"\nSubkeys ({len(scan_result.subkeys)}):")
        for subkey in scan_result.subkeys[:10]:  # Show first 10
            print(f"  {subkey['name']} (Values: {subkey['value_count']}, Subkeys: {subkey['subkey_count']})")
        if len(scan_result.subkeys) > 10:
            print(f"  ... and {len(scan_result.subkeys) - 10} more")
    
    # Show values
    if scan_result.values:
        print(f"\nValues ({len(scan_result.values)}):")
        for value in scan_result.values[:10]:  # Show first 10
            print(f"  {value['name']} = {value['data'][:100]}{'...' if len(str(value['data'])) > 100 else ''} [{value['type']}]")
        if len(scan_result.values) > 10:
            print(f"  ... and {len(scan_result.values) - 10} more")
    
    # Save results
    filepath = scanner.save_scan_result(scan_result, args.output_dir)
    if filepath:
        print(f"\nResults saved to: {filepath}")
    else:
        print("\nFailed to save results to file")
    
    print("\nScan completed.")


if __name__ == "__main__":
    main()