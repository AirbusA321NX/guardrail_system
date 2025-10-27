#!/usr/bin/env python3
"""
AI Risk Scoring for Registry Events

This module implements an AI-based risk scoring system for registry events
using the blueprint provided in the specification.
"""

import json
import hashlib
import time
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
import numpy as np

# Import our existing AI analysis function
try:
    from ai.mistral_analysis import analyze_text
    AI_AVAILABLE = True
except ImportError:
    analyze_text = None
    AI_AVAILABLE = False

# Import configuration
from registry.config import (
    PROCESS_PATTERNS,
    PATH_PATTERNS,
    COMMANDLINE_PATTERNS,
    MICROSOFT_ALLOWLIST_PROCESSES
)

@dataclass
class RegistryEvent:
    """Complete registry event with all required metadata"""
    event_id: str
    timestamp: float
    host: str
    user_sid: Optional[str]
    hive: str
    key_path: str
    value_name: Optional[str]
    value_type: Optional[str]
    value_data: Optional[str]
    operation: str
    process_name: Optional[str]
    process_cmdline: Optional[str]
    pid: Optional[int]
    ppid: Optional[int]
    parent_process_chain: List[str]
    process_hash: Optional[str]
    process_signed: Optional[bool]
    process_signature_subject: Optional[str]
    process_integrity: Optional[str]
    is_wow64: bool
    recent_file_writes: List[Dict[str, str]]
    recent_network_activity: List[str]
    host_baseline_freq: float
    global_freq: float
    source_feeds: List[str]
    signed_log_hmac: str

def calculate_binary_entropy(data: str) -> float:
    """Calculate binary entropy of data"""
    if not data:
        return 0.0
    
    # Convert to bytes if string
    if isinstance(data, str):
        try:
            byte_data = data.encode('utf-8')
        except UnicodeEncodeError:
            byte_data = data.encode('utf-8', errors='ignore')
    else:
        byte_data = data
    
    # Calculate frequency of each byte
    byte_counts = {}
    for byte_val in byte_data:
        byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
    
    # Calculate entropy
    total_bytes = len(byte_data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        if probability > 0:
            entropy -= probability * np.log2(probability)
    
    return entropy

def extract_key_tokens(key_path: str) -> List[str]:
    """Extract tokens from registry key path"""
    if not key_path:
        return []
    return [token.lower() for token in re.split(r'[\\\/]', key_path) if token]

def is_suspicious_substring(text: str) -> List[str]:
    """Check for suspicious substrings"""
    if not text:
        return []
    
    suspicious_patterns = [
        'powershell', 'encodedcommand', 'base64', 'certutil', 'mshta',
        'rundll32', 'regsvr32', 'wscript', 'cscript', 'cmd.exe',
        '-nop', '-w hidden', '-enc', '-encodedcommand'
    ]
    
    found = []
    text_lower = text.lower()
    for pattern in suspicious_patterns:
        if pattern in text_lower:
            found.append(pattern)
    
    return found

def featurize_event(event: RegistryEvent) -> Dict[str, Any]:
    """Extract features from registry event for AI scoring"""
    features = {}
    
    # Categorical features
    features['hive'] = event.hive
    features['key_tokens'] = extract_key_tokens(event.key_path)
    features['value_type'] = event.value_type or 'UNKNOWN'
    features['is_wow64'] = event.is_wow64
    features['process_signed'] = event.process_signed or False
    features['is_service_install'] = 'services' in (event.key_path or '').lower()
    
    # Numeric features
    features['value_length'] = len(event.value_data or '')
    features['binary_entropy'] = calculate_binary_entropy(event.value_data or '')
    features['process_age'] = time.time() - (event.timestamp or time.time())
    features['host_baseline_freq'] = event.host_baseline_freq
    features['global_freq'] = event.global_freq
    features['count_recent_network_connections'] = len(event.recent_network_activity or [])
    
    # Reputation features
    features['process_hash_reputation_score'] = 0.0  # Would integrate with hash reputation service
    features['domain_reputation_score'] = 0.0  # Would integrate with domain reputation service
    features['signed_by_microsoft'] = (event.process_signature_subject or '').lower() == 'microsoft corporation'
    features['appearances_in_feeds_count'] = len(event.source_feeds or [])
    
    # Textual features
    cmdline_suspicious = is_suspicious_substring(event.process_cmdline or '')
    value_suspicious = is_suspicious_substring(event.value_data or '')
    key_suspicious = is_suspicious_substring(event.key_path or '')
    
    features['suspicious_cmdline_count'] = len(cmdline_suspicious)
    features['suspicious_value_count'] = len(value_suspicious)
    features['suspicious_key_count'] = len(key_suspicious)
    
    # Temporal features
    dt = time.localtime(event.timestamp)
    features['time_of_day'] = dt.tm_hour
    features['is_night'] = dt.tm_hour < 6 or dt.tm_hour > 22
    features['is_weekend'] = dt.tm_wday >= 5  # Saturday = 5, Sunday = 6
    
    # Graph/ancestry features
    features['parent_chain_length'] = len(event.parent_process_chain or [])
    features['unusual_parent'] = not (event.parent_process_chain or []) or \
                               (event.parent_process_chain or [])[-1] not in ['explorer.exe', 'services.exe', 'svchost.exe']
    
    # Hard signals
    high_risk_keys = [
        'system\\currentcontrolset\\services',
        'software\\microsoft\\windows\\currentversion\\run',
        'software\\microsoft\\windows nt\\currentversion\\winlogon',
        'software\\microsoft\\windows\\currentversion\\explorer\\shellserviceobjects'
    ]
    
    features['writing_to_high_risk_key'] = any(key.lower() in (event.key_path or '').lower() for key in high_risk_keys)
    features['writing_to_services'] = 'services' in (event.key_path or '').lower()
    features['writing_driver_keys'] = 'drivers' in (event.key_path or '').lower()
    
    return features

def apply_deterministic_rules(event: RegistryEvent, features: Dict[str, Any]) -> Optional[Tuple[float, List[str]]]:
    """Apply deterministic rules for immediate high-confidence decisions"""
    
    # Microsoft signed processes are generally safe
    if features.get('signed_by_microsoft', False):
        return (0.02, ["microsoft_signed"])
    
    # Known bad combinations
    if (not event.process_signed and 
        features.get('writing_to_high_risk_key', False) and 
        features.get('suspicious_cmdline_count', 0) > 0):
        return (0.95, ["unsigned_process_writing_to_critical_key", "suspicious_command_line"])
    
    # Writing to services by unsigned process
    if (not event.process_signed and 
        features.get('writing_to_services', False)):
        return (0.90, ["unsigned_process_writing_to_services"])
    
    return None

def score_event_with_ai(event: RegistryEvent, features: Dict[str, Any]) -> Dict[str, Any]:
    """Score event using AI with explainability"""
    
    if not AI_AVAILABLE or analyze_text is None:
        # Fallback to rule-based scoring
        return score_event_rule_based(event, features)
    
    # Create prompt for AI analysis
    prompt = f"""
You are a security AI that scores registry events for risk. Analyze the following registry event and provide a risk score.

Event Details:
- Process: {event.process_name} (PID: {event.pid})
- Command Line: {event.process_cmdline}
- Operation: {event.operation} on {event.hive}\\{event.key_path}
- Value: {event.value_name} = {event.value_data}
- Process Hash: {event.process_hash}
- Signed: {event.process_signed}
- Integrity Level: {event.process_integrity}

Features:
{json.dumps(features, indent=2)}

Please respond with a JSON object containing:
1. "risk_score": number between 0.0 and 1.0 (0 = safe, 1 = highly dangerous)
2. "top_reasons": array of strings explaining the top contributing factors
3. "recommended_action": one of ["info", "investigate", "isolate"]
4. "explainability_blob": object with feature contributions (can be empty for now)

Example response format:
{{
    "risk_score": 0.85,
    "top_reasons": [
        "Unsigned process writing to Run key",
        "Suspicious command line containing PowerShell flags",
        "Process not signed by Microsoft"
    ],
    "recommended_action": "isolate",
    "explainability_blob": {{}}
}}
"""
    
    try:
        response = analyze_text(prompt)
        
        # Ensure we have the required fields
        if isinstance(response, dict):
            risk_score = response.get('risk_score', 0.5)
            top_reasons = response.get('top_reasons', [])
            recommended_action = response.get('recommended_action', 'info')
            explainability_blob = response.get('explainability_blob', {})
            
            # Validate risk score range
            risk_score = max(0.0, min(1.0, float(risk_score)))
            
            return {
                'risk_score': risk_score,
                'top_reasons': top_reasons,
                'recommended_action': recommended_action,
                'explainability_blob': explainability_blob
            }
        else:
            # Fallback if AI response is malformed
            return score_event_rule_based(event, features)
            
    except Exception as e:
        # Fallback on AI error
        return score_event_rule_based(event, features)

def score_event_rule_based(event: RegistryEvent, features: Dict[str, Any]) -> Dict[str, Any]:
    """Rule-based scoring as fallback when AI is not available"""
    
    risk_score = 0.5  # Base score
    
    # Adjust based on features
    if features.get('signed_by_microsoft', False):
        risk_score *= 0.1  # Much lower risk
    
    if features.get('writing_to_high_risk_key', False):
        risk_score += 0.3
    
    if features.get('suspicious_cmdline_count', 0) > 0:
        risk_score += 0.2 * features['suspicious_cmdline_count']
    
    if not event.process_signed:
        risk_score += 0.2
    
    if features.get('binary_entropy', 0) > 7.0:  # High entropy suggests obfuscation
        risk_score += 0.15
    
    # Clamp to 0-1 range
    risk_score = max(0.0, min(1.0, risk_score))
    
    # Determine action based on score
    if risk_score >= 0.9:
        action = "isolate"
    elif risk_score >= 0.7:
        action = "investigate"
    elif risk_score >= 0.4:
        action = "info"
    else:
        action = "info"
    
    # Generate reasons
    reasons = []
    if features.get('signed_by_microsoft', False):
        reasons.append("Process signed by Microsoft")
    if features.get('writing_to_high_risk_key', False):
        reasons.append("Writing to high-risk registry key")
    if features.get('suspicious_cmdline_count', 0) > 0:
        reasons.append(f"Found {features['suspicious_cmdline_count']} suspicious command line patterns")
    if not event.process_signed:
        reasons.append("Process is not signed")
    if features.get('binary_entropy', 0) > 7.0:
        reasons.append("High entropy in registry value suggests obfuscation")
    
    return {
        'risk_score': risk_score,
        'top_reasons': reasons,
        'recommended_action': action,
        'explainability_blob': {}
    }

def score_registry_event(event: RegistryEvent) -> Dict[str, Any]:
    """Main function to score a registry event"""
    
    # Extract features
    features = featurize_event(event)
    
    # Apply deterministic rules first
    rule_result = apply_deterministic_rules(event, features)
    if rule_result:
        risk_score, reasons = rule_result
        action = "isolate" if risk_score >= 0.9 else "investigate" if risk_score >= 0.7 else "info"
        return {
            'risk_score': risk_score,
            'top_reasons': reasons,
            'recommended_action': action,
            'explainability_blob': {}
        }
    
    # Use AI scoring
    return score_event_with_ai(event, features)

# Example usage
if __name__ == "__main__":
    # Example event
    example_event = RegistryEvent(
        event_id="test-123",
        timestamp=time.time(),
        host="test-host",
        user_sid="S-1-5-21-1234567890-1234567890-1234567890-1001",
        hive="HKCU",
        key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name="Updater",
        value_type="REG_SZ",
        value_data="C:\\temp\\evil.exe",
        operation="SET",
        process_name="powershell.exe",
        process_cmdline="powershell -nop -w hidden -c ...",
        pid=1234,
        ppid=5678,
        parent_process_chain=["explorer.exe", "cmd.exe", "powershell.exe"],
        process_hash="sha256:abc123...",
        process_signed=False,
        process_signature_subject=None,
        process_integrity="high",
        is_wow64=False,
        recent_file_writes=[{"path": "C:\\Users\\alice\\Downloads\\evil.exe", "hash": "sha256:..."}],
        recent_network_activity=["93.184.216.34:443"],
        host_baseline_freq=0.0005,
        global_freq=0.00002,
        source_feeds=["otx", "urlhaus"],
        signed_log_hmac="..."
    )
    
    result = score_registry_event(example_event)
    print(json.dumps(result, indent=2))