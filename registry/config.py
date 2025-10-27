"""
Enhanced Registry Monitoring Configuration

This configuration addresses all the issues identified:
1. Comprehensive persistence locations (not just 7 paths)
2. Separated filtering patterns by type
3. Microsoft allowlists
4. System noise filtering
5. Complete telemetry schema
"""

import os
import yaml


def load_yaml_config(filename):
    """Load configuration from YAML file"""
    config_path = os.path.join(os.path.dirname(__file__), 'config', filename)
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {filename}: {e}")
        return {}


# Load configurations from external YAML files
REGISTRY_WATCHLIST = load_yaml_config('registry_paths.yml')
PROCESS_INDICATORS = load_yaml_config('process_iocs.yml')
COMMANDLINE_INDICATORS = load_yaml_config('commandline_patterns.yml')
MICROSOFT_ALLOWLIST = load_yaml_config('microsoft_allowlist.yml')
SYSTEM_NOISE_ALLOWLIST = load_yaml_config('system_noise.yml')

# Extract lists from loaded configurations
REGISTRY_PERSISTENCE_PATHS = [
    item['path'] for item in REGISTRY_WATCHLIST.get('registry_watchlist', [])
] if REGISTRY_WATCHLIST else []

PROCESS_PATTERNS = [
    item['pattern'] for item in PROCESS_INDICATORS.get('process_indicators', [])
] if PROCESS_INDICATORS else []

PATH_PATTERNS = REGISTRY_PERSISTENCE_PATHS  # Use the same paths for pattern matching

COMMANDLINE_PATTERNS = [
    item['pattern'] for item in COMMANDLINE_INDICATORS.get('commandline_indicators', [])
] if COMMANDLINE_INDICATORS else []

MICROSOFT_ALLOWLIST_PROCESSES = [
    item['process'] for item in MICROSOFT_ALLOWLIST.get('microsoft_allowlist', [])
] if MICROSOFT_ALLOWLIST else []

SYSTEM_NOISE_PATTERNS = [
    item['pattern'] for item in SYSTEM_NOISE_ALLOWLIST.get('system_noise_allowlist', [])
] if SYSTEM_NOISE_ALLOWLIST else []

# Event batching configuration
BATCH_SIZE = 50
QUEUE_MAX_SIZE = 5000
PROCESS_INTERVAL = 0.5  # seconds

# CPU efficiency settings
CPU_SLEEP_INTERVAL = 0.01  # seconds to sleep when idle

# File output settings
OUTPUT_DIRECTORY = "logs"
MAX_EVENT_FILES = 10000  # Maximum number of event files to keep

# Telemetry schema version
SCHEMA_VERSION = "1.0"

# Monitoring settings
ENABLE_ETW_MONITORING = True
ENABLE_REGNOTIFY_MONITORING = True
ENABLE_LOGGING = True