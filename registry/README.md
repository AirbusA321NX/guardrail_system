# Enhanced Registry Monitoring with Threat Intelligence

This module implements a comprehensive Windows registry monitoring solution that integrates with threat intelligence feeds to proactively identify and monitor for emerging threats.

## Workflow

```
RSS Feed (news) → AI interprets → Predicts possible persistence/registry behavior → 
Feed monitoring agent → Alert if suspicious registry changes occur
```

## Key Features

### Data-Driven Configuration
All detection logic is configuration-driven rather than hardcoded:
- IOC definitions loaded from external YAML files
- Registry high-value targets maintained in external config
- Support for runtime updates without recompiling
- Integration with threat intelligence feeds

### Threat Intelligence Integration
- Processes RSS feeds from security sources
- Uses AI to analyze articles and predict registry threats
- Automatically updates monitoring configuration
- Continuous learning from new threat reports

### Comprehensive Coverage
- Monitors ALL registry keys using ETW (Event Tracing for Windows)
- Uses event-driven monitoring instead of polling
- Covers over 100+ known persistence locations
- Handles both 32-bit and 64-bit registry access

### Advanced Filtering
- Separated filtering patterns by type (process, path, command line)
- Microsoft allowlists to filter out system noise
- Complete metadata collection including:
  - Process information (name, PID, PPID, command line)
  - Binary hash (SHA-256) and signer verification
  - User context (SID, integrity level, elevation status)
  - Timestamp + monotonic event ID
  - Wow64 (32/64-bit registry hive) detection

## Configuration Files

The agent uses external YAML configuration files for all detection logic:

### `config/registry_paths.yml`
Contains high-value registry targets to monitor with risk levels and descriptions.

### `config/process_iocs.yml`
Defines suspicious process indicators with tags and descriptions.

### `config/commandline_patterns.yml`
Lists suspicious command line patterns with categorization.

### `config/microsoft_allowlist.yml`
Lists Microsoft-signed processes to filter out system noise.

### `config/system_noise.yml`
Defines system noise patterns to filter out benign registry activity.

## Threat Intelligence Workflow

The system implements a complete workflow for threat intelligence integration:

### Supported Feeds
- Malwarebytes Blog: https://blog.malwarebytes.com/feed/
- CrowdStrike Blog: https://www.crowdstrike.com/blog/feed/
- Krebs on Security: https://krebsonsecurity.com/feed/
- Threatpost: https://threatpost.com/feed/
- BleepingComputer: https://www.bleepingcomputer.com/feed/
- CISA Alerts: https://www.cisa.gov/uscert/ncas/alerts.xml
- CERT-EU: https://cert.europa.eu/rss/

## Usage

### Basic Registry Monitoring
```python
from registry.etw_registry_monitor import ETWRegistryMonitor

# Create monitor instance
monitor = ETWRegistryMonitor()

# Start monitoring
monitor.start_monitoring()

# Stop monitoring
monitor.stop_monitoring()
```

### Registry Scanner with AI Analysis
```python
from registry.registry_scanner import RegistryScanner

# Create scanner instance
scanner = RegistryScanner()

# Scan a specific registry path
scan_result = scanner.scan_registry_path("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")

# Save results to file
scanner.save_scan_result(scan_result)

# Access scan results
print(f"Risk Score: {scan_result.risk_score}")
print(f"Subkeys Found: {scan_result.subkey_count}")
print(f"Values Found: {scan_result.value_count}")
```

### Threat Intelligence Processing
```python
from registry.threat_intel_analyzer import ThreatIntelAnalyzer

# Process feeds once
analyzer = ThreatIntelAnalyzer()
results = analyzer.process_all_feeds()
analyzer.update_registry_config(results)
```

### Running the Registry Monitor
From the project root directory:
```bash
python -m monitor.registry_monitor
```

### Running the Registry Scanner
From the project root directory:
```bash
python -m registry.registry_scanner "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

For more options:
```bash
python -m registry.registry_scanner --help
```

## Extending Detection Logic

To update detection rules without code changes:
1. Modify the appropriate YAML file in the `config/` directory
2. The changes will be automatically loaded at runtime
3. For production deployments, consider implementing automatic updates from threat intel feeds

## Dependencies

- pywin32>=302
- PyYAML>=6.0
- feedparser>=6.0.0

Install dependencies with:
```bash
pip install -r registry/requirements.txt
```

## Integration with Existing System

The implementation integrates seamlessly with the existing Guardrail system:
- Uses the same AI analysis infrastructure
- Follows existing logging and alerting patterns
- Compatible with existing configuration management
- Extends rather than replaces existing functionality

# Application Threat Analyzer

This module monitors security feeds from sources like Malwarebytes, CrowdStrike, and others to identify applications that security experts recommend removing.

## Features

- Processes RSS feeds from multiple security sources
- Uses AI analysis to identify applications that should be removed
- Generates detailed reports with confidence scores
- Provides actionable recommendations for application removal
- Runs periodically to keep up with the latest threats

## Files

- `app_threat_analyzer.py` - Main analysis module
- `app_threat_scheduler.py` - Scheduler for periodic analysis
- `requirements.txt` - Dependencies (already included in main requirements)

## Usage

### One-time Analysis

```bash
python -m registry.app_threat_analyzer
```

This will:
1. Process all security feeds
2. Identify applications suggested for removal
3. Generate a detailed report
4. Save the report to a timestamped file

### Scheduled Analysis

```bash
python -m registry.app_threat_scheduler
```

This will:
1. Run an immediate analysis
2. Schedule checks every 12 hours
3. Generate reports for each analysis
4. Continue running until stopped with Ctrl+C

## How It Works

1. **Feed Processing**: The analyzer processes RSS feeds from major security sources
2. **AI Analysis**: Uses AI to understand articles and identify applications that should be removed
3. **Confidence Scoring**: Each recommendation includes a confidence score
4. **Reporting**: Generates human-readable reports with actionable recommendations
5. **Deduplication**: Tracks processed articles to avoid duplicate analysis

## Output

The analyzer generates reports in the following format:

```
=== APPLICATION THREAT ANALYSIS REPORT ===

Analysis completed: 2025-10-21 15:30:45
Number of articles analyzed: 3

SUGGESTED APPLICATION REMOVALS:
--------------------------------
Application: suspicious_app
  Confidence: 0.95
  Source: New Malware Found Targeting Windows Systems

Application: malware_tool
  Confidence: 0.87
  Source: Quarterly Threat Report

RECOMMENDATIONS:
----------------
1. Review the above applications and verify if they are legitimate
2. Use your system's uninstaller or security software to remove malicious applications
3. Run a full system scan to ensure complete removal
4. Keep this report for future reference
```

## Configuration

The module uses the same configuration directory as the main registry module:
- `registry/config/processed_app_articles.json` - Tracks processed articles to avoid duplicates

## Dependencies

All dependencies are already included in the project requirements:
- `feedparser` - For processing RSS feeds
- `PyYAML` - For configuration files
- AI modules (optional) - For enhanced analysis

## Extending the Module

To add new RSS feeds, modify the FEEDS list in `app_threat_analyzer.py`.
To adjust the analysis, modify the AI prompt or rule-based analysis functions.
