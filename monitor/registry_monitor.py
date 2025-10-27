#!/usr/bin/env python3
"""
Registry Monitor Module

This module provides registry monitoring capabilities using the enhanced ETW-based implementation.
"""

import sys
import os
import time
import argparse

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from registry.etw_registry_monitor import ETWRegistryMonitor
from utils.logger import log_event

def main():
    """Main entry point for the registry monitor"""
    parser = argparse.ArgumentParser(description='Registry Monitoring Agent')
    parser.add_argument('--batch-size', type=int, default=50, help='Batch size for event processing')
    parser.add_argument('--queue-size', type=int, default=5000, help='Maximum queue size')
    parser.add_argument('--no-threat-intel', action='store_true', help='Disable threat intelligence integration')
    parser.add_argument('--no-ai-risk-scoring', action='store_true', help='Disable AI risk scoring')
    
    args = parser.parse_args()
    
    print("Starting Registry Monitoring Agent...")
    print(f"Batch size: {args.batch_size}")
    print(f"Queue size: {args.queue_size}")
    print(f"Threat intelligence: {'Disabled' if args.no_threat_intel else 'Enabled'}")
    print(f"AI risk scoring: {'Disabled' if args.no_ai_risk_scoring else 'Enabled'}")
    
    # Create monitor instance
    monitor = ETWRegistryMonitor(batch_size=args.batch_size, queue_max_size=args.queue_size)
    
    # Disable AI risk scoring if requested
    if args.no_ai_risk_scoring:
        monitor.ai_risk_scoring_enabled = False
    
    try:
        # Start monitoring
        monitor.start_monitoring(enable_threat_intel=not args.no_threat_intel)
        
        print("Registry monitoring started. Press Ctrl+C to stop.")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping registry monitoring...")
    except Exception as e:
        log_event("REGISTRY_MONITOR_ERROR", f"Unexpected error: {e}")
        print(f"Error: {e}")
    finally:
        # Stop monitoring
        monitor.stop_monitoring()
        print("Registry monitoring stopped.")

if __name__ == "__main__":
    main()