#!/usr/bin/env python3
"""
Threat Intelligence Scheduler for Registry Monitoring

This module schedules periodic checks of threat intelligence feeds
and updates the registry monitoring configuration accordingly.
"""

import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional

from registry.threat_intel_analyzer import ThreatIntelAnalyzer

class ThreatIntelScheduler:
    """Scheduler for threat intelligence feed processing"""
    
    def __init__(self, check_interval_hours: int = 6):
        self.check_interval_hours = check_interval_hours
        self.analyzer = ThreatIntelAnalyzer()
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def process_threat_intel(self):
        """Process threat intelligence feeds and update registry monitoring"""
        try:
            self.logger.info("Starting threat intelligence processing...")
            
            # Process all feeds
            results = self.analyzer.process_all_feeds()
            
            if results:
                self.logger.info("Found %d relevant articles", len(results))
                
                # Update registry configuration
                self.analyzer.update_registry_config(results)
                
                # Log details of findings
                for result in results:
                    if result.predicted_registry_keys:
                        self.logger.info(
                            f"Article '{result.article_title}' suggests monitoring: "
                            f"{result.predicted_registry_keys}"
                        )
            else:
                self.logger.info("No new relevant threat intelligence found")
                
        except Exception as e:
            self.logger.error("Error processing threat intelligence: %s", e)
    
    def start_scheduler(self):
        """Start the threat intelligence scheduler"""
        if self.is_running:
            self.logger.warning("Threat intelligence scheduler is already running")
            return
        
        self.is_running = True
        
        # Run the first check immediately
        self.process_threat_intel()
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        self.logger.info(
            "Threat intelligence scheduler started, checking every %d hours",
            self.check_interval_hours
        )
    
    def stop_scheduler(self):
        """Stop the threat intelligence scheduler"""
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.logger.info("Threat intelligence scheduler stopped")
    
    def _run_scheduler(self):
        """Internal method to run the scheduler loop"""
        while self.is_running:
            try:
                # Sleep for the specified interval
                time.sleep(self.check_interval_hours * 3600)  # Convert hours to seconds
                
                if self.is_running:
                    self.process_threat_intel()
            except Exception as e:
                self.logger.error("Error in scheduler loop: %s", e)
    
    def run_once(self):
        """Run threat intelligence processing once"""
        self.process_threat_intel()

def main():
    """Main function for running the threat intelligence scheduler"""
    # Create scheduler
    scheduler = ThreatIntelScheduler(check_interval_hours=6)
    
    try:
        # Start scheduler
        scheduler.start_scheduler()
        
        print("Threat intelligence scheduler running. Press Ctrl+C to stop.")
        print("Checking feeds every 6 hours...")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping threat intelligence scheduler...")
        scheduler.stop_scheduler()
        print("Scheduler stopped.")

if __name__ == "__main__":
    main()