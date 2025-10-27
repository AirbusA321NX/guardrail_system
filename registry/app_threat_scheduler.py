#!/usr/bin/env python3
"""
Application Threat Scheduler

This module schedules periodic checks of threat intelligence feeds
and generates reports on applications that should be removed.
"""

import time
import threading
import logging
from datetime import datetime
from typing import Optional

from registry.app_threat_analyzer import AppThreatAnalyzer

class AppThreatScheduler:
    """Scheduler for application threat analysis"""
    
    def __init__(self, check_interval_hours: int = 12):
        self.check_interval_hours = check_interval_hours
        self.analyzer = AppThreatAnalyzer()
        self.is_running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def process_app_threats(self):
        """Process threat intelligence feeds and generate app removal reports"""
        try:
            self.logger.info("Starting application threat analysis...")
            
            # Process all feeds
            results = self.analyzer.process_all_feeds()
            
            if results:
                self.logger.info("Found %d articles suggesting app removals", len(results))
                
                # Generate report
                report = self.analyzer.generate_report(results)
                
                # Save report to file with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_file = f"app_threat_report_{timestamp}.txt"
                
                try:
                    with open(report_file, 'w') as f:
                        f.write(report)
                    self.logger.info("Report saved to: %s", report_file)
                except Exception as e:
                    self.logger.error("Could not save report: %s", e)
                
                # Log details of findings
                for result in results:
                    if result.suggested_app_removals:
                        self.logger.info(
                            "Article '%s' suggests removing: %s",
                            result.article_title,
                            result.suggested_app_removals
                        )
            else:
                self.logger.info("No new application threats found")
                
        except Exception as e:
            self.logger.error("Error processing application threats: %s", e)
    
    def start_scheduler(self):
        """Start the application threat scheduler"""
        if self.is_running:
            self.logger.warning("Application threat scheduler is already running")
            return
        
        self.is_running = True
        
        # Run the first check immediately
        self.process_app_threats()
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        self.logger.info(
            "Application threat scheduler started, checking every %d hours",
            self.check_interval_hours
        )
    
    def stop_scheduler(self):
        """Stop the application threat scheduler"""
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.logger.info("Application threat scheduler stopped")
    
    def _run_scheduler(self):
        """Internal method to run the scheduler loop"""
        while self.is_running:
            try:
                # Sleep for the specified interval
                time.sleep(self.check_interval_hours * 3600)  # Convert hours to seconds
                
                if self.is_running:
                    self.process_app_threats()
            except Exception as e:
                self.logger.error("Error in scheduler loop: %s", e)
    
    def run_once(self):
        """Run application threat analysis once"""
        self.process_app_threats()

def main():
    """Main function for running the application threat scheduler"""
    # Create scheduler
    scheduler = AppThreatScheduler(check_interval_hours=12)
    
    try:
        # Start scheduler
        scheduler.start_scheduler()
        
        print("Application threat scheduler running. Press Ctrl+C to stop.")
        print("Checking feeds every 12 hours...")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping application threat scheduler...")
        scheduler.stop_scheduler()
        print("Scheduler stopped.")

if __name__ == "__main__":
    main()