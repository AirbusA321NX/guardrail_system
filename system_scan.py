"""
System-wide security scanner using behavioral analysis
"""
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import logging

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent))

from ai.static_analyzer import ThreatAnalyzer, analyze_behavior, calculate_file_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('system_scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size to scan
SCAN_INTERVAL = 3600 * 24  # 24 hours between scans
SKIP_DIRS = [
    'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData',
    'AppData', 'Local Settings', 'Temp', 'tmp', '$Recycle.Bin',
    'System Volume Information', 'Windows.old'
]
SKIP_EXTENSIONS = ['.tmp', '.log', '.cache', '.dmp', '.bak', '.old', '.swp']

class SystemScanner:
    def __init__(self):
        self.analyzer = ThreatAnalyzer(feature_dim=100)
        self.scan_results: List[Dict[str, Any]] = []
        self.scan_start_time = datetime.now()
        
    def should_skip(self, path: Path) -> bool:
        """Check if a path should be skipped during scanning"""
        # Skip system and hidden files/directories
        if path.name.startswith('.') or path.name.startswith('~$'):
            return True
            
        # Skip temporary files
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return True
            
        # Skip system directories
        for skip_dir in SKIP_DIRS:
            if skip_dir.lower() in str(path).lower():
                return True
                
        # Skip large files
        try:
            if path.is_file() and path.stat().st_size > MAX_FILE_SIZE:
                return True
        except (OSError, PermissionError):
            return True
            
        return False
    
    def scan_directory(self, directory: str) -> None:
        """Recursively scan a directory and analyze files"""
        root = Path(directory)
        if not root.exists() or not root.is_dir():
            logger.error("Directory not found or not accessible: %s", directory)
            return
            
        try:
            for item in root.iterdir():
                try:
                    # Skip if we should skip this path
                    if self.should_skip(item):
                        continue
                        
                    if item.is_file():
                        self.analyze_file(item)
                    elif item.is_dir():
                        self.scan_directory(str(item))
                        
                except (PermissionError, OSError) as e:
                    logger.debug("Skipping %s: %s", item, str(e))
                    continue
                    
        except Exception as e:
            logger.error("Error scanning %s: %s", directory, str(e))
    
    def analyze_file(self, file_path: Path) -> None:
        """Analyze a single file and log results"""
        try:
            logger.info("Analyzing: %s", file_path)
            
            # Skip files that are too large
            if file_path.stat().st_size > MAX_FILE_SIZE:
                logger.debug("Skipping large file: %s", file_path)
                return
                
            # Analyze the file
            result = analyze_behavior(str(file_path), self.analyzer)
            
            if not result:
                return
                
            # Log suspicious files
            if result.get('is_anomaly', False):
                self.log_suspicious_file(file_path, result)
                
        except Exception as e:
            logger.error("Error analyzing %s: %s", file_path, str(e))
    
    def log_suspicious_file(self, file_path: Path, result: Dict[str, Any]) -> None:
        """Log details of suspicious files"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'file_path': str(file_path),
            'file_hash': result.get('file_hash', 'N/A'),
            'confidence': result.get('confidence', 0),
            'indicators': result.get('indicators', []),
            'reconstruction_error': result.get('reconstruction_error', 0),
            'threshold': result.get('threshold', 0),
            'action': result.get('action', 'N/A')
        }
        
        self.scan_results.append(log_entry)
        
        logger.warning("\n" + "=" * 80)
        logger.warning("SUSPICIOUS FILE DETECTED: %s", file_path)
        logger.warning("Confidence: %.2f%%", result.get('confidence', 0))
        logger.warning("Indicators: %s", ', '.join(result.get('indicators', [])))
        logger.warning("=" * 80 + "\n")
    
    def run_scan(self, directory: Optional[str] = None) -> None:
        """Run a system scan"""
        logger.info("Starting system scan at %s", self.scan_start_time)
        
        try:
            # If no directory specified, scan all drives on Windows
            if directory is None:
                import string
                import win32api
                
                # Get all available drives
                drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:")]
                
                for drive in drives:
                    logger.info("Scanning drive: %s", drive)
                    self.scan_directory(drive)
            else:
                self.scan_directory(directory)
                
        except Exception as e:
            logger.error("Fatal error during scan: %s", str(e))
        finally:
            self.save_scan_report()
    
    def save_scan_report(self) -> None:
        """Save scan results to a JSON report"""
        scan_end_time = datetime.now()
        report = {
            'scan_start': self.scan_start_time.isoformat(),
            'scan_end': scan_end_time.isoformat(),
            'duration_seconds': (scan_end_time - self.scan_start_time).total_seconds(),
            'files_scanned': len(self.scan_results),
            'suspicious_files': self.scan_results
        }
        
        report_path = f"security_scan_{self.scan_start_time.strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            import json
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info("Scan report saved to: %s", report_path)
        except Exception as e:
            logger.error("Failed to save scan report: %s", str(e))

def scan_system(scan_path: Optional[str] = None, debug: bool = False) -> List[Dict[str, Any]]:
    """
    Scan the system for potential threats.
    
    Args:
        scan_path: The path to scan. If None, scans all available drives on Windows.
        debug: Enable debug logging if True.
        
    Returns:
        List of dictionaries containing scan results.
    """
    # Set log level
    if debug:
        logger.setLevel(logging.DEBUG)
    
    scanner = SystemScanner()
    
    # Run the scan
    scanner.run_scan(scan_path)
    
    # Return the scan results
    return scanner.scan_results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='System Security Scanner')
    parser.add_argument('directory', nargs='?', default=None,
                       help='Directory to scan (default: all drives)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Run the scanner with the provided arguments
    results = scan_system(args.directory, args.debug)
    
    # Print a summary of the results
    if results:
        print(f"\nScan completed. Found {len(results)} suspicious files.")
        for i, result in enumerate(results[:5], 1):  # Show first 5 results
            print(f"{i}. {result.get('file_path', 'Unknown')} - {result.get('confidence', 0):.2f}% confidence")
        if len(results) > 5:
            print(f"... and {len(results) - 5} more suspicious files.")
    else:
        print("\nScan completed. No suspicious files found.")
