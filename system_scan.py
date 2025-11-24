"""
System-wide security scanner using behavioral analysis
"""
from ai.mistral_analysis import analyze_text
from ai.static_analyzer import analyze_file
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import logging
import hashlib

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent))

# Import the correct functions from static_analyzer

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
            logger.error(
                "Directory not found or not accessible: %s", directory)
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

            # Analyze the file using the static analyzer
            result_str = analyze_file(str(file_path))

            # Parse the result (assuming it's a JSON string)
            import json
            try:
                result = json.loads(result_str)
            except json.JSONDecodeError:
                logger.error(
                    "Failed to parse analysis result for %s", file_path)
                return

            if not result:
                return

            # Add file hash to the result
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    file_hash = hashlib.sha256(file_data).hexdigest()
                    result['file_hash'] = file_hash
            except Exception as e:
                logger.error(
                    "Error calculating file hash for %s: %s", file_path, str(e))
                result['file_hash'] = 'N/A'

            # Log suspicious files
            risk_score = result.get('risk_score', 0)
            # Consider files with risk score > 0.7 as suspicious
            if risk_score > 0.7:
                self.log_suspicious_file(file_path, result)

        except Exception as e:
            logger.error("Error analyzing %s: %s", file_path, str(e))

    def log_suspicious_file(self, file_path: Path, result: Dict[str, Any]) -> None:
        """Log details of suspicious files"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'file_path': str(file_path),
            'file_hash': result.get('file_hash', 'N/A'),
            # Convert to percentage
            'confidence': result.get('risk_score', 0) * 100,
            'indicators': result.get('reasoning', ''),
            'reconstruction_error': 0,  # Not applicable in this context
            'threshold': 0.7,  # Our threshold for suspicious files
            'action': 'investigate'  # Default action
        }

        self.scan_results.append(log_entry)

        logger.warning("\n" + "=" * 80)
        logger.warning("SUSPICIOUS FILE DETECTED: %s", file_path)
        logger.warning("Risk Score: %.2f%%", result.get('risk_score', 0) * 100)
        logger.warning("Reasoning: %s", result.get('reasoning', 'N/A'))
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
                drives = [
                    f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:")]

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
            print(
                f"{i}. {result.get('file_path', 'Unknown')} - {result.get('confidence', 0):.2f}% confidence")
        if len(results) > 5:
            print(f"... and {len(results) - 5} more suspicious files.")
    else:
        print("\nScan completed. No suspicious files found.")
