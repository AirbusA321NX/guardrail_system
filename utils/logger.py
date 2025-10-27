import logging
import sys
import json
from pathlib import Path
from datetime import datetime

LOG_DIR = Path("D:/pycharm/guardrail_system/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

def setup_logging(log_file_name: str = "training.log"):
    """
    Sets up a centralized logger for the application.
    This should be called only once at the application entry point.
    """
    log_file = LOG_DIR / log_file_name
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, mode='a')
        ],
        force=True  # Override any existing configurations
    )
    logging.info("Logging configured. Log file at: %s", log_file)

def get_logger(name: str) -> logging.Logger:
    """Retrieves a logger instance."""
    return logging.getLogger(name)

def log_event(event_type: str, message: str, **kwargs):
    """
    Logs a structured event with timestamp and additional context.
    
    Args:
        event_type: Type of event (e.g., 'ANALYSIS', 'ERROR')
        message: The message to log with placeholders for kwargs
        **kwargs: Additional context to include in the log
    """
    logger = get_logger(__name__)
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event_type,
        "message": message.format(**kwargs) if kwargs else message,
        **kwargs
    }
    logger.info(json.dumps(log_data))