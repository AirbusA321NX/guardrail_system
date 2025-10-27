"""
URL checker utility that verifies URLs against threat intelligence feeds
"""
import requests
import re
from typing import List
from utils.logger import log_event

# Threat intelligence feeds
THREAT_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/"
]

# More comprehensive URL pattern that doesn't rely on hardcoded TLDs
URL_PATTERN = re.compile(
    r'(?:(?:https?://|www\.)[^\s/$.?#].[^\s]*|[\w.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)',
    re.IGNORECASE
)

def command_might_contain_url(command: str) -> bool:
    """
    Quick check to see if a command might contain a URL.
    This avoids unnecessary processing of commands that definitely don't have URLs.
    """
    command_lower = command.lower()
    
    # Check for common URL indicators
    if any(indicator in command_lower for indicator in ['http://', 'https://', 'www.']):
        return True
    
    # Use the more comprehensive URL pattern to detect potential URLs
    if URL_PATTERN.search(command):
        return True
            
    return False

def fetch_feed_content(url: str) -> str:
    """Fetch content from a threat intelligence feed"""
    try:
        response = requests.get(url, timeout=15, headers={
            'User-Agent': 'url-checker-cli/1.0'
        })
        response.raise_for_status()
        return response.text
    except Exception as e:
        log_event("URL_CHECK_FEED_ERROR", f"Failed to fetch {url}: {str(e)}")
        return ""

def normalize_url(url: str) -> str:
    """Normalize URL for comparison"""
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Add protocol if missing
    if "://" not in url:
        url = "http://" + url
    
    # Convert to lowercase
    url = url.lower()
    
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
        
    return url

def extract_urls_from_feed(content: str) -> List[str]:
    """Extract URLs from feed content"""
    urls = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#') or line.startswith(';'):
            continue
            
        # Normalize the URL
        normalized = normalize_url(line)
        if normalized:
            urls.append(normalized)
            
    return urls

def is_malicious_url(url: str) -> bool:
    """
    Check if a URL is malicious by comparing against threat intelligence feeds
    Returns True if malicious, False otherwise
    """
    try:
        # Normalize the target URL
        target_url = normalize_url(url)
        
        # Check against each threat feed
        for feed_url in THREAT_FEEDS:
            # Fetch feed content
            feed_content = fetch_feed_content(feed_url)
            if not feed_content:
                continue
                
            # Extract URLs from feed
            feed_urls = extract_urls_from_feed(feed_content)
            
            # Check if target URL matches any in the feed
            for feed_entry in feed_urls:
                if not feed_entry:
                    continue
                    
                # Check for substring matches in both directions
                if (target_url in feed_entry) or (feed_entry in target_url):
                    log_event("URL_CHECK_MALICIOUS", f"URL {target_url} found in feed {feed_url}")
                    return True
                    
        # No matches found in any feeds
        log_event("URL_CHECK_CLEAN", f"URL {target_url} not found in threat feeds")
        return False
        
    except Exception as e:
        log_event("URL_CHECK_ERROR", f"Error checking URL {url}: {str(e)}")
        # In case of error, we don't block the URL but log the error
        return False

def extract_urls_from_command(command: str) -> List[str]:
    """
    Extract URLs from a command string
    Returns list of URLs found in the command
    """
    # Regex pattern to match URLs
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'
    urls = re.findall(url_pattern, command, re.IGNORECASE)
    return urls