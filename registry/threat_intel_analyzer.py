#!/usr/bin/env python3
"""
Threat Intelligence Analyzer for Registry Monitoring

This module processes RSS feeds from security sources, uses AI to analyze articles,
and predicts which registry keys might be targeted by new threats.
"""

import feedparser
import json
import re
import time
import logging
import threading
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import yaml
import os

# Import our registry configuration
from registry.config import (
    REGISTRY_PERSISTENCE_PATHS,
    PROCESS_PATTERNS,
    PATH_PATTERNS,
    COMMANDLINE_PATTERNS
)

# Try to import AI modules, but make them optional
try:
    from ai.mistral_analysis import analyze_text
    AI_AVAILABLE = True
except ImportError:
    analyze_text = None
    AI_AVAILABLE = False
    logging.warning("AI modules not available. Using rule-based analysis instead.")

# RSS feeds for threat intelligence
FEEDS = [
    "https://blog.malwarebytes.com/feed/",
    "https://www.crowdstrike.com/blog/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://threatpost.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "https://cert.europa.eu/rss/"
]

# Common registry patterns that might appear in threat reports
REGISTRY_PATTERNS = [
    r'HKEY_[A-Z_]+[\\][\w\\]+',
    r'HK[A-Z][\\][\w\\]+',
    r'SOFTWARE[\\][\w\\]+',
    r'SYSTEM[\\][\w\\]+',
    r'CurrentVersion[\\][\w\\]+',
    r'Classes[\\][\w\\]+'
]

@dataclass
class ThreatIntelResult:
    """Result from threat intelligence analysis"""
    article_title: str
    article_url: str
    published_date: str
    relevant: bool
    predicted_registry_keys: List[str]
    confidence_score: float
    threat_summary: str

class ThreatIntelAnalyzer:
    """Analyzer for processing threat intelligence feeds"""
    
    def __init__(self, config_dir: str = "registry/config"):
        self.config_dir = config_dir
        self.processed_articles = set()
        self.load_processed_articles()
        
    def load_processed_articles(self):
        """Load previously processed articles to avoid duplicates"""
        try:
            processed_file = os.path.join(self.config_dir, "processed_articles.json")
            if os.path.exists(processed_file):
                with open(processed_file, 'r') as f:
                    self.processed_articles = set(json.load(f))
        except Exception as e:
            logging.warning("Could not load processed articles: %s", e)
    
    def save_processed_articles(self):
        """Save processed articles to avoid duplicates in future runs"""
        try:
            processed_file = os.path.join(self.config_dir, "processed_articles.json")
            with open(processed_file, 'w') as f:
                json.dump(list(self.processed_articles), f)
        except Exception as e:
            logging.warning("Could not save processed articles: %s", e)
    
    def extract_registry_keys(self, text: str) -> List[str]:
        """Extract potential registry keys from text using regex patterns"""
        keys = set()
        for pattern in REGISTRY_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Clean up the match
                key = match.strip().strip('"').strip("'")
                if key and len(key) > 10:  # Filter out very short matches
                    keys.add(key)
        return list(keys)
    
    def is_article_relevant(self, title: str, summary: str) -> bool:
        """Determine if an article is relevant to registry monitoring"""
        # Keywords that suggest registry-related content
        registry_keywords = [
            'registry', 'regedit', 'hkcu', 'hklm', 'persistence',
            'autorun', 'startup', 'malware', 'trojan', 'ransomware',
            'backdoor', 'implant', 'injection', 'hijack', 'keylog',
            'run key', 'runonce', 'winlogon', 'services', 'clsid'
        ]
        
        # Keywords that suggest the article is NOT relevant
        irrelevant_keywords = [
            'phishing', 'spam', 'email', 'password', 'credential',
            'identity', 'theft', 'scam', 'fraud', 'social engineering'
        ]
        
        text = (title + " " + summary).lower()
        
        # If it contains irrelevant keywords and no registry keywords, it's likely not relevant
        has_irrelevant = any(keyword in text for keyword in irrelevant_keywords)
        has_registry = any(keyword in text for keyword in registry_keywords)
        
        # If it has registry keywords, it's relevant regardless of irrelevant keywords
        if has_registry:
            return True
            
        # If it has irrelevant keywords but no registry keywords, it's not relevant
        if has_irrelevant and not has_registry:
            return False
            
        # Otherwise, check for general security terms
        security_keywords = [
            'exploit', 'vulnerability', 'patch', 'update', 'security',
            'attack', 'threat', 'ioc', 'indicator', 'compromise'
        ]
        
        return any(keyword in text for keyword in security_keywords)
    
    def analyze_with_ai(self, title: str, summary: str) -> Dict:
        """Use AI to analyze article content and predict registry threats"""
        if not AI_AVAILABLE or analyze_text is None:
            # Fallback to rule-based analysis
            return self.rule_based_analysis(title, summary)
        
        prompt = f"""
        Analyze this security article and determine if it describes techniques that could involve registry modifications:
        
        Title: {title}
        Summary: {summary}
        
        Please answer with a JSON object containing:
        1. "relevant": boolean - whether this article describes registry-related threats
        2. "registry_keys": array - specific registry keys that might be targeted
        3. "confidence": number - confidence score from 0.0 to 1.0
        4. "threat_summary": string - brief summary of the registry threat
        
        Example response format:
        {{
            "relevant": true,
            "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\SYSTEM\\CurrentControlSet\\Services"],
            "confidence": 0.85,
            "threat_summary": "Describes a persistence mechanism using registry run keys"
        }}
        """
        
        try:
            response = analyze_text(prompt)
            # Try to parse the response as JSON
            if isinstance(response, str):
                # Extract JSON from the response
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = response[json_start:json_end]
                    return json.loads(json_str)
            return response if isinstance(response, dict) else {}
        except Exception as e:
            logging.warning("AI analysis failed: %s", e)
            return self.rule_based_analysis(title, summary)
    
    def rule_based_analysis(self, title: str, summary: str) -> Dict:
        """Rule-based analysis when AI is not available"""
        text = (title + " " + summary).lower()
        
        # Extract potential registry keys
        potential_keys = self.extract_registry_keys(text)
        
        # Determine relevance
        relevant = self.is_article_relevant(title, summary)
        
        # Simple confidence scoring
        confidence = 0.5
        if potential_keys:
            confidence += 0.3
        if relevant:
            confidence += 0.2
        confidence = min(1.0, confidence)
        
        return {
            "relevant": relevant,
            "registry_keys": potential_keys,
            "confidence": confidence,
            "threat_summary": "Rule-based analysis of potential registry threats"
        }
    
    def process_feed(self, feed_url: str) -> List[ThreatIntelResult]:
        """Process a single RSS feed"""
        results = []
        
        try:
            feed = feedparser.parse(feed_url)
            
            for entry in feed.entries:
                # Create a unique identifier for the article
                article_id = f"{entry.get('id', entry.get('link', ''))}_{entry.get('published', '')}"
                
                # Skip if already processed
                if article_id in self.processed_articles:
                    continue
                
                # Get article content
                title = getattr(entry, 'title', 'No title')
                summary = getattr(entry, 'summary', getattr(entry, 'description', ''))
                link = getattr(entry, 'link', '')
                published = getattr(entry, 'published', datetime.now().isoformat())
                
                # Check if article is relevant
                if not self.is_article_relevant(title, summary):
                    continue
                
                # Analyze with AI or rules
                analysis = self.analyze_with_ai(title, summary)
                
                # Create result
                result = ThreatIntelResult(
                    article_title=title,
                    article_url=link,
                    published_date=published,
                    relevant=analysis.get('relevant', False),
                    predicted_registry_keys=analysis.get('registry_keys', []),
                    confidence_score=analysis.get('confidence', 0.0),
                    threat_summary=analysis.get('threat_summary', '')
                )
                
                if result.relevant and result.confidence_score > 0.5:
                    results.append(result)
                    self.processed_articles.add(article_id)
                
        except Exception as e:
            logging.error("Error processing feed %s: %s", feed_url, e)
        
        return results
    
    def process_all_feeds(self) -> List[ThreatIntelResult]:
        """Process all RSS feeds and return relevant results"""
        all_results = []
        
        for feed_url in FEEDS:
            try:
                results = self.process_feed(feed_url)
                all_results.extend(results)
                # Be respectful to feed servers
                time.sleep(1)
            except Exception as e:
                logging.error("Error processing feed %s: %s", feed_url, e)
        
        # Save processed articles
        self.save_processed_articles()
        
        return all_results
    
    def update_registry_config(self, results: List[ThreatIntelResult]):
        """Update registry configuration with newly identified keys"""
        if not results:
            return
        
        # Load existing registry paths
        config_file = os.path.join(self.config_dir, "registry_paths.yml")
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logging.error("Could not load registry config: %s", e)
            return
        
        # Get existing paths
        existing_paths = set()
        for item in config.get('registry_watchlist', []):
            existing_paths.add(item['path'].lower())
        
        # Add new paths from threat intel
        new_entries = []
        for result in results:
            for key in result.predicted_registry_keys:
                clean_key = key.strip().strip('\\')
                if clean_key.lower() not in existing_paths:
                    new_entries.append({
                        'hive': 'HKLM' if 'hklm' in clean_key.lower() or 'hkey_local_machine' in clean_key.lower() else 'HKCU',
                        'path': clean_key,
                        'risk': 'high' if result.confidence_score > 0.8 else 'medium',
                        'description': f"Identified via threat intel: {result.threat_summary}"
                    })
                    existing_paths.add(clean_key.lower())
        
        # Add new entries to config
        if new_entries:
            config['registry_watchlist'].extend(new_entries)
            
            # Save updated config
            try:
                with open(config_file, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, indent=2)
                logging.info("Added %d new registry paths from threat intel", len(new_entries))
            except Exception as e:
                logging.error("Could not save updated registry config: %s", e)

def main():
    """Main function for testing the threat intel analyzer"""
    logging.basicConfig(level=logging.INFO)
    
    analyzer = ThreatIntelAnalyzer()
    
    print("Processing threat intelligence feeds...")
    results = analyzer.process_all_feeds()
    
    print(f"\nFound {len(results)} relevant articles:")
    for result in results:
        print(f"\nTitle: {result.article_title}")
        print(f"URL: {result.article_url}")
        print(f"Confidence: {result.confidence_score:.2f}")
        print(f"Predicted keys: {result.predicted_registry_keys}")
        print(f"Summary: {result.threat_summary}")
    
    # Update registry configuration
    if results:
        analyzer.update_registry_config(results)
        print(f"\nUpdated registry configuration with {len(results)} new threat intel results")

if __name__ == "__main__":
    main()