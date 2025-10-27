#!/usr/bin/env python3
"""
Application Threat Analyzer for Security Feed Monitoring

This module processes RSS feeds from security sources, uses AI to analyze articles,
and suggests applications that should be removed based on security threats.
"""

import feedparser
import json
import re
import time
import logging
import os
from typing import List, Dict, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import yaml

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

# Common application names that might appear in threat reports
APP_PATTERNS = [
    # Executable files
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.exe',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.dll',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.sys',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.msi',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.msp',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.msu',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.scr',
    
    # Script files
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.bat',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.cmd',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.ps1',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.psm1',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.vbs',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.vbe',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.js',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.jse',
    
    # Archive/Compressed files that might contain malicious content
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.zip',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.rar',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.7z',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.tar',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.gz',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.bz2',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.xz',
    
    # Mobile application files
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.apk',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.ipa',
    
    # Document files that can contain macros
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.doc',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.docx',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.xls',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.xlsx',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.ppt',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.pptx',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.pdf',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.rtf',
    
    # Configuration/Initialization files
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.ini',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.inf',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.reg',
    r'([A-Za-z0-9_\-\s\.\(\)]+)\.cfg',
    
    # Generic pattern for any file with suspicious naming
    r'([A-Za-z0-9_\-\s\.\(\)]{1,50})\s*-?\s*(malware|virus|trojan|spyware|adware|ransomware|keylogger|backdoor|rootkit|downloader|dropper)\.?[A-Za-z0-9_\-\s\.\(\)]*',
    r'(malware|virus|trojan|spyware|adware|ransomware|keylogger|backdoor|rootkit|downloader|dropper)[\s\-_]?([A-Za-z0-9_\-\s\.\(\)]{1,50})'
]

@dataclass
class AppThreatResult:
    """Result from application threat analysis"""
    article_title: str
    article_url: str
    published_date: str
    relevant: bool
    suggested_app_removals: List[str]
    confidence_score: float
    threat_summary: str

class AppThreatAnalyzer:
    """Analyzer for processing threat intelligence feeds and suggesting app removals"""
    
    def __init__(self, config_dir: str = "registry/config"):
        self.config_dir = config_dir
        self.processed_articles = set()
        self.load_processed_articles()
        
    def load_processed_articles(self):
        """Load previously processed articles to avoid duplicates"""
        try:
            processed_file = os.path.join(self.config_dir, "processed_app_articles.json")
            if os.path.exists(processed_file):
                with open(processed_file, 'r') as f:
                    self.processed_articles = set(json.load(f))
        except Exception as e:
            logging.warning("Could not load processed app articles: %s", e)
    
    def save_processed_articles(self):
        """Save processed articles to avoid duplicates in future runs"""
        try:
            processed_file = os.path.join(self.config_dir, "processed_app_articles.json")
            with open(processed_file, 'w') as f:
                json.dump(list(self.processed_articles), f)
        except Exception as e:
            logging.warning("Could not save processed app articles: %s", e)
    
    def extract_app_names(self, text: str) -> List[str]:
        """Extract potential application names from text"""
        apps = set()
        for pattern in APP_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Handle different match group structures
                if isinstance(match, tuple):
                    # Take the first non-empty group
                    app = next((group for group in match if group), '')
                else:
                    app = match
                
                # Clean up the match
                app = app.strip().strip('"').strip("'").strip('.').lower()
                
                # Filter out common system files and short names
                if app and len(app) > 2 and not app in ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9']:
                    # Remove common extensions for cleaner matching
                    extensions = [
                        '.exe', '.dll', '.sys', '.msi', '.msp', '.msu', '.scr',
                        '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse',
                        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
                        '.apk', '.ipa',
                        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf',
                        '.ini', '.inf', '.reg', '.cfg'
                    ]
                    for ext in extensions:
                        if app.endswith(ext):
                            app = app[:-len(ext)]
                            break
                    # Additional cleaning for common prefixes/suffixes
                    app = re.sub(r'^(install|setup|uninstall|remove|delete)[_\-\s]*', '', app)
                    app = re.sub(r'[_\-\s]*(install|setup|uninstall|remove|delete)$', '', app)
                    # Clean version numbers (e.g., appname_v1.2.3)
                    app = re.sub(r'[_\-\s]*v?\d+(\.\d+)*$', '', app)
                    # Only add if we still have a meaningful name
                    if len(app) > 2:
                        apps.add(app)
        return list(apps)
    
    def is_article_relevant(self, title: str, summary: str) -> bool:
        """Determine if an article is relevant to application threats"""
        # Let the AI determine relevance instead of hardcoded keywords
        # We'll use a simpler heuristic to avoid processing completely irrelevant articles
        text = (title + " " + summary).lower()
        
        # Basic check for security-related content
        security_indicators = [
            'security', 'malware', 'threat', 'virus', 'attack', 'exploit', 
            'cyber', 'hacking', 'breach', 'vulnerability', 'patch'
        ]
        
        return any(indicator in text for indicator in security_indicators)
    
    def analyze_with_ai(self, title: str, summary: str) -> Dict:
        """Use AI to analyze article content and suggest app removals"""
        if not AI_AVAILABLE or analyze_text is None:
            # Fallback to rule-based analysis
            return self.rule_based_analysis(title, summary)
        
        prompt = f"""
        Analyze this security article and determine if it recommends removing any applications:
        
        Title: {title}
        Summary: {summary}
        
        Please answer with a JSON object containing:
        1. "relevant": boolean - whether this article recommends removing applications
        2. "suggested_app_removals": array - specific applications that should be removed
        3. "confidence": number - confidence score from 0.0 to 1.0
        4. "threat_summary": string - brief summary of the threat
        
        When identifying applications for removal, look for:
        - Explicit mentions of malware, viruses, trojans, ransomware, spyware, adware, rootkits, keyloggers, backdoors, downloaders, or droppers
        - Applications that are specifically named as being malicious or compromised
        - Software that security researchers recommend removing or uninstalling
        - Programs that are identified as potentially unwanted applications (PUAs)
        - Mobile applications (especially Android APKs or iOS IPAs) identified as malicious
        - Browser extensions or plugins that are flagged as malicious
        - System utilities or legitimate software that has been compromised
        
        Pay special attention to:
        - Android malware (e.g., banking trojans, SMS stealers, spyware)
        - iOS malicious applications
        - Browser hijackers
        - Cryptominers
        - Remote access tools (RATs)
        - Fake antivirus software
        
        Example response format:
        {{
            "relevant": true,
            "suggested_app_removals": ["suspicious_app", "malware_tool", "unwanted_program"],
            "confidence": 0.95,
            "threat_summary": "Article describes a malware family that should be removed immediately"
        }}
        """
        
        try:
            response = analyze_text(prompt)
            # Try to parse the response as JSON
            if isinstance(response, str):
                # Extract JSON from the response
                json_start = response.find('{{')
                json_end = response.rfind('}}') + 2
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
        
        # Extract potential app names
        potential_apps = self.extract_app_names(text)
        
        # Simple heuristic for relevance - look for security-related terms
        security_terms = [
            'malware', 'virus', 'trojan', 'ransomware', 'backdoor', 'spyware', 
            'adware', 'rootkit', 'keylogger', 'downloader', 'dropper', 'pua',
            'unwanted', 'suspicious', 'infected', 'compromised', 'malicious',
            'android', 'apk', 'ios', 'ipa', 'mobile', 'app', 'application'
        ]
        
        relevant = any(term in text for term in security_terms) and len(potential_apps) > 0
        
        # Simple confidence scoring
        confidence = 0.3  # Base confidence
        if potential_apps:
            confidence += 0.4
        if relevant:
            confidence += 0.3
        confidence = min(1.0, confidence)
        
        return {
            "relevant": relevant,
            "suggested_app_removals": potential_apps if relevant else [],
            "confidence": confidence,
            "threat_summary": "Rule-based analysis of potential application threats" if relevant else "No significant threats identified"
        }
    
    def process_feed(self, feed_url: str) -> List[AppThreatResult]:
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
                result = AppThreatResult(
                    article_title=title,
                    article_url=link,
                    published_date=published,
                    relevant=analysis.get('relevant', False),
                    suggested_app_removals=analysis.get('suggested_app_removals', []),
                    confidence_score=analysis.get('confidence', 0.0),
                    threat_summary=analysis.get('threat_summary', '')
                )
                
                if result.relevant and result.confidence_score > 0.5:
                    results.append(result)
                    self.processed_articles.add(article_id)
                
        except Exception as e:
            logging.error("Error processing feed %s: %s", feed_url, e)
        
        return results
    
    def process_all_feeds(self) -> List[AppThreatResult]:
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
    
    def generate_report(self, results: List[AppThreatResult]) -> str:
        """Generate a human-readable report of suggested app removals"""
        if not results:
            return "No applications suggested for removal at this time."
        
        report = "=== APPLICATION THREAT ANALYSIS REPORT ===\n\n"
        report += f"Analysis completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Number of articles analyzed: {len(results)}\n\n"
        
        # Collect all unique suggested removals
        all_apps = set()
        for result in results:
            for app in result.suggested_app_removals:
                all_apps.add((app, result.confidence_score, result.article_title))
        
        if not all_apps:
            report += "No specific applications were suggested for removal.\n"
            return report
        
        report += "SUGGESTED APPLICATION REMOVALS:\n"
        report += "--------------------------------\n"
        
        # Sort by confidence score
        sorted_apps = sorted(all_apps, key=lambda x: x[1], reverse=True)
        
        for app, confidence, source in sorted_apps:
            report += f"Application: {app}\n"
            report += f"  Confidence: {confidence:.2f}\n"
            report += f"  Source: {source}\n\n"
        
        report += "RECOMMENDATIONS:\n"
        report += "----------------\n"
        report += "1. Review the above applications and verify if they are legitimate\n"
        report += "2. Use your system's uninstaller or security software to remove malicious applications\n"
        report += "3. Run a full system scan to ensure complete removal\n"
        report += "4. Keep this report for future reference\n\n"
        
        return report

def main():
    """Main function for running the application threat analyzer"""
    logging.basicConfig(level=logging.INFO)
    
    analyzer = AppThreatAnalyzer()
    
    print("Processing security feeds for application threat analysis...")
    results = analyzer.process_all_feeds()
    
    print(f"\nFound {len(results)} relevant articles suggesting app removals:")
    for result in results:
        print(f"\nTitle: {result.article_title}")
        print(f"URL: {result.article_url}")
        print(f"Confidence: {result.confidence_score:.2f}")
        print(f"Suggested removals: {result.suggested_app_removals}")
        print(f"Summary: {result.threat_summary}")
    
    # Generate and save report
    report = analyzer.generate_report(results)
    print("\n" + report)
    
    # Save report to file
    report_file = f"app_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\nReport saved to: {report_file}")
    except Exception as e:
        logging.error("Could not save report: %s", e)

if __name__ == "__main__":
    main()