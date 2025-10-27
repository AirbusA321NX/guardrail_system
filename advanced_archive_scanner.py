#!/usr/bin/env python3
"""
Advanced Triage Scanner with AI-Based Threat Analysis

This module implements an advanced triage scanner that assesses potential security threats 
in archive files using AI analysis and checks for indicators of compromise (IOCs) that 
may indicate an active infection. 

The scanner operates in two phases:
1. AI-based risk assessment: Uses LLM to analyze file metadata and predict potential threats
2. IOC verification: Checks if predicted IOCs are already present on the system, which 
   would indicate an active infection rather than just a potential threat

Note: This is a static triage tool, not a dynamic sandbox. It does not execute files or 
monitor for future behavior. Instead, this is a static triage tool.
"""

import os
import json
import zipfile
import tarfile
import tempfile
import hashlib
import time
import logging
import re
import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import threading
from pathlib import Path

# Import required libraries
import magic  # python-magic for file type detection
import py7zr  # For 7z archives
import rarfile  # For RAR archives
import psutil  # For process monitoring

# Try to import pefile for PE analysis
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False
    logging.warning("pefile not available. PE import analysis disabled.")

# Import our AI analysis module
try:
    from ai.mistral_analysis import analyze_text
    AI_AVAILABLE = True
except ImportError:
    analyze_text = None
    AI_AVAILABLE = False
    logging.warning("AI modules not available. Limited functionality.")

# Import our registry scanner for verification
try:
    from registry.registry_scanner import RegistryScanner
    REGISTRY_SCANNER_AVAILABLE = True
except ImportError:
    RegistryScanner = None
    REGISTRY_SCANNER_AVAILABLE = False
    logging.warning("Registry scanner not available. Registry verification disabled.")

# Import our logger
from utils.logger import log_event

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FileMetadata:
    """Metadata extracted from a file"""
    filename: str
    file_type: str
    size: int
    entropy: float
    extensions: List[str]
    embedded_urls: List[str]
    script_patterns: List[str]
    suspicious_indicators: List[str]
    # New fields for enhanced analysis
    human_readable_strings: List[str]  # Suspicious strings found in binary files
    pe_imports: List[str]  # PE import functions (for PE files)
    capabilities: List[str]  # High-level capabilities derived from imports
    pe_analysis_failed: bool = False  # Track if PE analysis failed

@dataclass
class StructuredHypothesis:
    """Structured hypothesis for verification"""
    type: str  # "registry", "process", "file", "network"
    value: str  # The specific artifact to check
    path: Optional[str] = None  # For registry keys
    confidence: float = 0.0  # Confidence in this hypothesis

@dataclass
class ArchiveAnalysisResult:
    """Complete analysis result for an archive"""
    scan_id: str
    timestamp: float
    timestamp_iso: str
    archive_path: str
    file_count: int
    extracted_metadata: List[FileMetadata]
    ai_assessment: Dict[str, Any]
    hypothesis_checks: List[Dict[str, Any]]
    overall_risk_score: float
    final_recommendation: str

class AdvancedArchiveScanner:
    """Advanced triage scanner with AI-based threat analysis for archive files.
    
    This scanner performs static analysis of archive contents and uses AI to predict
    potential security threats. It then verifies if any of the predicted indicators
    of compromise (IOCs) are already present on the system.
    
    MAIN LIMITATION (BY DESIGN): This is a static verification tool, not a dynamic 
    behavior monitor. It only checks for the current presence of predicted IOCs, not 
    future actions that would occur if the files were executed. If an AI hypothesis 
    predicts that a file "will create C:\\malware.exe", this tool only checks if 
    C:\\malware.exe already exists. If it doesn't, the hypothesis is marked "NOT FOUND," 
    even if the AI's prediction about the file's intent is correct.
    
    For dynamic behavior analysis and future action prediction, integration with a 
    sandbox environment would be required. This tool is designed as a static triage 
    system for initial threat assessment only.
    
    WHY FALSE POSITIVES CAN STILL HAPPEN:
    
    AI Misinterpretation (Most Likely Cause):
    - Stage 1 Error: The _analyze_file_individually AI is the first line of defense. 
      An unusual but benign file (e.g., a legitimate software installer using custom 
      packing, a data file with naturally high entropy, heavily obfuscated but safe 
      JavaScript) might confuse the AI. Despite the prompt's guardrails ("don't flag 
      just for high entropy"), the AI might still incorrectly assign a suspicion_score 
      above your threshold (e.g., 0.7).
    - Stage 2 Error: If an innocent file mistakenly gets passed to the _analyze_with_ai 
      stage, the second AI might also misinterpret it, especially if it appears alongside 
      other borderline files. It might see a "suspicious combination" that isn't actually 
      malicious.
    
    Benign Files Resembling Malware:
    Some legitimate software uses techniques common in malware (like packing for 
    protection, code obfuscation, or even functions like SetWindowsHookEx for legitimate 
    purposes like keyboard macro tools). The AI, trained on identifying malicious 
    patterns, might struggle to differentiate these benign edge cases without more context.
    
    Limitations of Static Analysis Data:
    While helpful, strings and imports only show potential capabilities and clues. 
    An innocent file might contain a suspicious string by coincidence or import a 
    function for a benign reason. The AI tries to look at the combination, but can 
    still make mistakes.
    
    Threshold Sensitivity:
    The suspicion_threshold (default 0.6) is a balancing act. If you set it too low 
    to catch more threats, you inevitably increase the risk of letting borderline 
    benign files pass through to the final analysis, raising the chance of a false positive.
    
    HOW THE SCRIPT TRIES TO PREVENT FALSE POSITIVES:
    - Two-Stage Filter: Most benign files should get a low score in Stage 1 and be 
      filtered out.
    - Prompt Engineering: The prompts explicitly tell the AI not to overreact to single 
      indicators like entropy and to look for malicious combinations.
    - Focus on Suspicious Files: The final AI (Stage 2) only sees files that already 
      looked suspicious, reducing the noise from obviously benign files.
    
    IN SUMMARY:
    The script is designed to be much better at avoiding false positives than simpler 
    methods. However, the reliance on AI judgment means perfection isn't guaranteed. 
    Unusual but legitimate files are the most likely candidates to be occasionally 
    misclassified.
    """
    
    def __init__(self, suspicion_threshold: float = 0.6, confidence_threshold: float = 0.7, ai_voting_rounds: int = 3):
        self.scan_id = self._generate_scan_id()
        self.timestamp = time.time()
        self.timestamp_iso = datetime.fromtimestamp(self.timestamp).isoformat()
        self.extracted_files_dir = None
        self.lock = threading.Lock()
        self.suspicion_threshold = suspicion_threshold  # Configurable threshold for Stage 2 analysis
        self.confidence_threshold = confidence_threshold  # Confidence threshold for hypothesis verification
        self.ai_voting_rounds = ai_voting_rounds  # Number of AI analyses for voting consensus
        self.analysis_history = []  # Track analysis results for consistency checking
        self.adaptive_thresholds = {}  # Store adaptive thresholds for different file types
        
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID"""
        return hashlib.sha256(f"{time.time()}_{os.getpid()}".encode()).hexdigest()[:16]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate the entropy of a byte sequence using Shannon entropy formula"""
        if not data:
            return 0.0
            
        # Count frequency of each byte
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
            
        # Calculate Shannon entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
            
        # Normalize to 0-1 range (max entropy for 256 symbols is 8)
        return entropy / 8.0 if entropy > 0 else 0.0
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from content"""
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = re.findall(url_pattern, content)
        return list(set(urls))  # Remove duplicates
    
    def _detect_script_patterns(self, content: str) -> List[str]:
        """Detect script patterns in content using AI analysis.
        
        This function uses the Mistral AI to analyze the content and identify
        potential script patterns that might suggest script-like behavior.
        
        Args:
            content: The content to analyze
            
        Returns:
            List of detected script pattern indicators
        """
        # Only analyze if AI is available and content is substantial
        if not AI_AVAILABLE or not analyze_text or len(content) < 50:
            return []
            
        # Limit content to prevent prompt overflow
        limited_content = content[:5000]
        
        # Create AI prompt for script pattern detection
        prompt = f"""
Analyze the following content and determine if it contains patterns indicative of scripting languages.

Content to analyze:
{limited_content}

Instructions:
1. Look for characteristics that suggest this content might be executable script code
2. Identify structural patterns typical of scripting languages (PowerShell, Python, JavaScript, etc.)
3. Check for command execution patterns, control flow structures, and variable manipulations
4. Identify any obfuscation or encoding techniques that might indicate malicious scripting
5. Do not simply flag content based on individual keywords
6. Focus on structural and contextual patterns that suggest scripting behavior
7. If you identify script patterns, provide specific indicators as a list

Respond with a JSON object containing only a "script_patterns" array with specific indicators, like:
{{
    "script_patterns": ["PowerShell cmdlet structure detected", "Base64 encoded command patterns"]
}}

If no script patterns are detected, return an empty array:
{{
    "script_patterns": []
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
                    import json
                    result = json.loads(json_str)
                    return result.get("script_patterns", [])
            elif isinstance(response, dict):
                return response.get("script_patterns", [])
        except Exception as e:
            log_event("SCRIPT_PATTERN_AI_ERROR", f"AI analysis failed for script patterns: {e}")
            
        return []
    
    def _deobfuscate_strings(self, strings: List[str]) -> List[str]:
        """Attempt advanced deobfuscation of strings commonly used in malware with AI pattern recognition.
        
        Args:
            strings: List of strings to deobfuscate
            
        Returns:
            List of potentially deobfuscated strings
        """
        deobfuscated = []
        
        # Import base64 at the method level to ensure it's available
        import base64
        
        for s in strings:
            # Try base64 decoding
            try:
                # Check if string looks like base64
                if len(s) > 8 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
                    decoded = base64.b64decode(s)
                    # Check if result is readable
                    if all(c < 127 and (chr(c).isprintable() or chr(c).isspace()) for c in decoded):
                        deobfuscated.append(decoded.decode('utf-8', errors='ignore'))
            except:
                pass
            
            # Try hex decoding
            try:
                if len(s) > 4 and re.match(r'^[0-9a-fA-F]+$', s) and len(s) % 2 == 0:
                    decoded = bytes.fromhex(s)
                    # Check if result is readable
                    if all(c < 127 and (chr(c).isprintable() or chr(c).isspace()) for c in decoded):
                        deobfuscated.append(decoded.decode('utf-8', errors='ignore'))
            except:
                pass
            
            # Try simple XOR decoding (common key: 0x55)
            try:
                if len(s) > 4:
                    decoded = ''.join(chr(ord(c) ^ 0x55) for c in s)
                    # Check if result is readable
                    if all(c.isprintable() or c.isspace() for c in decoded):
                        deobfuscated.append(decoded)
            except:
                pass
            
            # Try ROT13 decoding
            try:
                if len(s) > 4:
                    decoded = ''.join(chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if 'A' <= c <= 'Z' else 
                                     chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if 'a' <= c <= 'z' else c for c in s)
                    # Check if result has suspicious patterns
                    if any(susp in decoded.lower() for susp in ['http', 'cmd', 'powershell', 'script', 'download']):
                        deobfuscated.append(decoded)
            except:
                pass
            
            # Try detecting and reversing simple string reversal obfuscation
            try:
                if len(s) > 4:
                    reversed_s = s[::-1]
                    # Check if reversed string has suspicious patterns
                    if any(susp in reversed_s.lower() for susp in ['http', 'cmd', 'powershell', 'script', 'download']):
                        deobfuscated.append(reversed_s)
            except:
                pass
            
            # Try detecting multi-layer obfuscation (base64 + xor)
            try:
                if len(s) > 8 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
                    # First decode base64
                    import base64
                    intermediate = base64.b64decode(s)
                    # Then try XOR decoding
                    if all(c < 256 for c in intermediate):
                        decoded = bytes([c ^ 0x55 for c in intermediate])
                        # Check if result is readable
                        if all(c < 127 and (chr(c).isprintable() or chr(c).isspace()) for c in decoded):
                            result = decoded.decode('utf-8', errors='ignore')
                            if any(susp in result.lower() for susp in ['http', 'cmd', 'powershell', 'script', 'download']):
                                deobfuscated.append(result)
            except:
                pass
        
        return deobfuscated
    
    def _fallback_pe_analysis(self, file_path: str) -> List[str]:
        """Enhanced fallback PE analysis using AI analysis of file characteristics.
        
        This function uses the Mistral AI to analyze PE file characteristics
        to identify potential security concerns without relying on specific hardcoded patterns.
        
        Args:
            file_path: Path to the PE file to analyze
            
        Returns:
            List of identified security concerns
        """
        # Only analyze if AI is available
        if not AI_AVAILABLE or not analyze_text:
            return []
            
        try:
            with open(file_path, 'rb') as f:
                # Read more of the file for better analysis
                data = f.read(8192)  # Read first 8KB
            
            # Convert binary data to hex for AI analysis
            hex_data = data.hex()
            
            # Limit hex data to prevent prompt overflow
            limited_hex_data = hex_data[:10000]  # First 5KB of hex data
            
            # Create AI prompt for PE analysis
            prompt = f"""
Analyze the following hexadecimal representation of a PE file to identify potential security concerns.

File path: {file_path}
Hex data (first 5KB):
{limited_hex_data}

Instructions:
1. Look for characteristics that suggest this PE file might be malicious
2. Identify structural patterns, obfuscation techniques, or suspicious behaviors
3. Check for packing, injection capabilities, network communication patterns
4. Analyze section characteristics and potential code execution capabilities
5. Do not simply flag content based on individual bytes or offsets
6. Focus on structural and contextual patterns that suggest malicious intent
7. If you identify security concerns, provide specific indicators as a list

Respond with a JSON object containing only a "pe_indicators" array with specific indicators, like:
{{
    "pe_indicators": ["Packed executable detected", "Suspicious section characteristics"]
}}

If no security concerns are detected, return an empty array:
{{
    "pe_indicators": []
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
                        import json
                        result = json.loads(json_str)
                        return result.get("pe_indicators", [])
                elif isinstance(response, dict):
                    return response.get("pe_indicators", [])
            except Exception as e:
                log_event("PE_ANALYSIS_AI_ERROR", f"AI analysis failed for PE analysis: {e}")
                
        except Exception as e:
            log_event("FALLBACK_PE_ANALYSIS_ERROR", f"Fallback PE analysis failed for {file_path}: {e}")
            
        return []
    
    def _detect_suspicious_indicators(self, content: str, filename: str) -> List[str]:
        """Detect suspicious indicators in content and filename using AI analysis.
        
        This function uses the Mistral AI to analyze the content and filename to identify
        potential suspicious indicators that might suggest malicious intent.
        
        Args:
            content: The content to analyze
            filename: The name of the file being analyzed
            
        Returns:
            List of detected suspicious indicators
        """
        # Only analyze if AI is available and content is substantial
        if not AI_AVAILABLE or not analyze_text or len(content) < 50:
            return []
            
        # Limit content to prevent prompt overflow
        limited_content = content[:5000]
        
        # Create AI prompt for suspicious indicator detection
        prompt = f"""
Analyze the following file content and filename to identify potential suspicious indicators.

Filename: {filename}
Content to analyze:
{limited_content}

Instructions:
1. Look for characteristics that suggest this content might be malicious
2. Identify structural patterns, obfuscation techniques, or suspicious behaviors
3. Check for command execution patterns, persistence mechanisms, and data exfiltration attempts
4. Analyze the filename for suspicious naming conventions or structures
5. Do not simply flag content based on individual keywords
6. Focus on structural and contextual patterns that suggest malicious intent
7. If you identify suspicious indicators, provide specific indicators as a list

Respond with a JSON object containing only a "suspicious_indicators" array with specific indicators, like:
{{
    "suspicious_indicators": ["Obfuscated PowerShell command detected", "Suspicious registry persistence pattern"]
}}

If no suspicious indicators are detected, return an empty array:
{{
    "suspicious_indicators": []
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
                    import json
                    result = json.loads(json_str)
                    return result.get("suspicious_indicators", [])
            elif isinstance(response, dict):
                return response.get("suspicious_indicators", [])
        except Exception as e:
            log_event("SUSPICIOUS_INDICATORS_AI_ERROR", f"AI analysis failed for suspicious indicators: {e}")
            
        return []
    
    def _extract_readable_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract human-readable ASCII strings from a binary file with deobfuscation.
        
        
        Args:
            file_path: Path to the file to analyze
            min_length: Minimum length of strings to extract
            
        Returns:
            List of human-readable strings found in the file
        """
        strings = []
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Extract ASCII strings
            ascii_strings = re.findall(b'[\x20-\x7e]{%d,}' % min_length, data)
            strings.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])
            
            # Extract Unicode strings
            unicode_strings = re.findall(b'(?:[\x20-\x7e]\x00){%d,}' % min_length, data)
            strings.extend([s.decode('utf-16le', errors='ignore') for s in unicode_strings])
            
            # Basic deobfuscation attempts
            deobfuscated_strings = self._deobfuscate_strings(strings)
            strings.extend(deobfuscated_strings)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_strings = []
            for s in strings:
                if s not in seen:
                    seen.add(s)
                    unique_strings.append(s)
            
            # Instead of hardcoded suspicious patterns, we'll let the AI determine what's suspicious
            # Return all strings (up to a limit) for AI analysis
            return unique_strings[:300]  # Increased limit for better coverage
        except Exception as e:
            log_event("STRING_EXTRACTION_ERROR", f"Failed to extract strings from {file_path}: {e}")
            return []

    def _analyze_pe_imports(self, file_path: str) -> Tuple[List[str], List[str]]:
        """Analyze PE imports to determine capabilities (the "toolbox") with fallback methods.
        
        This technique analyzes what functions a PE file imports to understand
        what it's built to do at a fundamental level. Includes fallback analysis.
        
        Args:
            file_path: Path to the PE file to analyze
            
        Returns:
            Tuple of (all_imports, capabilities) where:
                all_imports: List of all imported functions
                capabilities: High-level capabilities derived from imports through AI analysis
        """
        if not PEFILE_AVAILABLE or not pefile:
            # Fallback: Try basic header analysis
            return self._fallback_pe_analysis(file_path), []
            
        try:
            # Check if this is a PE file
            if not file_path.lower().endswith(('.exe', '.dll', '.sys', '.ocx')):
                return [], []
                
            pe = pefile.PE(file_path)
            imports = []
            
            # Extract imports
            # Use getattr to safely access DIRECTORY_ENTRY_IMPORT to avoid type checking issues
            directory_entry = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None)
            if directory_entry is not None:
                for entry in directory_entry:
                    if hasattr(entry, 'imports'):
                        for imp in entry.imports:
                            if imp.name:
                                try:
                                    imports.append(imp.name.decode('utf-8', errors='ignore'))
                                except Exception:
                                    pass  # Ignore decoding errors for individual imports
            
            # Instead of hardcoded capability detection, we'll let the AI determine capabilities
            # based on the imports in the _analyze_file_individually method
            # Return empty capabilities list to be filled by AI analysis
            return imports[:300], []  # Increased limit for better AI context
        except pefile.PEFormatError as e:
            log_event("PE_FORMAT_ERROR", f"Invalid PE format for {file_path}: {e}")
            # Fallback analysis
            return self._fallback_pe_analysis(file_path), []
        except MemoryError as e:
            log_event("PE_MEMORY_ERROR", f"Memory error analyzing PE imports for {file_path}: {e}")
            return [], []
        except Exception as e:
            log_event("PE_ANALYSIS_ERROR", f"Failed to analyze PE imports for {file_path}: {e}")
            # Fallback analysis
            return self._fallback_pe_analysis(file_path), []

    def _extract_file_metadata(self, file_path: str) -> FileMetadata:
        """Extract metadata from a file"""
        try:
            # Get basic file info
            stat = os.stat(file_path)
            size = stat.st_size
            
            # Determine file type
            file_type = magic.from_file(file_path, mime=True)
            
            # Get file extensions
            extensions = []
            name = os.path.basename(file_path)
            parts = name.split('.')
            if len(parts) > 1:
                extensions = [f".{ext}" for ext in parts[1:]]
            
            # Read file content for analysis (limit to prevent memory issues)
            content = ""
            embedded_urls = []
            script_patterns = []
            suspicious_indicators = []
            
            # Only analyze text-based files
            text_types = ['text/', 'application/json', 'application/xml', 'application/javascript']
            if any(file_type.startswith(t) for t in text_types) and size < 10*1024*1024:  # 10MB limit
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(100000)  # Read first 100KB
                    
                # Analyze content
                embedded_urls = self._extract_urls(content)
                script_patterns = self._detect_script_patterns(content)
                suspicious_indicators = self._detect_suspicious_indicators(content, name)
            
            # Calculate entropy for binary files
            entropy = 0.0
            if size > 0 and size < 10*1024*1024:  # 10MB limit
                with open(file_path, 'rb') as f:
                    data = f.read(10000)  # Read first 10KB for entropy calculation
                    entropy = self._calculate_entropy(data)
            
            # Extract additional information for enhanced analysis
            human_readable_strings = []
            pe_imports = []
            capabilities = []  # Will be determined by AI in _analyze_file_individually
            pe_analysis_failed = False  # Track if PE analysis failed
            
            # Only analyze binary files for strings and PE imports
            binary_types = ['application/x-dosexec', 'application/x-executable', 'application/octet-stream']
            if any(file_type.startswith(t) for t in binary_types) and size < 20*1024*1024:  # 20MB limit
                # Extract human-readable strings
                human_readable_strings = self._extract_readable_strings(file_path)
                
                # Analyze PE imports if it's a PE file
                try:
                    pe_imports, capabilities = self._analyze_pe_imports(file_path)
                except Exception as e:
                    log_event("PE_ANALYSIS_FAILURE", f"PE analysis failed for {file_path}: {e}")
                    pe_analysis_failed = True
            
            return FileMetadata(
                filename=name,
                file_type=file_type,
                size=size,
                entropy=entropy,
                extensions=extensions,
                embedded_urls=embedded_urls,
                script_patterns=script_patterns,
                suspicious_indicators=suspicious_indicators,
                human_readable_strings=human_readable_strings,
                pe_imports=pe_imports,
                capabilities=capabilities,
                pe_analysis_failed=pe_analysis_failed
            )
        except Exception as e:
            log_event("METADATA_EXTRACTION_ERROR", f"Failed to extract metadata from {file_path}: {e}")
            return FileMetadata(
                filename=os.path.basename(file_path),
                file_type="unknown",
                size=0,
                entropy=0.0,
                extensions=[],
                embedded_urls=[],
                script_patterns=[],
                suspicious_indicators=[f"Extraction error: {str(e)}"],
                human_readable_strings=[],  # Add missing parameter
                pe_imports=[],              # Add missing parameter
                capabilities=[],            # Add missing parameter
                pe_analysis_failed=True     # Mark as failed due to extraction error
            )
    
    def _extract_archive(self, archive_path: str) -> str:
        """Extract archive to temporary directory"""
        temp_dir = tempfile.mkdtemp(prefix="archive_scan_")
        
        try:
            # Determine archive type by extension
            ext = os.path.splitext(archive_path)[1].lower()
            
            if ext == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            elif ext in ['.tar', '.gz', '.bz2', '.xz']:
                with tarfile.open(archive_path, 'r') as tar_ref:
                    tar_ref.extractall(temp_dir)
            elif ext == '.7z':
                with py7zr.SevenZipFile(archive_path, mode='r') as z7_ref:
                    z7_ref.extractall(temp_dir)
            elif ext == '.rar':
                with rarfile.RarFile(archive_path, 'r') as rar_ref:
                    rar_ref.extractall(temp_dir)
            else:
                # Try to detect by magic number
                mime_type = magic.from_file(archive_path, mime=True)
                if 'zip' in mime_type:
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                elif 'tar' in mime_type:
                    with tarfile.open(archive_path, 'r') as tar_ref:
                        tar_ref.extractall(temp_dir)
                else:
                    log_event("UNSUPPORTED_ARCHIVE", f"Unsupported archive type: {archive_path}")
                    raise ValueError(f"Unsupported archive type: {archive_path}")
                    
            return temp_dir
        except Exception as e:
            log_event("ARCHIVE_EXTRACTION_ERROR", f"Failed to extract archive {archive_path}: {e}")
            # Clean up temp directory on error
            try:
                import shutil
                shutil.rmtree(temp_dir)
            except:
                pass
            raise
    
    def _walk_extracted_files(self, directory: str) -> List[str]:
        """Walk through extracted files and return all file paths"""
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_paths.append(os.path.join(root, file))
        return file_paths
    
    def _calculate_adaptive_thresholds(self, metadata: FileMetadata) -> Dict[str, float]:
        """Calculate adaptive thresholds based on file characteristics.
        
        Args:
            metadata: File metadata
            
        Returns:
            Dictionary containing adaptive thresholds
        """
        thresholds = {
            "suspicion_threshold": self.suspicion_threshold,
            "confidence_threshold": self.confidence_threshold
        }
        
        try:
            # Adjust thresholds based on file type
            if 'application/x-dosexec' in metadata.file_type:
                # PE files are more likely to be malicious, so lower thresholds
                thresholds["suspicion_threshold"] = max(0.4, self.suspicion_threshold * 0.8)
                thresholds["confidence_threshold"] = max(0.5, self.confidence_threshold * 0.9)
            elif 'text/' in metadata.file_type:
                # Text files are less likely to be directly malicious, so higher thresholds
                thresholds["suspicion_threshold"] = min(0.8, self.suspicion_threshold * 1.2)
                thresholds["confidence_threshold"] = min(0.9, self.confidence_threshold * 1.1)
            
            # Adjust based on file size
            if metadata.size > 10 * 1024 * 1024:  # 10MB
                # Large files might be less suspicious, raise threshold
                thresholds["suspicion_threshold"] = min(0.8, thresholds["suspicion_threshold"] * 1.1)
            elif metadata.size < 1024:  # 1KB
                # Very small files might be more suspicious, lower threshold
                thresholds["suspicion_threshold"] = max(0.4, thresholds["suspicion_threshold"] * 0.9)
            
            # Adjust based on entropy
            if metadata.entropy > 0.9:
                # High entropy files are more suspicious, lower threshold
                thresholds["suspicion_threshold"] = max(0.4, thresholds["suspicion_threshold"] * 0.8)
            elif metadata.entropy < 0.3:
                # Low entropy files are less suspicious, raise threshold
                thresholds["suspicion_threshold"] = min(0.8, thresholds["suspicion_threshold"] * 1.1)
                
        except Exception as e:
            log_event("ADAPTIVE_THRESHOLD_ERROR", f"Failed to calculate adaptive thresholds: {e}")
            # Fall back to default thresholds
            thresholds = {
                "suspicion_threshold": self.suspicion_threshold,
                "confidence_threshold": self.confidence_threshold
            }
        
        return thresholds
    
    def _analyze_file_individually(self, metadata: FileMetadata) -> Dict[str, Any]:
        """Analyze a single file's metadata with AI for suspicion score using voting consensus."""
        if not AI_AVAILABLE or analyze_text is None:
            return {
                "suspicion_score": 0.5,
                "confidence": 0.3,
                "indicators": [],
                "reasoning": "AI analysis not available"
            }
        
        # Create a comprehensive summary of the file metadata
        summary = f"File: {metadata.filename}\n"
        summary += f"  Type: {metadata.file_type}\n"
        summary += f"  Size: {metadata.size} bytes\n"
        summary += f"  Entropy: {metadata.entropy:.2f}\n"
        if metadata.extensions:
            summary += f"  Extensions: {', '.join(metadata.extensions)}\n"
        if metadata.embedded_urls:
            summary += f"  URLs: {', '.join(metadata.embedded_urls[:5])}\n"  # Limit to first 5
        if metadata.script_patterns:
            summary += f"  Script patterns: {', '.join(metadata.script_patterns)}\n"
        if metadata.suspicious_indicators:
            summary += f"  Suspicious indicators: {', '.join(metadata.suspicious_indicators)}\n"
        if metadata.human_readable_strings:
            summary += f"  Readable strings: {', '.join(metadata.human_readable_strings[:50])}\n"  # Show first 50 strings
        if metadata.pe_imports:
            summary += f"  PE Imports: {', '.join(metadata.pe_imports[:100])}\n"  # Increased to first 100 for better context
        if metadata.pe_analysis_failed:
            summary += f"  PE Analysis: FAILED - Import data may be incomplete\n"
        
        # Create the enhanced AI prompt for individual file analysis with behavioral prediction
        prompt = f"""
You are a security expert AI analyst. Your task is to analyze the following file metadata 
and determine if it represents a security threat. Focus on combinations of indicators 
rather than individual suspicious elements. Predict potential behaviors based on code patterns.

File Metadata:
{summary}

Instructions:
1. Do NOT flag files just for high entropy. Benign installers and packers also have high entropy.
2. Look for combinations of indicators that suggest malicious intent:
   - High entropy + Suspicious strings = Likely obfuscated malware
   - Specific capabilities + Network functions = Likely C2 malware
   - Process injection capabilities + File manipulation = Likely infostealer
3. Based on the PE imports, determine what capabilities this file might have. Some examples:
   - Process injection: CreateRemoteThread, WriteProcessMemory, VirtualAlloc
   - Keylogging: SetWindowsHookEx, CallNextHookEx
   - Network communication: socket, connect, send, recv, InternetOpen
   - File manipulation: CreateFile, WriteFile, DeleteFile
   - Registry manipulation: RegSetValue, RegCreateKey, RegDeleteKey
   - Anti-debugging: IsDebuggerPresent, OutputDebugString
4. Analyze the readable strings for suspicious patterns such as:
   - PowerShell commands and encoded scripts
   - Network activity indicators (URLs, IP addresses)
   - Process injection APIs
   - Registry manipulation commands
   - File operation commands
   - Encoded or obfuscated commands
   - Suspicious API calls
5. Predict potential execution flows based on the combination of capabilities:
   - If the file has network and file APIs, it might download and execute additional payloads
   - If the file has process injection and network APIs, it might inject a C2 agent into another process
   - If the file has registry and file APIs, it might establish persistence
   - If the file has keylogging and network APIs, it might exfiltrate keystrokes
6. Explain your reasoning step-by-step before giving your final assessment.
7. Provide a suspicion score from 0.0 (benign) to 1.0 (malicious).
8. Provide a confidence score from 0.0 (low confidence) to 1.0 (high confidence) in your assessment.
9. List specific indicators that contributed to your assessment.
10. Identify capabilities based on the imports provided.
11. Predict potential behaviors the file might exhibit if executed.

IMPORTANT: Only flag files as suspicious if there are clear malicious indicators. 
Do not make assumptions based on single factors. Always look for combinations of suspicious elements.
If the file appears to be legitimate software, rate it as benign (0.0-0.3).

Respond with a JSON object containing:
{{
    "suspicion_score": 0.85,
    "confidence": 0.9,
    "indicators": ["High entropy", "Process Injection", "HTTP Communication"],
    "capabilities": ["Process Injection", "Network Communication"],
    "predicted_behaviors": ["Download additional payload", "Inject C2 agent"],
    "reasoning": "Step 1: The file has high entropy (7.9) suggesting obfuscation. Step 2: It imports CreateRemoteThread and WriteProcessMemory indicating process injection capability. Step 3: It imports InternetOpen suggesting network communication. Step 4: The combination suggests it might download and inject a C2 agent. The combination of obfuscation, injection capability, and network communication strongly indicates malicious intent."
}}

Example response for a legitimate file:
{{
    "suspicion_score": 0.1,
    "confidence": 0.95,
    "indicators": ["Normal entropy", "Standard imports"],
    "capabilities": ["File operations"],
    "predicted_behaviors": ["Read configuration files"],
    "reasoning": "Step 1: The file has normal entropy (4.2) which is typical for legitimate software. Step 2: It imports standard functions like CreateFile and ReadFile which are common in legitimate applications. Step 3: No suspicious strings or URLs found. This appears to be a normal application that reads configuration files."
}}

Example response for a suspicious file:
{{
    "suspicion_score": 0.85,
    "confidence": 0.9,
    "indicators": ["High entropy", "Process Injection", "HTTP Communication"],
    "capabilities": ["Process Injection", "Network Communication"],
    "predicted_behaviors": ["Download additional payload", "Inject C2 agent"],
    "reasoning": "Step 1: The file has high entropy (7.9) suggesting obfuscation. Step 2: It imports CreateRemoteThread and WriteProcessMemory indicating process injection capability. Step 3: It imports InternetOpen suggesting network communication. Step 4: The combination suggests it might download and inject a C2 agent. The combination of obfuscation, injection capability, and network communication strongly indicates malicious intent."
}}
"""
        
        # Use enhanced voting consensus with confidence calibration for more reliable AI analysis
        analysis_results = []
        
        for i in range(self.ai_voting_rounds):
            try:
                response = analyze_text(prompt)
                
                # Try to parse the response as JSON
                if isinstance(response, str):
                    # Extract JSON from the response
                    json_start = response.find('{')
                    json_end = response.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = response[json_start:json_end]
                        result = json.loads(json_str)
                        analysis_results.append(result)
                elif isinstance(response, dict):
                    analysis_results.append(response)
            except Exception as e:
                log_event("AI_FILE_ANALYSIS_ERROR", f"AI analysis round {i+1} failed for file {metadata.filename}: {e}")
                # Add a default result for voting
                analysis_results.append({
                    "suspicion_score": 0.5,
                    "confidence": 0.3,
                    "indicators": [],
                    "capabilities": [],
                    "reasoning": f"AI analysis round {i+1} failed: {str(e)}"
                })
        
        # Calculate consensus result with confidence calibration
        if analysis_results:
            # Filter out low confidence results (below 0.2)
            high_confidence_results = [r for r in analysis_results if r.get("confidence", 0.0) >= 0.2]
            
            # If we don't have enough high confidence results, use all results
            if len(high_confidence_results) < max(1, len(analysis_results) // 2):
                high_confidence_results = analysis_results
            
            # Calculate weighted average scores based on confidence
            total_weight = sum(r.get("confidence", 0.3) for r in high_confidence_results)
            if total_weight > 0:
                avg_suspicion = sum(r.get("suspicion_score", 0.5) * r.get("confidence", 0.3) for r in high_confidence_results) / total_weight
                avg_confidence = sum(r.get("confidence", 0.3) ** 2 for r in high_confidence_results) / total_weight  # Square to emphasize high confidence
            else:
                avg_suspicion = sum(r.get("suspicion_score", 0.5) for r in high_confidence_results) / len(high_confidence_results) if high_confidence_results else 0.5
                avg_confidence = sum(r.get("confidence", 0.3) for r in high_confidence_results) / len(high_confidence_results) if high_confidence_results else 0.3
            
            # Combine indicators and capabilities (remove duplicates)
            all_indicators = []
            all_capabilities = []
            all_behaviors = []
            reasonings = []
            
            for result in high_confidence_results:
                all_indicators.extend(result.get("indicators", []))
                all_capabilities.extend(result.get("capabilities", []))
                all_behaviors.extend(result.get("predicted_behaviors", []))
                if "reasoning" in result:
                    reasonings.append(result["reasoning"])
            
            # Remove duplicates and keep most frequent items
            from collections import Counter
            indicator_counts = Counter(all_indicators)
            capability_counts = Counter(all_capabilities)
            behavior_counts = Counter(all_behaviors)
            
            # Only include items that appear in more than half of the analyses
            threshold = len(high_confidence_results) // 2
            unique_indicators = [item for item, count in indicator_counts.items() if count > threshold]
            unique_capabilities = [item for item, count in capability_counts.items() if count > threshold]
            unique_behaviors = [item for item, count in behavior_counts.items() if count > threshold]
            
            # If no items meet the threshold, include all unique items
            if not unique_indicators:
                unique_indicators = list(set(all_indicators))
            if not unique_capabilities:
                unique_capabilities = list(set(all_capabilities))
            if not unique_behaviors:
                unique_behaviors = list(set(all_behaviors))
            
            # Create consensus result
            consensus_result = {
                "suspicion_score": avg_suspicion,
                "confidence": avg_confidence,
                "indicators": unique_indicators,
                "capabilities": unique_capabilities,
                "predicted_behaviors": unique_behaviors,
                "reasoning": f"Consensus from {len(high_confidence_results)} high-confidence AI analyses out of {len(analysis_results)} total. Individual reasonings: " + "; ".join(reasonings[:3])  # Limit reasonings for brevity
            }
            
            # Add to analysis history for consistency checking
            self.analysis_history.append({
                "filename": metadata.filename,
                "result": consensus_result,
                "individual_results": analysis_results
            })
            
            return consensus_result
        else:
            log_event("AI_FILE_ANALYSIS_ERROR", f"All AI analysis rounds failed for file {metadata.filename}")
            return {
                "suspicion_score": 0.5,
                "confidence": 0.3,
                "indicators": [],
                "capabilities": [],
                "predicted_behaviors": [],
                "reasoning": "All AI analysis rounds failed"
            }
    
    def _analyze_with_ai(self, metadata_list: List[FileMetadata]) -> Dict[str, Any]:
        """Use AI to analyze the extracted metadata with a scalable approach"""
        if not AI_AVAILABLE or analyze_text is None:
            return {
                "risk_score": 0.5,
                "reasoning": "AI analysis not available",
                "hypotheses": [],
                "confidence": 0.0
            }
        
        # Stage 1: Analyze files individually for suspicion scores
        suspicious_files = []
        for metadata in metadata_list:
            # Calculate adaptive thresholds for this file
            adaptive_thresholds = self._calculate_adaptive_thresholds(metadata)
            
            file_analysis = self._analyze_file_individually(metadata)
            suspicion_score = file_analysis.get("suspicion_score", 0.5)
            confidence = file_analysis.get("confidence", 0.5)
            
            # Only include files with high suspicion scores AND high confidence for further analysis
            # Use adaptive thresholds
            if suspicion_score >= adaptive_thresholds["suspicion_threshold"] and confidence >= adaptive_thresholds["confidence_threshold"]:
                suspicious_files.append({
                    "metadata": metadata,
                    "analysis": file_analysis,
                    "adaptive_thresholds": adaptive_thresholds
                })
        
        # If no suspicious files, return safe result
        if not suspicious_files:
            return {
                "risk_score": 0.1,
                "reasoning": "No suspicious files found in initial analysis",
                "hypotheses": [],
                "confidence": 0.9
            }
        
        # Limit to top suspicious files to prevent prompt overflow
        suspicious_files = sorted(suspicious_files, 
                                key=lambda x: x["analysis"].get("suspicion_score", 0) * x["analysis"].get("confidence", 0), 
                                reverse=True)[:50]  # Limit to top 50 files based on suspicion * confidence
        
        # Create a comprehensive summary of suspicious files
        summary_parts = []
        for item in suspicious_files:
            metadata = item["metadata"]
            analysis = item["analysis"]
            adaptive_thresholds = item.get("adaptive_thresholds", {})
            part = f"File: {metadata.filename}\n"
            part += f"  Suspicion Score: {analysis.get('suspicion_score', 0.0):.2f}\n"
            part += f"  Confidence: {analysis.get('confidence', 0.0):.2f}\n"
            part += f"  Type: {metadata.file_type}\n"
            part += f"  Size: {metadata.size} bytes\n"
            part += f"  Entropy: {metadata.entropy:.2f}\n"
            if adaptive_thresholds:
                part += f"  Adaptive Thresholds: Suspicion={adaptive_thresholds.get('suspicion_threshold', self.suspicion_threshold):.2f}, Confidence={adaptive_thresholds.get('confidence_threshold', self.confidence_threshold):.2f}\n"
            if metadata.extensions:
                part += f"  Extensions: {', '.join(metadata.extensions)}\n"
            if metadata.embedded_urls:
                part += f"  URLs: {', '.join(metadata.embedded_urls[:5])}\n"
            if metadata.script_patterns:
                part += f"  Script patterns: {', '.join(metadata.script_patterns)}\n"
            if metadata.suspicious_indicators:
                part += f"  Suspicious indicators: {', '.join(metadata.suspicious_indicators)}\n"
            if metadata.human_readable_strings:
                part += f"  Suspicious strings: {', '.join(metadata.human_readable_strings[:20])}\n"  # Increased to first 20
            if metadata.capabilities:
                part += f"  Capabilities: {', '.join(metadata.capabilities)}\n"
            if metadata.pe_imports:
                part += f"  Key imports: {', '.join(metadata.pe_imports[:50])}\n"  # Increased to first 50
            if metadata.pe_analysis_failed:
                part += f"  PE Analysis: FAILED - Import data may be incomplete\n"
            part += f"  Indicators: {', '.join(analysis.get('indicators', []))}\n"
            if analysis.get('predicted_behaviors'):
                part += f"  Predicted Behaviors: {', '.join(analysis.get('predicted_behaviors', []))}\n"
            part += f"  Reasoning: {analysis.get('reasoning', 'N/A')}\n"
            summary_parts.append(part)
        
        summary = "\n".join(summary_parts)
        
        # Stage 2: Enhanced meta-analysis with improved prompt engineering and behavioral prediction
        prompt = f"""
You are a senior security analyst AI. Analyze these suspicious files to determine if they 
represent a coordinated security threat. Focus on the combination of capabilities, 
intentions, and behaviors rather than individual indicators.

Suspicious Files:
{summary}

Instructions for Analysis:
1. Avoid False Positives: Do NOT flag files just because they have high entropy or 
   import common functions. Look for malicious combinations.
2. Look for Combinations: Identify patterns like:
   - Obfuscation (high entropy) + Malicious strings = Obfuscated malware
   - Process injection capabilities + Network functions = C2 malware
   - Keylogging capabilities + File writing = Infostealer
3. Predict potential coordinated behaviors based on file combinations:
   - If multiple files have network capabilities, they might form a download chain
   - If one file has process injection and another has network, they might work together for C2
   - If files have persistence and payload capabilities, they might form a dropper
4. Step-by-step thinking: Explain your analysis process before giving your final assessment.
5. Generate specific, testable hypotheses about what these files would do if executed.
6. Only provide a high risk score (0.7-1.0) if there are clear malicious patterns.
   For borderline cases, use a moderate score (0.4-0.6). For likely benign files, use low scores (0.0-0.3).
7. Provide a confidence score from 0.0 (low confidence) to 1.0 (high confidence) in your assessment.

IMPORTANT: Do not hallucinate or make up threats. Base your analysis only on the provided data.
If you cannot determine a clear threat, default to a lower risk score.

Respond with a JSON object containing:
{{
    "risk_score": 0.85,
    "reasoning": "Step 1: File A has obfuscation and malicious strings. Step 2: File B has process injection...",
    "hypotheses": [
        {{
            "type": "registry",     // One of: "registry", "process", "file", "network"
            "value": "malware.exe", // The specific artifact to check
            "path": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", // For registry keys
            "confidence": 0.9       // Confidence in this hypothesis
        }},
        {{
            "type": "process",
            "value": "updater.exe",
            "confidence": 0.8
        }}
    ],
    "confidence": 0.9
}}

Example response for benign files:
{{
    "risk_score": 0.2,
    "reasoning": "Step 1: Files have normal entropy levels and standard import functions. Step 2: No suspicious strings or network indicators found. Step 3: File patterns match legitimate software behavior.",
    "hypotheses": [],
    "confidence": 0.8
}}

Example response for suspicious files:
{{
    "risk_score": 0.92,
    "reasoning": "Step 1: updater.exe has high entropy (7.9) and contains strings 'CreateRemoteThread' and 'powershell.exe'. Step 2: loader.dll has process injection capabilities and imports InternetOpen. Step 3: The combination of obfuscated code with process injection and network communication indicates a sophisticated malware dropper.",
    "hypotheses": [
        {{
            "type": "process",
            "value": "updater.exe",
            "confidence": 0.95
        }},
        {{
            "type": "network",
            "value": "http://malicious-c2.com",
            "confidence": 0.85
        }},
        {{
            "type": "registry",
            "value": "Updater",
            "path": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            "confidence": 0.9
        }}
    ],
    "confidence": 0.92
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
            log_event("AI_ANALYSIS_ERROR", f"AI analysis failed: {e}")
            return {
                "risk_score": 0.5,
                "reasoning": f"AI analysis failed: {str(e)}",
                "hypotheses": [],
                "confidence": 0.0
            }
        
        # Fallback return in case of unexpected execution path
        return {
            "risk_score": 0.1,
            "reasoning": "Unexpected execution path",
            "hypotheses": [],
            "confidence": 0.0
        }
    
    def _verify_hypotheses(self, hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verify AI-generated structured hypotheses against the current system state with enhanced context correlation.
        
        This function checks if the AI's predicted indicators of compromise (IOCs) are
        already present on the system, which would indicate an active infection.
        
        CRITICAL LIMITATION: This is STATIC VERIFICATION of current system state, not 
        dynamic monitoring of future behavior. It only verifies if IOCs already exist, 
        not if they would be created when the malware executes.
        
        For example, if the AI predicts "The malware will create a backdoor process 
        named 'backdoor.exe'", this function only checks if 'backdoor.exe' is currently 
        running. If it's not running, the hypothesis is marked "NOT FOUND" even if the 
        AI's prediction about the malware's intent is correct.
        
        For dynamic behavior analysis and future action prediction, integration with a 
        sandbox environment would be required.
        
        Args:
            hypotheses: List of structured hypotheses from AI analysis
            
        Returns:
            List of verification results for each hypothesis
        """
        checks = []
        
        # Gather system context for correlation
        system_context = self._gather_system_context()
        
        for hypothesis in hypotheses:
            # Convert to StructuredHypothesis for type safety
            structured_hypothesis = StructuredHypothesis(
                type=hypothesis.get("type", ""),
                value=hypothesis.get("value", ""),
                path=hypothesis.get("path"),
                confidence=hypothesis.get("confidence", 0.0)
            )
            
            check_result = {
                "hypothesis": f"{structured_hypothesis.type}: {structured_hypothesis.value}",
                "verification_method": structured_hypothesis.type,
                "found": False,
                "details": "",
                "confidence": structured_hypothesis.confidence,
                "context_score": 0.0,  # Additional score for contextual relevance
                "correlation_score": 0.0  # Score based on system context correlation
            }
            
            # Check based on hypothesis type with contextual awareness
            if structured_hypothesis.type == "registry" and REGISTRY_SCANNER_AVAILABLE and RegistryScanner:
                try:
                    # Scan the registry path
                    path = structured_hypothesis.path or structured_hypothesis.value
                    scanner = RegistryScanner()
                    result = scanner.scan_registry_path(path, enable_ai_analysis=False)
                    if result.subkey_count > 0 or result.value_count > 0:
                        check_result["found"] = True
                        check_result["details"] = f"Registry path {path} exists with {result.subkey_count} subkeys and {result.value_count} values"
                        
                        # Add contextual scoring - check if values contain suspicious content
                        suspicious_values = 0
                        for value in result.values:
                            # Check for suspicious content in registry values
                            value_data = value.get('data', '') if isinstance(value, dict) else str(value)
                            if any(susp in str(value_data).lower() for susp in ['powershell', 'cmd', 'http', 'script']):
                                suspicious_values += 1
                        
                        # Context score based on suspicious content
                        if result.value_count > 0:
                            check_result["context_score"] = min(1.0, suspicious_values / result.value_count)
                        
                        # Correlation with system context
                        check_result["correlation_score"] = self._correlate_with_system_context(
                            "registry", path, system_context)
                    else:
                        check_result["details"] = f"Registry path {path} does not exist or is empty"
                except Exception as e:
                    check_result["details"] = f"Registry check failed: {str(e)}"
                
            elif structured_hypothesis.type == "process":
                try:
                    # Check if process is running with additional context
                    process_name = structured_hypothesis.value
                    suspicious_processes = 0
                    total_processes = 0
                    
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        total_processes += 1
                        if process_name.lower() in proc.info['name'].lower():
                            check_result["found"] = True
                            
                            # Check for suspicious command line arguments
                            cmdline = ' '.join(proc.info.get('cmdline', []))
                            if any(susp in cmdline.lower() for susp in ['powershell', '-enc', 'http', 'script', 'download']):
                                suspicious_processes += 1
                            
                            check_result["details"] = f"Process {process_name} is currently running (PID: {proc.info['pid']})"
                            if suspicious_processes > 0:
                                check_result["details"] += f" with suspicious arguments"
                            break
                    
                    if not check_result["found"]:
                        check_result["details"] = f"Process {process_name} is not currently running"
                    elif total_processes > 0:
                        # Context score based on suspicious processes
                        check_result["context_score"] = min(1.0, suspicious_processes / total_processes)
                        
                        # Correlation with system context
                        check_result["correlation_score"] = self._correlate_with_system_context(
                            "process", process_name, system_context)
                except Exception as e:
                    check_result["details"] = f"Process check failed: {str(e)}"
            
            elif structured_hypothesis.type == "file":
                try:
                    # Check if file exists with additional context
                    file_path = structured_hypothesis.value
                    if os.path.exists(file_path):
                        check_result["found"] = True
                        check_result["details"] = f"File path {file_path} exists on filesystem"
                        
                        # Add contextual scoring - check file properties
                        try:
                            stat = os.stat(file_path)
                            # Check if file is executable
                            if os.access(file_path, os.X_OK):
                                check_result["details"] += f" and is executable"
                                check_result["context_score"] = 0.7  # Higher score for executable files
                            
                            # Check file size for suspiciously small or large files
                            if stat.st_size < 1024:  # Less than 1KB
                                check_result["details"] += f" (suspiciously small: {stat.st_size} bytes)"
                                check_result["context_score"] = max(check_result["context_score"], 0.8)
                            elif stat.st_size > 100*1024*1024:  # More than 100MB
                                check_result["details"] += f" (suspiciously large: {stat.st_size} bytes)"
                                check_result["context_score"] = max(check_result["context_score"], 0.6)
                        except:
                            pass
                        
                        # Correlation with system context
                        check_result["correlation_score"] = self._correlate_with_system_context(
                            "file", file_path, system_context)
                    else:
                        check_result["details"] = f"File path {file_path} does not exist"
                except Exception as e:
                    check_result["details"] = f"File check failed: {str(e)}"
            
            elif structured_hypothesis.type == "network":
                try:
                    # Check for network connections
                    network_target = structured_hypothesis.value
                    connections = psutil.net_connections()
                    matching_connections = [
                        conn for conn in connections 
                        if network_target in str(conn.raddr) or network_target in str(conn.laddr)
                    ]
                    
                    if matching_connections:
                        check_result["found"] = True
                        check_result["details"] = f"Found {len(matching_connections)} network connections matching {network_target}"
                        
                        # Correlation with system context
                        check_result["correlation_score"] = self._correlate_with_system_context(
                            "network", network_target, system_context)
                    else:
                        check_result["details"] = f"No network connections found matching {network_target}"
                except Exception as e:
                    check_result["details"] = f"Network check failed: {str(e)}"
            
            else:
                check_result["verification_method"] = "unknown"
                check_result["details"] = f"Unknown hypothesis type: {structured_hypothesis.type}"
            
            checks.append(check_result)
        
        return checks
    
    def _gather_system_context(self) -> Dict[str, Any]:
        """Gather enhanced system context with temporal analysis for hypothesis correlation.
        
        Returns:
            Dictionary containing system context information
        """
        context = {
            "active_processes": [],
            "network_connections": [],
            "system_users": [],
            "timestamp": time.time(),
            "historical_context": self._get_historical_context()
        }
        
        try:
            # Gather active processes with more details
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    # Calculate process age
                    process_age = time.time() - proc.info.get('create_time', time.time())
                    
                    context["active_processes"].append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "username": proc.info['username'],
                        "cmdline": ' '.join(proc.info.get('cmdline', [])),
                        "age_seconds": process_age,
                        "is_suspicious": self._is_suspicious_process(proc.info)
                    })
                except:
                    pass
            
            # Gather network connections with more details
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.raddr:
                        context["network_connections"].append({
                            "local": str(conn.laddr),
                            "remote": str(conn.raddr),
                            "status": conn.status,
                            "is_suspicious": self._is_suspicious_connection(conn)
                        })
            except:
                pass
            
            # Gather system users
            try:
                users = psutil.users()
                for user in users:
                    context["system_users"].append({
                        "name": user.name,
                        "terminal": user.terminal,
                        "host": user.host,
                        "started": user.started
                    })
            except:
                pass
                
        except Exception as e:
            log_event("SYSTEM_CONTEXT_ERROR", f"Failed to gather system context: {e}")
        
        return context
    
    def _get_historical_context(self) -> Dict[str, Any]:
        """Get historical system context for temporal analysis.
        
        Returns:
            Dictionary containing historical context information
        """
        # For now, we'll return a simple historical context
        # In a more advanced implementation, this could read from logs or a database
        return {
            "recent_processes": [],
            "recent_network_activity": [],
            "baseline_metrics": {}
        }
    
    def _is_suspicious_process(self, proc_info: Dict[str, Any]) -> bool:
        """Determine if a process is suspicious based on its properties.
        
        Args:
            proc_info: Process information dictionary
            
        Returns:
            True if process is suspicious, False otherwise
        """
        try:
            name = proc_info.get('name', '').lower()
            cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
            
            # Check for suspicious process names
            suspicious_names = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32']
            if any(susp_name in name for susp_name in suspicious_names):
                # Check if running with suspicious arguments
                suspicious_args = ['encodedcommand', '-enc', 'http', 'download']
                if any(susp_arg in cmdline for susp_arg in suspicious_args):
                    return True
                    
            # Check for processes running from suspicious locations
            suspicious_paths = ['\\temp\\', '\\appdata\\', '\\programdata\\']
            if any(susp_path in cmdline for susp_path in suspicious_paths):
                return True
                
        except:
            pass
            
        return False
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Determine if a network connection is suspicious.
        
        Args:
            conn: Network connection object
            
        Returns:
            True if connection is suspicious, False otherwise
        """
        try:
            remote_addr = str(conn.raddr)
            
            # Check for connections to known suspicious ports
            suspicious_ports = [4444, 5555, 8080, 9999]  # Common C2 ports
            if hasattr(conn.raddr, 'port') and conn.raddr.port in suspicious_ports:
                return True
                
            # Check for connections to private IP ranges that might indicate lateral movement
            if '192.168.' in remote_addr or '10.' in remote_addr or '172.' in remote_addr:
                # This is a simplified check - in reality, you'd want more sophisticated logic
                pass
                
        except:
            pass
            
        return False
    
    def _correlate_with_system_context(self, hypothesis_type: str, value: str, context: Dict[str, Any]) -> float:
        """Correlate hypothesis with system context to determine relevance.
        
        Args:
            hypothesis_type: Type of hypothesis (process, file, registry, network)
            value: Value to correlate
            context: System context information
            
        Returns:
            Correlation score from 0.0 to 1.0
        """
        try:
            if hypothesis_type == "process":
                # Check if process is running in suspicious context
                for proc in context.get("active_processes", []):
                    if value.lower() in proc["name"].lower():
                        # Check if process is running under suspicious user context
                        username = proc.get("username", "").lower()
                        if any(susp_user in username for susp_user in ["system", "admin", "root"]):
                            return 0.8  # Higher correlation for system/admin processes
                        return 0.5  # Basic correlation
                
            elif hypothesis_type == "network":
                # Check if network connection exists in active connections
                for conn in context.get("network_connections", []):
                    if value in conn.get("remote", "") or value in conn.get("local", ""):
                        return 0.7  # Moderate correlation for network matches
                
            elif hypothesis_type == "file":
                # Check file path context (system directories, temp directories)
                suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\"]
                if any(susp_path in value.lower() for susp_path in suspicious_paths):
                    return 0.6  # Moderate correlation for suspicious paths
                
            elif hypothesis_type == "registry":
                # Check registry path context (autorun locations, suspicious keys)
                suspicious_keys = [
                    "\\software\\microsoft\\windows\\currentversion\\run",
                    "\\software\\microsoft\\windows\\currentversion\\runonce",
                    "\\software\\policies\\microsoft\\windows\\system",
                    "\\software\\microsoft\\windows nt\\currentversion\\winlogon"
                ]
                if any(susp_key in value.lower() for susp_key in suspicious_keys):
                    return 0.7  # Higher correlation for autorun/suspicious registry keys
                
        except Exception as e:
            log_event("CORRELATION_ERROR", f"Failed to correlate {hypothesis_type} {value}: {e}")
        
        return 0.3  # Default low correlation
    
    def scan_archive(self, archive_path: str) -> ArchiveAnalysisResult:
        """Scan an archive file for potential threats and check for active infections.
        
        This function performs two main functions:
        1. AI-based threat assessment of archive contents
        2. Verification of predicted IOCs against current system state
        
        IMPORTANT LIMITATION: This is STATIC VERIFICATION of current system state, 
        not dynamic monitoring of future behavior. It only verifies if IOCs already 
        exist, not if they would be created when the malware executes.
        
        If IOCs are found to already exist, this indicates an active infection that
        predates the current scan. If no IOCs are found, this indicates either:
        - A false positive prediction, or
        - A genuine threat that has not yet been executed on this system
        
        For dynamic behavior analysis and future action prediction, integration with a 
        sandbox environment would be required.
        """
        log_event("ARCHIVE_SCAN_START", f"Starting scan of {archive_path}")
        
        # Extract the archive
        temp_dir = self._extract_archive(archive_path)
        self.extracted_files_dir = temp_dir
        
        try:
            # Get list of extracted files
            file_paths = self._walk_extracted_files(temp_dir)
            log_event("FILES_EXTRACTED", f"Extracted {len(file_paths)} files from archive")
            
            # Extract metadata from each file
            metadata_list = []
            for file_path in file_paths:
                metadata = self._extract_file_metadata(file_path)
                metadata_list.append(metadata)
            
            # Analyze with AI using scalable approach
            ai_assessment = self._analyze_with_ai(metadata_list)
            
            # Extract hypotheses from AI assessment
            hypotheses = ai_assessment.get("hypotheses", [])
            
            # Verify hypotheses
            hypothesis_checks = self._verify_hypotheses(hypotheses)
            
            # Calculate overall risk score with confidence weighting and behavioral analysis
            ai_risk_score = ai_assessment.get("risk_score", 0.5)
            ai_confidence = ai_assessment.get("confidence", 0.5)
            
            # Adjust risk score based on hypothesis verification, context, and behavioral predictions
            verified_risks = 0
            total_hypotheses = len(hypothesis_checks)
            context_score_sum = 0.0
            correlation_score_sum = 0.0
            behavioral_confidence_sum = 0.0
            
            for check in hypothesis_checks:
                if check["found"]:
                    # Weight verified hypotheses by their confidence, context score, and correlation score
                    context_weight = check.get("context_score", 0.0)
                    correlation_weight = check.get("correlation_score", 0.0)
                    # Combined weight: 40% confidence, 25% context, 20% correlation, 15% behavioral confidence
                    weight = check["confidence"] * (0.4 + 0.25 * context_weight + 0.2 * correlation_weight + 0.15 * behavioral_confidence_sum / max(1, len(hypothesis_checks)))
                    verified_risks += weight
                context_score_sum += check.get("context_score", 0.0)
                correlation_score_sum += check.get("correlation_score", 0.0)
                # Add behavioral confidence from AI assessment
                behavioral_confidence_sum += ai_confidence
            
            # Average context, correlation, and behavioral scores
            avg_context_score = context_score_sum / total_hypotheses if total_hypotheses > 0 else 0.0
            avg_correlation_score = correlation_score_sum / total_hypotheses if total_hypotheses > 0 else 0.0
            avg_behavioral_confidence = behavioral_confidence_sum / total_hypotheses if total_hypotheses > 0 else ai_confidence
            
            if total_hypotheses > 0:
                # Normalize verified risks
                normalized_risks = min(1.0, verified_risks / total_hypotheses)
                # Combine AI risk score, confidence, verification results, and behavioral analysis
                # Weighting: 30% AI score*confidence, 35% verified risks, 15% context, 10% correlation, 10% behavioral confidence
                overall_risk_score = min(1.0, 
                    (ai_risk_score * ai_confidence * 0.3) + 
                    (normalized_risks * 0.35) + 
                    (avg_context_score * 0.15) + 
                    (avg_correlation_score * 0.1) + 
                    (avg_behavioral_confidence * 0.1)
                )
            else:
                # If no hypotheses, use AI risk score weighted by confidence and behavioral analysis
                overall_risk_score = min(1.0, ai_risk_score * ai_confidence * 0.7 + avg_behavioral_confidence * 0.3)
            
            # Determine recommendation based on risk score with additional context checks
            if overall_risk_score >= 0.8:
                recommendation = "immediate_quarantine"
            elif overall_risk_score >= 0.6:
                recommendation = "quarantine_and_investigate"
            elif overall_risk_score >= 0.4:
                # Additional check for borderline cases
                if avg_context_score > 0.5:  # High context score indicates more suspicious elements
                    recommendation = "investigate"
                else:
                    recommendation = "monitor"
            else:
                recommendation = "monitor"
            
            # Create result object
            result = ArchiveAnalysisResult(
                scan_id=self.scan_id,
                timestamp=self.timestamp,
                timestamp_iso=self.timestamp_iso,
                archive_path=archive_path,
                file_count=len(file_paths),
                extracted_metadata=metadata_list,
                ai_assessment=ai_assessment,
                hypothesis_checks=hypothesis_checks,
                overall_risk_score=overall_risk_score,
                final_recommendation=recommendation
            )
            
            log_event("ARCHIVE_SCAN_COMPLETE", f"Completed scan of {archive_path} with risk score {overall_risk_score:.2f}")
            return result
            
        finally:
            # Clean up extracted files
            try:
                import shutil
                shutil.rmtree(temp_dir)
                self.extracted_files_dir = None
            except Exception as e:
                log_event("CLEANUP_ERROR", f"Failed to clean up temp directory {temp_dir}: {e}")
    
    def save_result(self, result: ArchiveAnalysisResult, output_dir: str = "logs") -> str:
        """Save analysis result to a JSON file"""
        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Convert result to dictionary
            result_dict = asdict(result)
            
            # Create filename with timestamp
            timestamp = datetime.fromtimestamp(result.timestamp).strftime("%Y%m%d_%H%M%S")
            filename = f"ArchiveScan_{timestamp}_{result.scan_id}.json"
            filepath = os.path.join(output_dir, filename)
            
            # Save result
            with open(filepath, 'w') as f:
                json.dump(result_dict, f, indent=2, default=str)
                
            log_event("SCAN_RESULT_SAVED", f"Saved scan result to {filepath}")
            return filepath
        except Exception as e:
            log_event("SAVE_RESULT_ERROR", f"Failed to save scan result: {e}")
            return ""

def scan_folder_for_archives(folder_path: str, output_dir: str = "logs", suspicion_threshold: float = 0.6, confidence_threshold: float = 0.7):
    """Scan a folder for archive files and analyze them"""
    scanner = AdvancedArchiveScanner(suspicion_threshold=suspicion_threshold, confidence_threshold=confidence_threshold)
    
    # Supported archive extensions
    archive_extensions = {'.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar'}
    
    # Walk through the folder
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            _, ext = os.path.splitext(file_path)
            
            # Check if it's an archive file
            if ext.lower() in archive_extensions:
                try:
                    log_event("ARCHIVE_FOUND", f"Found archive: {file_path}")
                    result = scanner.scan_archive(file_path)
                    saved_path = scanner.save_result(result, output_dir)
                    if saved_path:
                        print(f"Analysis saved to: {saved_path}")
                except Exception as e:
                    log_event("ARCHIVE_SCAN_FAILED", f"Failed to scan {file_path}: {e}")
                    print(f"Error scanning {file_path}: {e}")

def main():
    """Main entry point for the advanced triage scanner.
    
    This tool performs static triage analysis of archive files to:
    1. Assess potential security risks using AI analysis
    2. Check for indicators of active infection by verifying predicted IOCs
    
    IMPORTANT LIMITATION: This is a STATIC ANALYSIS TOOL, not a dynamic sandbox. 
    It does not execute files or monitor for future behavior. It only performs 
    static analysis and verification of CURRENT system state.
    
    The verification step checks if predicted IOCs (files, processes, registry keys, 
    network connections) already exist on the system. It CANNOT confirm if malware 
    would perform these actions if executed in the future.
    
    For dynamic behavior analysis, integration with a sandbox environment would be 
    required. This tool is designed for initial triage and current infection detection.
    
    UNDERSTANDING FALSE POSITIVES:
    
    While this tool is designed to minimize false positives, they can still occur:
    
    1. AI Misinterpretation: The AI might incorrectly flag legitimate files that have
       characteristics similar to malware (high entropy, obfuscation, etc.)
       
    2. Benign Resembling Malware: Some legitimate software uses techniques common in
       malware for legitimate purposes (packing, obfuscation, certain API calls)
       
    3. Threshold Sensitivity: The suspicion threshold (default 0.6) is a balance between
       catching threats and avoiding false positives. Adjusting it affects both.
       
    4. Context Limitations: Static analysis provides limited context compared to
       dynamic analysis in a sandbox environment.
       
    RECOMMENDATIONS:
    - Review flagged files manually, especially those with moderate suspicion scores
    - Consider the file's source and purpose when evaluating results
    - Use this tool as part of a layered security approach, not as a sole decision maker
    - Adjust the suspicion threshold based on your environment and risk tolerance
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Archive Scanner with AI Analysis')
    parser.add_argument('path', help='Path to archive file or folder containing archives')
    parser.add_argument('--output-dir', default='logs', help='Output directory for scan results')
    parser.add_argument('--threshold', type=float, default=0.6, help='Suspicion threshold for Stage 2 analysis (default: 0.6)')
    parser.add_argument('--confidence', type=float, default=0.7, help='Confidence threshold for AI analysis (default: 0.7)')
    
    args = parser.parse_args()
    
    path = args.path
    output_dir = args.output_dir
    suspicion_threshold = args.threshold
    confidence_threshold = args.confidence
    
    # Check if path is a file or directory
    if os.path.isfile(path):
        # Single archive file
        scanner = AdvancedArchiveScanner(suspicion_threshold=suspicion_threshold, confidence_threshold=confidence_threshold)
        try:
            result = scanner.scan_archive(path)
            saved_path = scanner.save_result(result, output_dir)
            if saved_path:
                print(f"Analysis saved to: {saved_path}")
                
                # Print summary
                print("\n" + "="*80)
                print("ARCHIVE ANALYSIS RESULTS")
                print("="*80)
                print(f"Scan ID: {result.scan_id}")
                print(f"Timestamp: {result.timestamp_iso}")
                print(f"Archive: {result.archive_path}")
                print(f"Files analyzed: {result.file_count}")
                print(f"Overall risk score: {result.overall_risk_score:.2f}")
                print(f"Recommendation: {result.final_recommendation}")
                print(f"AI reasoning: {result.ai_assessment.get('reasoning', 'N/A')}")
                
                # Print hypothesis verification results
                if result.hypothesis_checks:
                    print(f"\nHypothesis verification results:")
                    for check in result.hypothesis_checks:
                        status = "VERIFIED" if check["found"] else "NOT FOUND"
                        print(f"  [{status}] {check['hypothesis']} (Confidence: {check['confidence']:.2f})")
                        if check["details"]:
                            print(f"    Details: {check['details']}")
            else:
                print("Failed to save analysis results")
        except Exception as e:
            log_event("SCAN_ERROR", f"Failed to scan archive {path}: {e}")
            print(f"Error: {e}")
    elif os.path.isdir(path):
        # Folder containing archives
        print(f"Scanning folder: {path}")
        scan_folder_for_archives(path, output_dir, suspicion_threshold, confidence_threshold)
    else:
        print(f"Error: Path {path} does not exist")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())