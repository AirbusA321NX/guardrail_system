import os
import hashlib
import datetime
from pathlib import Path
import math
import re
import pefile
import json
import sys
import feedparser # Added for RSS feeds
import time # Added for timing
# NOTE: Replace 'mistral' with the actual library/bindings you are using for Mistral 7B
# Using the existing analyze_text function from mistral_analysis module
from ai.mistral_analysis import analyze_text

# ----- Configuration and Precompilation -----
# Define config_path outside try block to fix scoping issue
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
try:
    # Ensure config.json is in the same directory or provide a full path
    # Use __file__ to get the directory of the current script
    with open(config_path, 'r') as cf:
        config = json.load(cf)
    print(f"Configuration loaded successfully from {config_path}")
except FileNotFoundError:
    print(f"FATAL: config.json not found at {config_path}.", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"FATAL: config.json is not valid JSON: {e}", file=sys.stderr)
    sys.exit(1)
except KeyError as e:
    print(f"FATAL: Missing required key in config.json: {e}", file=sys.stderr)
    sys.exit(1)

# Initialize configuration only (using existing analyze_text function from mistral_analysis module)
print("Using Ollama-based Mistral 7B model via analyze_text function.")

# This regex finds sequences of printable chars (incl. Unicode)
# Length is configurable, default 4
min_str_len = config.get('MIN_STRING_LENGTH', 4)
try:
    # Use a more robust regex for printable characters, including many Unicode ranges
    # Excludes control characters C0, C1 and surrogate pairs but includes many symbols/letters
    STRINGS_REGEX = re.compile(rb"([^\x00-\x1F\x7F-\x9F]){%d,}" % min_str_len)
    print(f"Strings regex compiled for minimum length {min_str_len}.")
except re.error as e:
     print(f"FATAL: Invalid MIN_STRING_LENGTH ({min_str_len}) in config.json or regex error: {e}", file=sys.stderr)
     sys.exit(1)


# --- Precompile regex and sets for O(N) string scanning ---
# ALL config keywords MUST be lowercase for this to work.
ALL_KEYWORDS = list(set( # Deduplicate keywords just in case
    [k.lower() for k in config.get('VENDOR_KEYWORDS', [])] +
    [k.lower() for k in config.get('SYSTEM_KEYWORDS', [])] +
    [k.lower() for k in config.get('SCRIPT_INDICATORS', [])]
))

if not ALL_KEYWORDS:
    print("WARNING: No keywords defined in config.json (VENDOR_KEYWORDS, SYSTEM_KEYWORDS, SCRIPT_INDICATORS). String analysis will be empty.", file=sys.stderr)
    COMPILED_KEYWORDS_REGEX = None
else:
    # Use word boundaries (\b) for precise, anchored matching.
    # Escape special regex characters in keywords.
    try:
        # Sort keywords by length descending to match longer keywords first (e.g., "cmd.exe" before "cmd")
        ALL_KEYWORDS.sort(key=len, reverse=True)
        regex_pattern = '|'.join(fr'\b({re.escape(k)})\b' for k in ALL_KEYWORDS)
        COMPILED_KEYWORDS_REGEX = re.compile(regex_pattern, re.IGNORECASE)
        print(f"Compiled regex for {len(ALL_KEYWORDS)} keywords.")
    except re.error as e:
        print(f"FATAL: Error compiling keywords regex (check config.json keywords for invalid chars): {e}", file=sys.stderr)
        sys.exit(1)


VENDOR_KEYWORDS_SET = {k.lower() for k in config.get('VENDOR_KEYWORDS', [])}
PE_INDICATORS_SET = {k.lower() for k in config.get('SYSTEM_KEYWORDS', [])}
SCRIPT_INDICATORS_SET = {k.lower() for k in config.get('SCRIPT_INDICATORS', [])}

# Use a set of lowercase APIs for the robust check
DANGEROUS_APIS_SET = {api.lower() for api in config.get('DANGEROUS_APIS', [])}
# --- End of precompilation ---

# Global variable to store detected trends
CURRENT_TRENDS = []

# ----- Utility functions -----
def calculate_entropy(data):
    """Calculates the Shannon entropy of a byte string."""
    if not data: return 0
    byte_counts = [0]*256
    data_len = len(data)
    if data_len == 0: return 0 # Avoid division by zero
    for b in data: byte_counts[b] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0: continue
        p = count / data_len
        # Handle log2(0) case mathematically correctly (p*log2(p) -> 0 as p -> 0)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def file_timestamps(file_path):
    """Extracts creation and modification timestamps in ISO format."""
    try:
        stats = os.stat(file_path)
        # Use ISO format for better readability/parsing and UTC for consistency
        return {
            "creation_utc": datetime.datetime.fromtimestamp(stats.st_ctime, datetime.timezone.utc).isoformat(),
            "modification_utc": datetime.datetime.fromtimestamp(stats.st_mtime, datetime.timezone.utc).isoformat()
        }
    except OSError as e:
        print(f"Warning: Could not stat file {file_path}: {e}", file=sys.stderr)
        return {"creation_utc": "Unknown", "modification_utc": "Unknown"}

def extract_pe_metadata(file_data):
    """Extracts all PE metadata in a single pass using pefile."""
    metadata = {}
    pe = None # Ensure pe is defined for finally block
    try:
        pe = pefile.PE(data=file_data, fast_load=True) # Use fast_load

        # Section analysis (single loop)
        section_names, section_entropy = [], {}
        if hasattr(pe, 'sections'):
            for s in pe.sections:
                try:
                    name = s.Name.decode(errors='replace').strip('\x00') # Replace errors
                    section_names.append(name)
                    # Limit entropy calculation for huge sections? Potential performance hit.
                    section_data = s.get_data()
                    section_entropy[name] = calculate_entropy(section_data)
                except Exception as e_sec:
                     print(f"Warning: Error processing section {s.Name}: {e_sec}", file=sys.stderr)
        metadata['sections'] = section_names
        metadata['section_entropy'] = section_entropy

        # Import analysis (clean, no None)
        imports = []
        # Use getattr to safely access DIRECTORY_ENTRY_IMPORT to avoid type checking issues
        directory_entry = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None)
        if directory_entry is not None:
            for entry in directory_entry:
                 if hasattr(entry, 'imports'):
                     for imp in entry.imports:
                         if imp.name:
                             try: imports.append(imp.name.decode(errors='replace')) # Replace errors
                             except Exception: pass # Ignore decoding errors for individual imports
        metadata['imports'] = imports

        # Resource analysis (Focus on Version Info)
        resources = {} # Use dict for better structure
        if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'VS_FIXEDFILEINFO'):
             if pe.VS_FIXEDFILEINFO:
                  # Access VS_FIXEDFILEINFO attributes if they exist
                  fixed_info = pe.VS_FIXEDFILEINFO[0] # Usually only one
                  # Example: metadata['file_version'] = f"{fixed_info.FileVersionMS >> 16}.{fixed_info.FileVersionMS & 0xFFFF}..."

             if hasattr(pe, 'FileInfo') and pe.FileInfo:
                 for fileinfo_list in pe.FileInfo:
                      for fileinfo in fileinfo_list:
                          if hasattr(fileinfo, 'StringTable') and fileinfo.StringTable:
                              for st in fileinfo.StringTable:
                                   if hasattr(st, 'entries'):
                                       for k_bytes, v_bytes in st.entries.items():
                                           try:
                                               key = k_bytes.decode(errors='replace')
                                               value = v_bytes.decode(errors='replace')
                                               resources[key] = value # Store key-value pairs
                                           except Exception: pass # Ignore decoding errors
        metadata['resources_version_info'] = resources # Store under a specific key

        metadata['size'] = len(file_data)

        # Imphash calculation requires imports, do it after
        try: metadata['imphash'] = pe.get_imphash()
        except AttributeError: metadata['imphash'] = "N/A (pefile error)"


    except pefile.PEFormatError: metadata['error'] = "Not a PE file"
    except MemoryError:
        metadata['error'] = "Memory Error during PE parsing (file too complex?)"
        print("FATAL: MemoryError parsing PE file.", file=sys.stderr)
    except Exception as e:
        metadata['error'] = f"PE parsing error: {e}" # Catch broader errors
    finally:
        # Ensure pefile object is closed to release resources
        if pe:
             try: pe.close()
             except Exception: pass # Ignore close errors

    return metadata

def extract_strings(file_data):
    """Extracts printable strings (ASCII & Unicode-like) using the compiled regex."""
    if not file_data: return []
    strings = []
    try:
        # Iterate through potential matches without decoding the whole file at once
        for match in STRINGS_REGEX.finditer(file_data):
            try:
                # Group 1 should be the printable sequence
                # Decode found bytes using utf-8 with replacement for errors
                strings.append(match.group(1).decode('utf-8', errors='replace'))
            except Exception:
                pass # Ignore decoding errors on individual strings
    except Exception as e:
        # Catch errors during finditer itself (e.g., on extremely large/malformed data)
        print(f"Warning: Error during string extraction regex: {e}", file=sys.stderr)
    return strings


def determine_context(file_path):
    """Determines file context from its path and system logs."""
    try:
        if not isinstance(file_path, (str, Path)):
             raise TypeError("file_path must be a string or Path object")
        path = Path(file_path).resolve() # Resolve symlinks/relative paths
        folder = str(path.parent)
        name = path.name
    except Exception as e:
         print(f"Error parsing file path '{file_path}': {e}", file=sys.stderr)
         # Return a minimal context with error
         return {"error": f"Invalid path: {e}", "folder": "Unknown", "filename": "Unknown"}

    timestamps = file_timestamps(file_path) # Assumes file exists after path resolution
    system_root = os.environ.get("SystemRoot", config.get('DEFAULT_SYSTEM_ROOT', "C:\\Windows"))
    # Normalize paths for comparison
    try:
        system32 = Path(os.path.join(system_root, config.get('SYSTEM32_FOLDER', 'System32'))).resolve()
        downloads = Path(os.path.join(Path.home(), config.get('DOWNLOADS_FOLDER', 'Downloads'))).resolve()
    except Exception as path_e:
        print(f"Warning: Could not resolve standard paths (System32/Downloads): {path_e}", file=sys.stderr)
        system32 = Path("C:\\Windows\\System32") # Fallback, might be incorrect
        downloads = Path(os.path.join(Path.home(), "Downloads"))


    script_exts = tuple(ext.lower() for ext in config.get('SCRIPT_EXTENSIONS', [])) # Normalize extensions
    context = {
        "folder": folder, "filename": name, "timestamps": timestamps,
        "is_system32": path.parent.samefile(system32) if system32.exists() else False, # Safer comparison
        "downloaded_by_user": path.is_relative_to(downloads) if downloads.exists() else False, # Safer comparison
        "windows_update": False,
        "script_file": name.lower().endswith(script_exts)
    }
    cbs_log_path_tuple = tuple(config.get('CBS_LOG_PATH', []))
    if cbs_log_path_tuple:
        cbs_log = os.path.join(system_root, *cbs_log_path_tuple)
        if os.path.exists(cbs_log):
            try:
                # Read line by line for large logs
                with open(cbs_log, "r", encoding="utf-8", errors="ignore") as f:
                    # Check if filename is mentioned, case-insensitive might be better
                    for line in f:
                        if name in line: context["windows_update"] = True; break
            except Exception as e:
                print(f"Warning: Could not read CBS.log {cbs_log}: {e}", file=sys.stderr)
    return context

# ----- Unified string and evidence analysis -----
def analyze_strings(strings, config):
    """Scans all strings in O(N) using the precompiled regex."""
    findings = {'vendor_hints': {}, 'pe_indicators': {}, 'script_indicators': {}}
    if not COMPILED_KEYWORDS_REGEX or not strings: return findings

    max_str_len = config.get('MAX_EVIDENCE_STRING_LENGTH', 256)
    half_max_len = max_str_len // 2 # Precalculate

    for s in strings:
        if not isinstance(s, str) or not s: continue # Skip non-strings or empty strings
        try:
            for match in COMPILED_KEYWORDS_REGEX.finditer(s):
                # group(1) is the first (and only) capture group, already escaped/normalized in regex
                keyword_found = match.group(1).lower()

                # Calculate snippet bounds safely using match object indices
                idx = match.start(1)
                end_idx = match.end(1)
                start = max(0, idx - half_max_len)
                end = min(len(s), end_idx + half_max_len)
                snippet = s[start:end]
                # Add ellipsis more carefully
                if start > 0: snippet = "..." + snippet
                if end < len(s): snippet = snippet + "..."

                # Categorize using the sets and a *consistent* evidence model
                # Store the normalized keyword as the key
                if keyword_found in VENDOR_KEYWORDS_SET:
                    findings['vendor_hints'].setdefault(keyword_found, []).append(snippet)
                elif keyword_found in PE_INDICATORS_SET:
                    findings['pe_indicators'].setdefault(keyword_found, []).append(snippet)
                elif keyword_found in SCRIPT_INDICATORS_SET:
                    findings['script_indicators'].setdefault(keyword_found, []).append(snippet)
        except Exception as e:
            # Catch potential regex errors on malformed strings
            print(f"Warning: Regex error processing string snippet '{s[:50]}...': {e}", file=sys.stderr)
            continue # Move to next string

    return findings

# ----- Truncate helper -----
def truncate_list(lst, max_items=None):
    """Truncates a list for safe inclusion in the prompt."""
    if not isinstance(lst, list): return lst, "" # Handle non-lists gracefully
    if max_items is None:
        max_items = config.get('MAX_LIST_ITEMS', 50)
    truncated = lst[:max_items]
    note = f"... ({len(lst)} total)" if len(lst) > max_items else ""
    return truncated, note

# ----- Trend Analysis Functions -----
def fetch_feed_data(feed_urls):
    """Fetches titles and summaries from multiple RSS feeds."""
    all_entries_text = []
    print("Fetching cybersecurity news feeds...")
    feed_urls = feed_urls or [] # Ensure it's a list
    for url in feed_urls:
        if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
             print(f"Warning: Skipping invalid feed URL: {url}", file=sys.stderr)
             continue
        try:
            # Add User-Agent to avoid potential blocking
            headers = {'User-Agent': config.get('FEED_USER_AGENT', 'Mozilla/5.0')}
            feed = feedparser.parse(url, agent=headers.get('User-Agent'))
            # Check for errors reported by feedparser
            if feed.bozo:
                 print(f"Warning: Feed at {url} may be malformed. Error: {feed.bozo_exception}", file=sys.stderr)
            # Check HTTP status with proper type checking
            if hasattr(feed, 'status') and isinstance(feed.status, int) and (feed.status < 200 or feed.status >= 300):
                 print(f"Warning: Feed at {url} returned HTTP status {feed.status}", file=sys.stderr)

            print(f"  - Fetched {len(feed.entries)} entries from {url}")
            for entry in feed.entries:
                title = entry.get('title', '')
                summary = entry.get('summary', entry.get('description', ''))
                # Basic cleaning - Remove HTML more robustly with type checking
                if isinstance(summary, str):
                    summary = re.sub('<[^<]+?>', ' ', summary) # Replace tags with space
                    summary = ' '.join(summary.split()) # Normalize whitespace
                if title and summary and isinstance(title, str) and isinstance(summary, str):
                     # Combine title and summary for better context
                     all_entries_text.append(f"Title: {title}. Summary: {summary}\n---\n")
        except Exception as e:
            print(f"Error fetching or parsing feed {url}: {e}", file=sys.stderr)
    print(f"Total entries fetched for analysis: {len(all_entries_text)}")
    return all_entries_text

def analyze_trends_with_ai(feed_entries):
    """Uses Mistral 7B to analyze feed entries and extract malware trends."""
    global CURRENT_TRENDS
    if not feed_entries:
        print("No feed entries to analyze for trends.")
        return

    print("Analyzing news feeds for current malware trends using AI...")
    max_chars = config.get('MAX_CHARS_FOR_TREND_ANALYSIS', 15000)
    combined_text = "".join(feed_entries)
    truncated_text = combined_text[:max_chars]
    trunc_note = "... (truncated)" if len(combined_text) > max_chars else ""

    trend_prompt = f"""
Analyze the following cybersecurity news summaries. Identify specific, actionable malware trends relevant to STATIC file analysis.
Focus ONLY on techniques, tools (LOLbas), file types, filenames, strings, registry keys, or specific malware family indicators mentioned.

News Summaries:
{truncated_text}
{trunc_note}

Instructions:
Output ONLY a valid JSON list of trends. Each trend object MUST have:
- "trend_name": A short descriptive name (e.g., "Qakbot uses specific DLL names").
- "indicators": A list of specific, lowercase strings, filenames, or patterns (suitable for static matching).
Only include trends with clear static indicators. Avoid behavioral descriptions (e.g., "uses process injection"). Be specific (e.g., prefer "rundll32.exe" over "lolbas").

Example Output:
[
  {{
    "trend_name": "IcedID uses Gzip archives in phishing",
    "indicators": [".gz", "powershell", "downloadstring"]
  }},
  {{
    "trend_name": "SocGholish uses fake browser updates (JS files)",
    "indicators": [".js", "wscript.shell", "eval", "update.js"]
  }},
  {{
    "trend_name": "LockBit registry persistence",
    "indicators": ["hkcu\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run", "lockbit", "readme.txt"]
  }}
]

Extracted Trends (JSON List Only):
"""
    try:
        # Use analyze_text function instead of model.generate
        result = analyze_text(trend_prompt)
        # Extract the response content from the result
        response = result.get('reasoning', '') if isinstance(result, dict) else str(result)
        # Find the JSON list within the response more reliably, handle potential markdown
        json_match = re.search(r'```json\s*(\[.*?\])\s*```|(\[.*?\])', response, re.DOTALL | re.MULTILINE)
        if json_match:
            # Prioritize markdown block if found, otherwise use plain list
            trends_json_str = json_match.group(1) or json_match.group(2)
            try:
                parsed_trends = json.loads(trends_json_str)
                # More robust validation
                valid_trends = []
                if isinstance(parsed_trends, list):
                    for t in parsed_trends:
                        if (isinstance(t, dict) and
                            'trend_name' in t and isinstance(t['trend_name'], str) and t['trend_name'] and
                            'indicators' in t and isinstance(t['indicators'], list) and t['indicators'] and # Ensure indicators not empty
                            all(isinstance(ind, str) and ind for ind in t['indicators'])): # Ensure all indicators are non-empty strings
                            # Ensure indicators are lowercase strings
                            t['indicators'] = [ind.lower() for ind in t['indicators']]
                            valid_trends.append(t)
                        else:
                            print(f"Warning: Skipping invalid trend format: {t}", file=sys.stderr)
                CURRENT_TRENDS = valid_trends
                print(f"Successfully extracted {len(CURRENT_TRENDS)} valid trends.")
            except json.JSONDecodeError as json_e:
                print(f"Error: Could not parse JSON from AI trend response: {json_e}", file=sys.stderr)
                print(f"AI Response Snippet: {trends_json_str[:500]}...", file=sys.stderr)
        else:
            print("Error: No valid JSON list found in AI trend response.", file=sys.stderr)
            print(f"AI Response Snippet: {response[:500]}...", file=sys.stderr)

    except Exception as ai_e:
        print(f"Error during AI trend analysis: {ai_e}", file=sys.stderr)

def check_file_against_trends(context, pe_metadata, capabilities):
    """Checks the file's static properties against extracted trends."""
    matched_trends = []
    if not CURRENT_TRENDS or not isinstance(capabilities, dict):
        return matched_trends

    # Combine all potential indicators from the file into one lowercase set
    file_indicators = set()
    filename_lower = context.get('filename', '').lower()
    if filename_lower:
        file_indicators.add(filename_lower)
        file_ext = os.path.splitext(filename_lower)[1]
        if file_ext: file_indicators.add(file_ext)

    # Add indicators from capabilities (which store normalized keys)
    file_indicators.update(capabilities.keys())

    # Add PE specific indicators if not a script
    if not context.get('script_file', False): # Default to False if context missing key
        file_indicators.update(imp.lower() for imp in pe_metadata.get('imports', []))
        file_indicators.update(s.lower() for s in pe_metadata.get('sections', []))
        if pe_metadata.get('imphash'):
             file_indicators.add(pe_metadata['imphash']) # Imphash is already lowercase

    # Add resource strings values (could be noisy but might catch specific strings)
    for key, value in pe_metadata.get('resources_version_info', {}).items():
         if isinstance(value, str): file_indicators.add(value.lower())


    for trend in CURRENT_TRENDS:
        trend_indicators = set(trend['indicators'])
        # Check for intersection
        if not trend_indicators.isdisjoint(file_indicators):
            matched_trends.append(trend['trend_name'])

    return matched_trends


# ----- Prompt generation -----
def generate_prompt(file_path, file_data):
    """Generates the final, evidence-based prompt for the LLM."""
    context = determine_context(file_path)
    if 'error' in context: return f'{{"risk_score": -1, "reasoning": "{context["error"]}"}}' # Return error early

    strings = extract_strings(file_data)
    string_analysis = analyze_strings(strings, config)
    try:
        file_hash = hashlib.sha256(file_data).hexdigest()
    except Exception as hash_e:
        print(f"Error calculating SHA256 for {file_path}: {hash_e}", file=sys.stderr)
        file_hash = "Error calculating hash"

    matched_trends = [] # Initialize here
    prompt_template = "" # Will hold the final prompt string
    final_capabilities = {} # Will hold capabilities relevant to the file type

    # Determine file type and build evidence accordingly
    if context.get('script_file', False):
        # --- SCRIPT ANALYSIS PATH ---
        pe_metadata = {'size': len(file_data)} # Basic size info
        vendor = "N/A (Script)"
        final_capabilities = string_analysis.get('script_indicators', {}) # Get script keywords
        matched_trends = check_file_against_trends(context, pe_metadata, final_capabilities)

        script_content = ""
        max_script_content_len = config.get('MAX_SCRIPT_CONTENT_LENGTH', 4096)
        try:
            script_content = file_data.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            try: script_content = file_data.decode('cp1252', errors='ignore')
            except Exception as e:
                print(f"Warning: Could not decode script content for {file_path}: {e}", file=sys.stderr)
                script_content = "[Decoding Error]"

        truncated_content, content_note = truncate_list([script_content], 1) # Use truncate_list logic for note
        truncated_content = truncated_content[0] if truncated_content else ""
        if len(script_content) > max_script_content_len:
            truncated_content = script_content[:max_script_content_len]
            content_note = f"... (truncated to {max_script_content_len} chars)"

        # Define Script Prompt Template
        prompt_template = f"""
You are a Security Analyst specializing in **Fileless Malware** and **Living Off The Land (LOLbas)** techniques.
Analyze the following script file based on its **content**, context, keyword indicators, and current threat trends.
Focus on identifying malicious **intent and logic** within the script code itself.

File Context:
- Path: {file_path}
- Filename: {context.get('filename','N/A')}
- Folder: {context.get('folder','N/A')}
- Size: {pe_metadata.get('size', 'Unknown')} bytes
- Timestamps: {context.get('timestamps','N/A')}
- Located in System32: {context.get('is_system32','N/A')}
- Downloaded by user: {context.get('downloaded_by_user','N/A')}
- SHA256: {file_hash}
- Matched Current Trends: {{matched_trends}}

Keyword Indicators Found: {{truncated_caps}}

Script Content (Truncated): {content_note}
```
{truncated_content}
```

Instructions:
Provide a risk score from 0 (benign) to 10 (highly malicious) based on the script's likely actions and intent derived from its code.
Explain your reasoning, focusing on the script's logic. Mention specific commands, obfuscation, use of LOLbas tools (powershell, wscript, bitsadmin, certutil), attempts at persistence (registry, scheduled tasks), network activity (downloading/uploading data), and correlation with current trends.
Output *only* a valid JSON object with 'risk_score' and 'reasoning' keys.

Example Benign Script Analysis:
{{
  "risk_score": 1,
  "reasoning": "Simple batch script performing standard file operations ('copy', 'del'). No network activity, persistence, obfuscation, or matching trends observed. Low risk."
}}

Example Malicious Script Analysis:
{{
  "risk_score": 9,
  "reasoning": "High-confidence fileless malware dropper. Script code attempts to download a remote file using 'bitsadmin' (LOLbas) and execute it. Uses Base64 encoding (obfuscation). Establishes persistence via registry 'Run' key. Matches current trend 'Malware using bitsadmin for download'."
}}

Your Analysis:
"""

    else:
        # --- PE FILE ANALYSIS PATH ---
        pe_metadata = extract_pe_metadata(file_data)

        # Handle case where file is neither script nor valid PE
        if 'error' in pe_metadata and pe_metadata['error'] == "Not a PE file":
             print(f"Warning: File {file_path} is not a script and not a valid PE file.", file=sys.stderr)
             final_capabilities = string_analysis.get('pe_indicators', {}) # Use PE keywords for generic binary
             vendor = "Unknown (Not a valid PE / Non-script)"
             matched_trends = check_file_against_trends(context, {}, final_capabilities)
             truncated_caps = {} # Reuse this var name
             max_snippet_len = config.get('MAX_EVIDENCE_STRING_LENGTH', 256)
             for key, value_list in final_capabilities.items():
                  if isinstance(value_list, list):
                      t_list_snippets = [s[:max_snippet_len] for s in value_list]
                      t_list, note = truncate_list(t_list_snippets)
                      truncated_caps[key] = {'matches': t_list, 'note': note.strip()}

             prompt = f"""
You are a Security Analyst evaluating an unknown file type. It is not a script and failed PE parsing.
Analyze based ONLY on context, string keywords, and trends.

File Context:
- Path: {file_path}
- Filename: {context.get('filename','N/A')}
- Folder: {context.get('folder','N/A')}
- Size: {len(file_data)} bytes
- Timestamps: {context.get('timestamps','N/A')}
- SHA256: {file_hash}
- Matched Current Trends: {matched_trends or "None"}

Keyword Indicators Found: {json.dumps(truncated_caps, indent=2)}

Instructions:
Provide a risk score (0-10) based on the limited available evidence. Acknowledge the uncertainty due to the unknown file type.
Output *only* a valid JSON object with 'risk_score' and 'reasoning' keys.

Your Analysis:
"""
             return prompt # Return early for non-PE/non-script

        # Continue if it *is* a valid PE file
        pe_vendor_res = pe_metadata.get('resources_version_info', {}).get('CompanyName', None)
        string_hints_dict = string_analysis['vendor_hints']

        if pe_vendor_res:
            vendor = f"PE Resource: '{pe_vendor_res}'"
            if string_hints_dict and pe_vendor_res.lower() not in string_hints_dict:
                vendor += f", CONFLICTING String Hints: {json.dumps(string_hints_dict, indent=2)}"
        elif string_hints_dict: vendor = f"String Hints: {json.dumps(string_hints_dict, indent=2)}"
        else: vendor = "Unknown"

        final_capabilities = string_analysis.get('pe_indicators', {})
        imported_apis_lower = {imp.lower() for imp in pe_metadata.get('imports', [])}
        api_caps = []
        # Robust O(N*M) check for safety
        if DANGEROUS_APIS_SET and imported_apis_lower: # Avoid loop if no APIs/keywords
            for dangerous_api in DANGEROUS_APIS_SET:
                for imp in imported_apis_lower:
                    if imp.startswith(dangerous_api): api_caps.append(imp)
        if api_caps: final_capabilities['dangerous_api_imports'] = list(set(api_caps))

        matched_trends = check_file_against_trends(context, pe_metadata, final_capabilities)

        # Define PE Prompt Template
        prompt_template = f"""
You are a Tier 3 Malware Analyst analyzing a PE file (e.g., .exe, .dll).
Your goal is to provide a risk score from 0 (benign) to 10 (highly malicious) based on static evidence and current threat trends.

File Evidence:
- Path: {file_path}
- Filename: {context.get('filename','N/A')}
- Folder: {context.get('folder','N/A')}
- Size: {pe_metadata.get('size', 'Unknown')} bytes
- PE Sections: {{truncated_sections}} {{sec_note}}
- Section Entropy: {json.dumps(pe_metadata.get('section_entropy', {}), indent=2)}
- PE Imports: {{truncated_imports}} {{imp_note}}
- Resources/VersionInfo: {{truncated_resources}} {{res_note}}
- Imphash: {pe_metadata.get('imphash', 'None')}
- Capabilities Detected: {{truncated_caps}}
- Vendor Guess: {vendor}
- Timestamps: {context.get('timestamps','N/A')}
- Located in System32: {context.get('is_system32','N/A')}
- Downloaded by user: {context.get('downloaded_by_user','N/A')}
- Installed via Windows Update: {context.get('windows_update','N/A')}
- Script File: {context.get('script_file','N/A')}
- SHA256: {file_hash}
- Matched Current Trends: {{matched_trends}}

Instructions:
Provide a risk score (0-10) and explain your reasoning, correlating evidence (context, entropy, imports, vendor conflicts, strings) with matched current trends. High entropy or dangerous APIs in isolation might be benign if context suggests otherwise. Focus on suspicious *combinations* and trend matches.
Output *only* a valid JSON object with 'risk_score' and 'reasoning' keys.

Example PE Analysis (Malicious):
{{
  "risk_score": 9,
  "reasoning": "High-confidence malware. Combination of: User-downloaded, high entropy (7.8) indicating packing, dangerous APIs ('CreateRemoteThread'), no valid vendor, and matches current trend 'Threat actor XYZ using packed loaders'."
}}

Example PE Analysis (Suspicious):
{{
  "risk_score": 7,
  "reasoning": "Suspicious. Claims 'Microsoft' in resources but downloaded by user and has conflicting string hints ('evil_corp'). Benign imports suggest packing or backdoor. Matches trend 'Fake Microsoft updates observed'. Requires dynamic analysis."
}}

Your Analysis:
"""

    # --- Common Formatting for Both PE and Script (after capabilities determined) ---
    truncated_caps_json = "{}" # Default empty JSON
    if final_capabilities: # Check if capabilities dict is not empty
        truncated_caps_dict = {}
        max_snippet_len = config.get('MAX_EVIDENCE_STRING_LENGTH', 256)
        for key, value_list in final_capabilities.items():
            if isinstance(value_list, list):
                # Ensure snippets are strings and truncate
                t_list_snippets = [str(s)[:max_snippet_len] for s in value_list if isinstance(s, str)]
                t_list, note = truncate_list(t_list_snippets)
                # Only add if there are matches after filtering/truncation
                if t_list:
                    truncated_caps_dict[key] = {'matches': t_list, 'note': note.strip()}
            # Do not include non-list capability values unless explicitly needed
        if truncated_caps_dict: # Only dump if not empty
             truncated_caps_json = json.dumps(truncated_caps_dict, indent=2)

    # Use .format() for delayed substitution after all variables are set
    final_prompt = prompt_template.format(
        truncated_caps=truncated_caps_json,
        matched_trends=matched_trends or "None",
        # These are only needed for PE, provide defaults for scripts
        truncated_sections=truncate_list(pe_metadata.get('sections', []))[0],
        sec_note=truncate_list(pe_metadata.get('sections', []))[1],
        truncated_imports=truncate_list(pe_metadata.get('imports', []))[0],
        imp_note=truncate_list(pe_metadata.get('imports', []))[1],
        truncated_resources=truncate_list(pe_metadata.get('resources', []))[0], # Using raw resources list for PE
        res_note=truncate_list(pe_metadata.get('resources', []))[1]
    )

    return final_prompt


def analyze_file(file_path):
    """Analyzes a single file and generates a report."""
    start_time = time.time() # Start timing
    print(f"\n--- Analyzing file: {file_path} ---")
    try:
        # Read file with size check BEFORE reading content
        max_file_size_mb = config.get("MAX_FILE_SIZE_MB", 100)
        file_size = os.path.getsize(file_path)
        file_size_mb = file_size / (1024 * 1024)

        if file_size_mb > max_file_size_mb:
            err_msg = f"File size ({file_size_mb:.2f} MB) exceeds maximum limit ({max_file_size_mb} MB)."
            print(f"Error: {err_msg}", file=sys.stderr)
            return f'{{"risk_score": -1, "reasoning": "{err_msg}"}}'

        print(f"File size: {file_size_mb:.2f} MB.")
        with open(file_path, "rb") as f:
            file_data = f.read()

    except (IOError, OSError) as e: # Catch file access errors
        print(f"Error accessing file: {e}", file=sys.stderr)
        return f'{{"risk_score": -1, "reasoning": "Error accessing file: {e}"}}'

    # Generate the appropriate prompt based on file type
    prompt = generate_prompt(file_path, file_data)
    if not prompt or '"risk_score": -1' in prompt[:50]: # Check start of string for early errors
        print("Analysis skipped due to error during prompt generation.", file=sys.stderr)
        return prompt or f'{{"risk_score": -1, "reasoning": "Unknown error during prompt generation."}}'

    # Make the call to the AI using analyze_text function
    try:
        print("Sending prompt to AI for analysis...")
        ai_start_time = time.time()
        # Use analyze_text function instead of model.generate
        result = analyze_text(prompt)
        ai_duration = time.time() - ai_start_time
        print(f"AI analysis completed in {ai_duration:.2f} seconds.")

        # --- Robust JSON Extraction ---
        # Look for JSON block potentially wrapped in markdown
        # Extract the response content from the result dictionary
        response_content = result.get('reasoning', '') if isinstance(result, dict) else str(result)
        json_match = re.search(r'```json\s*(\{.*?\}\s*)```|(\{.*?\})', response_content, re.DOTALL | re.MULTILINE)
        final_json_str = None
        if json_match:
            json_str_candidate = json_match.group(1) or json_match.group(2)
            try:
                # Validate final JSON structure
                parsed_json = json.loads(json_str_candidate)
                if 'risk_score' in parsed_json and 'reasoning' in parsed_json:
                    final_json_str = json_str_candidate # It's good JSON
                else:
                    raise ValueError("Missing required keys")
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Warning: AI output contained JSON-like text but parsing/validation failed ({e}).", file=sys.stderr)
        else:
            print("Warning: Could not find valid JSON object {...} in AI output.", file=sys.stderr)

        total_duration = time.time() - start_time
        print(f"Total analysis time: {total_duration:.2f} seconds.")

        if final_json_str:
             return final_json_str # Return only the valid JSON part
        else:
             # Fallback: Return an error JSON if extraction failed
             print(f"Raw AI output snippet: {result[:500]}...", file=sys.stderr)
             return f'{{"risk_score": -1, "reasoning": "Failed to extract valid JSON from AI response."}}'
        # --- End Robust JSON Extraction ---

    except NotImplementedError as e:
         print(f"FATAL: Mistral7B library error: {e}", file=sys.stderr)
         return '{"risk_score": -1, "reasoning": "Mistral7B library error: ' + str(e) + '"}'
    except Exception as e:
        print(f"Error during AI generation for {file_path}: {e}", file=sys.stderr)
        # Add total duration even on error
        total_duration = time.time() - start_time
        print(f"Total analysis time (ended in error): {total_duration:.2f} seconds.")
        return '{"risk_score": -1, "reasoning": "Error during AI generation: ' + str(e) + '"}'


# ----- Main Execution -----
if __name__ == "__main__":
    startup_start_time = time.time()
    print("--- Initializing Semantic File Analyzer ---")

    # --- Fetch and Analyze Trends ONCE at Startup ---
    feed_urls = config.get("CYBERSECURITY_FEEDS", [
        # Provide sensible defaults if not in config
        "https://blog.malwarebytes.com/feed/",
        "https://www.crowdstrike.com/blog/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://threatpost.com/feed/",
        "https://www.bleepingcomputer.com/feed/",
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
        # "https://cert.europa.eu/rss/" # Sometimes problematic
    ])
    if feed_urls:
        feed_entries = fetch_feed_data(feed_urls)
        analyze_trends_with_ai(feed_entries)
    else:
        print("No 'CYBERSECURITY_FEEDS' found or configured. Skipping trend analysis.")
    startup_duration = time.time() - startup_start_time
    print(f"--- Initialization and trend analysis completed in {startup_duration:.2f} seconds ---")
    # --- End Trend Analysis ---

    if len(sys.argv) != 2:
        print("\nUsage: python semantic_file_analyzer_with_trends.py <file_path>")
        sys.exit(1)

    file_path_arg = sys.argv[1]
    if not os.path.exists(file_path_arg):
        print(f"Error: File does not exist: {file_path_arg}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(file_path_arg):
         print(f"Error: Provided path is not a file: {file_path_arg}", file=sys.stderr)
         sys.exit(1)


    semantic_report_json_str = analyze_file(file_path_arg)
    print("\n=== Semantic File Analysis Result ===\n")
    # Attempt to pretty-print if it's valid JSON, otherwise print raw
    try:
        report_json = json.loads(semantic_report_json_str)
        print(json.dumps(report_json, indent=2))
    except json.JSONDecodeError:
        print("Analysis resulted in non-JSON or invalid JSON output:")
        print(semantic_report_json_str)
    except Exception as e:
         print(f"Error processing final report: {e}")
         print(semantic_report_json_str)
