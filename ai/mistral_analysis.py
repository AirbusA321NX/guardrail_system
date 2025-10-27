import threading
import json
import ollama
import sqlite3
import numpy as np
from utils.logger import log_event
from sklearn.metrics.pairwise import cosine_similarity
import os
from pathlib import Path

# Import the MLflow tracker
try:
    from monitor.mlflow_model_tracker import track_model_decision
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    track_model_decision = None
    log_event("MLFLOW_IMPORT_ERROR", "Failed to import MLflow tracker")

# Simple embedding function using character n-grams
def simple_embedding(text, n=3, dim=128):
    """Generate a simple embedding using character n-grams"""
    # Create character n-grams
    ngrams = [text[i:i+n] for i in range(len(text)-n+1)]
    
    # Create a fixed-size vector
    vector = np.zeros(dim)
    
    # Hash n-grams to vector positions
    for ngram in ngrams:
        # Simple hash function
        hash_val = hash(ngram) % dim
        vector[hash_val] += 1
    
    # Normalize the vector
    norm = np.linalg.norm(vector)
    if norm > 0:
        vector = vector / norm
    
    return vector

# RAG Components
class RAGPipeline:
    def __init__(self, db_path="rag_embeddings.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database for storing embeddings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS embeddings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text_chunk TEXT NOT NULL,
                embedding BLOB NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
    
    def add_examples(self, examples):
        """Add examples to the RAG database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for example in examples:
            # Generate embedding using simple method
            embedding = simple_embedding(example)
            # Convert to bytes for storage
            embedding_blob = embedding.astype(np.float32).tobytes()
            
            # Insert into database
            cursor.execute(
                "INSERT INTO embeddings (text_chunk, embedding) VALUES (?, ?)",
                (example, embedding_blob)
            )
        
        conn.commit()
        conn.close()
    
    def retrieve_examples(self, query, top_k=5):
        """Retrieve relevant examples for a query"""
        # Generate query embedding
        query_embedding = simple_embedding(query)
        query_embedding = query_embedding.astype(np.float32).reshape(1, -1)
        
        # Retrieve all embeddings from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT text_chunk, embedding FROM embeddings")
        
        examples = []
        similarities = []
        
        for text_chunk, embedding_blob in cursor.fetchall():
            # Convert blob back to numpy array
            stored_embedding = np.frombuffer(embedding_blob, dtype=np.float32).reshape(1, -1)
            
            # Calculate cosine similarity
            similarity = cosine_similarity(
                query_embedding,
                stored_embedding
            )[0][0]
            
            examples.append(text_chunk)
            similarities.append(similarity)
        
        conn.close()
        
        # Sort by similarity and return top_k
        sorted_pairs = sorted(zip(examples, similarities), key=lambda x: x[1], reverse=True)
        return [example for example, _ in sorted_pairs[:top_k]]

# Initialize RAG pipeline
rag_pipeline = RAGPipeline()

def initialize_rag_with_dataset(dataset_path=None):
    """
    Initialize the RAG pipeline with security examples.
    If dataset_path is provided, load examples from that file.
    Otherwise, use a set of default security examples.
    """
    # If dataset path is provided and exists, load examples from it
    if dataset_path and os.path.exists(dataset_path):
        try:
            # Handle different dataset formats
            if dataset_path.endswith('.json'):
                with open(dataset_path, 'r') as f:
                    # Assuming dataset is a JSON file with a list of examples
                    dataset_examples = json.load(f)
                    if isinstance(dataset_examples, list):
                        # Add dataset examples to RAG
                        rag_pipeline.add_examples(dataset_examples)
                        log_event("RAG_INITIALIZED", f"RAG initialized with {len(dataset_examples)} examples from dataset")
                        return
            elif dataset_path.endswith('.txt'):
                with open(dataset_path, 'r') as f:
                    # Assuming each line is an example
                    dataset_examples = [line.strip() for line in f.readlines() if line.strip()]
                    rag_pipeline.add_examples(dataset_examples)
                    log_event("RAG_INITIALIZED", f"RAG initialized with {len(dataset_examples)} examples from dataset")
                    return
            elif os.path.isdir(dataset_path):
                # If it's a directory, look for JSON files inside (Avast CTU CAPEv2 format)
                json_files = list(Path(dataset_path).rglob("*.json"))
                all_examples = []
                
                # Process JSON files (Avast CTU CAPEv2 format)
                for json_file in json_files[:2000]:  # Increase limit to 2000 files for better coverage
                    try:
                        with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                            data = json.load(f)
                            
                            # Extract behavior summary information
                            if 'behavior' in data and 'summary' in data['behavior']:
                                summary = data['behavior']['summary']
                                
           
                                if 'keys' in summary and summary['keys']:
                                    for key in summary['keys'][:5]:  # Increase to first 5 keys
                                        all_examples.append(f"Registry modification: {key}")
                                
                                # File-related examples with more comprehensive extraction
                                if 'files' in summary and summary['files']:
                                    for file in summary['files'][:5]:  # Increase to first 5 files
                                        all_examples.append(f"File access: {file}")
                                
                                # Mutex-related examples with more comprehensive extraction
                                if 'mutexes' in summary and summary['mutexes']:
                                    for mutex in summary['mutexes'][:5]:  # Increase to first 5 mutexes
                                        all_examples.append(f"Mutex creation: {mutex}")
                                
                                # Service-related examples with more comprehensive extraction
                                if 'created_services' in summary and summary['created_services']:
                                    for service in summary['created_services'][:3]:  # Increase to first 3 services
                                        all_examples.append(f"Service creation: {service}")
                                
                                # Command-related examples with more comprehensive extraction
                                if 'executed_commands' in summary and summary['executed_commands']:
                                    for command in summary['executed_commands'][:3]:  # Increase to first 3 commands
                                        all_examples.append(f"Command execution: {command}")
                                
                                # Process-related examples
                                if 'processes' in summary and summary['processes']:
                                    for process in summary['processes'][:3]:  # Add first 3 processes
                                        all_examples.append(f"Process creation: {process}")
                                
                                # Network-related examples
                                if 'urls' in summary and summary['urls']:
                                    for url in summary['urls'][:3]:  # Add first 3 URLs
                                        all_examples.append(f"Network connection: {url}")
                                
                                # Write file examples
                                if 'write_files' in summary and summary['write_files']:
                                    for file in summary['write_files'][:3]:  # Add first 3 write files
                                        all_examples.append(f"File write: {file}")
                                
                                # Delete file examples
                                if 'delete_files' in summary and summary['delete_files']:
                                    for file in summary['delete_files'][:3]:  # Add first 3 delete files
                                        all_examples.append(f"File deletion: {file}")
                                
                                # Read file examples
                                if 'read_files' in summary and summary['read_files']:
                                    for file in summary['read_files'][:3]:  # Add first 3 read files
                                        all_examples.append(f"File read: {file}")
                                
                                # Started services examples
                                if 'started_services' in summary and summary['started_services']:
                                    for service in summary['started_services'][:3]:  # Add first 3 started services
                                        all_examples.append(f"Service start: {service}")
                                
                                # Delete keys examples
                                if 'delete_keys' in summary and summary['delete_keys']:
                                    for key in summary['delete_keys'][:3]:  # Add first 3 delete keys
                                        all_examples.append(f"Registry deletion: {key}")
                                
                                # Resolved APIs examples
                                if 'resolved_apis' in summary and summary['resolved_apis']:
                                    for api in summary['resolved_apis'][:3]:  # Add first 3 resolved APIs
                                        all_examples.append(f"API call: {api}")
                    
                    except (json.JSONDecodeError, KeyError, IOError) as e:
                        # Skip files that can't be processed
                        continue
                
                if all_examples:
                    # Limit to a reasonable number of examples to avoid memory issues
                    limited_examples = all_examples[:10000]  # Increase to 10000 examples for better coverage
                    rag_pipeline.add_examples(limited_examples)
                    log_event("RAG_INITIALIZED", f"RAG initialized with {len(limited_examples)} examples from dataset directory")
                    return
        except Exception as e:
            log_event("RAG_DATASET_ERROR", f"Failed to load dataset: {str(e)}")
    
    # If no dataset provided or loading failed, initialize with empty database
    log_event("RAG_INITIALIZED", "RAG initialized with empty database")

# Initialize RAG with the Avast dataset if available
# Check multiple possible paths for the dataset
possible_dataset_paths = [
    "dataset/Public_Avast_CTU_CAPEv2_Dataset_Small/extracted_reports/public_small_reports",
    "dataset/Public_Avast_CTU_CAPEv2_Dataset_Small",
    "dataset/Public_avast_CTU_CAPEv2",
    "Public_avast_CTU_CAPEv2"
]

dataset_path_to_use = None
for path in possible_dataset_paths:
    if os.path.exists(path):
        dataset_path_to_use = path
        break

if dataset_path_to_use:
    initialize_rag_with_dataset(dataset_path_to_use)
else:
    log_event("RAG_DATASET_NOT_FOUND", "No dataset found, initializing with empty database")

_lock = threading.Lock()

def analyze_text(prompt: str, **metadata) -> dict:
    content = ""  # Initialize content to avoid unbound variable error
    result = {
        "DANGEROUS": False,
        "reason": "Default safe response"
    }  # Initialize result with a default safe response
    
    # Initialize variables that might be used later
    is_threat_intel = False
    full_prompt = prompt
    relevant_examples = []  # Initialize here to fix unbound variable error
    
    try:
        # Check if this is a threat intelligence prompt (different from command analysis)
        is_threat_intel = "Analyze this security article" in prompt
        
        # Use RAG to retrieve relevant examples
        relevant_examples = rag_pipeline.retrieve_examples(prompt, top_k=5)
        
        if is_threat_intel:
            # Use a prompt format suitable for threat intelligence analysis
            # Include retrieved examples if available
            if relevant_examples:
                examples_text = "\n\nRelevant examples from security dataset:\n" + "\n".join(f"- {example}" for example in relevant_examples)
                full_prompt = prompt + examples_text
            else:
                full_prompt = prompt
        else:
            # Use the original prompt format for command analysis
            # Include retrieved examples if available
            if relevant_examples:
                examples_text = "\n\nRelevant examples from security dataset:\n" + "\n".join(f"- {example}" for example in relevant_examples)
                full_prompt = (
                    "You are a security monitoring AI. Carefully analyze the following command.\n"
                    "Respond ONLY in this strict JSON format:\n"
                    '{ "DANGEROUS": true/false, "reason": "Short explanation of the risk or why it is safe." }\n\n'
                    "Consider these similar examples when analyzing:\n" + examples_text + "\n\n"
                    "Command:\n" + prompt
                )
            else:
                full_prompt = (
                    "You are a security monitoring AI. Carefully analyze the following command.\n"
                    "Respond ONLY in this strict JSON format:\n"
                    '{ "DANGEROUS": true/false, "reason": "Short explanation of the risk or why it is safe." }\n\n'
                    "Command:\n" + prompt
                )

        with _lock:
            response = ollama.chat(
                model="mistral:7b",  # Updated to match your installed model
                messages=[{"role": "user", "content": full_prompt}]
            )

        content = response.get("message", {}).get("content", "").strip()

        # Try to parse the response as JSON
        parsed = None
        try:
            # Extract JSON from the response if it's embedded in other text
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                parsed = json.loads(json_str)
            else:
                # Try to parse the entire content as JSON
                parsed = json.loads(content)
        except json.JSONDecodeError:
            # If JSON parsing fails, return an appropriate error response
            pass

        # Check if we have a valid parsed response
        if parsed is not None:
            if isinstance(parsed, dict):
                # Check if it's in the command analysis format
                if "DANGEROUS" in parsed and "reason" in parsed:
                    result = parsed
                # Check if it's in the threat intelligence format
                elif "relevant" in parsed and "confidence" in parsed:
                    result = parsed
                # If it's a valid dict but not in expected formats, return as-is
                else:
                    result = parsed
            else:
                # If parsed is not a dict, create a default safe response
                result = {
                    "DANGEROUS": False,
                    "reason": "Invalid response format. Treated as safe."
                }
        else:
            # If we get here, the response format is unexpected
            # But let's try to handle the case where the JSON is valid but not properly extracted
            try:
                # Try to parse the content again, being more permissive
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    result = parsed
                else:
                    log_event(event_type="AI_BAD_RESPONSE", message="Unexpected format: {content}", content=content)
                    result = {
                        "DANGEROUS": False,
                        "reason": "Invalid response format. Treated as safe."
                    }
            except json.JSONDecodeError:
                log_event(event_type="AI_BAD_RESPONSE", message="Unexpected format: {content}", content=content)
                result = {
                    "DANGEROUS": False,
                    "reason": "Invalid response format. Treated as safe."
                }

    except json.JSONDecodeError:
        log_event(event_type="AI_JSON_FAIL", message="Failed to parse JSON from: {content}", content=content)
        result = {
            "DANGEROUS": False,
            "reason": "Malformed AI response. Treated as safe."
        }

    except (RuntimeError, OSError) as e:
        log_event(event_type="AI_ERROR", message="Ollama exception: {error}", error=str(e))
        result = {
            "DANGEROUS": False,
            "reason": "AI error. Command assumed safe."
        }
    
    # Track the model decision with MLflow if available
    if MLFLOW_AVAILABLE and track_model_decision is not None:
        try:
            # Determine the module name based on the prompt content
            module_name = "threat_intel" if is_threat_intel else "command_analysis"
            
            # Add any additional metadata passed to the function
            tracking_metadata = {
                "is_threat_intel": is_threat_intel,
                "response_type": type(result).__name__,
                "rag_examples_count": len(relevant_examples),
                **metadata  # Include any additional metadata passed to the function
            }
            
            track_model_decision(module_name, full_prompt, result, tracking_metadata)
        except Exception as e:
            log_event("MLFLOW_TRACKING_ERROR", "Failed to track model decision: %s" % str(e))
    
    return result