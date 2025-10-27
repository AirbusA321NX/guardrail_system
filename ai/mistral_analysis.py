import threading
import json
import ollama
from utils.logger import log_event

# Import the MLflow tracker
try:
    from monitor.mlflow_model_tracker import track_model_decision
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False
    track_model_decision = None
    log_event("MLFLOW_IMPORT_ERROR", "Failed to import MLflow tracker")

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
    
    try:
        # Check if this is a threat intelligence prompt (different from command analysis)
        is_threat_intel = "Analyze this security article" in prompt
        
        if is_threat_intel:
            # Use a prompt format suitable for threat intelligence analysis
            full_prompt = prompt
        else:
            # Use the original prompt format for command analysis
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
                **metadata  # Include any additional metadata passed to the function
            }
            
            track_model_decision(module_name, full_prompt, result, tracking_metadata)
        except Exception as e:
            log_event("MLFLOW_TRACKING_ERROR", "Failed to track model decision: %s" % str(e))
    
    return result