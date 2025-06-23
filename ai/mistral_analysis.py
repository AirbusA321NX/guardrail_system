import threading
import json
import ollama
from utils.logger import log_event

_lock = threading.Lock()

def analyze_text(prompt: str) -> dict:
    try:
        full_prompt = (
            "You are a security monitoring AI. Carefully analyze the following command.\n"
            "Respond ONLY in this strict JSON format:\n"
            '{ "DANGEROUS": true/false, "reason": "Short explanation of the risk or why it is safe." }\n\n'
            "Command:\n" + prompt
        )

        with _lock:
            response = ollama.chat(
                model="mistral:7b-instruct-q4_K_M",  # Or your actual model tag
                messages=[{"role": "user", "content": full_prompt}]
            )

        content = response.get("message", {}).get("content", "").strip()

        # Parse AI response strictly as JSON
        parsed = json.loads(content)
        if isinstance(parsed, dict) and "DANGEROUS" in parsed and "reason" in parsed:
            return parsed
        else:
            log_event("AI_BAD_RESPONSE", f"Unexpected format: {content}")
            return {
                "DANGEROUS": False,
                "reason": "Invalid response format. Treated as safe."
            }

    except json.JSONDecodeError:
        log_event("AI_JSON_FAIL", f"Failed to parse JSON from: {content}")
        return {
            "DANGEROUS": False,
            "reason": "Malformed AI response. Treated as safe."
        }

    except Exception as e:
        log_event("AI_ERROR", f"Ollama exception: {e}")
        return {
            "DANGEROUS": False,
            "reason": "AI error. Command assumed safe."
        }
