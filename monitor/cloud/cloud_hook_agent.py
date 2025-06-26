# monitor/cloud/cloud_hook_agent.py

import os
import json
import time
import threading
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

# Configuration for serverless scanning thresholds
SCAN_CONFIG = {
    "max_scan_time_ms": 300,
    "fallback_mode": "isolate_and_scan_async"
}

# Simulated metadata from cloud functions (replace with actual hooks if integrated)
def fetch_lambda_metadata(event, context):
    return {
        "function_name": context.function_name,
        "aws_region": context.invoked_function_arn.split(":")[3],
        "trigger_type": event.get("trigger", "unknown"),
        "payload_preview": str(event)[:2000],
        "timeout": context.timeout
    }

def analyze_lambda_function(metadata):
    prompt = f"""
You are an AI malware detection engine for serverless environments.
Analyze this Lambda function invocation and determine if it may be malicious or abused:

Function: {metadata['function_name']}
Region: {metadata['aws_region']}
Trigger: {metadata['trigger_type']}
Timeout: {metadata['timeout']}s
Payload Snippet: {metadata['payload_preview']}

Is this invocation suspicious? Respond with reasoning and risk level.
"""

    return analyze_text(prompt)

def scan_lambda_invocation(event, context):
    try:
        metadata = fetch_lambda_metadata(event, context)

        def async_scan():
            result = analyze_lambda_function(metadata)
            if isinstance(result, dict) and result.get("DANGEROUS"):
                reason = result.get("reason", "Flagged as suspicious Lambda usage.")
                show_popup("Guardrail Cloud Alert", f"{metadata['function_name']}:\n{reason}")
                log_event("LAMBDA_SUSPICIOUS", f"{metadata['function_name']} | {reason}")
            else:
                log_event("LAMBDA_CLEAN", f"{metadata['function_name']} | {result}")

        scan_thread = threading.Thread(target=async_scan)
        scan_thread.start()

        if SCAN_CONFIG["fallback_mode"] == "isolate_and_scan_async":
            log_event("LAMBDA_ASYNC_SCAN", f"{metadata['function_name']} - Delayed analysis")
        else:
            scan_thread.join(timeout=SCAN_CONFIG["max_scan_time_ms"] / 1000.0)

    except Exception as e:
        log_event("LAMBDA_SCAN_FAIL", str(e))
