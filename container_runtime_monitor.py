import docker
import time
import json
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

def collect_container_metadata(container):
    try:
        inspect = container.attrs
        processes = container.top().get("Processes", [])
        logs = container.logs(tail=100).decode('utf-8', errors='ignore')

        metadata = {
            "name": container.name,
            "id": container.short_id,
            "privileged": inspect.get("HostConfig", {}).get("Privileged", False),
            "capabilities": inspect.get("HostConfig", {}).get("CapAdd", []),
            "log_snippet": logs[:1000],
            "env": inspect.get("Config", {}).get("Env", []),
            "entrypoint": inspect.get("Config", {}).get("Entrypoint", []),
            "cmd": inspect.get("Config", {}).get("Cmd", []),
            "processes": processes
        }
        return metadata
    except Exception as e:
        log_event("CONTAINER_METADATA_ERROR", str(e))
        return None

def analyze_container_with_ai(metadata):
    try:
        prompt = (
            "You are a cybersecurity AI analyzing Docker container behavior.\n"
            "Analyze the following metadata and determine if it is suspicious or malicious:\n\n"
            f"{json.dumps(metadata, indent=2)}\n\n"
            "Respond ONLY in this JSON format:\n"
            '{ "DANGEROUS": true/false, "reason": "Concise reason for classification" }'
        )
        result = analyze_text(prompt)
        return result if isinstance(result, dict) else None
    except Exception as e:
        log_event("MISTRAL_ANALYSIS_ERROR", str(e))
        return None

def monitor_containers():
    client = docker.from_env()

    while True:
        try:
            containers = client.containers.list()
            for container in containers:
                metadata = collect_container_metadata(container)
                if not metadata:
                    continue

                result = analyze_container_with_ai(metadata)
                if not result:
                    continue

                if result.get("DANGEROUS", False):
                    reason = result.get("reason", "Unknown reason")
                    show_popup("Guardrail Alert: Container Threat Detected", f"{metadata['name']}\n{reason}")
                    log_event("CONTAINER_FLAGGED", f"{metadata['name']} | {reason}")
                else:
                    log_event("CONTAINER_SAFE", f"{metadata['name']} | {result.get('reason', 'No issues')}")
        except Exception as e:
            log_event("CONTAINER_MONITOR_ERROR", str(e))

        time.sleep(10)  # Adjustable scan interval
