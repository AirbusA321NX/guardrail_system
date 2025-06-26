import os
from kubernetes import client, config
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup


def collect_pod_metadata(pod):
    metadata = {
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "node": pod.spec.node_name,
        "service_account": pod.spec.service_account_name,
        "hostPID": pod.spec.host_pid,
        "hostIPC": pod.spec.host_ipc,
        "hostNetwork": pod.spec.host_network,
        "volumes": [vol.host_path.path for vol in pod.spec.volumes or [] if vol.host_path],
        "containers": []
    }

    for container in pod.spec.containers:
        container_info = {
            "name": container.name,
            "image": container.image,
            "command": container.command,
            "args": container.args,
            "resources": str(container.resources),
            "privileged": getattr(container.security_context, 'privileged', False),
            "env": []
        }

        for env in container.env or []:
            if hasattr(env, 'value_from') and getattr(env.value_from, 'secret_key_ref', None):
                container_info["env"].append(f"{env.name}=<REDACTED_SECRET>")
            else:
                container_info["env"].append(f"{env.name}")

        metadata["containers"].append(container_info)

    return metadata


def summarize_containers(container_list):
    summary = ""
    for c in container_list:
        summary += (
            f"- Name: {c['name']}, Image: {c['image']}, "
            f"Command: {c['command']}, Args: {c['args']}, "
            f"Privileged: {c['privileged']}, Env Vars: {c['env']}\n"
        )
    return summary


def analyze_pod_with_mistral(pod_metadata):
    container_summary = summarize_containers(pod_metadata["containers"])

    prompt = f"""Analyze this Kubernetes pod for signs of malicious activity or misconfiguration:

Pod Name: {pod_metadata['name']}
Namespace: {pod_metadata['namespace']}
Node: {pod_metadata['node']}
Service Account: {pod_metadata['service_account']}
HostPID: {pod_metadata['hostPID']}
HostIPC: {pod_metadata['hostIPC']}
HostNetwork: {pod_metadata['hostNetwork']}
Mounted Host Paths: {pod_metadata['volumes']}

Containers:
{container_summary}

Please determine if this pod is dangerous or suspicious and explain why."""

    return analyze_text(prompt)


def monitor_kubernetes_pods():
    try:
        config.load_kube_config()
    except Exception:
        config.load_incluster_config()

    v1 = client.CoreV1Api()
    pods = v1.list_pod_for_all_namespaces(watch=False)

    for pod in pods.items:
        try:
            pod_metadata = collect_pod_metadata(pod)
            result = analyze_pod_with_mistral(pod_metadata)

            pod_name = f"{pod_metadata['namespace']}/{pod_metadata['name']}"

            if isinstance(result, dict) and result.get("DANGEROUS"):
                reason = result.get("reason", "No reason provided")
                show_popup("Guardrail Kubernetes Alert", f"Pod: {pod_name}\n\n{reason}")
                log_event("K8S_POD_FLAGGED", f"{pod_name} | {reason}")
            elif isinstance(result, dict):
                log_event("K8S_POD_SAFE", f"{pod_name} | {result}")
            else:
                log_event("K8S_AI_INVALID_RESPONSE", f"{pod_name} | Raw result: {result}")
        except Exception as e:
            log_event("K8S_POD_SCAN_ERROR", f"{pod.metadata.name}: {str(e)}")
