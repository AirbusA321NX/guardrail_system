# monitor/mlflow_model_tracker.py

import os
import mlflow
from datetime import datetime
from utils.logger import log_event

MLFLOW_TRACKING_URI = os.getenv("GUARDRAIL_MLFLOW_URI", "http://localhost:5000")
EXPERIMENT_NAME = "Guardrail_Mistral_AuditTrail"

mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
mlflow.set_experiment(EXPERIMENT_NAME)


def track_model_decision(module_name, input_prompt, mistral_response, metadata=None):
    """
    Logs AI decisions and metadata into MLflow for reproducibility and compliance.
    """
    try:
        with mlflow.start_run(run_name=f"{module_name}_{datetime.utcnow().isoformat()}"):
            mlflow.log_param("Module", module_name)
            mlflow.log_param("Timestamp", datetime.utcnow().isoformat())

            mlflow.log_text(input_prompt, "input_prompt.txt")
            mlflow.log_text(str(mistral_response), "mistral_response.json")

            if metadata:
                for key, val in metadata.items():
                    mlflow.log_param(key, str(val))

            log_event("MLFLOW_TRACK_SUCCESS", f"{module_name} decision logged.")
    except Exception as e:
        log_event("MLFLOW_TRACK_FAIL", f"{module_name} | {str(e)}")
