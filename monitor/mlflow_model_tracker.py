# monitor/mlflow_model_tracker.py

import os
from utils.logger import log_event

# Configuration
MLFLOW_TRACKING_URI = os.getenv("GUARDRAIL_MLFLOW_URI", "http://localhost:5000")
EXPERIMENT_NAME = "Guardrail_Mistral_AuditTrail"

# Don't import mlflow at module level to prevent connection attempts during import
# MLFLOW_AVAILABLE will be set to False by default and only set to True if mlflow can be imported and connected
MLFLOW_AVAILABLE = False

def track_model_decision(module_name, input_prompt, mistral_response, metadata=None):
    """
    Logs AI decisions and metadata into MLflow for reproducibility and compliance.
    This function is completely lazy - it only imports and initializes MLflow when first called.
    """
    global MLFLOW_AVAILABLE
    
    # If MLflow is already determined to be unavailable, skip tracking
    if not MLFLOW_AVAILABLE and MLFLOW_AVAILABLE is not None:
        return
    
    # If this is the first call, try to import and initialize MLflow
    if MLFLOW_AVAILABLE is False:
        try:
            # Import mlflow only when needed
            import mlflow
            
            # Set tracking URI
            mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
            
            # Try to set experiment (this will test the connection)
            mlflow.set_experiment(EXPERIMENT_NAME)
            
            # Test connection by trying to get the experiment
            mlflow.get_experiment_by_name(EXPERIMENT_NAME)
            
            MLFLOW_AVAILABLE = True
            log_event("MLFLOW_CONNECTED", "Successfully connected to MLflow at %s" % MLFLOW_TRACKING_URI)
            
            # Now proceed with tracking
            _do_track_model_decision(mlflow, module_name, input_prompt, mistral_response, metadata)
        except Exception as e:
            log_event("MLFLOW_CONNECTION_ERROR", "Failed to connect to MLflow server at %s: %s" % (MLFLOW_TRACKING_URI, str(e)))
            log_event("MLFLOW_FALLBACK", "MLflow tracking will be disabled for the rest of this session")
            MLFLOW_AVAILABLE = None  # Use None to indicate we've tried and failed
            return
    # If MLflow is available, proceed with tracking
    elif MLFLOW_AVAILABLE:
        try:
            import mlflow
            _do_track_model_decision(mlflow, module_name, input_prompt, mistral_response, metadata)
        except Exception as e:
            log_event("MLFLOW_TRACK_FAIL", "%s | %s" % (module_name, str(e)))

def _do_track_model_decision(mlflow, module_name, input_prompt, mistral_response, metadata=None):
    """
    Actually perform the MLflow tracking.
    """
    from datetime import datetime
    
    try:
        with mlflow.start_run(run_name="%s_%s" % (module_name, datetime.utcnow().isoformat().replace(':', '-'))):
            mlflow.log_param("Module", module_name)
            mlflow.log_param("Timestamp", datetime.utcnow().isoformat())

            mlflow.log_text(input_prompt, "input_prompt.txt")
            mlflow.log_text(str(mistral_response), "mistral_response.json")

            if metadata:
                for key, val in metadata.items():
                    mlflow.log_param(key, str(val))

            log_event("MLFLOW_TRACK_SUCCESS", "%s decision logged." % module_name)
    except Exception as e:
        log_event("MLFLOW_TRACK_FAIL", "%s | %s" % (module_name, str(e)))