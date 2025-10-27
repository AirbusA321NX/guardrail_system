import sys
from pathlib import Path
import json
import pandas as pd
import requests
from tqdm import tqdm
import argparse

# Add the project root to the Python path
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.append(str(project_root))

from utils.logger import setup_logging, get_logger

# --- Setup ---
setup_logging("ollama_analysis.log")
logger = get_logger(__name__)

def query_ollama(prompt: str, model_name: str, ollama_host: str) -> str:
    """Sends a prompt to the Ollama API and returns the response."""
    try:
        url = f"http://{ollama_host}:11434/api/generate"
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": 50 # Limit response length
            }
        }
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        return response.json().get('response', '').strip()
    except requests.exceptions.RequestException as e:
        logger.error("Failed to connect to Ollama at %s: %s", ollama_host, e)
        return "Error: Could not connect to Ollama."

def create_analysis_prompt(report: dict, classification_families: list) -> str:
    """Creates a detailed prompt for the LLM based on the CAPE report."""
    
    summary = report.get('behavior', {}).get('summary', {})
    api_calls = summary.get('resolved_apis', [])[:20]
    reg_keys = summary.get('read_keys', [])[:10] + summary.get('write_keys', [])[:10]
    
    prompt = f"""
Analyze the following malware report summary and classify it into one of the following categories: {', '.join(classification_families)}.
Provide only the single best category name as your answer.

Report Details:
- Resolved API Calls: {', '.join(api_calls)}
- Accessed Registry Keys: {', '.join(reg_keys)}

Based on this data, what is the most likely malware classification?
Category: """
    return prompt

def main():
    parser = argparse.ArgumentParser(description="Analyze CAPE reports using an Ollama LLM.")
    parser.add_argument('--dataset_dir', type=str, default="D:/pycharm/guardrail_system/dataset/Public_Avast_CTU_CAPEv2_Dataset_Small", help="Path to the root dataset directory.")
    parser.add_argument('--ollama_model', type=str, default="cape-mistral:latest", help="Name of the custom fine-tuned Ollama model to use.")
    parser.add_argument('--ollama_host', type=str, default="localhost", help="Hostname or IP address of the Ollama server.")
    parser.add_argument('--limit', type=int, default=100, help="Number of reports to analyze (default: 100).")
    args = parser.parse_args()

    # --- Configuration ---
    dataset_dir = Path(args.dataset_dir)
    reports_dir = dataset_dir / "extracted_reports" / "public_small_reports"
    labels_file = dataset_dir / "public_labels.csv"

    if not dataset_dir.exists():
        logger.error("Dataset directory not found: %s", dataset_dir)
        return

    # --- Load Data ---
    logger.info("Loading labels...")
    labels_df = pd.read_csv(labels_file)
    labels_map = labels_df.set_index('sha256')['classification_family'].to_dict()
    unique_labels = sorted(labels_df['classification_family'].unique().tolist())
    
    logger.info("Found %d labels across %d families.", len(labels_map), len(unique_labels))

    # --- Analysis Loop ---
    correct_predictions = 0
    total_analyzed = 0
    
    # Limit the number of items to process
    items_to_process = list(labels_map.items())[:args.limit]

    logger.info("Starting analysis of %d reports with Ollama model '%s'...", len(items_to_process), args.ollama_model)

    for sha256, true_label in tqdm(items_to_process, desc="Analyzing Reports"):
        report_path = reports_dir / f"{sha256}.json"
        if not report_path.exists():
            continue

        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            logger.warning("Could not read or parse %s", report_path)
            continue

        # Create prompt and query Ollama
        prompt = create_analysis_prompt(report_data, unique_labels)
        llm_response = query_ollama(prompt, args.ollama_model, args.ollama_host)

        # Clean up the response to get just the label
        predicted_label = llm_response.split('\n')[0].strip().lower()
        true_label_lower = true_label.lower()

        if predicted_label == true_label_lower:
            correct_predictions += 1
            logger.info("CORRECT: %s -> Predicted: '%s', True: '%s'", sha256, predicted_label, true_label_lower)
        else:
            logger.warning("INCORRECT: %s -> Predicted: '%s', True: '%s'", sha256, predicted_label, true_label_lower)
        
        total_analyzed += 1

    # --- Report Results ---
    if total_analyzed > 0:
        accuracy = (correct_predictions / total_analyzed) * 100
        logger.info("\n--- Analysis Complete ---")
        logger.info("Total Reports Analyzed: %d", total_analyzed)
        logger.info("Correct Predictions: %d", correct_predictions)
        logger.info("Accuracy: %.2f%%", accuracy)
    else:
        logger.info("No reports were analyzed.")

if __name__ == "__main__":
    # Make sure your Ollama server is running before executing this script.
    # Example: ollama run llama3:8b
    main()