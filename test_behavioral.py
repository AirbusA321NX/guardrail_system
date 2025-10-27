import os
import sys
import logging
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).parent))

from ai.static_analyzer import ThreatAnalyzer, analyze_behavior

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('behavioral_analysis.log')
    ]
)
logger = logging.getLogger(__name__)

def test_behavioral_analysis(file_path: str):
    """Test behavioral analysis on a file"""
    try:
        # Initialize the analyzer with 128-dimensional features
        analyzer = ThreatAnalyzer(feature_dim=128)
        
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error("File not found: %s", file_path)
            return
            
        logger.info("Analyzing file: %s", file_path)
        
        # Analyze the file
        result = analyze_behavior(file_path, analyzer)
        
        # Print results
        print("\n=== Analysis Results ===")
        print(f"File: {result.get('file_path')}")
        print(f"Hash: {result.get('file_hash')}")
        print(f"Is Anomaly: {result.get('is_anomaly', False)}")
        print(f"Confidence: {result.get('confidence', 0):.2f}%")
        print(f"Reconstruction Error: {result.get('reconstruction_error', 0):.4f}")
        print(f"Threshold: {result.get('threshold', 0.1):.4f}")
        print(f"Action: {result.get('action', 'Unknown')}")
        
        if result.get('is_anomaly'):
            print("\nIndicators:")
            for indicator in result.get('indicators', []):
                print(f"- {indicator}")
        
        similar = result.get('similar_cases', [])
        if similar:
            print("\nSimilar Cases:")
            for case in similar:
                print(f"- {case.get('file_path', 'Unknown')} (Similarity: {case.get('similarity', 0):.2f})")
        
        return result
        
    except Exception as e:
        logger.error("Error during analysis: %s", str(e), exc_info=True)
        raise

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_behavioral.py <path_to_file>")
        sys.exit(1)
    
    test_behavioral_analysis(sys.argv[1])
