"""
Test script for the behavioral analysis system
"""
import os
import sys
import json
import argparse
from pathlib import Path
from ai.behavior_analyzer import ThreatAnalyzer, analyze_behavior, calculate_file_hash

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Behavioral Analysis Scanner')
    
    # Add arguments
    parser.add_argument('-f', '--file', help='Scan a single file')
    parser.add_argument('-d', '--directory', help='Scan a directory')
    parser.add_argument('-m', '--menu', action='store_true', help='Show interactive menu')
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    return parser.parse_args()

def scan_single_file(file_path):
    # Initialize the analyzer with 100-dimensional features
    feature_dim = 100
    analyzer = ThreatAnalyzer(feature_dim=feature_dim)
    
    if not os.path.exists(file_path):
        print(f"Error: Test file not found: {file_path}")
        print("Please specify a valid path to an executable file.")
        return
    
    print(f"Analyzing file: {file_path}")
    
    try:
        # Analyze the file
        result = analyze_behavior(file_path, analyzer)
        if not result:
            print("Error: Analysis returned no results")
            return
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return
    
    # Print results
    print("\nAnalysis Results:")
    if not result or 'file_path' not in result:
        print("Analysis failed. No results returned.")
        return
    
    # Calculate file hash if not present
    if 'file_hash' not in result:
        try:
            result['file_hash'] = calculate_file_hash(file_path)
            print("Calculated file hash since it was missing from results")
        except Exception as e:
            print(f"Warning: Could not calculate file hash: {str(e)}")
    
    print(f"File: {result.get('file_path', 'N/A')}")
    print(f"Hash: {result.get('file_hash', 'N/A')}")
    print(f"Is Anomaly: {result.get('is_anomaly', 'N/A')}")
    print(f"Confidence: {result.get('confidence', 0):.2f}%")
    print(f"Reconstruction Error: {result.get('reconstruction_error', 0):.4f}")
    print(f"Threshold: {result.get('threshold', 0):.4f}")
    print(f"Action: {result.get('action', 'N/A')}")
    
    if result.get('is_anomaly'):
        print("\nIndicators:")
        for indicator in result.get('indicators', []):
            print(f"- {indicator}")
    
    if result.get('similar_cases'):
        print("\nSimilar Cases:")
        for case in result.get('similar_cases', []):
            print(f"- {case.get('file_path', 'Unknown')} (Similarity: {case.get('similarity', 0):.2f})")
    
    # Only provide feedback if we have a valid file hash
    if 'file_hash' in result and result['file_hash']:
        print("\nProviding feedback that this was a false positive...")
        try:
            analyzer.update_from_feedback(result['file_hash'], is_false_positive=True)
            print("Feedback submitted successfully")
        except Exception as e:
            print(f"Error providing feedback: {str(e)}")
    else:
        print("\nSkipping feedback - no valid file hash available")
    
    # Save the updated model
    model_path = analyzer.save_model()
    print(f"\nModel saved to: {model_path}")

def scan_directory(directory_path):
    # Initialize the analyzer with 100-dimensional features
    feature_dim = 100
    analyzer = ThreatAnalyzer(feature_dim=feature_dim)
    
    if not os.path.exists(directory_path):
        print(f"Error: Directory not found: {directory_path}")
        print("Please specify a valid path to a directory.")
        return
    
    print(f"Scanning directory: {directory_path}")
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # Analyze the file
                result = analyze_behavior(file_path, analyzer)
                if not result:
                    print(f"Error: Analysis returned no results for {file_path}")
                    continue
            except Exception as e:
                print(f"Error during analysis of {file_path}: {str(e)}")
                continue
            
            # Print results
            print(f"\nAnalysis Results for {file_path}:")
            if not result or 'file_path' not in result:
                print("Analysis failed. No results returned.")
                continue
            
            # Calculate file hash if not present
            if 'file_hash' not in result:
                try:
                    result['file_hash'] = calculate_file_hash(file_path)
                    print("Calculated file hash since it was missing from results")
                except Exception as e:
                    print(f"Warning: Could not calculate file hash: {str(e)}")
            
            print(f"File: {result.get('file_path', 'N/A')}")
            print(f"Hash: {result.get('file_hash', 'N/A')}")
            print(f"Is Anomaly: {result.get('is_anomaly', 'N/A')}")
            print(f"Confidence: {result.get('confidence', 0):.2f}%")
            print(f"Reconstruction Error: {result.get('reconstruction_error', 0):.4f}")
            print(f"Threshold: {result.get('threshold', 0):.4f}")
            print(f"Action: {result.get('action', 'N/A')}")
            
            if result.get('is_anomaly'):
                print("\nIndicators:")
                for indicator in result.get('indicators', []):
                    print(f"- {indicator}")
            
            if result.get('similar_cases'):
                print("\nSimilar Cases:")
                for case in result.get('similar_cases', []):
                    print(f"- {case.get('file_path', 'Unknown')} (Similarity: {case.get('similarity', 0):.2f})")
            
            # Only provide feedback if we have a valid file hash
            if 'file_hash' in result and result['file_hash']:
                print("\nProviding feedback that this was a false positive...")
                try:
                    analyzer.update_from_feedback(result['file_hash'], is_false_positive=True)
                    print("Feedback submitted successfully")
                except Exception as e:
                    print(f"Error providing feedback: {str(e)}")
            else:
                print("\nSkipping feedback - no valid file hash available")
    
    # Save the updated model
    model_path = analyzer.save_model()
    print(f"\nModel saved to: {model_path}")

def show_menu():
    print("Interactive Menu:")
    print("1. Scan a single file")
    print("2. Scan a directory")
    print("3. Quit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        file_path = input("Enter the file path: ")
        scan_single_file(file_path)
    elif choice == "2":
        directory_path = input("Enter the directory path: ")
        scan_directory(directory_path)
    elif choice == "3":
        print("Goodbye!")
        sys.exit(0)
    else:
        print("Invalid choice. Please try again.")
        show_menu()

def main():
    args = parse_arguments()
    
    try:
        if args.file:
            scan_single_file(args.file)
        elif args.directory:
            scan_directory(args.directory)
        elif args.menu or not any([args.file, args.directory]):
            show_menu()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
