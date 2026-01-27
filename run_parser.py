import sys
import os

from custom_parse import custom_scan, generate_report

def main():
    # Check if the path was provided as an argument
    if len(sys.argv) < 2:
        print("Usage: python run_parser.py <path_to_dump>")
        sys.exit(1)

    dump_path = sys.argv[1]

    # Validate that the file exists before starting
    if not os.path.exists(dump_path):
        print(f"[-] Error: File {dump_path} not found.")
        sys.exit(1)

    print(f"[*] Starting analysis on: {dump_path}")
    
    # Pass the input path to your functions
    evidence, d_hash = custom_scan(dump_path)
    
    if evidence:
        generate_report(evidence, d_hash)
    else:
        print("[-] No artifacts found.")

if __name__ == "__main__":
    main()