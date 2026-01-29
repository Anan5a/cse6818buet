import sys
import os

from custom_parse import custom_scan, generate_report

def main():
    # Checks if the path was provided as an argument
    if len(sys.argv) < 2:
        print("Usage: python run_parser.py <path_to_dump>")
        sys.exit(1)

    dump_path = sys.argv[1]

    if not os.path.exists(dump_path):
        print(f"[-] Error: File {dump_path} not found.")
        sys.exit(1)

    print(f"[*] Starting analysis on: {dump_path}")
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 run_parser.py <dump_path>")
    else:
        results, h = custom_scan(sys.argv[1])
        if results:
            generate_report(results, h)
        else:
            print("[-] No artifacts found.")

            
