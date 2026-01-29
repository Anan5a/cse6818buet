import re
import csv
import hashlib
import struct
import sys
import os
import mmap
from datetime import datetime
from collections import Counter

def custom_scan(dump_path):
    url_pattern = re.compile(rb'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?')
    browser_sigs = {b'firefox': 'Firefox', b'chrome': 'Chrome', b'brave': 'Brave'}
    incognito_sigs = [b'--incognito', b'--private-window']
    
    findings = []
    
    if not os.path.exists(dump_path):
        print(f"[-] Error: {dump_path} not found.")
        return None, None

    print(f"[*] Memory Mapping and Scanning: {dump_path}")
    
    with open(dump_path, 'rb') as f:
        # map the file into memory
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # Faster Hash Calculation using mmap
            sha256 = hashlib.sha256()
            sha256.update(mm)
            file_hash = sha256.hexdigest()

            # Optimized Regex Search
            for match in url_pattern.finditer(mm):
                url_data = match.group().decode('utf-8', 'ignore')
                
                # Preliminary filter for noise
                if len(url_data) < 20 or any(x in url_data for x in ['.js', '.css', '.png', 'googleads']):
                    continue

                # Check 1KB before the match
                start_ctx = max(0, match.start() - 1024)
                context_area = mm[start_ctx : match.start()]

                # Skip "Zero Pages" (we got nothing here, probably)
                if context_area.count(b'\x00') > 900: # Over 90% null bytes
                    # we do not append anything in this case
                    # findings.append(("N/A", "Unknown", "False", url_data))
                    continue

                # Identify Browser & Incognito via proximity
                this_browser = "Unknown"
                for sig, name in browser_sigs.items():
                    if sig in context_area:
                        this_browser = name
                        break
                if this_browser == "Unknown":
                    continue  # Skip if browser is unknown
                
                is_incognito = "True" if any(x in context_area for x in incognito_sigs) else "False"

                # Sliding-Window Timestamp (Binary Unpacking)
                timestamp = "N/A"
                # Search back 64 bytes for a valid 8-byte or 4-byte timestamp
                for i in range(len(context_area) - 8, len(context_area) - 64, -1):
                    try:
                        # Try 8-byte PRTime (Microseconds)
                        val_8 = struct.unpack('<Q', context_area[i:i+8])[0] / 1000000
                        if 1672531200 < val_8 < 1893456000: # 2023-2030
                            timestamp = datetime.fromtimestamp(val_8).strftime('%Y-%m-%d %H:%M:%S')
                            break
                        
                        # Try 4-byte Unix Epoch
                        val_4 = struct.unpack('<I', context_area[i:i+4])[0]
                        if 1672531200 < val_4 < 1893456000:
                            timestamp = datetime.fromtimestamp(val_4).strftime('%Y-%m-%d %H:%M:%S')
                            break
                    except: continue

                findings.append((timestamp, this_browser, is_incognito, url_data))

    return findings, file_hash

def generate_report(data, file_hash):
    # Frequency Filter: Group by all fields and count hits
    counts = Counter(data)
    
    # Sort by Hits (Descending)
    sorted_results = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    
    output_file = 'reports/forensic_report'+datetime.now().strftime('%Y%m%d_%H%M%S')+'.csv'
    fieldnames = ["Hits", "Timestamp", "Browser", "Incognito", "Data"]

    with open(output_file, 'w', newline='') as f:
        f.write(f"# Evidence SHA256: {file_hash}\n")
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for (ts, browser, incog, url), hit_count in sorted_results:
            writer.writerow({
                "Hits": hit_count,
                "Timestamp": ts,
                "Browser": browser,
                "Incognito": incog,
                "Data": url
            })
        
    print(f"[+] Report generated: {output_file}")
