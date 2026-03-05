import re
import json
import hashlib
import struct
import sys
import os
import mmap
import math
from datetime import datetime
from collections import Counter

def calculate_entropy(data):
    """Calculates Shannon entropy to distinguish real data from memory noise."""
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def custom_scan(dump_path):
    url_pattern = re.compile(rb'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?')
    browser_sigs = {b'firefox': 'Firefox', b'chrome': 'Chrome', b'brave': 'Brave'}
    incognito_sigs = [b'--incognito', b'--private-window']
    
    findings = []
    
    if not os.path.exists(dump_path):
        print(f"[-] Error: {dump_path} not found.")
        return None, None

    with open(dump_path, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            sha256 = hashlib.sha256(mm).hexdigest()
            print(f"[*] Analyzing Evidence: {sha256}")

            for match in url_pattern.finditer(mm):
                url_data = match.group().decode('utf-8', 'ignore')
                
                # Filter 1: Basic Noise (Images/Scripts)
                if len(url_data) < 15 or any(x in url_data for x in ['.js', '.css', '.png', '.jpg']):
                    continue

                # Filter 2: Context Analysis (256 bytes before the URL)
                start_ctx = max(0, match.start() - 256)
                context = mm[start_ctx : match.start()]
                
                score = 0
                is_incog = "False"
                
                # Marker Check: Is it an active HTTP request?
                if any(m in context for m in [b'GET ', b'POST ', b'HTTP', b'Host:', b'Referer:']):
                    score += 50 
                
                # Browser Check: Find signatures in a 4KB window
                browser_name = "Unknown"
                wide_start = max(0, match.start() - 2048)
                wide_end = min(len(mm), match.start() + 2048)
                wide_context = mm[wide_start : wide_end]
                
                for sig, name in browser_sigs.items():
                    if sig in wide_context:
                        browser_name = name
                        score += 30
                        break
                
                # Incognito Check
                if any(sig in wide_context for sig in incognito_sigs):
                    is_incog = "True"
                    score += 10

                # Entropy Check: (Validates data density)
                entropy = calculate_entropy(context)
                if 3.5 < entropy < 5.5:
                    score += 10

                # THRESHOLD: Only keep if it has some forensic validity (score > 20)
                if score >= 20:
                    timestamp = "N/A"
                    for i in range(len(context) - 8, 0, -1):
                        try:
                            val = struct.unpack('<Q', context[i:i+8])[0] / 1000000
                            if 1672531200 < val < 1893456000: # 2023-2030
                                timestamp = datetime.fromtimestamp(val).strftime('%Y-%m-%d %H:%M:%S')
                                break
                        except: continue

                    # We store 5 items in the tuple: (ts, browser, incog, url, score)
                    findings.append((timestamp, browser_name, is_incog, url_data, score))

    return findings, sha256

def generate_reports(data, file_hash):
    counts = Counter(data)
    sorted_results = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    
    report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. JSON Report
    json_data = {
        "metadata": {"generated": timestamp_str, "sha256": file_hash},
        "findings": []
    }
    for (ts, br, incog, url, score), count in sorted_results:
        json_data["findings"].append({
            "hits": count, "time": ts, "browser": br, "incognito": incog, "url": url, "confidence": score
        })

    with open(f'reports/custom_forensic_report_{report_id}.json', 'w') as jf:
        json.dump(json_data, jf, indent=4)

    html_content = f"""
    <html>
    <head>
        <title>Forensic Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 30px; background: #f4f4f9; }}
            .container {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }}
            th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 10px; border-bottom: 1px solid #eee; word-wrap: break-word; font-size: 0.9em; }}
            .score-high {{ color: #27ae60; font-weight: bold; }}
            .score-med {{ color: #f39c12; font-weight: bold; }}
            .badge {{ background: #3498db; color: white; padding: 2px 8px; border-radius: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Memory Forensics: Browser Activity</h1>
            <p><strong>SHA256:</strong> {file_hash}</p>
            <table>
                <tr>
                    <th style="width: 50px;">Hits</th>
                    <th style="width: 140px;">Timestamp</th>
                    <th style="width: 100px;">Source</th>
                    <th style="width: 80px;">Confidence</th>
                    <th>URL / Artifact</th>
                </tr>
    """
    for (ts, br, incog, url, score), count in sorted_results:
        s_class = "score-high" if score > 50 else "score-med"
        html_content += f"""
                <tr>
                    <td><span class="badge">{count}</span></td>
                    <td>{ts}</td>
                    <td>{br} {"(x)" if incog == "True" else ""}</td>
                    <td class="{s_class}">{score}%</td>
                    <td>{url}</td>
                </tr>
        """
    html_content += "</table></div></body></html>"
    
    with open(f'reports/custom_forensic_report_{report_id}.html', 'w') as hf:
        hf.write(html_content)
        
    print(f"\n[+] Success! View your results in: custom_forensic_report_{report_id}.html")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 custom_parse.py <dump_path>")
    else:
        results, h = custom_scan(sys.argv[1])
        if results:
            generate_reports(results, h)