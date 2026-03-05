import subprocess
import json
import os
import sys
from datetime import datetime

SYMBOL_PATH = os.path.abspath("vol-symbols")

def run_vol_command(dump_path, plugin, extra_args=[]):
    """Executes a Volatility 3 command and returns parsed JSON output."""
    cmd = [
        "vol", 
        "-f", dump_path,
        "-s", SYMBOL_PATH,
        "-r", "json",
        plugin
    ] + extra_args
    
    try:
        print(f"[*] Executing Plugin: {plugin}...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] Volatility Error ({plugin}): {result.stderr.strip()}")
            return None
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[-] Execution Error ({plugin}): {e}")
        return None

def generate_baseline(dump_path):
    report_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    baseline_data = {
        "metadata": {"source": dump_path, "generated_at": timestamp_str},
        "browsers": [],
        "carved_urls": []
    }

    # Identify Target Browser PIDs
    print("[*] Identifying browser processes for targeted scanning...")
    ps_data = run_vol_command(dump_path, "linux.pslist.PsList")
    target_pids = []
    if ps_data:
        targets = ['firefox', 'chrome', 'brave', 'chromium']
        for entry in ps_data:
            name = entry.get("Name", entry.get("COMM", "")).lower()
            if any(t in name for t in targets):
                pid = entry.get("PID")
                target_pids.append(pid)
                baseline_data["browsers"].append({"PID": pid, "Name": name})

    # Carve URLs using VmaRegExScan (Reference: Volatility Foundation Method)
    # Instead of scanning the whole RAM, we scan the memory maps (VMA) of the browsers
    if target_pids:
        print(f"[*] Carving URLs from PIDs {target_pids} using VmaRegExScan...")
        # Regex for common URL patterns
        url_regex = "https?://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,3}(?:/[^\\s<>\"']*)?"
        
        # We run the scan for the first few identified browser PIDs to avoid massive bloat
        for pid in target_pids[:3]: 
            args = ["--pid", str(pid), "--regex", url_regex]
            scan_results = run_vol_command(dump_path, "linux.vmaregexscan.VmaRegExScan", args)
            
            if scan_results:
                for hit in scan_results:
                    # 'Data' contains the carved string from the VMA
                    url = hit.get("Data", "")
                    if url and len(url) > 15:
                        baseline_data["carved_urls"].append({
                            "PID": pid,
                            "URL": url,
                            "Offset": hit.get("Offset")
                        })

    # Save JSON
    with open(f"reports/vol_carved_baseline_{report_id}.json", "w") as jf:
        json.dump(baseline_data, jf, indent=4)

    # Save HTML
    html_content = f"""
    <html>
    <head>
        <title>Volatility Carved History</title>
        <style>
            body {{ font-family: sans-serif; margin: 30px; background: #f4f7f6; }}
            .container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 10px; border-bottom: 1px solid #eee; word-break: break-all; font-size: 0.85em; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Volatility 3 URL Carving Report</h1>
            <p>Scanning method inspired by Volatility Foundation Guide (VMA Analysis)</p>
            
            <h2>Carved Browser URLs</h2>
            <table>
                <tr><th>PID</th><th>Memory Offset</th><th>Carved URL</th></tr>
    """
    # Limit to top 200 findings to keep the HTML readable
    for c in baseline_data["carved_urls"][:200]:
        html_content += f"<tr><td>{c['PID']}</td><td>{hex(c['Offset'])}</td><td>{c['URL']}</td></tr>"

    html_content += "</table></div></body></html>"
    
    with open(f"reports/vol_carved_baseline_{report_id}.html", "w") as hf:
        hf.write(html_content)
    
    print(f"\n[+] Analysis Finished. Carved {len(baseline_data['carved_urls'])} URLs.")
    print(f"    - Report: vol_carved_baseline_{report_id}.html")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 vol_baseline.py <dump_path>")
    else:
        generate_baseline(sys.argv[1])









