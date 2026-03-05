import subprocess
import json
import os
import sys
from datetime import datetime

def run_vol_command(dump_path, symbol_path, plugin):
    """Executes a Volatility command with improved error reporting."""
    # Use the base plugin name; Volatility 3 resolves the class automatically
    cmd = ["vol", "-f", dump_path, "-s", symbol_path, "-r", "json", plugin]
    
    try:
        # We use stderr=subprocess.PIPE to capture the real reason for failure
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[-] Volatility Error ({plugin}): {result.stderr.strip()}")
            return None
            
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[-] Execution Error ({plugin}): {e}")
        return None

def generate_baseline_reports(dump_path):
    # Important: Volatility 3 often looks for a 'symbols' folder.
    # Ensure this path is the parent directory of your JSON.XZ files.
    symbol_path = os.path.abspath("vol-symbols")
    report_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    baseline = {
        "meta": {"date": str(datetime.now()), "file": dump_path},
        "browsers": [],
        "network": []
    }

    print(f"[*] Starting Baseline Extraction for {dump_path}...")

    # Process Analysis - Trying linux.psaux first
    ps_data = run_vol_command(dump_path, symbol_path, "linux.psaux")
    if not ps_data:
        # Fallback to pslist if psaux fails
        ps_data = run_vol_command(dump_path, symbol_path, "linux.pslist")

    if ps_data:
        targets = ['firefox', 'chrome', 'brave', 'chromium']
        for entry in ps_data:
            # Handle different key names between pslist and psaux
            name = str(entry.get("COMM", entry.get("Name", ""))).lower()
            args = str(entry.get("Args", "")).lower()
            
            if any(t in name or t in args for t in targets):
                baseline["browsers"].append({
                    "PID": entry.get("PID"),
                    "Name": name,
                    "Incognito": any(s in args for s in ["--incognito", "--private"]),
                    "Command": args if args else "N/A (pslist)"
                })

    # Network Analysis - Try linux.netstat

    net_data = run_vol_command(dump_path, symbol_path, "linux.sockstat.Sockstat")
    if net_data:
        for sock in net_data:
            # Sockstat provides Type, Family, State, and Address info
            state = sock.get("State", "UNKNOWN")
            if state in ["TCP_ESTABLISHED", "TCP_LISTEN", "ESTABLISHED", "LISTEN"]:
                baseline["network"].append({
                    "Proto": sock.get("Type"),
                    "Local": sock.get("Source Address"),
                    "Port": sock.get("Source Port"),
                    "Foreign": sock.get("Destination Address"),
                    "FPort": sock.get("Destination Port"),
                    "State": state
                })
    else:
        print("[!] Network baseline empty or plugin failed.")

    with open(f"reports/vol_baseline_{report_id}.json", "w") as jf:
        json.dump(baseline, jf, indent=4)


    html = f"""
    <html>
    <head>
        <title>Volatility Baseline Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 30px; background: #eceff1; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            h1, h2 {{ color: #455a64; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th {{ background: #607d8b; color: white; padding: 10px; text-align: left; }}
            td {{ padding: 10px; border-bottom: 1px solid #cfd8dc; font-size: 0.9em; }}
            .incog-yes {{ color: #d32f2f; font-weight: bold; }}
            .incog-no {{ color: #388e3c; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>OS Level Baseline (Volatility 3)</h1>
            <p><strong>Source:</strong> {dump_path}</p>
        </div>
        
        <div class="card">
            <h2>Detected Browser Processes</h2>
            <table>
                <tr><th>PID</th><th>Name</th><th>Incognito Mode</th><th>Command Line</th></tr>
    """
    for b in baseline["browsers"]:
        i_status = "YES" if b['Incognito'] else "NO"
        i_class = "incog-yes" if b['Incognito'] else "incog-no"
        html += f"<tr><td>{b['PID']}</td><td>{b['Name']}</td><td class='{i_class}'>{i_status}</td><td>{b['Command']}</td></tr>"
    
    html += """
            </table>
        </div>

        <div class="card">
            <h2>Active Network Sockets</h2>
            <table>
                <tr><th>Proto</th><th>Local Address</th><th>Foreign Address</th><th>State</th></tr>
    """
    for n in baseline["network"]:
        html += f"<tr><td>{n.get('Proto')}</td><td>{n.get('LocalAddr')}:{n.get('LocalPort')}</td><td>{n.get('ForeignAddr')}:{n.get('ForeignPort')}</td><td>{n.get('State')}</td></tr>"

    html += "</table></div></body></html>"
    
    with open(f"reports/vol_baseline_{report_id}.html", "w") as hf:
        hf.write(html)
    
    print(f"[+] Baseline Reports generated: vol_baseline_{report_id}.html/json")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 vol_baseline.py <dump_path>")
    else:
        generate_baseline_reports(sys.argv[1])


