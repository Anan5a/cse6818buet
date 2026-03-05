from collections import Counter
import datetime
import json

def generate_report(data, file_hash):
    counts = Counter(data)
    sorted_results = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    json_output = {
        "report_metadata": {
            "report_id": report_id,
            "generated_at": timestamp_str,
            "evidence_hash_sha256": file_hash
        },
        "findings": []
    }
    
    for (ts, browser, url), count in sorted_results:
        json_output["findings"].append({
            "hits": count,
            "timestamp": ts,
            "browser_source": browser,
            "url": url
        })
    
    with open(f'forensic_report_{report_id}.json', 'w') as jf:
        json.dump(json_output, jf, indent=4)

    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Forensic Artifact Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f7f6; }}
            .container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .metadata {{ margin-bottom: 20px; padding: 15px; background: #eef2f3; border-left: 5px solid #3498db; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background-color: #34495e; color: white; text-align: left; padding: 12px; }}
            td {{ padding: 10px; border-bottom: 1px solid #ddd; word-break: break-all; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .hit-badge {{ background: #3498db; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }}
            .incognito {{ color: #e74c3c; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Browser Artifact Recovery Report</h1>
            <div class="metadata">
                <strong>Report Generated:</strong> {timestamp_str}<br>
                <strong>Evidence SHA256:</strong> {file_hash}<br>
                <strong>Total Unique Artifacts:</strong> {len(sorted_results)}
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Hits</th>
                        <th>Carved Timestamp</th>
                        <th>Source Process</th>
                        <th>URL / Artifact Data</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for (ts, browser, url), count in sorted_results:
        html_template += f"""
                    <tr>
                        <td><span class="hit-badge">{count}</span></td>
                        <td>{ts}</td>
                        <td><strong>{browser.upper()}</strong></td>
                        <td>{url}</td>
                    </tr>
        """
        
    html_template += """
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    with open(f'forensic_report_{report_id}.html', 'w') as hf:
        hf.write(html_template)
        
    print(f"\n[+] Reports Successfully Generated:")
    print(f"    - JSON: forensic_report_{report_id}.json")
    print(f"    - HTML: forensic_report_{report_id}.html")