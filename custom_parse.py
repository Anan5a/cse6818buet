import re
import csv
import hashlib

def custom_scan(dump_path):
    # Regex for URLs and User-Agents
    url_pattern = re.compile(rb'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?')
    ua_pattern = re.compile(rb'Mozilla/5.0 \([^\)]+\)')
    
    findings = []
    
    with open(dump_path, 'rb') as f:
        # Calculate Hash for Integrity
        sha256 = hashlib.sha256()
        print("[*] Scanning memory and calculating hash...")
        
        for chunk in iter(lambda: f.read(1024*1024*50), b''): # 50MB chunks
            sha256.update(chunk)
            urls = url_pattern.findall(chunk)
            uas = ua_pattern.findall(chunk)
            
            for u in set(urls):
                findings.append({"Type": "URL", "Data": u.decode('utf-8', 'ignore')})
            for ua in set(uas):
                findings.append({"Type": "User-Agent", "Data": ua.decode('utf-8', 'ignore')})
                
    return findings, sha256.hexdigest()

def generate_report(data, file_hash):
    with open('custom_report.csv', 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["Type", "Data"])
        f.write(f"# Evidence SHA256: {file_hash}\n")
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] Custom Report generated with {len(data)} artifacts.")