# Run this inside the Target Linux VM
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import time

def generate_evidence():
    print("[!] Starting Browser Simulation...")
    options = Options()
    options.headless = True  
    driver = webdriver.Firefox(options=options)
    
    urls = [
        "https://github.com/sqlmapproject/sqlmap",
        "https://www.example.com/",
        "https://google.com/"
    ]
    
    for url in urls:
        print(f"[*] Visiting: {url}")
        driver.get(url)
        time.sleep(10) # Residence time to ensure RAM population
        
    driver.quit()
    print("[+] Evidence generated. Keep the VM running for acquisition.")

if __name__ == "__main__":
    generate_evidence()