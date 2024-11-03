import requests
from bs4 import BeautifulSoup
import subprocess

# حمولات XSS
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

# حمولات File Inclusion
file_inclusion_payloads = ["../etc/passwd", "../../etc/passwd"]

# ملف التقرير
report_file = "vulnerability_report.html"

# تهيئة ملف التقرير
def init_report():
    with open(report_file, "w") as report:
        report.write("<html><head><title>Vulnerability Report</title></head><body>")
        report.write("<h1>Vulnerability Scan Report</h1><hr>")

def log_results(result):
    with open(report_file, "a") as report:
        report.write(result + "<br>")

def close_report():
    with open(report_file, "a") as report:
        report.write("</body></html>")

# استخراج الروابط الفرعية من الصفحة الرئيسية
def extract_links(url):
    print(f"[*] Extracting links from {url}")
    links = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link['href']
            # تأكد من أن الرابط فرعي ومكمل للرابط الأساسي
            if href.startswith("/"):
                href = url + href
            elif not href.startswith("http"):
                continue
            links.append(href)
    except Exception as e:
        print(f"[!] Error extracting links: {e}")
    return links

# تشغيل SQLMap لفحص ثغرات SQL Injection
def run_sqlmap(url):
    print(f"[*] Running SQLMap on {url}")
    try:
        result = subprocess.check_output(["sqlmap", "-u", url, "--batch", "-v", "1"], stderr=subprocess.STDOUT)
        decoded_result = result.decode()
        if "parameter" in decoded_result:
            print(f"[+] SQL Injection vulnerability detected by SQLMap in {url}")
            log_results(f"<b>SQL Injection vulnerability found by SQLMap in {url}</b>")
        else:
            print("[-] No SQL Injection vulnerability detected by SQLMap.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running SQLMap: {e.output.decode()}")

# فحص ثغرات XSS
def test_xss(url, param):
    print(f"[*] Testing XSS on {url}")
    for payload in xss_payloads:
        data = {param: payload}
        response = requests.get(url, params=data)
        if payload in response.text:
            print(f"[+] XSS vulnerability detected with payload: {payload}")
            log_results(f"<b>XSS vulnerability found in {url} with payload: {payload}</b>")
        else:
            print(f"[-] No XSS vulnerability detected with payload: {payload}")

# فحص ثغرات تضمين الملفات
def test_file_inclusion(url):
    print(f"[*] Testing File Inclusion on {url}")
    for payload in file_inclusion_payloads:
        response = requests.get(url + payload)
        if "root:x" in response.text or "bin/bash" in response.text:
            print(f"[+] File Inclusion vulnerability detected with payload: {payload}")
            log_results(f"<b>File Inclusion vulnerability found in {url} with payload: {payload}</b>")
        else:
            print(f"[-] No File Inclusion vulnerability detected with payload: {payload}")

# التشغيل الرئيسي للأداة
def main():
    print("[*] Welcome to AutoVulnScanner!")
    
    # طلب إدخال الرابط الأساسي من المستخدم
    base_url = input("Enter the target URL (e.g., http://example.com): ")
    
    # تهيئة التقرير
    init_report()

    # استخراج الروابط الفرعية من الرابط الأساسي
    print("[*] Scanning for sub-links...")
    links = extract_links(base_url)
    
    # فحص SQL Injection باستخدام SQLMap، وفحص XSS، وفحص File Inclusion لكل رابط
    for link in links:
        print(f"\n[*] Scanning {link}")
        
        # فحص SQL Injection
        run_sqlmap(link)

        # فحص XSS
        test_xss(link, "id")  # تعديل 'id' بحسب اسم المدخل في الرابط

        # فحص File Inclusion
        test_file_inclusion(link)

    # إنهاء التقرير
    close_report()
    print(f"[*] Scan complete. Results saved in {report_file}")

# تنفيذ الأداة
if __name__ == "__main__":
    main()
