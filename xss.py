import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
import time
import logging

# إعداد التسجيل (Logging) لتسجيل الأخطاء والأنشطة
logging.basicConfig(filename='security_scan_log.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# تحديد عدد الخيوط الافتراضي وعدد المحاولات
MAX_THREADS = 5
RETRY_COUNT = 3

lock = threading.Lock()

# Function to handle HTTP requests with retries
def make_request(url, method="GET", **kwargs):
    for attempt in range(RETRY_COUNT):
        try:
            if method == "POST":
                return requests.post(url, **kwargs)
            return requests.get(url, **kwargs)
        except requests.RequestException as e:
            logging.error(f"Request error for {url} (Attempt {attempt+1}/{RETRY_COUNT}): {e}")
            time.sleep(1)  # Wait before retrying
    return None  # Return None if all retries fail

# Vulnerability check functions
def check_xss(url):
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in xss_payloads:
        test_url = f"{url}?test={payload}"
        response = make_request(test_url)
        if response and payload in response.text:
            return True
    return False

def check_sql_injection(url):
    sql_payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "' AND '1'='1"]
    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"
        response = make_request(test_url)
        if response and ("mysql" in response.text.lower() or "sql" in response.text.lower()):
            return True
    return False

def check_file_upload(url):
    files = {'file': ('test.php', '<?php echo "File Upload Vulnerable"; ?>')}
    upload_url = f"{url}/upload.php"
    response = make_request(upload_url, method="POST", files=files)
    if response and response.status_code == 200 and "File Upload Vulnerable" in response.text:
        return True
    return False

def check_csrf(url):
    csrf_test_url = f"{url}/admin/update_settings.php"
    headers = {'Referer': 'http://malicious-site.com'}
    response = make_request(csrf_test_url, method="POST", headers=headers)
    if response and response.status_code == 200 and "Settings Updated" in response.text:
        return True
    return False

def check_ssrf(url):
    ssrf_test_url = f"{url}/?url=http://127.0.0.1"
    response = make_request(ssrf_test_url)
    if response and "127.0.0.1" in response.text:
        return True
    return False

def check_http_headers(url):
    response = make_request(url)
    if response:
        headers = response.headers
        results = {
            "Content-Security-Policy": "Content-Security-Policy" in headers,
            "Strict-Transport-Security": "Strict-Transport-Security" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers
        }
        return results
    return {}

def check_same_site_cookie(url):
    response = make_request(url)
    if response:
        cookies = response.cookies
        for cookie in cookies:
            if "SameSite" not in cookie._rest:
                return False
    return True

def detect_waf(url):
    response = make_request(url)
    if response:
        headers = response.headers
        if 'X-Sucuri-ID' in headers or 'X-Frame-Options' in headers or 'X-XSS-Protection' in headers:
            return "Detected WAF or Security Headers"
    return "No WAF detected"

# Function to extract all internal links from a webpage
def get_internal_links(url):
    internal_links = set()
    response = make_request(url)
    if response:
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(url, href)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                internal_links.add(full_url)
    return internal_links

# Multi-threaded function to handle scanning for each link
def scan_link(link, results):
    print(f"\nScanning {link} ...")
    start_time = time.time()
    vulnerabilities = {
        "XSS": check_xss(link),
        "SQL Injection": check_sql_injection(link),
        "File Upload": check_file_upload(link),
        "CSRF": check_csrf(link),
        "SSRF": check_ssrf(link),
        "Content-Security-Policy": check_http_headers(link).get("Content-Security-Policy"),
        "Strict-Transport-Security": check_http_headers(link).get("Strict-Transport-Security"),
        "X-Frame-Options": check_http_headers(link).get("X-Frame-Options"),
        "SameSite Cookie": check_same_site_cookie(link),
        "WAF": detect_waf(link)
    }
    end_time = time.time()

    with lock:
        results[link] = {
            "vulnerabilities": vulnerabilities,
            "response_time": round(end_time - start_time, 2)
        }

# Generate TXT report
def generate_txt_report(results):
    with open("security_scan_report.txt", "w") as report_file:
        report_file.write("Security Scan Report\n")
        report_file.write("=====================\n\n")
        
        summary = {
            "total_links": len(results),
            "vulnerable_links": sum(1 for res in results.values() if any(res["vulnerabilities"].values()))
        }
        report_file.write(f"Total links scanned: {summary['total_links']}\n")
        report_file.write(f"Links with vulnerabilities: {summary['vulnerable_links']}\n\n")

        for url, data in results.items():
            report_file.write(f"Results for {url} (Response time: {data['response_time']} seconds):\n")
            for vuln, status in data["vulnerabilities"].items():
                result = "Vulnerable" if status else "Not Vulnerable"
                report_file.write(f"- {vuln}: {result}\n")
            report_file.write("\n")
    
    print("\n[+] TXT report generated as security_scan_report.txt")

# Main scanning function with threading and error handling
def main():
    url = input("Enter the site URL (e.g., http://example.com): ")
    max_threads = int(input(f"Enter the max number of threads (default is {MAX_THREADS}): ") or MAX_THREADS)
    print("\n[*] Starting scan on:", url)
    
    internal_links = get_internal_links(url)
    print(f"\n[+] Found {len(internal_links)} internal links to scan.")

    all_results = {}
    threads = []

    for link in internal_links:
        while threading.active_count() > max_threads:
            time.sleep(0.1)

        thread = threading.Thread(target=scan_link, args=(link, all_results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    generate_txt_report(all_results)
    print("\n[+] Scan completed.")

if __name__ == "__main__":
    main()
