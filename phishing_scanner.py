#!/usr/bin/env python3

import os
import re
import sys
import json
import requests
from io import StringIO
from datetime import datetime
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
import tldextract
from colorama import Fore, Style, init
import argparse

# Initialize colorama
init(autoreset=True)

# === LIVE CONFIG LOADERS ===

def get_phishing_domains_from_openphish():
    try:
        print(Fore.YELLOW + "🌐 Fetching phishing domains from OpenPhish...")
        resp = requests.get("https://openphish.com/feed.txt", timeout=10)
        urls = resp.text.splitlines()
        domains = {
            tldextract.extract(urlparse(u).hostname or "").registered_domain
            for u in urls if u
        }
        print(Fore.GREEN + f"✅ Loaded {len(domains)} suspicious domains.")
        return domains
    except Exception as e:
        print(Fore.RED + f"⚠️ Could not fetch phishing domains: {e}")
        return set()

def get_phishing_keywords():
    try:
        print(Fore.YELLOW + "🌐 Fetching phishing keywords from GitHub list...")
        url = "https://raw.githubusercontent.com/marshyski/phishing-keywords/main/keywords.json"
        resp = requests.get(url, timeout=10)
        keywords = resp.json()
        print(Fore.GREEN + f"✅ Loaded {len(keywords)} keywords.")
        return keywords
    except:
        print(Fore.RED + "⚠️ Failed to fetch keywords. Using fallback list.")
        return [
            "verify", "update password", "reset your password", "login now",
            "urgent", "invoice", "bank", "confirm your account", "security alert",
            "click here", "account will be closed", "suspend", "act now"
        ]

def get_common_brands():
    return {
        "paypal": "paypal.com",
        "google": "google.com",
        "facebook": "facebook.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "bank of america": "bankofamerica.com"
    }

# === EMAIL PROCESSING FUNCTIONS ===

def load_eml(file_path):
    with open(file_path, 'rb') as f:
        return BytesParser(policy=policy.default).parse(f)

def extract_email_info(msg):
    sender = msg['From']
    subject = msg['Subject']
    body_part = msg.get_body(preferencelist=('plain', 'html'))
    body = body_part.get_content() if body_part else ""
    return sender, subject, body

def extract_domain(email_addr):
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_addr or "")
    if match:
        domain = match.group(1)
        return tldextract.extract(domain).registered_domain
    return None

def extract_urls(text):
    url_pattern = r'https?://[^\s)>\"]+'
    return re.findall(url_pattern, text)

def is_ip_address_url(url):
    parsed = urlparse(url)
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.hostname or '') is not None

def scan_for_keywords(text, keyword_list):
    found = []
    for word in keyword_list:
        if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            found.append(word)
    return found

def detect_brand_mismatch(sender_name, domain, brand_list):
    for brand, legit_domain in brand_list.items():
        if brand.lower() in sender_name.lower() and legit_domain not in (domain or "").lower():
            return brand, legit_domain
    return None, None

# === REPORT HANDLING ===

def save_report(output, filename):
    report_dir = "report_output"
    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, filename)
    with open(path, "w") as f:
        f.write(output)
    print(Fore.GREEN + f"📝 Report saved to: {path}")

# === MAIN SCAN FUNCTION ===

def scan_email(file_path, phishing_keywords, phishing_domains, brands, mode="both"):
    output = StringIO()
    print_to = lambda x: print(x, file=output) if mode in ["save", "both"] else print(x)

    print_to(Fore.YELLOW + f"\n📨 Scanning: {file_path}")
    try:
        msg = load_eml(file_path)
    except Exception as e:
        print_to(Fore.RED + f"❌ Failed to parse email: {e}")
        return

    sender, subject, body = extract_email_info(msg)
    print_to(f"From: {sender}")
    print_to(f"Subject: {subject}")

    domain = extract_domain(sender)
    print_to(f"Sender domain: {domain}")

    keywords = scan_for_keywords(body, phishing_keywords)
    print_to("\n🔎 Phishing Keywords:")
    if keywords:
        for kw in keywords:
            print_to(Fore.RED + f"- {kw}")
    else:
        print_to(Fore.GREEN + "None")

    if domain and domain.lower() in [d.lower() for d in phishing_domains]:
        print_to(Fore.RED + f"\n🚨 Suspicious domain detected: {domain}")
    else:
        print_to(Fore.GREEN + "\n✅ Domain looks normal")

    urls = extract_urls(body)
    print_to(Fore.BLUE + f"\n🔗 URLs Found ({len(urls)}):")
    for url in urls:
        parsed_domain = tldextract.extract(urlparse(url).hostname or "").registered_domain
        if is_ip_address_url(url):
            print_to(Fore.RED + f"- IP-based URL: {url}")
        elif domain and parsed_domain != domain:
            print_to(Fore.MAGENTA + f"- External URL: {url} (domain mismatch)")
        else:
            print_to(Fore.GREEN + f"- {url}")

    sender_name = re.sub(r"<.*?>", "", sender or "")
    brand, legit = detect_brand_mismatch(sender_name, domain, brands)
    if brand:
        print_to(Fore.RED + f"\n🚨 Brand impersonation detected: '{brand.title()}' but domain is not {legit}")

    print_to(Fore.CYAN + "\n✅ Scan complete.\n")

    if mode in ["save", "both"]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"{os.path.basename(file_path).replace('.eml', '')}_report_{timestamp}.txt"
        save_report(output.getvalue(), report_name)

# === MAIN ENTRY POINT ===

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Email Scanner")
    parser.add_argument(
        "--mode", choices=["print", "save", "both"], default="both",
        help="Choose how to display results: print to terminal, save to file, or both"
    )
    args = parser.parse_args()

    folder = "sample_emails"
    if not os.path.exists(folder):
        print(Fore.RED + f"❌ Folder not found: {folder}")
        sys.exit(1)

    phishing_keywords = get_phishing_keywords()
    phishing_domains = get_phishing_domains_from_openphish()
    legitimate_brands = get_common_brands()

    eml_files = [f for f in os.listdir(folder) if f.endswith('.eml')]

    if not eml_files:
        print(Fore.RED + "❌ No .eml files found in sample_emails/")
        sys.exit(1)

    print(Fore.CYAN + f"\n🔍 Starting batch scan: {len(eml_files)} email(s) found.")

    for filename in eml_files:
        full_path = os.path.join(folder, filename)
        scan_email(full_path, phishing_keywords, phishing_domains, legitimate_brands, mode=args.mode)
