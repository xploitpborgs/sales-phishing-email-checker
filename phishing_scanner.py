import os
import re
import sys
from email import policy
from email.parser import BytesParser
import tldextract
from colorama import Fore, Style, init
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

# === CONFIGURATION ===
PHISHING_KEYWORDS = [
    "verify", "update password", "reset your password", "login now",
    "urgent", "invoice", "bank", "confirm your account", "security alert",
    "click here", "your account will be closed", "suspend your account", "act now"
]

SUSPICIOUS_DOMAINS = [
    "g00gle.com", "paypa1.com", "faceb00k.com", "secure-mail.net", "bank-login.net"
]

LEGITIMATE_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "apple": "apple.com",
    "bank of america": "bankofamerica.com"
}

# === FUNCTIONS ===
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

def scan_for_keywords(text):
    found = []
    for word in PHISHING_KEYWORDS:
        if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            found.append(word)
    return found

def detect_brand_mismatch(sender_name, domain):
    for brand, legit_domain in LEGITIMATE_BRANDS.items():
        if brand.lower() in sender_name.lower() and legit_domain not in (domain or "").lower():
            return brand, legit_domain
    return None, None

def scan_email(file_path):
    print(Fore.YELLOW + f"\n📨 Scanning: {file_path}")
    try:
        msg = load_eml(file_path)
    except Exception as e:
        print(Fore.RED + f"❌ Failed to parse email: {e}")
        return

    sender, subject, body = extract_email_info(msg)
    print(f"From: {sender}")
    print(f"Subject: {subject}")

    domain = extract_domain(sender)
    print(f"Sender domain: {domain}")

    # Check phishing keywords
    keywords = scan_for_keywords(body)
    print("\n🔎 Phishing Keywords:")
    if keywords:
        for kw in keywords:
            print(Fore.RED + f"- {kw}")
    else:
        print(Fore.GREEN + "None")

    # Domain check
    if domain and domain.lower() in [d.lower() for d in SUSPICIOUS_DOMAINS]:
        print(Fore.RED + f"\n🚨 Suspicious domain detected: {domain}")
    else:
        print(Fore.GREEN + "\n✅ Domain looks normal")

    # URL analysis
    urls = extract_urls(body)
    print(Fore.BLUE + f"\n🔗 URLs Found ({len(urls)}):")
    for url in urls:
        parsed_domain = tldextract.extract(urlparse(url).hostname or "").registered_domain
        if is_ip_address_url(url):
            print(Fore.RED + f"- IP-based URL: {url}")
        elif domain and parsed_domain != domain:
            print(Fore.MAGENTA + f"- External URL: {url} (domain mismatch)")
        else:
            print(Fore.GREEN + f"- {url}")

    # Brand impersonation
    sender_name = re.sub(r"<.*?>", "", sender or "")
    brand, legit = detect_brand_mismatch(sender_name, domain)
    if brand:
        print(Fore.RED + f"\n🚨 Brand impersonation detected: '{brand.title()}' but domain is not {legit}")

    print(Fore.CYAN + "\n✅ Scan complete.\n")

# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    folder = "sample_emails"
    if not os.path.exists(folder):
        print(Fore.RED + f"❌ Folder not found: {folder}")
        sys.exit(1)

    eml_files = [f for f in os.listdir(folder) if f.endswith('.eml')]

    if not eml_files:
        print(Fore.RED + "❌ No .eml files found in sample_emails/")
        sys.exit(1)

    print(Fore.CYAN + f"🔍 Starting batch scan: {len(eml_files)} email(s) found.\n")

    for filename in eml_files:
        full_path = os.path.join(folder, filename)
        scan_email(full_path)
