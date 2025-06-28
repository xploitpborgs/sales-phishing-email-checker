import os
import re
import email
from email import policy
from email.parser import BytesParser
import tldextract
from colorama import Fore, Style

# === CONFIGURATION ===
PHISHING_KEYWORDS = [
    "verify", "update password", "reset your password", "login now", 
    "urgent", "invoice", "bank", "confirm your account", "security alert"
]

SUSPICIOUS_DOMAINS = [
    "g00gle.com", "paypa1.com", "faceb00k.com", "secure-mail.net", "bank-login.net"
]

# === FUNCTIONS ===
def load_eml(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def extract_email_info(msg):
    sender = msg['From']
    subject = msg['Subject']
    body = msg.get_body(preferencelist=('plain')).get_content()
    return sender, subject, body

def scan_for_keywords(text):
    found = []
    for word in PHISHING_KEYWORDS:
        if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            found.append(word)
    return found

def extract_domain(email_addr):
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_addr)
    if match:
        domain = match.group(1)
        return tldextract.extract(domain).registered_domain
    return None

def scan_email(file_path):
    print(Fore.YELLOW + f"\n📨 Scanning email: {file_path}" + Style.RESET_ALL)
    msg = load_eml(file_path)
    sender, subject, body = extract_email_info(msg)

    print(f"From: {sender}")
    print(f"Subject: {subject}")

    domain = extract_domain(sender)
    print(f"Sender domain: {domain}")

    flagged_keywords = scan_for_keywords(body)
    print("\n🔎 Phishing Keywords Found:")
    for word in flagged_keywords:
        print(Fore.RED + f"- {word}" + Style.RESET_ALL)

    if domain in SUSPICIOUS_DOMAINS:
        print(Fore.RED + f"\n🚨 Suspicious domain detected: {domain}" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"\n✅ Domain looks normal" + Style.RESET_ALL)

    print(Fore.CYAN + "\nScan complete.\n" + Style.RESET_ALL)

# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    target_file = "sample_emails/sample1.eml"
    if os.path.exists(target_file):
        scan_email(target_file)
    else:
        print(Fore.RED + f"❌ File not found: {target_file}" + Style.RESET_ALL)

