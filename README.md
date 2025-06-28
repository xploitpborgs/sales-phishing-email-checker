# Phishing Email Scanner

A Python-based tool for scanning `.eml` email files to detect phishing attempts using known phishing domains, suspicious keywords, and brand impersonation patterns.

---

## Features

- ✅ Parses `.eml` email files
- 🌐 Fetches real-time phishing domains from OpenPhish
- 📄 Scans email content for phishing-related keywords
- 🕵️ Detects brand impersonation using domain mismatches
- 🔗 Extracts and analyzes URLs, including IP-based and mismatched domains
- 💾 Saves detailed scan reports to disk

---

## 📂 Folder Structure

```
phishing-scanner/
├── phishing_scanner.py      # Main script
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation
├── sample_emails/           # Folder for test .eml files
│   └── (Add .eml files here)
└── report_output/           # Scan results (auto-generated)
    └── .gitkeep             # Keeps folder tracked in Git
```

---

## Requirements

Install Python dependencies using:

```bash
pip install -r requirements.txt
```

Contents of `requirements.txt`:

```
requests
tldextract
colorama
```

---

## Usage

1. Place your `.eml` email files inside the `sample_emails/` folder.

2. Run the script:

```bash
python3 phishing_scanner.py --mode both
```

### Available Modes

| Mode   | Description                                          |
|--------|------------------------------------------------------|
| print  | Output scan results to the terminal                  |
| save   | Save results as text files in `report_output/`       |
| both   | Do both print and save (this is the default)         |

Example usage:

```bash
python3 phishing_scanner.py --mode save
```

---

## How It Works

- Downloads phishing domain feeds and keyword lists from GitHub/OpenPhish
- Parses sender info, subject, and body from the email
- Scans the body for known phishing keywords
- Extracts all URLs and checks for:
  - IP-based links
  - Domain mismatches
- Detects brand impersonation (e.g., "PayPal" in sender but domain is not `paypal.com`)
- Outputs results to terminal and/or saves a report to file

---

##  Example Output

```bash
📨 Scanning: sample1.eml
From: "PayPal Support" <support@not-paypal.com>
Subject: Urgent: Verify Your Account

🔎 Phishing Keywords:
- urgent
- verify your account

🚨 Suspicious domain detected: not-paypal.com
🚨 Brand impersonation detected: 'Paypal' but domain is not paypal.com

✅ Scan complete.
```

---

## 👤 Author

Oluwasola Adebayo

---

## 📄 License

MIT License
