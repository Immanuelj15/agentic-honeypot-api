"""
Intelligence extraction module.
Robust regex-based extraction for phone numbers, UPI IDs, emails,
bank accounts, phishing links, and case/reference IDs.
"""

import re
from typing import Dict, List

# Known email domains (to separate UPI from email)
KNOWN_EMAIL_DOMAINS = {
    "gmail", "yahoo", "hotmail", "outlook", "protonmail", "icloud",
    "aol", "mail", "zoho", "yandex", "live", "msn", "rediffmail",
    "gmx", "inbox", "fastmail", "tutanota", "pm", "hey",
}

# Known UPI provider suffixes
KNOWN_UPI_PROVIDERS = {
    "paytm", "ybl", "oksbi", "okaxis", "okicici", "okhdfcbank",
    "axisbank", "sbi", "hdfcbank", "icici", "kotak", "indus",
    "boi", "pnb", "canara", "unionbank", "rbl", "federal",
    "dbs", "hsbc", "sc", "citi", "idbi", "bob", "ubi",
}


def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers in various Indian formats."""
    patterns = [
        r'(\+91[-\s]?\d{10})',
        r'(\+91[-\s]?\d{5}[-\s]?\d{5})',
        r'(?<!\d)(\d{10})(?!\d)',
        r'(\d{3}[-\s]\d{3}[-\s]\d{4})',
        r'(\d{5}[-\s]\d{5})',
    ]
    results = []
    for p in patterns:
        results.extend(re.findall(p, text))
    cleaned = []
    for num in set(results):
        digits = re.sub(r'[^\d]', '', num)
        if 10 <= len(digits) <= 13:
            cleaned.append(num.strip())
    return cleaned


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs, differentiating from email addresses."""
    pattern = r'\b([a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,})\b'
    matches = re.findall(pattern, text)
    upi_ids = []
    for match in matches:
        domain = match.split('@')[1].lower()
        if domain in KNOWN_UPI_PROVIDERS:
            upi_ids.append(match)
        elif domain not in KNOWN_EMAIL_DOMAINS:
            # No dot in domain and not a known email provider = likely UPI
            if '.' not in domain:
                upi_ids.append(match)
    return list(set(upi_ids))


def extract_emails(text: str) -> List[str]:
    """Extract email addresses, excluding UPI IDs."""
    pattern = r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b'
    matches = re.findall(pattern, text)
    upi_ids = extract_upi_ids(text)
    return list(set(m for m in matches if m not in upi_ids))


def extract_bank_accounts(text: str) -> List[str]:
    """Extract bank account numbers (9-18 digits), excluding phone numbers."""
    pattern = r'(?<!\d)(\d{9,18})(?!\d)'
    matches = re.findall(pattern, text)
    phones = set(re.sub(r'[^\d]', '', p) for p in extract_phone_numbers(text))
    return list(set(m for m in matches if m not in phones and len(m) >= 9))


def extract_links(text: str) -> List[str]:
    """Extract suspicious URLs, filtering out safe domains."""
    pattern = r'(https?://[^\s\])<>\"\']+)'
    matches = re.findall(pattern, text)
    safe_domains = {"google.com", "facebook.com", "twitter.com", "wikipedia.org"}
    results = []
    for link in set(matches):
        link = link.rstrip('.,;:!?)')
        if not any(safe in link.lower() for safe in safe_domains):
            results.append(link)
    return results


def extract_case_ids(text: str) -> List[str]:
    """Extract case/reference IDs with letter+digit requirement."""
    patterns = [
        r'\b([A-Z]{2,5}-\d{3,10})\b',
        r'\b([A-Z]{2,5}\d{4,10})\b',
        r'\b((?:CASE|REF|TXN|ORDER|POLICY|TKT)[:#\s]+[A-Z0-9-]{4,15})\b',
        r'\b(\d{3,5}/[A-Z]{2,5}/\d{3,5})\b',
    ]
    results = []
    for p in patterns:
        results.extend(re.findall(p, text, re.IGNORECASE))
    cleaned = []
    for m in set(m.strip() for m in results):
        if len(m) >= 5 and re.search(r'[A-Za-z]', m) and re.search(r'\d', m):
            cleaned.append(m)
    return cleaned


def extract_all_intelligence(text: str) -> Dict[str, List[str]]:
    """Extract all types of intelligence from a text."""
    return {
        "phoneNumbers": extract_phone_numbers(text),
        "bankAccounts": extract_bank_accounts(text),
        "upiIds": extract_upi_ids(text),
        "phishingLinks": extract_links(text),
        "emailAddresses": extract_emails(text),
        "caseIds": extract_case_ids(text),
    }


def merge_intelligence(existing: Dict, new: Dict) -> Dict:
    """Merge two intelligence dictionaries, deduplicating values."""
    merged = {}
    for key in existing:
        merged[key] = list(set(existing.get(key, []) + new.get(key, [])))
    return merged


def scan_full_history(conversation_history: list) -> Dict[str, List[str]]:
    """Scan all scammer messages in conversation history for intelligence."""
    combined = {"phoneNumbers": [], "bankAccounts": [], "upiIds": [],
                "phishingLinks": [], "emailAddresses": [], "caseIds": []}
    for msg in conversation_history:
        if msg.get("sender") == "scammer":
            intel = extract_all_intelligence(msg.get("text", ""))
            combined = merge_intelligence(combined, intel)
    return combined
