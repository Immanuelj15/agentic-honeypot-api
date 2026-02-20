"""
Intelligence extraction module for the Honeypot API.
Extracts phone numbers, UPI IDs, emails, bank accounts, links, and identifiers
from scammer messages with minimal cross-contamination.
"""

import re
from typing import List, Dict, Set

# Email domains that should NOT be classified as UPI IDs
EMAIL_DOMAINS = {
    "gmail", "yahoo", "hotmail", "outlook", "protonmail", "icloud",
    "aol", "mail", "zoho", "yandex", "live", "msn", "rediffmail",
    "gmx", "inbox", "fastmail", "tutanota", "pm", "hey",
}

# Known UPI provider suffixes
UPI_PROVIDERS = {
    "upi", "okhdfcbank", "okicici", "oksbi", "okaxis", "paytm",
    "ybl", "ibl", "apl", "axl", "fbl", "ikwik", "abfspay",
    "axisbank", "sbi", "hdfcbank", "icici", "kotak", "indus",
    "boi", "pnb", "canara", "unionbank", "rbl", "federal",
    "dbs", "hsbc", "sc", "citi", "idbi", "bob", "ubi",
}


def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers, handling Indian and international formats."""
    if not text:
        return []
    # Match patterns like +91-9876543210, +91 98765 43210, 9876543210, etc.
    patterns = [
        r'\+\d{1,3}[-.\s]?\d{4,5}[-.\s]?\d{4,6}',   # International format
        r'\+\d{1,3}[-.\s]?\d{10}',                      # +CC followed by 10 digits
        r'\b0\d{10}\b',                                  # Indian landline with 0 prefix
        r'(?<!\d)\d{10}(?!\d)',                          # 10-digit mobile numbers
    ]
    results = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        results.extend(matches)
    # Clean and deduplicate
    cleaned = []
    for num in results:
        num = num.strip()
        # Only keep if it has enough digits (at least 10)
        digits = re.sub(r'\D', '', num)
        if len(digits) >= 10:
            cleaned.append(num)
    return list(set(cleaned))


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs while filtering out standard email addresses."""
    if not text:
        return []
    # UPI format: something@bankprovider
    pattern = r'\b([a-zA-Z0-9._-]{2,}@[a-zA-Z0-9.-]+)\b'
    matches = re.findall(pattern, text)

    upi_ids = []
    for match in matches:
        parts = match.split('@')
        if len(parts) != 2:
            continue
        domain = parts[1].lower()

        # Check if domain matches known UPI providers
        is_upi = False
        for provider in UPI_PROVIDERS:
            if provider in domain:
                is_upi = True
                break

        # Also check: if domain does NOT have a standard TLD (.com, .org, etc.)
        # and is not a known email domain, treat as UPI
        has_tld = bool(re.search(r'\.[a-zA-Z]{2,}$', domain))
        domain_base = domain.split('.')[0] if '.' in domain else domain

        if is_upi:
            upi_ids.append(match)
        elif not has_tld and domain_base not in EMAIL_DOMAINS:
            upi_ids.append(match)

    return list(set(upi_ids))


def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses, excluding UPI IDs."""
    if not text:
        return []
    pattern = r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b'
    matches = re.findall(pattern, text)

    emails = []
    upi_ids = set(extract_upi_ids(text))
    for match in matches:
        if match not in upi_ids:
            emails.append(match)

    return list(set(emails))


def extract_bank_accounts(text: str) -> List[str]:
    """Extract bank account numbers (9-18 digits), excluding phone numbers."""
    if not text:
        return []
    phone_numbers = set()
    for phone in extract_phone_numbers(text):
        digits = re.sub(r'\D', '', phone)
        phone_numbers.add(digits)

    # Match 9-18 digit numbers not preceded by + (phone) or . (decimal)
    pattern = r'(?<![+\d.])\b(\d{9,18})\b(?!\.\d)'
    matches = re.findall(pattern, text)

    accounts = []
    for match in matches:
        # Skip if this number matches a known phone number's digits
        if match in phone_numbers or any(match in p for p in phone_numbers):
            continue
        # Skip 10-digit numbers that look like phone numbers
        if len(match) == 10 and match[0] in '6789':
            continue
        accounts.append(match)

    return list(set(accounts))


def extract_phishing_links(text: str) -> List[str]:
    """Extract suspicious URLs and links."""
    if not text:
        return []
    patterns = [
        r'https?://[^\s<>"\']+',
        r'www\.[^\s<>"\']+',
    ]
    results = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        results.extend(matches)

    # Clean trailing punctuation
    cleaned = []
    for link in results:
        link = link.rstrip('.,;:!?)')
        cleaned.append(link)

    return list(set(cleaned))


def extract_case_ids(text: str) -> List[str]:
    """Extract case IDs, reference numbers, policy numbers, order numbers."""
    if not text:
        return []
    patterns = [
        r'\b([A-Z]{2,5}-\d{3,10})\b',                  # SBI-12345, REF-78901
        r'\b([A-Z]{2,5}\d{4,10})\b',                    # REF0012345
        r'\b((?:CASE|REF|TXN|ORDER|POLICY|TKT)[:#\s]+[A-Z0-9-]{4,15})\b',  # CASE: ABC123
        r'\b(\d{3,5}/[A-Z]{2,5}/\d{3,5})\b',            # 123/REF/456
    ]
    results = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        results.extend(matches)

    # Clean and deduplicate — must have at least one letter AND one digit
    cleaned = []
    for m in set(m.strip() for m in results):
        if len(m) >= 5 and re.search(r'[A-Za-z]', m) and re.search(r'\d', m):
            cleaned.append(m)
    return cleaned


def extract_all_intelligence(text: str) -> Dict[str, List[str]]:
    """Extract all types of intelligence from a text message."""
    return {
        "phoneNumbers": extract_phone_numbers(text),
        "bankAccounts": extract_bank_accounts(text),
        "upiIds": extract_upi_ids(text),
        "phishingLinks": extract_phishing_links(text),
        "emailAddresses": extract_email_addresses(text),
        "caseIds": extract_case_ids(text),
    }


def merge_intelligence(existing: Dict[str, List[str]], new: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Merge new intelligence into existing, deduplicating."""
    merged = {}
    all_keys = set(list(existing.keys()) + list(new.keys()))
    for key in all_keys:
        existing_vals = set(existing.get(key, []))
        new_vals = set(new.get(key, []))
        merged[key] = list(existing_vals | new_vals)
    return merged


def extract_from_conversation_history(history: List[Dict]) -> Dict[str, List[str]]:
    """Extract intelligence from full conversation history."""
    combined = {
        "phoneNumbers": [],
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "emailAddresses": [],
        "caseIds": [],
    }
    for msg in history:
        text = msg.get("text", "")
        sender = msg.get("sender", "")
        if sender == "scammer":
            intel = extract_all_intelligence(text)
            combined = merge_intelligence(combined, intel)
    return combined
