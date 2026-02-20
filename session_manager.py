"""
Session management for the Honeypot API.
Thread-safe session tracking with scam detection, intelligence merging,
red flag identification, and final output builder.
"""

import time
from typing import Dict, Any
from extraction import extract_all_intelligence, merge_intelligence, scan_full_history

# Scam type classification patterns
SCAM_PATTERNS = {
    "bank_fraud": [
        "bank", "account compromised", "suspicious transaction", "fraud department",
        "sbi", "hdfc", "icici", "axis", "pnb", "rbi", "reserve bank",
        "account blocked", "account suspended", "debit card", "credit card",
    ],
    "upi_fraud": [
        "upi", "paytm", "phonepe", "gpay", "google pay", "send money",
        "collect request", "upi pin", "cashback", "refund",
    ],
    "phishing": [
        "click", "link", "verify", "update kyc", "login", "password",
        "amazon", "flipkart", "offer", "prize", "lottery", "won",
        "selected", "free", "claim", "reward",
    ],
    "otp_fraud": [
        "otp", "one time password", "verification code", "sms code",
        "share code", "send otp", "enter otp",
    ],
    "insurance_fraud": [
        "insurance", "policy", "premium", "claim settlement",
        "lic", "policy lapsed", "bonus",
    ],
}

RED_FLAG_KEYWORDS = [
    "urgent", "immediately", "blocked", "suspended", "otp", "verify",
    "click", "link", "fee", "charge", "limited time", "expire",
    "arrest", "legal", "penalty", "hurry", "last chance",
]

# In-memory session store
session_store: Dict[str, Dict[str, Any]] = {}


def get_or_create_session(session_id: str) -> Dict[str, Any]:
    """Get existing session or create a new one."""
    if session_id not in session_store:
        session_store[session_id] = {
            "startTime": time.time(),
            "scamDetected": False,
            "scamType": "unknown",
            "confidenceLevel": 0.0,
            "intelligence": {
                "phoneNumbers": [], "bankAccounts": [], "upiIds": [],
                "phishingLinks": [], "emailAddresses": [], "caseIds": [],
            },
            "redFlagsFound": [],
            "questionsAsked": 0,
            "totalMessagesExchanged": 0,
            "callbackSent": False,
            "usedResponses": set(),
        }
    return session_store[session_id]


def get_session(session_id: str):
    """Get session by ID, returns None if not found."""
    return session_store.get(session_id)


def mark_callback_sent(session_id: str):
    """Mark that the callback has been sent for a session."""
    if session_id in session_store:
        session_store[session_id]["callbackSent"] = True


def classify_scam(text: str) -> tuple:
    """Classify scam type based on keyword scoring."""
    t = text.lower()
    scores = {}
    for scam_type, keywords in SCAM_PATTERNS.items():
        score = sum(1 for k in keywords if k in t)
        if score > 0:
            scores[scam_type] = score
    if scores:
        best = max(scores, key=scores.get)
        confidence = min(scores[best] / 5.0, 1.0)
        return best, confidence
    return "unknown", 0.0


def update_session(session_id: str, text: str, conversation_history: list, reply: str):
    """Update session with new intelligence, scam detection, and metrics."""
    session = get_or_create_session(session_id)

    # Extract from current message
    current_intel = extract_all_intelligence(text)

    # Also scan full history
    history_intel = scan_full_history(conversation_history)

    # Merge all intelligence
    session["intelligence"] = merge_intelligence(session["intelligence"], current_intel)
    session["intelligence"] = merge_intelligence(session["intelligence"], history_intel)

    # Detect scam using full conversation text
    full_text = text + " " + " ".join(
        m.get("text", "") for m in conversation_history if m.get("sender") == "scammer"
    )
    scam_type, confidence = classify_scam(full_text)
    if confidence > 0:
        session["scamDetected"] = True
        if confidence > session["confidenceLevel"]:
            session["scamType"] = scam_type
            session["confidenceLevel"] = confidence

    # Red flags
    t = text.lower()
    for flag in RED_FLAG_KEYWORDS:
        if flag in t and flag not in session["redFlagsFound"]:
            session["redFlagsFound"].append(flag)

    # Questions asked
    session["questionsAsked"] += reply.count("?")

    # Message count — history + current scammer message + our reply
    session["totalMessagesExchanged"] = len(conversation_history) + 2

    return session


def build_final_output(session_id: str) -> Dict[str, Any]:
    """Build the final output payload for submission."""
    session = get_or_create_session(session_id)
    duration = int(time.time() - session["startTime"])

    is_scam = session["scamDetected"]

    red_flags_str = ", ".join(session["redFlagsFound"][:10]) if session["redFlagsFound"] else "suspicious behavior"
    agent_notes = (
        f"Scam type detected: {session['scamType']}. "
        f"Red flags identified: {red_flags_str}. "
        f"Scammer used social engineering tactics including urgency, impersonation, and verification pressure. "
        f"Total questions asked: {session['questionsAsked']}. "
        f"Intelligence extracted across {session['totalMessagesExchanged']} messages."
    )

    return {
        "sessionId": session_id,
        "scamDetected": is_scam,
        "scamType": session["scamType"] if is_scam else "none",
        "confidenceLevel": max(session["confidenceLevel"], 0.75) if is_scam else 0.0,
        "totalMessagesExchanged": session["totalMessagesExchanged"],
        "engagementDurationSeconds": max(duration, 1),
        "extractedIntelligence": {
            "phoneNumbers": session["intelligence"]["phoneNumbers"],
            "bankAccounts": session["intelligence"]["bankAccounts"],
            "upiIds": session["intelligence"]["upiIds"],
            "phishingLinks": session["intelligence"]["phishingLinks"],
            "emailAddresses": session["intelligence"]["emailAddresses"],
            "caseIds": session["intelligence"]["caseIds"],
        },
        "agentNotes": agent_notes,
    }
