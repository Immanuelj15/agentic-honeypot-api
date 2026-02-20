"""
Session management for the Honeypot API.
Tracks conversation state, extracted intelligence, and scoring metrics.
"""

import time
import threading
from typing import Dict, Any, List, Optional
from extraction import extract_all_intelligence, merge_intelligence, extract_from_conversation_history


# Thread-safe session store
_sessions: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()

# Scam type detection patterns
SCAM_PATTERNS = {
    "bank_fraud": [
        "bank", "account compromised", "suspicious transaction", "fraud department",
        "sbi", "hdfc", "icici", "axis", "pnb", "rbi", "reserve bank",
        "account blocked", "account suspended", "debit card", "credit card"
    ],
    "upi_fraud": [
        "upi", "paytm", "gpay", "google pay", "phonepe", "cashback",
        "payment pending", "collect request", "upi pin", "refund",
        "money transfer", "bhim"
    ],
    "phishing": [
        "click", "link", "verify", "update kyc", "kyc expired",
        "offer", "prize", "winner", "congratulations", "claim",
        "lottery", "reward", "coupon", "deal", "free"
    ],
    "tech_support": [
        "computer", "virus", "malware", "microsoft", "windows",
        "remote access", "anydesk", "teamviewer", "tech support",
        "software", "license"
    ],
    "insurance_fraud": [
        "insurance", "policy", "premium", "maturity", "claim settlement",
        "lic", "policy lapsed", "bonus", "endowment"
    ],
    "delivery_fraud": [
        "delivery", "package", "courier", "shipment", "order",
        "customs", "parcel", "tracking", "amazon", "flipkart"
    ],
}

# Red flag keywords
RED_FLAGS = [
    "urgent", "immediately", "otp", "verify", "expir", "blocked",
    "suspended", "warn", "penalty", "legal action", "arrest",
    "police", "court", "freeze", "deadline", "last chance",
    "act now", "right away", "don't delay", "hurry", "emergency",
    "fine", "fee", "charge", "pay now", "transfer", "time sensitive"
]


def get_or_create_session(session_id: str) -> Dict[str, Any]:
    """Get existing session or create a new one."""
    with _lock:
        if session_id not in _sessions:
            _sessions[session_id] = {
                "startTime": time.time(),
                "scamDetected": False,
                "callbackSent": False,
                "totalMessagesExchanged": 0,
                "intelligence": {
                    "phoneNumbers": [],
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "emailAddresses": [],
                    "caseIds": [],
                },
                "scamType": "unknown",
                "confidenceLevel": 0.0,
                "redFlagsFound": [],
                "questionsAsked": 0,
                "usedResponses": set(),
                "allScammerTexts": [],
                "historyProcessed": False,
            }
        return _sessions[session_id]


def update_session(session_id: str, text: str, conversation_history: List[Dict], reply: str) -> Dict[str, Any]:
    """Update session with new message data and return updated session."""
    session = get_or_create_session(session_id)

    with _lock:
        # Process full conversation history on first encounter
        if not session["historyProcessed"] and conversation_history:
            history_intel = extract_from_conversation_history(conversation_history)
            session["intelligence"] = merge_intelligence(session["intelligence"], history_intel)

            # Extract red flags from history
            for msg in conversation_history:
                if msg.get("sender") == "scammer":
                    msg_text = msg.get("text", "").lower()
                    for flag in RED_FLAGS:
                        if flag in msg_text and flag not in session["redFlagsFound"]:
                            session["redFlagsFound"].append(flag)

            session["historyProcessed"] = True

        # Store scammer text
        session["allScammerTexts"].append(text)

        # Extract intelligence from current message
        current_intel = extract_all_intelligence(text)
        session["intelligence"] = merge_intelligence(session["intelligence"], current_intel)

        # Update message count — history has both scammer + user messages
        # Plus current scammer message + our reply = +2
        session["totalMessagesExchanged"] = len(conversation_history) + 2

        # Detect scam
        text_lower = text.lower()
        scam_signals = 0
        scam_keywords = [
            "otp", "verify", "urgent", "blocked", "suspended", "kyc",
            "fraud", "security", "transaction", "click", "link",
            "immediately", "expired", "penalty", "legal", "arrest",
            "fee", "charge", "transfer", "pin", "password", "cvv"
        ]
        for keyword in scam_keywords:
            if keyword in text_lower:
                scam_signals += 1

        if scam_signals > 0:
            session["scamDetected"] = True

        # Detect scam type
        all_text = " ".join(session["allScammerTexts"]).lower()
        best_type = "unknown"
        best_score = 0
        for stype, patterns in SCAM_PATTERNS.items():
            score = sum(1 for p in patterns if p in all_text)
            if score > best_score:
                best_score = score
                best_type = stype
        session["scamType"] = best_type

        # Calculate confidence
        total_signals = scam_signals
        for prev_text in session["allScammerTexts"][:-1]:
            for keyword in scam_keywords:
                if keyword in prev_text.lower():
                    total_signals += 1
        session["confidenceLevel"] = min(1.0, round(total_signals * 0.15, 2))

        # Extract red flags
        for flag in RED_FLAGS:
            if flag in text_lower and flag not in session["redFlagsFound"]:
                session["redFlagsFound"].append(flag)

        # Count questions in our reply
        if "?" in reply:
            session["questionsAsked"] += reply.count("?")

        # Track used responses
        session["usedResponses"].add(reply)

    return session


def build_final_output(session_id: str) -> Dict[str, Any]:
    """Build the final output payload for submission."""
    session = get_or_create_session(session_id)

    duration = int(time.time() - session["startTime"])

    # Build agent notes
    red_flags_str = ", ".join(session["redFlagsFound"][:10]) if session["redFlagsFound"] else "suspicious behavior"
    agent_notes = (
        f"Scam type detected: {session['scamType']}. "
        f"Red flags identified: {red_flags_str}. "
        f"Scammer used social engineering tactics including urgency, impersonation, and verification pressure. "
        f"Total questions asked: {session['questionsAsked']}. "
        f"Intelligence extracted across {session['totalMessagesExchanged']} messages."
    )

    is_scam = session["scamDetected"]

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


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session data (read-only)."""
    with _lock:
        return _sessions.get(session_id)


def mark_callback_sent(session_id: str):
    """Mark that callback has been sent for this session."""
    with _lock:
        if session_id in _sessions:
            _sessions[session_id]["callbackSent"] = True
