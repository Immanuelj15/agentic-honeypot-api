from fastapi import FastAPI, Header, HTTPException, Body, BackgroundTasks
from typing import Optional, Dict, Any, List
import re
import requests

app = FastAPI(title="Agentic Honeypot API")

API_KEY = "test123"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

session_store: Dict[str, Dict[str, Any]] = {}


@app.get("/")
def root():
    return {"message": "Honeypot API Running"}


def safe_lower(s: str) -> str:
    return (s or "").lower().strip()


def get_turn_count(history: List[Dict[str, Any]]) -> int:
    return len(history) if history else 0


def extract_upi_ids(text: str) -> List[str]:
    pattern = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
    return list(set(re.findall(pattern, text or "")))


def extract_links(text: str) -> List[str]:
    pattern = r"(https?://[^\s]+|www\.[^\s]+)"
    return list(set(re.findall(pattern, text or "")))


def extract_phone_numbers(text: str) -> List[str]:
    pattern = r"(\+91[\s\-]?\d{10}|\b\d{10}\b)"
    return list(set(re.findall(pattern, text or "")))


def extract_bank_accounts(text: str) -> List[str]:
    pattern = r"\b\d{9,18}\b"
    return list(set(re.findall(pattern, text or "")))


def extract_keywords(text: str) -> List[str]:
    keywords = [
        "urgent", "verify", "blocked", "suspended", "suspend", "account",
        "otp", "upi", "kyc", "fraud", "security", "transaction",
        "click", "link", "immediately", "bank"
    ]
    t = safe_lower(text)
    found = [k for k in keywords if k in t]
    return list(set(found))


def is_scam_message(text: str) -> bool:
    t = safe_lower(text)
    scam_signals = [
        "otp", "upi", "account blocked", "account suspended", "verify immediately",
        "click link", "kyc", "fraud", "security team", "urgent", "sbi",
        "bank account", "suspicious transaction"
    ]
    return any(sig in t for sig in scam_signals)


def keyword_reply(text: str) -> Optional[str]:
    t = safe_lower(text)

    if "otp" in t:
        return "An OTP? Is it safe to share an OTP with anyone? Why are you asking for it?"
    if "upi" in t:
        return "Is it safe to share my UPI ID? Can you prove you are an official representative?"
    if "account" in t and ("blocked" in t or "suspend" in t):
        return "Why is my account being blocked or suspended? What is the exact reason?"
    if "link" in t or "http" in t or "www" in t:
        return "Okay, please send the verification link again. I will check it."
    if "transaction" in t or "debited" in t or "credited" in t:
        return "Which transaction are you referring to? Please share the amount and reference number."
    if "security" in t or "fraud" in t:
        return "If you are from the bank security team, please share your employee ID and official helpline number."
    if "kyc" in t:
        return "KYC updates usually happen through the official app. Please share the official process details."
    if "card" in t or "cvv" in t:
        return "I cannot share card details. Please provide an official branch contact number."

    return None


def turn_based_reply(turn: int) -> str:
    if turn <= 0:
        return "Why is my account being suspended?"
    if turn <= 2:
        return "Can you tell me your employee ID and which branch you are calling from?"
    if turn <= 4:
        return "Okay, please send the official verification link. I will check."
    if turn <= 6:
        return "I am not comfortable sharing an OTP. What is the UPI ID again? Please type it clearly."
    return "I need your official helpline number and a reference ticket ID. Please share that."


def send_final_callback(payload: Dict[str, Any]) -> None:
    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception:
        pass


@app.post("/honeypot")
def honeypot(
    payload: Dict[str, Any] = Body(...),
    background_tasks: BackgroundTasks = None,
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = payload.get("sessionId", "unknown-session")
    message = payload.get("message", {})
    text = message.get("text", "")

    conversation_history = payload.get("conversationHistory", [])
    turn = get_turn_count(conversation_history)

    if session_id not in session_store:
        session_store[session_id] = {
            "totalMessagesExchanged": 0,
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [],
            "scamDetected": False,
            "callbackSent": False
        }

    store = session_store[session_id]
    store["totalMessagesExchanged"] = turn + 1

    if is_scam_message(text):
        store["scamDetected"] = True

    store["upiIds"] = list(set(store["upiIds"] + extract_upi_ids(text)))
    store["phishingLinks"] = list(set(store["phishingLinks"] + extract_links(text)))
    store["phoneNumbers"] = list(set(store["phoneNumbers"] + extract_phone_numbers(text)))
    store["bankAccounts"] = list(set(store["bankAccounts"] + extract_bank_accounts(text)))
    store["suspiciousKeywords"] = list(set(store["suspiciousKeywords"] + extract_keywords(text)))

    reply = keyword_reply(text)
    if not reply:
        reply = turn_based_reply(turn)

    if store["scamDetected"] and store["totalMessagesExchanged"] >= 8 and not store["callbackSent"]:
        callback_payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": store["totalMessagesExchanged"],
            "extractedIntelligence": {
                "bankAccounts": store["bankAccounts"],
                "upiIds": store["upiIds"],
                "phishingLinks": store["phishingLinks"],
                "phoneNumbers": store["phoneNumbers"],
                "suspiciousKeywords": store["suspiciousKeywords"]
            },
            "agentNotes": "The scammer used urgency and verification tactics to request sensitive details."
        }

        store["callbackSent"] = True

        if background_tasks is not None:
            background_tasks.add_task(send_final_callback, callback_payload)
        else:
            send_final_callback(callback_payload)

    return {
        "status": "success",
        "reply": reply
    }
git add .